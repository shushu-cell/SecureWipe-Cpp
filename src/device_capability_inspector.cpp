#include "internal/secure_wipe_engine.h"

#if defined(__linux__)
#include "internal/linux_mount_utils.h"
#endif

#include <array>
#include <cctype>
#include <fstream>
#include <optional>
#include <sstream>
#include <string_view>
#include <system_error>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>

#ifdef DeviceCapabilities
#undef DeviceCapabilities
#endif
#endif

namespace securewipe::detail {

namespace {

void append_evidence(std::vector<std::string>& evidence, std::string_view line) {
    evidence.emplace_back(line);
}

CapabilityState classify_device_sanitize_review(const DeviceProbeSnapshot& snapshot, StorageKind storage_kind) {
    if (storage_kind == StorageKind::NetworkShare || snapshot.bus_kind == DeviceBusKind::Network) {
        return CapabilityState::Restricted;
    }

    if (snapshot.usb_bridge_suspected) {
        return CapabilityState::Restricted;
    }

    switch (snapshot.bus_kind) {
    case DeviceBusKind::Nvme:
    case DeviceBusKind::Ata:
    case DeviceBusKind::Sata:
    case DeviceBusKind::Scsi:
        return CapabilityState::Supported;
    case DeviceBusKind::Usb:
    case DeviceBusKind::Virtual:
        return CapabilityState::Restricted;
    case DeviceBusKind::Network:
        return CapabilityState::Restricted;
    case DeviceBusKind::Unknown:
        return CapabilityState::Unknown;
    }

    return CapabilityState::Unknown;
}

CapabilityState classify_crypto_erase_review(const DeviceProbeSnapshot& snapshot, StorageKind storage_kind) {
    if (storage_kind == StorageKind::NetworkShare || snapshot.bus_kind == DeviceBusKind::Network) {
        return CapabilityState::Restricted;
    }

    if (snapshot.usb_bridge_suspected) {
        return CapabilityState::Restricted;
    }

    switch (snapshot.bus_kind) {
    case DeviceBusKind::Nvme:
    case DeviceBusKind::Ata:
    case DeviceBusKind::Sata:
        return storage_kind == StorageKind::RotationalDisk
            ? CapabilityState::Unsupported
            : CapabilityState::Supported;
    case DeviceBusKind::Scsi:
        return storage_kind == StorageKind::SolidState
            ? CapabilityState::Supported
            : CapabilityState::Unknown;
    case DeviceBusKind::Usb:
    case DeviceBusKind::Virtual:
        return CapabilityState::Restricted;
    case DeviceBusKind::Network:
        return CapabilityState::Restricted;
    case DeviceBusKind::Unknown:
        return storage_kind == StorageKind::RotationalDisk
            ? CapabilityState::Unsupported
            : CapabilityState::Unknown;
    }

    return CapabilityState::Unknown;
}

#if defined(_WIN32)
std::wstring volume_device_path_from_root(const fs::path& root) {
    const std::wstring root_string = root.wstring();
    if (root_string.size() < 2 || root_string[1] != L':') {
        return {};
    }

    return LR"(\\.\)" + root_string.substr(0, 2);
}

DeviceBusKind map_windows_bus_type(STORAGE_BUS_TYPE bus_type) {
    switch (bus_type) {
    case BusTypeUsb:
        return DeviceBusKind::Usb;
    case BusTypeAta:
        return DeviceBusKind::Ata;
    case BusTypeSata:
        return DeviceBusKind::Sata;
    case BusTypeNvme:
        return DeviceBusKind::Nvme;
    case BusTypeScsi:
        return DeviceBusKind::Scsi;
    case BusTypeVirtual:
    case BusTypeFileBackedVirtual:
    case BusTypeSpaces:
        return DeviceBusKind::Virtual;
    default:
        return DeviceBusKind::Unknown;
    }
}

CapabilityState query_trim_support(HANDLE handle) {
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceTrimProperty;
    query.QueryType = PropertyStandardQuery;

    DEVICE_TRIM_DESCRIPTOR descriptor{};
    DWORD bytes_returned = 0;
    if (DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query,
            sizeof(query),
            &descriptor,
            sizeof(descriptor),
            &bytes_returned,
            nullptr) == 0) {
        return CapabilityState::Unknown;
    }

    return descriptor.TrimEnabled != 0
        ? CapabilityState::Supported
        : CapabilityState::Unsupported;
}

void populate_windows_device_descriptor(HANDLE handle, DeviceProbeSnapshot& snapshot) {
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    std::array<std::byte, 1024> buffer{};
    DWORD bytes_returned = 0;
    if (DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query,
            sizeof(query),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &bytes_returned,
            nullptr) == 0) {
        append_evidence(snapshot.evidence, "Windows storage property query was unavailable for this path.");
        return;
    }

    const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
    snapshot.bus_kind = map_windows_bus_type(descriptor->BusType);
    snapshot.is_removable_media = snapshot.is_removable_media || descriptor->RemovableMedia != 0;
    snapshot.usb_bridge_suspected = snapshot.bus_kind == DeviceBusKind::Usb;

    if (snapshot.bus_kind != DeviceBusKind::Unknown) {
        append_evidence(snapshot.evidence, "Windows storage stack reported a concrete device bus type.");
    }
}
#endif

#if defined(__linux__)

std::string read_text_file(const fs::path& path) {
    std::ifstream input(path);
    if (!input) {
        return {};
    }

    std::string value;
    std::getline(input, value);
    return value;
}

DeviceBusKind infer_linux_bus_kind(std::string_view sysfs_path, std::string_view device_name) {
    if (device_name.rfind("nvme", 0) == 0 || sysfs_path.find("/nvme/") != std::string_view::npos) {
        return DeviceBusKind::Nvme;
    }

    if (sysfs_path.find("/usb") != std::string_view::npos) {
        return DeviceBusKind::Usb;
    }

    if (sysfs_path.find("/virtio") != std::string_view::npos ||
        sysfs_path.find("/virtual/") != std::string_view::npos ||
        sysfs_path.find("/vmbus/") != std::string_view::npos) {
        return DeviceBusKind::Virtual;
    }

    if (sysfs_path.find("/ata") != std::string_view::npos) {
        return DeviceBusKind::Sata;
    }

    if (sysfs_path.find("/scsi") != std::string_view::npos) {
        return DeviceBusKind::Scsi;
    }

    return DeviceBusKind::Unknown;
}

CapabilityState read_discard_support(const std::string& device_name) {
    const std::string discard_max_bytes = read_text_file(
        fs::path("/sys/class/block") / device_name / "queue" / "discard_max_bytes");
    if (discard_max_bytes.empty()) {
        return CapabilityState::Unknown;
    }

    try {
        return std::stoull(discard_max_bytes) > 0
            ? CapabilityState::Supported
            : CapabilityState::Unsupported;
    } catch (...) {
        return CapabilityState::Unknown;
    }
}
#endif

} // namespace

DeviceProbeSnapshot SystemDeviceCapabilityProbe::probe(const fs::path& path, StorageKind storage_kind) const {
    DeviceProbeSnapshot snapshot;
    snapshot.is_removable_media = storage_kind == StorageKind::RemovableDisk;

    if (storage_kind == StorageKind::NetworkShare) {
        snapshot.bus_kind = DeviceBusKind::Network;
        append_evidence(snapshot.evidence, "Network-backed paths do not expose a local block device for direct inspection.");
        return snapshot;
    }

#if defined(_WIN32)
    const fs::path root = path.root_path();
    if (root.empty()) {
        append_evidence(snapshot.evidence, "Path does not expose a stable root for Windows storage probing.");
        return snapshot;
    }

    const std::wstring device_path = volume_device_path_from_root(root);
    if (device_path.empty()) {
        append_evidence(snapshot.evidence, "Windows volume device path could not be derived from the target root.");
        return snapshot;
    }

    const HANDLE handle = CreateFileW(
        device_path.c_str(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        append_evidence(snapshot.evidence, "Windows volume handle could not be opened for read-only capability probing.");
        return snapshot;
    }

    populate_windows_device_descriptor(handle, snapshot);
    snapshot.trim_support = query_trim_support(handle);
    if (snapshot.trim_support != CapabilityState::Unknown) {
        append_evidence(snapshot.evidence, "Windows storage stack returned trim/discard capability information.");
    }
    CloseHandle(handle);
#elif defined(__linux__)
    const auto best_match = find_best_linux_mount_entry(path);
    if (!best_match) {
        append_evidence(snapshot.evidence, "Linux mount metadata could not be resolved for this path.");
        return snapshot;
    }

    if (best_match->source.rfind("/dev/", 0) != 0) {
        append_evidence(snapshot.evidence, "Linux mount source is not a direct /dev block device.");
        return snapshot;
    }

    const std::string device_name = normalize_linux_block_device_name(best_match->source);
    if (device_name.empty()) {
        append_evidence(snapshot.evidence, "Linux block device name could not be normalized from the mount source.");
        return snapshot;
    }

    const std::string removable = read_text_file(fs::path("/sys/class/block") / device_name / "removable");
    snapshot.is_removable_media = snapshot.is_removable_media || removable == "1";
    snapshot.trim_support = read_discard_support(device_name);

    std::error_code ec;
    const fs::path sysfs_device = fs::weakly_canonical(fs::path("/sys/class/block") / device_name / "device", ec);
    if (!ec) {
        const std::string sysfs_path = sysfs_device.string();
        snapshot.bus_kind = infer_linux_bus_kind(sysfs_path, device_name);
        snapshot.usb_bridge_suspected = snapshot.bus_kind == DeviceBusKind::Usb;
    }

    append_evidence(snapshot.evidence, "Linux sysfs and mount metadata were used to infer device capabilities.");
#else
    (void)path;
    append_evidence(snapshot.evidence, "Detailed device capability probing is not implemented on this platform.");
#endif

    return snapshot;
}

DeviceCapabilityInspector::DeviceCapabilityInspector(const DeviceCapabilityProbe& probe) noexcept
    : probe_(probe) {
}

DeviceCapabilities DeviceCapabilityInspector::inspect(const fs::path& path, StorageKind storage_kind) const {
    const DeviceProbeSnapshot snapshot = probe_.probe(path, storage_kind);

    DeviceCapabilities capabilities;
    capabilities.bus_kind = snapshot.bus_kind;
    capabilities.trim_support = snapshot.trim_support;
    capabilities.device_sanitize_review = classify_device_sanitize_review(snapshot, storage_kind);
    capabilities.crypto_erase_review = classify_crypto_erase_review(snapshot, storage_kind);
    capabilities.is_removable_media = snapshot.is_removable_media;
    capabilities.usb_bridge_suspected = snapshot.usb_bridge_suspected;
    capabilities.evidence = snapshot.evidence;
    return capabilities;
}

} // namespace securewipe::detail