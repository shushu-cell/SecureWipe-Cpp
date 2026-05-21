#include "internal/secure_wipe_engine.h"

#if defined(__linux__)
#include "internal/linux_mount_utils.h"
#endif

#include <array>
#include <cctype>
#include <fstream>
#include <optional>
#include <ranges>
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

enum class ReviewKind {
    DeviceSanitize,
    CryptoErase,
};

struct ReviewPolicy {
    ReviewKind review_kind;
    DeviceBusKind bus_kind;
    CapabilityState default_state;
    std::optional<StorageKind> override_storage_kind;
    CapabilityState override_state;
};

constexpr std::array kReviewPolicies{
    ReviewPolicy{
        ReviewKind::DeviceSanitize,
        DeviceBusKind::Nvme,
        CapabilityState::Supported,
        std::nullopt,
        CapabilityState::Supported,
    },
    ReviewPolicy{
        ReviewKind::DeviceSanitize,
        DeviceBusKind::Ata,
        CapabilityState::Supported,
        std::nullopt,
        CapabilityState::Supported,
    },
    ReviewPolicy{
        ReviewKind::DeviceSanitize,
        DeviceBusKind::Sata,
        CapabilityState::Supported,
        std::nullopt,
        CapabilityState::Supported,
    },
    ReviewPolicy{
        ReviewKind::DeviceSanitize,
        DeviceBusKind::Scsi,
        CapabilityState::Supported,
        std::nullopt,
        CapabilityState::Supported,
    },
    ReviewPolicy{
        ReviewKind::CryptoErase,
        DeviceBusKind::Nvme,
        CapabilityState::Supported,
        StorageKind::RotationalDisk,
        CapabilityState::Unsupported,
    },
    ReviewPolicy{
        ReviewKind::CryptoErase,
        DeviceBusKind::Ata,
        CapabilityState::Supported,
        StorageKind::RotationalDisk,
        CapabilityState::Unsupported,
    },
    ReviewPolicy{
        ReviewKind::CryptoErase,
        DeviceBusKind::Sata,
        CapabilityState::Supported,
        StorageKind::RotationalDisk,
        CapabilityState::Unsupported,
    },
    ReviewPolicy{
        ReviewKind::CryptoErase,
        DeviceBusKind::Scsi,
        CapabilityState::Unknown,
        StorageKind::SolidState,
        CapabilityState::Supported,
    },
    ReviewPolicy{
        ReviewKind::CryptoErase,
        DeviceBusKind::Unknown,
        CapabilityState::Unknown,
        StorageKind::RotationalDisk,
        CapabilityState::Unsupported,
    },
};

void append_probe_evidence(
    DeviceProbeSnapshot& snapshot,
    EvidenceSubject subject,
    EvidenceSource source,
    EvidenceConfidence confidence,
    std::string summary) {
    snapshot.evidence_items.push_back(CapabilityEvidenceItem{
        .subject = subject,
        .source = source,
        .confidence = confidence,
        .summary = summary,
    });
    snapshot.evidence.push_back(std::move(summary));
}

void append_capability_evidence(
    DeviceCapabilities& capabilities,
    EvidenceSubject subject,
    EvidenceSource source,
    EvidenceConfidence confidence,
    std::string summary) {
    capabilities.evidence_items.push_back(CapabilityEvidenceItem{
        .subject = subject,
        .source = source,
        .confidence = confidence,
        .summary = summary,
    });
    capabilities.evidence.push_back(std::move(summary));
}

std::string_view review_label(ReviewKind review_kind) noexcept {
    switch (review_kind) {
    case ReviewKind::DeviceSanitize:
        return "device-level sanitization";
    case ReviewKind::CryptoErase:
        return "crypto-erase";
    }

    return "manual review";
}

EvidenceSubject review_subject(ReviewKind review_kind) noexcept {
    switch (review_kind) {
    case ReviewKind::DeviceSanitize:
        return EvidenceSubject::DeviceSanitizeReview;
    case ReviewKind::CryptoErase:
        return EvidenceSubject::CryptoEraseReview;
    }

    return EvidenceSubject::Restriction;
}

EvidenceConfidence review_confidence(CapabilityState state) noexcept {
    switch (state) {
    case CapabilityState::Supported:
    case CapabilityState::Unsupported:
        return EvidenceConfidence::Inferred;
    case CapabilityState::Restricted:
    case CapabilityState::Unknown:
        return EvidenceConfidence::ConservativeFallback;
    }

    return EvidenceConfidence::ConservativeFallback;
}

std::string build_review_summary(
    ReviewKind review_kind,
    CapabilityState state,
    const DeviceProbeSnapshot& snapshot,
    StorageKind storage_kind) {
    const std::string review_name(review_label(review_kind));

    if (storage_kind == StorageKind::NetworkShare || snapshot.bus_kind == DeviceBusKind::Network) {
        return "Network-backed paths keep " + review_name + " on a restricted review path.";
    }

    if (snapshot.usb_bridge_suspected) {
        return "USB bridge scenarios keep " + review_name + " on a restricted review path.";
    }

    switch (state) {
    case CapabilityState::Supported:
        return "Current bus and storage signals support reviewing " + review_name + " for the underlying device.";
    case CapabilityState::Unsupported:
        return "Current bus and storage signals do not support reviewing " + review_name + " for the underlying device.";
    case CapabilityState::Restricted:
        return "Current path keeps " + review_name + " on a restricted review path.";
    case CapabilityState::Unknown:
        return "Current signals are insufficient to determine whether " + review_name + " should be reviewed for the underlying device.";
    }

    return "Current signals do not provide a stable review recommendation.";
}

void append_review_state_evidence(
    DeviceCapabilities& capabilities,
    ReviewKind review_kind,
    CapabilityState state,
    const DeviceProbeSnapshot& snapshot,
    StorageKind storage_kind) {
    append_capability_evidence(
        capabilities,
        review_subject(review_kind),
        EvidenceSource::HeuristicGuard,
        review_confidence(state),
        build_review_summary(review_kind, state, snapshot, storage_kind));
}

constexpr bool is_restricted_bus(DeviceBusKind bus_kind) noexcept {
    return bus_kind == DeviceBusKind::Usb
        || bus_kind == DeviceBusKind::Virtual
        || bus_kind == DeviceBusKind::Network;
}

const ReviewPolicy* find_review_policy(ReviewKind review_kind, DeviceBusKind bus_kind) {
    const auto policy = std::ranges::find_if(kReviewPolicies, [review_kind, bus_kind](const ReviewPolicy& candidate) {
        return candidate.review_kind == review_kind && candidate.bus_kind == bus_kind;
    });

    return policy != kReviewPolicies.end() ? &*policy : nullptr;
}

CapabilityState classify_restricted_review_state(const DeviceProbeSnapshot& snapshot, StorageKind storage_kind) {
    if (storage_kind == StorageKind::NetworkShare || snapshot.bus_kind == DeviceBusKind::Network) {
        return CapabilityState::Restricted;
    }

    if (snapshot.usb_bridge_suspected) {
        return CapabilityState::Restricted;
    }

    return CapabilityState::Unknown;
}

CapabilityState classify_review_for_bus(ReviewKind review_kind, DeviceBusKind bus_kind, StorageKind storage_kind) {
    if (is_restricted_bus(bus_kind)) {
        return CapabilityState::Restricted;
    }

    if (const ReviewPolicy* policy = find_review_policy(review_kind, bus_kind); policy != nullptr) {
        if (policy->override_storage_kind == storage_kind) {
            return policy->override_state;
        }

        return policy->default_state;
    }

    return CapabilityState::Unknown;
}

CapabilityState classify_review_state(
    ReviewKind review_kind,
    const DeviceProbeSnapshot& snapshot,
    StorageKind storage_kind) {
    const CapabilityState restricted_state = classify_restricted_review_state(snapshot, storage_kind);
    if (restricted_state == CapabilityState::Restricted) {
        return restricted_state;
    }

    return classify_review_for_bus(review_kind, snapshot.bus_kind, storage_kind);
}

#if defined(_WIN32)
class ScopedWindowsHandle final {
public:
    explicit ScopedWindowsHandle(HANDLE handle) noexcept
        : handle_(handle) {
    }

    ~ScopedWindowsHandle() noexcept {
        if (is_valid()) {
            CloseHandle(handle_);
        }
    }

    ScopedWindowsHandle(const ScopedWindowsHandle&) = delete;
    ScopedWindowsHandle& operator=(const ScopedWindowsHandle&) = delete;

    [[nodiscard]] HANDLE get() const noexcept {
        return handle_;
    }

    [[nodiscard]] bool is_valid() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE handle_;
};

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
        append_probe_evidence(
            snapshot,
            EvidenceSubject::Restriction,
            EvidenceSource::WindowsStorageQuery,
            EvidenceConfidence::ConservativeFallback,
            "Windows storage property query was unavailable for this path.");
        return;
    }

    const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
    snapshot.bus_kind = map_windows_bus_type(descriptor->BusType);
    snapshot.is_removable_media = snapshot.is_removable_media || descriptor->RemovableMedia != 0;
    snapshot.usb_bridge_suspected = snapshot.bus_kind == DeviceBusKind::Usb;

    if (snapshot.bus_kind != DeviceBusKind::Unknown) {
        append_probe_evidence(
            snapshot,
            EvidenceSubject::BusKind,
            EvidenceSource::WindowsStorageQuery,
            EvidenceConfidence::Observed,
            "Windows storage stack reported a concrete device bus type.");
    }
}

DeviceProbeSnapshot probe_windows_device_capabilities(const fs::path& path, DeviceProbeSnapshot snapshot) {
    const fs::path root = path.root_path();
    if (root.empty()) {
        append_probe_evidence(
            snapshot,
            EvidenceSubject::Restriction,
            EvidenceSource::PathInspection,
            EvidenceConfidence::ConservativeFallback,
            "Path does not expose a stable root for Windows storage probing.");
        return snapshot;
    }

    const std::wstring device_path = volume_device_path_from_root(root);
    if (device_path.empty()) {
        append_probe_evidence(
            snapshot,
            EvidenceSubject::Restriction,
            EvidenceSource::WindowsStorageQuery,
            EvidenceConfidence::ConservativeFallback,
            "Windows volume device path could not be derived from the target root.");
        return snapshot;
    }

    const ScopedWindowsHandle handle(CreateFileW(
        device_path.c_str(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr));
    if (!handle.is_valid()) {
        append_probe_evidence(
            snapshot,
            EvidenceSubject::Restriction,
            EvidenceSource::WindowsStorageQuery,
            EvidenceConfidence::ConservativeFallback,
            "Windows volume handle could not be opened for read-only capability probing.");
        return snapshot;
    }

    populate_windows_device_descriptor(handle.get(), snapshot);
    snapshot.trim_support = query_trim_support(handle.get());
    if (snapshot.trim_support != CapabilityState::Unknown) {
        append_probe_evidence(
            snapshot,
            EvidenceSubject::TrimSupport,
            EvidenceSource::WindowsStorageQuery,
            EvidenceConfidence::Observed,
            "Windows storage stack returned trim/discard capability information.");
    }

    return snapshot;
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

DeviceProbeSnapshot probe_linux_device_capabilities(const fs::path& path, DeviceProbeSnapshot snapshot) {
    const auto best_match = find_best_linux_mount_entry(path);
    if (!best_match) {
        append_probe_evidence(
            snapshot,
            EvidenceSubject::Restriction,
            EvidenceSource::LinuxMountMetadata,
            EvidenceConfidence::ConservativeFallback,
            "Linux mount metadata could not be resolved for this path.");
        return snapshot;
    }

    if (best_match->source.rfind("/dev/", 0) != 0) {
        append_probe_evidence(
            snapshot,
            EvidenceSubject::Restriction,
            EvidenceSource::LinuxMountMetadata,
            EvidenceConfidence::ConservativeFallback,
            "Linux mount source is not a direct /dev block device.");
        return snapshot;
    }

    const std::string device_name = normalize_linux_block_device_name(best_match->source);
    if (device_name.empty()) {
        append_probe_evidence(
            snapshot,
            EvidenceSubject::Restriction,
            EvidenceSource::LinuxMountMetadata,
            EvidenceConfidence::ConservativeFallback,
            "Linux block device name could not be normalized from the mount source.");
        return snapshot;
    }

    const std::string removable = read_text_file(fs::path("/sys/class/block") / device_name / "removable");
    snapshot.is_removable_media = snapshot.is_removable_media || removable == "1";
    snapshot.trim_support = read_discard_support(device_name);
    if (snapshot.trim_support != CapabilityState::Unknown) {
        append_probe_evidence(
            snapshot,
            EvidenceSubject::TrimSupport,
            EvidenceSource::LinuxSysfs,
            EvidenceConfidence::Observed,
            "Linux sysfs exposed trim/discard capability information for this device.");
    }

    std::error_code ec;
    const fs::path sysfs_device = fs::weakly_canonical(fs::path("/sys/class/block") / device_name / "device", ec);
    if (!ec) {
        const std::string sysfs_path = sysfs_device.string();
        snapshot.bus_kind = infer_linux_bus_kind(sysfs_path, device_name);
        snapshot.usb_bridge_suspected = snapshot.bus_kind == DeviceBusKind::Usb;
        if (snapshot.bus_kind != DeviceBusKind::Unknown) {
            append_probe_evidence(
                snapshot,
                EvidenceSubject::BusKind,
                EvidenceSource::LinuxSysfs,
                EvidenceConfidence::Inferred,
                "Linux sysfs exposed a concrete device bus hint for this path.");
        } else {
            append_probe_evidence(
                snapshot,
                EvidenceSubject::Restriction,
                EvidenceSource::LinuxSysfs,
                EvidenceConfidence::ConservativeFallback,
                "Linux sysfs did not expose a concrete device bus classification for this path.");
        }
    } else {
        append_probe_evidence(
            snapshot,
            EvidenceSubject::Restriction,
            EvidenceSource::LinuxSysfs,
            EvidenceConfidence::ConservativeFallback,
            "Linux sysfs device metadata could not be resolved for this path.");
    }

    return snapshot;
}
#endif

DeviceProbeSnapshot probe_unsupported_platform_capabilities(const fs::path& path, DeviceProbeSnapshot snapshot) {
    (void)path;
    append_probe_evidence(
        snapshot,
        EvidenceSubject::Restriction,
        EvidenceSource::PlatformFallback,
        EvidenceConfidence::ConservativeFallback,
        "Detailed device capability probing is not implemented on this platform.");
    return snapshot;
}

} // namespace

DeviceProbeSnapshot SystemDeviceCapabilityProbe::probe(const fs::path& path, StorageKind storage_kind) const {
    DeviceProbeSnapshot snapshot;
    snapshot.is_removable_media = storage_kind == StorageKind::RemovableDisk;

    if (storage_kind == StorageKind::NetworkShare) {
        snapshot.bus_kind = DeviceBusKind::Network;
        append_probe_evidence(
            snapshot,
            EvidenceSubject::Restriction,
            EvidenceSource::PathInspection,
            EvidenceConfidence::ConservativeFallback,
            "Network-backed paths do not expose a local block device for direct inspection.");
        return snapshot;
    }

#if defined(_WIN32)
    return probe_windows_device_capabilities(path, std::move(snapshot));
#elif defined(__linux__)
    return probe_linux_device_capabilities(path, std::move(snapshot));
#else
    return probe_unsupported_platform_capabilities(path, std::move(snapshot));
#endif
}

DeviceCapabilityInspector::DeviceCapabilityInspector(const DeviceCapabilityProbe& probe) noexcept
    : probe_(probe) {
}

DeviceCapabilities DeviceCapabilityInspector::inspect(const DeviceInspectionContext& context) const {
    const DeviceProbeSnapshot snapshot = probe_.probe(context.resolved_path, context.storage_kind);

    DeviceCapabilities capabilities;
    capabilities.bus_kind = snapshot.bus_kind;
    capabilities.trim_support = snapshot.trim_support;
    capabilities.device_sanitize_review = classify_review_state(
        ReviewKind::DeviceSanitize,
        snapshot,
        context.storage_kind);
    capabilities.crypto_erase_review = classify_review_state(
        ReviewKind::CryptoErase,
        snapshot,
        context.storage_kind);
    capabilities.is_removable_media = snapshot.is_removable_media;
    capabilities.usb_bridge_suspected = snapshot.usb_bridge_suspected;
    capabilities.evidence = snapshot.evidence;
    capabilities.evidence_items = snapshot.evidence_items;
    append_review_state_evidence(
        capabilities,
        ReviewKind::DeviceSanitize,
        capabilities.device_sanitize_review,
        snapshot,
        context.storage_kind);
    append_review_state_evidence(
        capabilities,
        ReviewKind::CryptoErase,
        capabilities.crypto_erase_review,
        snapshot,
        context.storage_kind);
    return capabilities;
}

} // namespace securewipe::detail