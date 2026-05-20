#include "internal/secure_wipe_engine.h"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <system_error>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#endif

namespace securewipe::detail {

namespace {

bool is_missing_path_error(const std::error_code& error) {
    return error == std::errc::no_such_file_or_directory;
}

std::string decode_mount_field(std::string value) {
    std::string result;
    result.reserve(value.size());
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index + 3 < value.size() && value.compare(index, 4, "\\040") == 0) {
            result.push_back(' ');
            index += 3;
            continue;
        }
        result.push_back(value[index]);
    }
    return result;
}

#if defined(_WIN32)
std::string wide_to_utf8(const std::wstring& value) {
    if (value.empty()) return {};

    const int required_size = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (required_size <= 0) return {};

    std::string converted(static_cast<std::size_t>(required_size), '\0');
    const int converted_size = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        converted.data(),
        required_size,
        nullptr,
        nullptr);
    if (converted_size <= 0) return {};

    return converted;
}
#endif

} // namespace

InspectionReport PathInspector::inspect(const std::string& path) const {
    return inspect(fs::path(path));
}

InspectionReport PathInspector::inspect(const fs::path& path) const {
    InspectionReport report;
    const fs::path resolved = resolve_path(path);
    report.canonical_path = resolved.string();
    report.volume_name = filesystem_hint_for_path(resolved);

    std::error_code ec;
    const fs::file_status link_status = fs::symlink_status(path, ec);
    if (ec) {
        if (is_missing_path_error(ec)) {
            report.message = "Path does not exist";
            return report;
        }

        report.message = "Failed to inspect path: " + ec.message();
        return report;
    }

    if (!fs::exists(link_status)) {
        report.message = "Path does not exist";
        return report;
    }

    report.ok = true;
    report.storage_kind = detect_storage_kind(resolved);

    if (fs::is_symlink(link_status)) {
        report.target_kind = TargetKind::Symlink;
        report.recommendation = StrategyRecommendation::Refuse;
        report.message = "Refusing to follow symlinks for destructive operations.";
        report.warnings.push_back("Symlink targets can escape the intended directory tree.");
        return report;
    }

    if (fs::is_regular_file(link_status)) {
        report.target_kind = TargetKind::RegularFile;
        report.recommendation = StrategyRecommendation::BestEffortFileOverwrite;
        report.message = "File can be overwritten and removed as a best-effort operation.";
    } else if (fs::is_directory(link_status)) {
        report.target_kind = TargetKind::Directory;
        report.dangerous = is_dangerous_directory(resolved);
        report.recommendation = report.dangerous
            ? StrategyRecommendation::Refuse
            : StrategyRecommendation::BestEffortDirectoryWipe;
        report.message = report.dangerous
            ? "Directory is considered too dangerous for recursive wipe."
            : "Directory can be traversed and wiped as a best-effort operation.";
    } else {
        report.target_kind = TargetKind::Other;
        report.recommendation = StrategyRecommendation::Refuse;
        report.message = "Only regular files and directories are supported.";
    }

    if (report.storage_kind == StorageKind::NetworkShare) {
        report.recommendation = StrategyRecommendation::Refuse;
        report.warnings.push_back("Network-backed paths are not supported for secure wiping.");
    }

    if (report.target_kind == TargetKind::RegularFile || report.target_kind == TargetKind::Directory) {
        report.warnings.push_back(
            "Modern filesystems, snapshots, and journaled metadata can preserve data outside the overwritten extent.");
        if (is_probably_ssd_unsafe(report.storage_kind)) {
            report.warnings.push_back(
                "The underlying storage may be SSD-backed or otherwise remapped. File-level overwrite is best-effort only.");
            if (report.recommendation != StrategyRecommendation::Refuse) {
                report.recommendation = StrategyRecommendation::ReviewBeforeWipe;
            }
        }
    }

    return report;
}

fs::path PathInspector::resolve_path(const fs::path& path) const {
    return canonical_or_absolute(path);
}

fs::path PathInspector::canonical_or_absolute(const fs::path& path) {
    std::error_code ec;
    fs::path resolved = fs::weakly_canonical(path, ec);
    if (!ec) return resolved;

    ec.clear();
    resolved = fs::absolute(path, ec);
    if (!ec) return resolved;

    return path;
}

bool PathInspector::paths_equal(const fs::path& left, const fs::path& right) {
    return canonical_or_absolute(left) == canonical_or_absolute(right);
}

bool PathInspector::is_root_path(const fs::path& path) {
    const fs::path resolved = canonical_or_absolute(path);
    return !resolved.empty() && resolved == resolved.root_path();
}

std::string PathInspector::environment_value(const char* name) {
#if defined(_WIN32)
    char* value = nullptr;
    std::size_t length = 0;
    if (_dupenv_s(&value, &length, name) != 0 || value == nullptr) return {};

    std::string result(value);
    std::free(value);
    return result;
#else
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
#endif
}

std::string PathInspector::filesystem_hint_for_path(const fs::path& path) {
#if defined(_WIN32)
    const fs::path root = canonical_or_absolute(path).root_path();
    if (root.empty()) return {};

    wchar_t fs_name[MAX_PATH] = {};
    if (GetVolumeInformationW(
            root.c_str(),
            nullptr,
            0,
            nullptr,
            nullptr,
            nullptr,
            fs_name,
            static_cast<DWORD>(std::size(fs_name))) == 0) {
        return root.string();
    }

    return wide_to_utf8(fs_name);
#elif defined(__linux__)
    std::ifstream mounts("/proc/self/mounts");
    if (!mounts) return {};

    const fs::path resolved = canonical_or_absolute(path);
    std::string best_mount;
    std::string best_type;
    std::string line;
    while (std::getline(mounts, line)) {
        std::istringstream input(line);
        std::string source;
        std::string mount_point;
        std::string mount_type;
        if (!(input >> source >> mount_point >> mount_type)) continue;

        mount_point = decode_mount_field(mount_point);
        if (resolved.string().rfind(mount_point, 0) != 0) continue;
        if (mount_point.size() < best_mount.size()) continue;

        best_mount = mount_point;
        best_type = mount_type;
    }

    return best_type;
#else
    (void)path;
    return {};
#endif
}

StorageKind PathInspector::detect_storage_kind(const fs::path& path) {
#if defined(_WIN32)
    const fs::path root = canonical_or_absolute(path).root_path();
    if (root.empty()) return StorageKind::Unknown;

    switch (GetDriveTypeW(root.c_str())) {
    case DRIVE_FIXED:
        return StorageKind::FixedDisk;
    case DRIVE_REMOVABLE:
        return StorageKind::RemovableDisk;
    case DRIVE_REMOTE:
        return StorageKind::NetworkShare;
    default:
        return StorageKind::Unknown;
    }
#elif defined(__linux__)
    std::ifstream mounts("/proc/self/mounts");
    if (!mounts) return StorageKind::Unknown;

    const fs::path resolved = canonical_or_absolute(path);
    std::string best_source;
    std::string best_mount;
    std::string line;
    while (std::getline(mounts, line)) {
        std::istringstream input(line);
        std::string source;
        std::string mount_point;
        std::string mount_type;
        if (!(input >> source >> mount_point >> mount_type)) continue;

        mount_point = decode_mount_field(mount_point);
        if (resolved.string().rfind(mount_point, 0) != 0) continue;
        if (mount_point.size() < best_mount.size()) continue;

        best_source = source;
        best_mount = mount_point;
    }

    if (best_source.rfind("/dev/", 0) != 0) return StorageKind::Unknown;

    std::string device_name = fs::path(best_source).filename().string();
    if (device_name.rfind("nvme", 0) == 0 || device_name.rfind("mmcblk", 0) == 0) {
        const std::size_t partition_marker = device_name.find('p');
        if (partition_marker != std::string::npos) {
            device_name = device_name.substr(0, partition_marker);
        }
    } else {
        while (!device_name.empty() && std::isdigit(static_cast<unsigned char>(device_name.back())) != 0) {
            device_name.pop_back();
        }
    }

    std::ifstream rotational("/sys/class/block/" + device_name + "/queue/rotational");
    if (!rotational) return StorageKind::Unknown;

    int rotational_value = 1;
    rotational >> rotational_value;
    if (!rotational) return StorageKind::Unknown;

    return rotational_value == 0 ? StorageKind::SolidState : StorageKind::RotationalDisk;
#else
    (void)path;
    return StorageKind::Unknown;
#endif
}

bool PathInspector::is_dangerous_directory(const fs::path& path) {
    const fs::path resolved = canonical_or_absolute(path);
    if (resolved.empty()) return true;
    if (is_root_path(resolved)) return true;

#if defined(_WIN32)
    const std::string user_profile = environment_value("USERPROFILE");
    if (!user_profile.empty() && paths_equal(resolved, fs::path(user_profile))) return true;

    const std::string system_root = environment_value("SystemRoot");
    if (!system_root.empty() && paths_equal(resolved, fs::path(system_root))) return true;

    const std::string program_files = environment_value("ProgramFiles");
    if (!program_files.empty() && paths_equal(resolved, fs::path(program_files))) return true;

    const std::string program_files_x86 = environment_value("ProgramFiles(x86)");
    if (!program_files_x86.empty() && paths_equal(resolved, fs::path(program_files_x86))) return true;
#else
    if (resolved == fs::path("/System") ||
        resolved == fs::path("/Library") ||
        resolved == fs::path("/Applications")) {
        return true;
    }

    const std::string home = environment_value("HOME");
    if (!home.empty() && paths_equal(resolved, fs::path(home))) return true;
#endif

    return false;
}

bool PathInspector::is_probably_ssd_unsafe(StorageKind storage_kind) noexcept {
    return storage_kind == StorageKind::Unknown ||
           storage_kind == StorageKind::FixedDisk ||
           storage_kind == StorageKind::SolidState ||
           storage_kind == StorageKind::RemovableDisk;
}

} // namespace securewipe::detail