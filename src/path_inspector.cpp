#include "internal/secure_wipe_engine.h"

#if defined(__linux__)
#include "internal/linux_mount_utils.h"
#endif

#include <algorithm>
#include <array>
#include <cstdlib>
#include <fstream>
#include <ranges>
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

#if defined(_WIN32)
std::string wide_to_utf8(std::wstring_view value) {
    if (value.empty()) return {};

    const int required_size = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.data(),
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
        value.data(),
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

InspectionReport PathInspector::inspect(std::string_view path) const {
    return inspect(path_from_view(path));
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
    const fs::path resolved = canonical_or_absolute(path);
    const auto best_match = find_best_linux_mount_entry(resolved);
    return best_match ? best_match->mount_type : std::string{};
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
    const fs::path resolved = canonical_or_absolute(path);
    const auto best_match = find_best_linux_mount_entry(resolved);
    if (!best_match || best_match->source.rfind("/dev/", 0) != 0) return StorageKind::Unknown;

    const std::string device_name = normalize_linux_block_device_name(best_match->source);

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
    const std::array dangerous_environment_roots{
        "USERPROFILE",
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
    };
    return std::ranges::any_of(dangerous_environment_roots, [&resolved](const char* variable_name) {
        const std::string environment_path = environment_value(variable_name);
        return !environment_path.empty() && paths_equal(resolved, fs::path(environment_path));
    });
#else
    const std::array dangerous_paths{
        fs::path("/System"),
        fs::path("/Library"),
        fs::path("/Applications"),
    };
    if (std::ranges::any_of(dangerous_paths, [&resolved](const fs::path& dangerous_path) {
            return resolved == dangerous_path;
        })) {
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