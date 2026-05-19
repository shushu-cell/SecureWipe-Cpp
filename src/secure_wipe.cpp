#include "secure_wipe.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <io.h>
#endif

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

#if defined(__linux__)
#include <algorithm>
#include <sys/statvfs.h>
#endif

namespace fs = std::filesystem;

namespace securewipe {

static std::string errstr(const char* prefix) {
#if defined(_WIN32)
    char buffer[256] = {};
    strerror_s(buffer, sizeof(buffer), errno);
    return std::string(prefix) + ": " + buffer;
#else
    return std::string(prefix) + ": " + std::strerror(errno);
#endif
}

static std::string get_env_value(const char* name) {
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

static fs::path canonical_or_absolute(const fs::path& path) {
    std::error_code ec;
    fs::path resolved = fs::weakly_canonical(path, ec);
    if (!ec) return resolved;

    ec.clear();
    resolved = fs::absolute(path, ec);
    if (!ec) return resolved;

    return path;
}

static bool paths_equal(const fs::path& left, const fs::path& right) {
    return canonical_or_absolute(left) == canonical_or_absolute(right);
}

static bool is_root_path(const fs::path& path) {
    fs::path resolved = canonical_or_absolute(path);
    return !resolved.empty() && resolved == resolved.root_path();
}

static bool flush_to_disk(std::FILE* file) {
    if (std::fflush(file) != 0) return false;

#if defined(_WIN32)
    const int fd = _fileno(file);
    if (fd < 0) return false;
    const intptr_t handle_value = _get_osfhandle(fd);
    if (handle_value == -1) return false;
    return FlushFileBuffers(reinterpret_cast<HANDLE>(handle_value)) != 0;
#elif defined(__unix__) || defined(__APPLE__)
    const int fd = fileno(file);
    if (fd < 0) return false;
    return fsync(fd) == 0;
#else
    return true;
#endif
}

static std::FILE* open_file_for_overwrite(const fs::path& path) {
#if defined(_WIN32)
    std::FILE* file = nullptr;
    if (_wfopen_s(&file, path.c_str(), L"r+b") != 0) return nullptr;
    return file;
#else
    return std::fopen(path.c_str(), "r+b");
#endif
}

#if defined(__linux__)
static std::string escape_mount_field(std::string value) {
    std::string result;
    result.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i + 3 < value.size() && value.compare(i, 4, "\\040") == 0) {
            result.push_back(' ');
            i += 3;
            continue;
        }
        result.push_back(value[i]);
    }
    return result;
}
#endif

static bool is_probably_ssd_unsafe(StorageKind storage_kind) {
    return storage_kind == StorageKind::Unknown ||
           storage_kind == StorageKind::FixedDisk ||
           storage_kind == StorageKind::SolidState ||
           storage_kind == StorageKind::RemovableDisk;
}

static fs::path derive_rename_candidate(const fs::path& path, int attempt) {
    const std::string stem = path.stem().string();
    const std::string extension = path.extension().string();
    std::string scrambled(stem.empty() ? 8 : stem.size(), 'x');
    if (attempt > 0) scrambled += std::to_string(attempt);
    return path.parent_path() / (scrambled + extension);
}

static bool obscure_name_best_effort(fs::path* path) {
    if (path == nullptr || path->empty()) return false;

    std::error_code ec;
    for (int attempt = 0; attempt < 8; ++attempt) {
        fs::path candidate = derive_rename_candidate(*path, attempt);
        if (candidate == *path) continue;

        ec.clear();
        fs::rename(*path, candidate, ec);
        if (!ec) {
            *path = std::move(candidate);
            return true;
        }
    }

    return false;
}

#if defined(_WIN32)
static std::string wide_to_utf8(const std::wstring& value) {
    if (value.empty()) return {};

    const int required_size = WideCharToMultiByte(
        CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
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

static std::string filesystem_hint_for_path(const fs::path& path) {
#if defined(_WIN32)
    const fs::path root = canonical_or_absolute(path).root_path();
    if (root.empty()) return {};

    wchar_t fs_name[MAX_PATH] = {};
    if (GetVolumeInformationW(root.c_str(), nullptr, 0, nullptr, nullptr, nullptr, fs_name,
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

        mount_point = escape_mount_field(mount_point);
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

static StorageKind detect_storage_kind(const fs::path& path) {
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

        mount_point = escape_mount_field(mount_point);
        if (resolved.string().rfind(mount_point, 0) != 0) continue;
        if (mount_point.size() < best_mount.size()) continue;

        best_source = source;
        best_mount = mount_point;
    }

    if (best_source.rfind("/dev/", 0) != 0) return StorageKind::Unknown;

    std::string device_name = fs::path(best_source).filename().string();
    if (device_name.rfind("nvme", 0) == 0) {
        const std::size_t partition_marker = device_name.find('p');
        if (partition_marker != std::string::npos) {
            device_name = device_name.substr(0, partition_marker);
        }
    } else if (device_name.rfind("mmcblk", 0) == 0) {
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

static bool is_dangerous_dir(const fs::path& path) {
    const fs::path resolved = canonical_or_absolute(path);
    if (resolved.empty()) return true;
    if (is_root_path(resolved)) return true;

#if defined(_WIN32)
    const std::string user_profile = get_env_value("USERPROFILE");
    if (!user_profile.empty() && paths_equal(resolved, fs::path(user_profile))) return true;

    const std::string system_root = get_env_value("SystemRoot");
    if (!system_root.empty() && paths_equal(resolved, fs::path(system_root))) return true;

    const std::string program_files = get_env_value("ProgramFiles");
    if (!program_files.empty() && paths_equal(resolved, fs::path(program_files))) return true;

    const std::string program_files_x86 = get_env_value("ProgramFiles(x86)");
    if (!program_files_x86.empty() && paths_equal(resolved, fs::path(program_files_x86))) return true;
#else
    if (resolved == fs::path("/System") ||
        resolved == fs::path("/Library") ||
        resolved == fs::path("/Applications")) {
        return true;
    }

    const std::string home = get_env_value("HOME");
    if (!home.empty() && paths_equal(resolved, fs::path(home))) return true;
#endif

    return false;
}

InspectionReport inspect_target(const std::string& path) {
    InspectionReport report;
    const fs::path input(path);
    const fs::path resolved = canonical_or_absolute(input);
    report.canonical_path = resolved.string();
    report.volume_name = filesystem_hint_for_path(resolved);

    std::error_code ec;
    const fs::file_status link_status = fs::symlink_status(input, ec);
    if (ec) {
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
        report.dangerous = is_dangerous_dir(resolved);
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

WipeResult wipe_file(const std::string& path, const WipeOptions& opt) {
    WipeResult result;

    const InspectionReport inspection = inspect_target(path);
    if (!inspection.ok) {
        result.message = inspection.message;
        return result;
    }
    if (inspection.target_kind != TargetKind::RegularFile) {
        result.message = "Path is not a regular file";
        return result;
    }

    std::error_code ec;
    const fs::path file_path = canonical_or_absolute(fs::path(path));
    const auto file_size = fs::file_size(file_path, ec);
    if (ec) {
        result.message = "Failed to get file size: " + ec.message();
        return result;
    }

    if (opt.passes < 1) {
        result.message = "passes must be >= 1";
        return result;
    }
    if (opt.block_size == 0) {
        result.message = "block_size must be >= 1";
        return result;
    }

    std::vector<unsigned char> buffer(opt.block_size, 0);
    std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 255);

    std::FILE* file = open_file_for_overwrite(file_path);
    if (file == nullptr) {
        result.message = errstr("Failed to open file for overwrite");
        return result;
    }

    for (int pass = 1; pass <= opt.passes; ++pass) {
        if (std::fseek(file, 0, SEEK_SET) != 0) {
            std::fclose(file);
            result.message = errstr("Failed to seek during overwrite");
            return result;
        }

        std::uintmax_t remaining = file_size;
        while (remaining > 0) {
            std::size_t chunk = static_cast<std::size_t>(
                std::min<std::uintmax_t>(remaining, buffer.size()));

            if (opt.pattern == Pattern::Zeros) {
                std::fill(buffer.begin(), buffer.begin() + chunk, static_cast<unsigned char>(0));
            } else {
                for (std::size_t i = 0; i < chunk; ++i) {
                    buffer[i] = static_cast<unsigned char>(dist(rng));
                }
            }

            if (std::fwrite(buffer.data(), 1, chunk, file) != chunk) {
                std::fclose(file);
                result.message = errstr("Write failed during overwrite");
                return result;
            }
            remaining -= chunk;
        }

        if (!flush_to_disk(file)) {
            std::fclose(file);
            result.message = errstr("Flush failed");
            return result;
        }
    }

    if (std::fclose(file) != 0) {
        result.message = errstr("Failed to close file after overwrite");
        return result;
    }

    fs::resize_file(file_path, 0, ec);
    if (ec) {
        result.message = "Failed to truncate file before deletion: " + ec.message();
        return result;
    }

    fs::path delete_path = file_path;
    obscure_name_best_effort(&delete_path);
    ec.clear();
    if (!fs::remove(delete_path, ec) || ec) {
        result.message = "Failed to delete file: " + (ec ? ec.message() : std::string("unknown error"));
        return result;
    }

    result.ok = true;
    result.files_total = 1;
    result.files_wiped = 1;
    result.message = inspection.recommendation == StrategyRecommendation::ReviewBeforeWipe
        ? "Wiped and deleted successfully (best-effort only; inspect warnings for media caveats)"
        : "Wiped and deleted successfully";
    return result;
}

WipeResult wipe_directory(const std::string& dir, const WipeOptions& opt, bool dry_run, bool yes) {
    WipeResult result;
    result.dry_run = dry_run;

    const InspectionReport inspection = inspect_target(dir);
    if (!inspection.ok) {
        result.message = inspection.message;
        return result;
    }
    if (inspection.target_kind != TargetKind::Directory) {
        result.message = "Path is not a directory";
        return result;
    }
    if (inspection.dangerous) {
        result.message = inspection.message;
        return result;
    }

    fs::path d(dir);
    std::error_code ec;

    if (!dry_run && !yes) {
        result.message = "Safety stop: wipe-dir requires --dry-run (preview) or --yes (execute).";
        return result;
    }

    std::uint64_t total_files = 0;
    std::uint64_t wiped_files = 0;
    std::uint64_t failed_files = 0;

    for (auto it = fs::recursive_directory_iterator(d, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) continue;

        const fs::path p = it->path();

        std::error_code ec2;
        if (fs::is_symlink(p, ec2)) {
            it.disable_recursion_pending();
            continue;
        }

        if (fs::is_regular_file(p, ec2) && !ec2) {
            ++total_files;
            if (dry_run) {
                std::cout << "[DRY-RUN] would wipe: " << p.string() << "\n";
            }
        }
    }

    if (dry_run) {
        result.ok = true;
        result.files_total = total_files;
        result.message = "Dry-run complete. Files to wipe: " + std::to_string(total_files) +
                         ". Re-run with --yes to execute.";
        return result;
    }

    for (auto it = fs::recursive_directory_iterator(d, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) continue;

        const fs::path p = it->path();

        std::error_code ec2;
        if (fs::is_symlink(p, ec2)) {
            it.disable_recursion_pending();
            continue;
        }

        if (fs::is_regular_file(p, ec2) && !ec2) {
            auto res = wipe_file(p.string(), opt);
            if (res.ok) ++wiped_files;
            else {
                ++failed_files;
                std::cerr << "[FAIL] " << p.string() << " : " << res.message << "\n";
            }
        }
    }

    std::vector<fs::path> dirs;
    for (auto it = fs::recursive_directory_iterator(d, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) continue;
        std::error_code ec3;
        if (fs::is_directory(it->path(), ec3) && !ec3) dirs.push_back(it->path());
    }
    for (auto it = dirs.rbegin(); it != dirs.rend(); ++it) {
        std::error_code ec4;
        fs::remove(*it, ec4);
    }

    result.ok = (failed_files == 0);
    result.files_total = total_files;
    result.files_wiped = wiped_files;
    result.files_failed = failed_files;
    result.message = "wipe-dir complete. total=" + std::to_string(total_files) +
                     ", wiped=" + std::to_string(wiped_files) +
                     ", failed=" + std::to_string(failed_files);
    return result;
}

} // namespace securewipe