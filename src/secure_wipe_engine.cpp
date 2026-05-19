#include "internal/secure_wipe_engine.h"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <system_error>

#if defined(_WIN32)
#define NOMINMAX
#include <io.h>
#include <windows.h>
#endif

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

namespace securewipe::detail {

namespace {

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
        if (ec == std::errc::no_such_file_or_directory) {
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

NativeFile::NativeFile(const fs::path& path) {
#if defined(_WIN32)
    if (_wfopen_s(&handle_, path.c_str(), L"r+b") != 0 || handle_ == nullptr) {
        open_error_ = last_error("Failed to open file for overwrite");
    }
#else
    handle_ = std::fopen(path.c_str(), "r+b");
    if (handle_ == nullptr) {
        open_error_ = last_error("Failed to open file for overwrite");
    }
#endif
}

NativeFile::~NativeFile() noexcept {
    if (handle_ != nullptr) {
        std::fclose(handle_);
    }
}

NativeFile::NativeFile(NativeFile&& other) noexcept
    : handle_(other.handle_), open_error_(std::move(other.open_error_)) {
    other.handle_ = nullptr;
}

NativeFile& NativeFile::operator=(NativeFile&& other) noexcept {
    if (this == &other) return *this;

    if (handle_ != nullptr) {
        std::fclose(handle_);
    }

    handle_ = other.handle_;
    open_error_ = std::move(other.open_error_);
    other.handle_ = nullptr;
    return *this;
}

bool NativeFile::is_open() const noexcept {
    return handle_ != nullptr;
}

const std::string& NativeFile::open_error() const noexcept {
    return open_error_;
}

std::string NativeFile::seek_to_start() {
    if (handle_ == nullptr) return "File handle is not open";
    if (std::fseek(handle_, 0, SEEK_SET) == 0) return {};
    return last_error("Failed to seek during overwrite");
}

std::string NativeFile::write(const unsigned char* buffer, std::size_t size) {
    if (handle_ == nullptr) return "File handle is not open";
    if (std::fwrite(buffer, 1, size, handle_) == size) return {};
    return last_error("Write failed during overwrite");
}

std::string NativeFile::flush() {
    if (handle_ == nullptr) return "File handle is not open";
    if (std::fflush(handle_) != 0) return last_error("Flush failed");

#if defined(_WIN32)
    const int fd = _fileno(handle_);
    if (fd < 0) return last_error("Flush failed");

    const intptr_t handle_value = _get_osfhandle(fd);
    if (handle_value == -1) return last_error("Flush failed");
    if (FlushFileBuffers(reinterpret_cast<HANDLE>(handle_value)) != 0) return {};
    return last_error("Flush failed");
#elif defined(__unix__) || defined(__APPLE__)
    const int fd = fileno(handle_);
    if (fd < 0) return last_error("Flush failed");
    if (fsync(fd) == 0) return {};
    return last_error("Flush failed");
#else
    return {};
#endif
}

std::string NativeFile::close() {
    if (handle_ == nullptr) return {};

    if (std::fclose(handle_) != 0) {
        handle_ = nullptr;
        return last_error("Failed to close file after overwrite");
    }

    handle_ = nullptr;
    return {};
}

std::string NativeFile::last_error(const char* prefix) {
#if defined(_WIN32)
    char buffer[256] = {};
    strerror_s(buffer, sizeof(buffer), errno);
    return std::string(prefix) + ": " + buffer;
#else
    return std::string(prefix) + ": " + std::strerror(errno);
#endif
}

FileWiper::FileWiper(const PathInspector& inspector)
    : inspector_(inspector) {
}

WipeResult FileWiper::wipe(const std::string& path, const WipeOptions& options) const {
    return wipe(fs::path(path), options);
}

WipeResult FileWiper::wipe(const fs::path& path, const WipeOptions& options) const {
    WipeResult result;

    const InspectionReport inspection = inspector_.inspect(path);
    if (!inspection.ok) {
        result.message = inspection.message;
        return result;
    }

    if (inspection.target_kind != TargetKind::RegularFile) {
        result.message = "Path is not a regular file";
        return result;
    }

    if (options.passes < 1) {
        result.message = "passes must be >= 1";
        return result;
    }

    if (options.block_size == 0) {
        result.message = "block_size must be >= 1";
        return result;
    }

    const fs::path file_path = inspector_.resolve_path(path);
    std::error_code ec;
    const auto file_size = fs::file_size(file_path, ec);
    if (ec) {
        result.message = "Failed to get file size: " + ec.message();
        return result;
    }

    NativeFile file(file_path);
    if (!file.is_open()) {
        result.message = file.open_error();
        return result;
    }

    std::vector<unsigned char> buffer(options.block_size, 0);
    std::mt19937_64 rng(std::random_device{}());
    for (int pass = 0; pass < options.passes; ++pass) {
        if (const auto error = file.seek_to_start(); !error.empty()) {
            result.message = error;
            return result;
        }

        std::uintmax_t remaining = file_size;
        while (remaining > 0) {
            const std::size_t chunk = static_cast<std::size_t>(
                std::min<std::uintmax_t>(remaining, buffer.size()));
            fill_buffer(buffer, chunk, options.pattern, rng);
            if (const auto error = file.write(buffer.data(), chunk); !error.empty()) {
                result.message = error;
                return result;
            }
            remaining -= chunk;
        }

        if (const auto error = file.flush(); !error.empty()) {
            result.message = error;
            return result;
        }
    }

    if (const auto error = file.close(); !error.empty()) {
        result.message = error;
        return result;
    }

    fs::resize_file(file_path, 0, ec);
    if (ec) {
        result.message = "Failed to truncate file before deletion: " + ec.message();
        return result;
    }

    fs::path delete_path = file_path;
    obscure_name_best_effort(delete_path);
    ec.clear();
    if (!fs::remove(delete_path, ec) || ec) {
        result.message = "Failed to delete file: " + (ec ? ec.message() : std::string("unknown error"));
        return result;
    }

    result.ok = true;
    result.files_total = 1;
    result.files_wiped = 1;
    result.message = success_message(inspection);
    return result;
}

fs::path FileWiper::rename_candidate(const fs::path& path, int attempt) {
    const std::string stem = path.stem().string();
    const std::string extension = path.extension().string();
    std::string scrambled(stem.empty() ? 8 : stem.size(), 'x');
    if (attempt > 0) scrambled += std::to_string(attempt);
    return path.parent_path() / (scrambled + extension);
}

void FileWiper::fill_buffer(
    std::vector<unsigned char>& buffer,
    std::size_t chunk,
    Pattern pattern,
    std::mt19937_64& rng) {
    if (pattern == Pattern::Zeros) {
        std::fill(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(chunk), static_cast<unsigned char>(0));
        return;
    }

    std::uniform_int_distribution<int> distribution(0, 255);
    std::generate_n(
        buffer.begin(),
        static_cast<std::ptrdiff_t>(chunk),
        [&distribution, &rng]() {
            return static_cast<unsigned char>(distribution(rng));
        });
}

bool FileWiper::obscure_name_best_effort(fs::path& path) {
    std::error_code ec;
    for (int attempt = 0; attempt < 8; ++attempt) {
        const fs::path candidate = rename_candidate(path, attempt);
        if (candidate == path) continue;

        ec.clear();
        fs::rename(path, candidate, ec);
        if (!ec) {
            path = candidate;
            return true;
        }
    }

    return false;
}

std::string FileWiper::success_message(const InspectionReport& report) {
    if (report.recommendation == StrategyRecommendation::ReviewBeforeWipe) {
        return "Wiped and deleted successfully (best-effort only; inspect warnings for media caveats)";
    }
    return "Wiped and deleted successfully";
}

DirectoryWiper::DirectoryWiper(
    const PathInspector& inspector,
    const FileWiper& file_wiper,
    std::ostream& output,
    std::ostream& error_output)
    : inspector_(inspector),
      file_wiper_(file_wiper),
      output_(output),
      error_output_(error_output) {
}

WipeResult DirectoryWiper::wipe(const std::string& path, const WipeOptions& options, bool dry_run, bool yes) const {
    WipeResult result;
    result.dry_run = dry_run;

    const InspectionReport inspection = inspector_.inspect(path);
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

    if (!dry_run && !yes) {
        result.message = "Safety stop: wipe-dir requires --dry-run (preview) or --yes (execute).";
        return result;
    }

    const DirectoryScan scan_result = scan(fs::path(path));
    result.files_total = static_cast<std::uint64_t>(scan_result.files.size());

    if (dry_run) {
        print_dry_run(scan_result);
        result.ok = true;
        result.message = "Dry-run complete. Files to wipe: " + std::to_string(result.files_total) +
                         ". Re-run with --yes to execute.";
        return result;
    }

    for (const auto& file_path : scan_result.files) {
        const WipeResult file_result = file_wiper_.wipe(file_path, options);
        if (file_result.ok) {
            ++result.files_wiped;
        } else {
            ++result.files_failed;
            error_output_ << "[FAIL] " << file_path.string() << " : " << file_result.message << "\n";
        }
    }

    remove_empty_directories(scan_result.directories);

    result.ok = (result.files_failed == 0);
    result.message = "wipe-dir complete. total=" + std::to_string(result.files_total) +
                     ", wiped=" + std::to_string(result.files_wiped) +
                     ", failed=" + std::to_string(result.files_failed);
    return result;
}

DirectoryScan DirectoryWiper::scan(const fs::path& root) const {
    DirectoryScan result;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator();
         it.increment(ec)) {
        if (ec) continue;

        const fs::path current = it->path();
        std::error_code status_error;
        if (fs::is_symlink(current, status_error)) {
            it.disable_recursion_pending();
            continue;
        }

        if (fs::is_directory(current, status_error) && !status_error) {
            result.directories.push_back(current);
            continue;
        }

        if (fs::is_regular_file(current, status_error) && !status_error) {
            result.files.push_back(current);
        }
    }
    return result;
}

void DirectoryWiper::print_dry_run(const DirectoryScan& scan) const {
    for (const auto& file_path : scan.files) {
        output_ << "[DRY-RUN] would wipe: " << file_path.string() << "\n";
    }
}

void DirectoryWiper::remove_empty_directories(const std::vector<fs::path>& directories) const {
    for (auto it = directories.rbegin(); it != directories.rend(); ++it) {
        std::error_code ec;
        fs::remove(*it, ec);
    }
}

SecureWipeFacade::SecureWipeFacade(std::ostream& output, std::ostream& error_output)
    : inspector_(),
      file_wiper_(inspector_),
      directory_wiper_(inspector_, file_wiper_, output, error_output) {
}

InspectionReport SecureWipeFacade::inspect(const std::string& path) const {
    return inspector_.inspect(path);
}

WipeResult SecureWipeFacade::wipe_file(const std::string& path, const WipeOptions& options) const {
    return file_wiper_.wipe(path, options);
}

WipeResult SecureWipeFacade::wipe_directory(
    const std::string& path,
    const WipeOptions& options,
    bool dry_run,
    bool yes) const {
    return directory_wiper_.wipe(path, options, dry_run, yes);
}

} // namespace securewipe::detail