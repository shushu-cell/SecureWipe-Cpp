#include "internal/secure_wipe_engine.h"

namespace securewipe::detail {

namespace {

WipeResult make_error_result(std::string message, bool dry_run = false) {
    WipeResult result;
    result.dry_run = dry_run;
    result.message = std::move(message);
    return result;
}

} // namespace

DirectoryWiper::DirectoryWiper(
    const PathInspector& inspector,
    const FileWiper& file_wiper,
    OperationReporter& reporter)
    : inspector_(inspector),
      file_wiper_(file_wiper),
      reporter_(reporter) {
}

WipeResult DirectoryWiper::wipe(const std::string& path, const WipeOptions& options, bool dry_run, bool yes) const {
    const InspectionReport inspection = inspector_.inspect(path);
    if (!inspection.ok) {
        return make_error_result(inspection.message, dry_run);
    }

    if (inspection.target_kind != TargetKind::Directory) {
        return make_error_result("Path is not a directory", dry_run);
    }

    if (inspection.dangerous) {
        return make_error_result(inspection.message, dry_run);
    }

    if (!dry_run && !yes) {
        return make_error_result(
            "Safety stop: wipe-dir requires --dry-run (preview) or --yes (execute).",
            dry_run);
    }

    const DirectoryScan scan_result = scan(fs::path(path));

    WipeResult result;
    result.dry_run = dry_run;
    result.files_total = static_cast<std::uint64_t>(scan_result.files.size());

    if (dry_run) {
        for (const auto& file_path : scan_result.files) {
            reporter_.on_dry_run_file(file_path);
        }
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
            reporter_.on_file_failure(file_path, file_result.message);
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

void DirectoryWiper::remove_empty_directories(const std::vector<fs::path>& directories) const {
    for (auto it = directories.rbegin(); it != directories.rend(); ++it) {
        std::error_code ec;
        fs::remove(*it, ec);
    }
}

} // namespace securewipe::detail