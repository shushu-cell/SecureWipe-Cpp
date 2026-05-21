#include "internal/secure_wipe_engine.h"

namespace securewipe::detail {

void NullOperationReporter::on_dry_run_file(const fs::path& path) {
    (void)path;
}

void NullOperationReporter::on_file_failure(const fs::path& path, std::string_view message) {
    (void)path;
    (void)message;
}

StreamOperationReporter::StreamOperationReporter(std::ostream& output, std::ostream& error_output) noexcept
    : output_(output),
      error_output_(error_output) {
}

void StreamOperationReporter::on_dry_run_file(const fs::path& path) {
    output_ << "[DRY-RUN] would wipe: " << path.string() << "\n";
}

void StreamOperationReporter::on_file_failure(const fs::path& path, std::string_view message) {
    error_output_ << "[FAIL] " << path.string() << " : " << message << "\n";
}

SecureWipeFacade::SecureWipeFacade(OperationReporter& reporter)
    : inspector_{},
    device_capability_probe_{},
    device_capability_inspector_{device_capability_probe_},
    erase_path_advisor_{},
      file_wiper_{inspector_},
      directory_wiper_{inspector_, file_wiper_, reporter} {
}

InspectionReport SecureWipeFacade::inspect(std::string_view path) const {
    InspectionReport report = inspector_.inspect(path);
    if (!report.ok) {
        return report;
    }

    const DeviceInspectionContext inspection_context{
        .resolved_path = inspector_.resolve_path(path_from_view(path)),
        .storage_kind = report.storage_kind,
    };
    report.device_capabilities = device_capability_inspector_.inspect(inspection_context);
    report.erase_path_advice = erase_path_advisor_.advise(report);
    return report;
}

WipeResult SecureWipeFacade::wipe_file(std::string_view path, const WipeOptions& options) const {
    return file_wiper_.wipe(path, options);
}

WipeResult SecureWipeFacade::wipe_directory(
    std::string_view path,
    const WipeOptions& options,
    bool dry_run,
    bool yes) const {
    return directory_wiper_.wipe(path, options, dry_run, yes);
}

} // namespace securewipe::detail