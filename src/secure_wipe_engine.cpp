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
      file_wiper_{inspector_},
      directory_wiper_{inspector_, file_wiper_, reporter} {
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