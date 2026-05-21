#include "capability_inspection_tests.h"

#include <sstream>

#include "capability_test_support.h"
#include "src/internal/cli_application.h"
#include "secure_wipe.h"
#include "test_support.h"

namespace {

using test_support::TempDir;
using test_support::contains;
using test_support::matches_any;
using test_support::read_field_value;
using test_support::require;
using test_support::write_text_file;
using capability_test_support::FakeDeviceCapabilityProbe;
using capability_test_support::make_inspection_context;
using capability_test_support::make_report;
using capability_test_support::make_review_before_wipe_report;

namespace fs = std::filesystem;

void test_cli_inspect_detail_reports_capability_fields() {
    TempDir temp;
    const fs::path file = temp.path() / "sample.txt";
    write_text_file(file, "secret");

    std::ostringstream output;
    std::ostringstream error_output;
    securewipe::app::CommandLineApplication application(output, error_output);

    const int exit_code = application.run({"inspect", "--detail", file.string()});
    require(exit_code == 0, "CLI inspect --detail should succeed for a regular file");
    require(error_output.str().empty(), "CLI inspect --detail should not emit stderr on success");

    const std::string report = output.str();
    require(matches_any(read_field_value(report, "device-bus"),
                        {"unknown", "usb", "ata", "sata", "nvme", "scsi", "virtual", "network"}),
            "CLI inspect --detail should render the supported device bus labels");
    require(matches_any(read_field_value(report, "trim-support"),
                        {"unknown", "unsupported", "supported", "restricted"}),
            "CLI inspect --detail should render the supported capability labels");
    require(matches_any(read_field_value(report, "preferred-erase-method"),
                        {"unknown", "refuse", "best-effort-file-overwrite", "best-effort-directory-wipe",
                         "device-sanitize-review", "crypto-erase-review", "manual-review"}),
            "CLI inspect --detail should render the supported erase method labels");
    require(contains(report, "erase-advice:"), "CLI inspect --detail should include erase path advice lines");
}

void test_device_capability_inspector_maps_probe_snapshot() {
    FakeDeviceCapabilityProbe probe;
    probe.snapshot.bus_kind = securewipe::DeviceBusKind::Usb;
    probe.snapshot.trim_support = securewipe::CapabilityState::Supported;
    probe.snapshot.is_removable_media = true;
    probe.snapshot.usb_bridge_suspected = true;
    probe.snapshot.evidence.push_back("fake capability probe evidence");

    securewipe::detail::DeviceCapabilityInspector inspector(probe);
        const auto context = make_inspection_context(securewipe::StorageKind::SolidState);
        const auto capabilities = inspector.inspect(context);

    require(capabilities.bus_kind == securewipe::DeviceBusKind::Usb,
            "DeviceCapabilityInspector should preserve the probed bus kind");
    require(capabilities.trim_support == securewipe::CapabilityState::Supported,
            "DeviceCapabilityInspector should preserve trim support state");
    require(capabilities.device_sanitize_review == securewipe::CapabilityState::Restricted,
            "USB bridge scenarios should restrict device-level sanitize review");
    require(capabilities.crypto_erase_review == securewipe::CapabilityState::Restricted,
            "USB bridge scenarios should restrict crypto-erase review");
    require(capabilities.is_removable_media, "DeviceCapabilityInspector should preserve removable-media state");
    require(capabilities.usb_bridge_suspected, "DeviceCapabilityInspector should preserve USB bridge suspicion");
    require(!capabilities.evidence.empty(), "DeviceCapabilityInspector should propagate evidence lines");
}

void test_device_capability_inspector_keeps_rotational_unknown_bus_conservative() {
    FakeDeviceCapabilityProbe probe;
    probe.snapshot.bus_kind = securewipe::DeviceBusKind::Unknown;

    securewipe::detail::DeviceCapabilityInspector inspector(probe);
        const auto context = make_inspection_context(securewipe::StorageKind::RotationalDisk);
        const auto capabilities = inspector.inspect(context);

    require(capabilities.device_sanitize_review == securewipe::CapabilityState::Unknown,
            "Unknown bus on rotational storage should keep device sanitize review conservative");
    require(capabilities.crypto_erase_review == securewipe::CapabilityState::Unsupported,
            "Unknown bus on rotational storage should not over-promise crypto-erase review support");
}

void test_device_capability_inspector_supports_scsi_crypto_erase_review_for_ssd() {
    FakeDeviceCapabilityProbe probe;
    probe.snapshot.bus_kind = securewipe::DeviceBusKind::Scsi;

    securewipe::detail::DeviceCapabilityInspector inspector(probe);
    const auto context = make_inspection_context(securewipe::StorageKind::SolidState);
    const auto capabilities = inspector.inspect(context);

    require(capabilities.device_sanitize_review == securewipe::CapabilityState::Supported,
            "SCSI SSD targets should keep device sanitize review available");
    require(capabilities.crypto_erase_review == securewipe::CapabilityState::Supported,
            "SCSI SSD targets should advertise crypto-erase review when the policy allows it");
}

void test_erase_path_advisor_prefers_device_sanitize_review_for_ssd_like_targets() {
        securewipe::InspectionReport report = make_review_before_wipe_report(
                securewipe::StorageKind::SolidState,
                securewipe::DeviceBusKind::Nvme);
    report.device_capabilities.device_sanitize_review = securewipe::CapabilityState::Supported;

    const auto advice = securewipe::detail::ErasePathAdvisor{}.advise(report);
    require(advice.preferred_method == securewipe::EraseMethod::DeviceSanitizeReview,
            "ErasePathAdvisor should escalate SSD-like review paths to device sanitize review");
    require(!advice.reasons.empty() && contains(advice.reasons.front(), "device-level sanitization"),
            "ErasePathAdvisor should explain why device sanitize review was chosen");
}

void test_erase_path_advisor_falls_back_to_crypto_erase_review() {
        securewipe::InspectionReport report = make_review_before_wipe_report(
                securewipe::StorageKind::SolidState,
                securewipe::DeviceBusKind::Scsi);
    report.device_capabilities.device_sanitize_review = securewipe::CapabilityState::Unknown;
    report.device_capabilities.crypto_erase_review = securewipe::CapabilityState::Supported;

    const auto advice = securewipe::detail::ErasePathAdvisor{}.advise(report);
    require(advice.preferred_method == securewipe::EraseMethod::CryptoEraseReview,
            "ErasePathAdvisor should fall back to crypto-erase review when device sanitize review is unavailable");
    require(!advice.reasons.empty() && contains(advice.reasons.front(), "crypto-erase"),
            "ErasePathAdvisor should explain why crypto-erase review was chosen");
}

void test_erase_path_advisor_falls_back_to_manual_review_without_supported_reviews() {
        securewipe::InspectionReport report = make_review_before_wipe_report(
                securewipe::StorageKind::SolidState,
                securewipe::DeviceBusKind::Unknown);
        report.device_capabilities.device_sanitize_review = securewipe::CapabilityState::Unknown;
        report.device_capabilities.crypto_erase_review = securewipe::CapabilityState::Unknown;

        const auto advice = securewipe::detail::ErasePathAdvisor{}.advise(report);
        require(advice.preferred_method == securewipe::EraseMethod::ManualReview,
                        "ErasePathAdvisor should fall back to manual review when no supported review path is available");
        require(!advice.reasons.empty() && contains(advice.reasons.front(), "additional review"),
                        "ErasePathAdvisor should explain the manual review fallback");
}

void test_erase_path_advisor_keeps_best_effort_for_rotational_file_paths() {
        securewipe::InspectionReport report = make_report(
                securewipe::StrategyRecommendation::BestEffortFileOverwrite,
                securewipe::StorageKind::RotationalDisk);
    report.device_capabilities.bus_kind = securewipe::DeviceBusKind::Sata;
    report.device_capabilities.device_sanitize_review = securewipe::CapabilityState::Supported;

    const auto advice = securewipe::detail::ErasePathAdvisor{}.advise(report);
    require(advice.preferred_method == securewipe::EraseMethod::BestEffortFileOverwrite,
            "ErasePathAdvisor should keep rotational single-file targets on the best-effort overwrite path");
}

void test_erase_path_advisor_reports_unknown_when_no_recommendation_exists() {
        const securewipe::InspectionReport report = make_report(securewipe::StrategyRecommendation::None);

    const auto advice = securewipe::detail::ErasePathAdvisor{}.advise(report);
    require(advice.preferred_method == securewipe::EraseMethod::Unknown,
            "ErasePathAdvisor should keep unknown erase method when there is no strategy recommendation");
    require(!advice.reasons.empty() && contains(advice.reasons.front(), "did not produce a strategy recommendation"),
            "ErasePathAdvisor should explain why no erase path is available");
}

} // namespace

void run_capability_inspection_tests() {
    test_cli_inspect_detail_reports_capability_fields();
    test_device_capability_inspector_maps_probe_snapshot();
    test_device_capability_inspector_keeps_rotational_unknown_bus_conservative();
        test_device_capability_inspector_supports_scsi_crypto_erase_review_for_ssd();
    test_erase_path_advisor_prefers_device_sanitize_review_for_ssd_like_targets();
    test_erase_path_advisor_falls_back_to_crypto_erase_review();
        test_erase_path_advisor_falls_back_to_manual_review_without_supported_reviews();
    test_erase_path_advisor_keeps_best_effort_for_rotational_file_paths();
        test_erase_path_advisor_reports_unknown_when_no_recommendation_exists();
}