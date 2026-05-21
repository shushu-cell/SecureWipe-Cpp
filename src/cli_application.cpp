#include "internal/cli_application.h"

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <functional>
#include <map>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace securewipe::app {

using namespace std::literals;

namespace {

template <typename Enum>
struct EnumLabel {
    Enum value;
    std::string_view label;
};

template <typename Enum, std::size_t LabelCount>
constexpr std::string_view enum_label_or_unknown(
    Enum value,
    const std::array<EnumLabel<Enum>, LabelCount>& labels) noexcept {
    const auto entry = std::ranges::find(labels, value, &EnumLabel<Enum>::value);

    return entry != labels.end() ? entry->label : "unknown"sv;
}

constexpr std::array<EnumLabel<TargetKind>, 5> kTargetKindLabels{{
    {TargetKind::Missing, "missing"sv},
    {TargetKind::RegularFile, "regular-file"sv},
    {TargetKind::Directory, "directory"sv},
    {TargetKind::Symlink, "symlink"sv},
    {TargetKind::Other, "other"sv},
}};

constexpr std::array<EnumLabel<StorageKind>, 6> kStorageKindLabels{{
    {StorageKind::Unknown, "unknown"sv},
    {StorageKind::FixedDisk, "fixed-disk"sv},
    {StorageKind::RotationalDisk, "rotational-disk"sv},
    {StorageKind::SolidState, "solid-state"sv},
    {StorageKind::RemovableDisk, "removable-disk"sv},
    {StorageKind::NetworkShare, "network-share"sv},
}};

constexpr std::array<EnumLabel<StrategyRecommendation>, 5> kRecommendationLabels{{
    {StrategyRecommendation::None, "none"sv},
    {StrategyRecommendation::Refuse, "refuse"sv},
    {StrategyRecommendation::BestEffortFileOverwrite, "best-effort-file-overwrite"sv},
    {StrategyRecommendation::BestEffortDirectoryWipe, "best-effort-directory-wipe"sv},
    {StrategyRecommendation::ReviewBeforeWipe, "review-before-wipe"sv},
}};

constexpr std::array<EnumLabel<DeviceBusKind>, 8> kDeviceBusLabels{{
    {DeviceBusKind::Unknown, "unknown"sv},
    {DeviceBusKind::Usb, "usb"sv},
    {DeviceBusKind::Ata, "ata"sv},
    {DeviceBusKind::Sata, "sata"sv},
    {DeviceBusKind::Nvme, "nvme"sv},
    {DeviceBusKind::Scsi, "scsi"sv},
    {DeviceBusKind::Virtual, "virtual"sv},
    {DeviceBusKind::Network, "network"sv},
}};

constexpr std::array<EnumLabel<CapabilityState>, 4> kCapabilityStateLabels{{
    {CapabilityState::Unknown, "unknown"sv},
    {CapabilityState::Unsupported, "unsupported"sv},
    {CapabilityState::Supported, "supported"sv},
    {CapabilityState::Restricted, "restricted"sv},
}};

constexpr std::array<EnumLabel<EraseMethod>, 7> kEraseMethodLabels{{
    {EraseMethod::Unknown, "unknown"sv},
    {EraseMethod::Refuse, "refuse"sv},
    {EraseMethod::BestEffortFileOverwrite, "best-effort-file-overwrite"sv},
    {EraseMethod::BestEffortDirectoryWipe, "best-effort-directory-wipe"sv},
    {EraseMethod::DeviceSanitizeReview, "device-sanitize-review"sv},
    {EraseMethod::CryptoEraseReview, "crypto-erase-review"sv},
    {EraseMethod::ManualReview, "manual-review"sv},
}};

constexpr std::array<EnumLabel<EvidenceSubject>, 5> kEvidenceSubjectLabels{{
    {EvidenceSubject::BusKind, "bus-kind"sv},
    {EvidenceSubject::TrimSupport, "trim-support"sv},
    {EvidenceSubject::DeviceSanitizeReview, "device-sanitize-review"sv},
    {EvidenceSubject::CryptoEraseReview, "crypto-erase-review"sv},
    {EvidenceSubject::Restriction, "restriction"sv},
}};

constexpr std::array<EnumLabel<EvidenceSource>, 6> kEvidenceSourceLabels{{
    {EvidenceSource::PathInspection, "path-inspection"sv},
    {EvidenceSource::WindowsStorageQuery, "windows-storage-query"sv},
    {EvidenceSource::LinuxMountMetadata, "linux-mount-metadata"sv},
    {EvidenceSource::LinuxSysfs, "linux-sysfs"sv},
    {EvidenceSource::HeuristicGuard, "heuristic-guard"sv},
    {EvidenceSource::PlatformFallback, "platform-fallback"sv},
}};

constexpr std::array<EnumLabel<EvidenceConfidence>, 3> kEvidenceConfidenceLabels{{
    {EvidenceConfidence::Observed, "observed"sv},
    {EvidenceConfidence::Inferred, "inferred"sv},
    {EvidenceConfidence::ConservativeFallback, "conservative-fallback"sv},
}};

constexpr std::array<EnumLabel<PreflightRisk>, 5> kPreflightRiskLabels{{
    {PreflightRisk::NetworkBacked, "network-backed"sv},
    {PreflightRisk::UsbBridgeSuspected, "usb-bridge-suspected"sv},
    {PreflightRisk::VirtualizedStorage, "virtualized-storage"sv},
    {PreflightRisk::PlatformProbeGap, "platform-probe-gap"sv},
    {PreflightRisk::UnderlyingDeviceReviewRecommended, "underlying-device-review-recommended"sv},
}};

constexpr std::array<EnumLabel<ActionCandidateState>, 4> kActionCandidateStateLabels{{
    {ActionCandidateState::Preferred, "preferred"sv},
    {ActionCandidateState::Available, "available"sv},
    {ActionCandidateState::Blocked, "blocked"sv},
    {ActionCandidateState::Unavailable, "unavailable"sv},
}};

constexpr std::array<EnumLabel<ActionTargetScope>, 2> kActionTargetScopeLabels{{
    {ActionTargetScope::CurrentPath, "current-path"sv},
    {ActionTargetScope::UnderlyingDevice, "underlying-device"sv},
}};

const std::map<std::string, Pattern> kPatternOptions{
    {"zeros", Pattern::Zeros},
    {"random", Pattern::Random},
};

constexpr std::string_view kCliFooter = R"(Examples:
  securewipe inspect test.txt
    securewipe inspect --json test.txt
  securewipe wipe test.txt --passes 1 --pattern zeros
  securewipe wipe-dir ./tmp --dry-run
  securewipe wipe-dir ./tmp --passes 1 --pattern zeros --yes
)";

void configure_shared_wipe_options(CLI::App& command, std::string& path, WipeOptions& options) {
    command.add_option("path", path, "Target path")->required();
    command.add_option("--passes", options.passes, "Overwrite pass count")
        ->check(CLI::PositiveNumber)
        ->default_val(options.passes);
    command.add_option("--pattern", options.pattern, "Overwrite pattern")
        ->transform(CLI::CheckedTransformer(kPatternOptions))
        ->default_str("zeros");
}

std::string select_help(
    const CLI::App& app,
    const CLI::App& inspect_command,
    const CLI::App& wipe_command,
    const CLI::App& wipe_directory_command) {
    const std::array help_selection_order{
        std::cref(inspect_command),
        std::cref(wipe_command),
        std::cref(wipe_directory_command),
    };

    const auto selected_command = std::ranges::find_if(help_selection_order, [](const auto& command) {
        return command.get().parsed();
    });

    if (selected_command != help_selection_order.end()) {
        return selected_command->get().help();
    }

    return app.help();
}

} // namespace

CommandLineApplication::CommandLineApplication(std::ostream& output, std::ostream& error_output)
    : output_(output), error_output_(error_output) {
}

int CommandLineApplication::run(const std::vector<std::string>& args) const {
    const ParseResult parse_result = parse(args);
    if (!parse_result.ok) {
        if (!parse_result.error_message.empty()) {
            error_output_ << parse_result.error_message << "\n\n";
        }
        if (!parse_result.help_text.empty()) {
            error_output_ << parse_result.help_text;
        }
        return to_exit_code(parse_result.exit_code);
    }

    switch (parse_result.request.kind) {
    case CommandKind::Help:
        output_ << parse_result.help_text;
        return to_exit_code(ExitCode::Success);
    case CommandKind::Inspect:
        return run_inspect(parse_result.request);
    case CommandKind::WipeFile:
        return run_wipe_file(parse_result.request);
    case CommandKind::WipeDirectory:
        return run_wipe_directory(parse_result.request);
    }

    error_output_ << "Error: unsupported command\n";
    return to_exit_code(ExitCode::Rejected);
}

CommandLineApplication::ParseResult CommandLineApplication::parse(const std::vector<std::string>& args) {
    ParseResult result;
    CommandRequest request;

    CLI::App app{"SecureWipe-Cpp"};
    app.name("securewipe");
    app.footer(std::string(kCliFooter));
    app.require_subcommand(0, 1);

    auto* inspect_command = app.add_subcommand("inspect", "Inspect a target and report the recommended wipe strategy.");
    inspect_command->add_option("path", request.path, "Target path")->required();
    inspect_command->add_flag("--detail", request.detail, "Show device capability details and erase path advice");
    inspect_command->add_flag("--json", request.json, "Emit the full read-only inspection report as JSON");

    auto* wipe_command = app.add_subcommand("wipe", "Best-effort wipe of a single file.");
    configure_shared_wipe_options(*wipe_command, request.path, request.options);

    auto* wipe_directory_command = app.add_subcommand("wipe-dir", "Best-effort recursive wipe of a directory.");
    configure_shared_wipe_options(*wipe_directory_command, request.path, request.options);
    wipe_directory_command->add_flag("--dry-run", request.dry_run, "List files without deleting them");
    wipe_directory_command->add_flag("--yes", request.yes, "Confirm destructive directory wipe");

    if (args.empty()) {
        result.ok = true;
        result.request.kind = CommandKind::Help;
        result.help_text = app.help();
        return result;
    }

    try {
        std::vector<std::string> parse_args(args.rbegin(), args.rend());
        app.parse(parse_args);
    } catch (const CLI::ParseError& error) {
        if (error.get_exit_code() == 0) {
            result.ok = true;
            result.request.kind = CommandKind::Help;
            result.help_text = select_help(app, *inspect_command, *wipe_command, *wipe_directory_command);
            return result;
        }

        result.exit_code = ExitCode::Rejected;
        result.error_message = error.what();
        result.help_text = select_help(app, *inspect_command, *wipe_command, *wipe_directory_command);
        return result;
    }

    result.ok = true;
    result.request = std::move(request);
    const std::array command_bindings{
        std::pair{std::cref(*inspect_command), CommandKind::Inspect},
        std::pair{std::cref(*wipe_command), CommandKind::WipeFile},
        std::pair{std::cref(*wipe_directory_command), CommandKind::WipeDirectory},
    };

    const auto selected_command = std::ranges::find_if(command_bindings, [](const auto& binding) {
        return binding.first.get().parsed();
    });

    if (selected_command != command_bindings.end()) {
        result.request.kind = selected_command->second;
    } else {
        result.request.kind = CommandKind::Help;
        result.help_text = app.help();
    }

    return result;
}

int CommandLineApplication::to_exit_code(ExitCode exit_code) noexcept {
    return static_cast<int>(exit_code);
}

void CommandLineApplication::write_field(std::ostream& output, std::string_view key, std::string_view value) {
    output << key << ": " << value << '\n';
}

std::string_view CommandLineApplication::to_string(TargetKind kind) noexcept {
    return enum_label_or_unknown(kind, kTargetKindLabels);
}

std::string_view CommandLineApplication::to_string(StorageKind kind) noexcept {
    return enum_label_or_unknown(kind, kStorageKindLabels);
}

std::string_view CommandLineApplication::to_string(StrategyRecommendation recommendation) noexcept {
    return enum_label_or_unknown(recommendation, kRecommendationLabels);
}

std::string_view CommandLineApplication::to_string(DeviceBusKind bus_kind) noexcept {
    return enum_label_or_unknown(bus_kind, kDeviceBusLabels);
}

std::string_view CommandLineApplication::to_string(CapabilityState state) noexcept {
    return enum_label_or_unknown(state, kCapabilityStateLabels);
}

std::string_view CommandLineApplication::to_string(EraseMethod method) noexcept {
    return enum_label_or_unknown(method, kEraseMethodLabels);
}

std::string_view CommandLineApplication::to_string(EvidenceSubject subject) noexcept {
    return enum_label_or_unknown(subject, kEvidenceSubjectLabels);
}

std::string_view CommandLineApplication::to_string(EvidenceSource source) noexcept {
    return enum_label_or_unknown(source, kEvidenceSourceLabels);
}

std::string_view CommandLineApplication::to_string(EvidenceConfidence confidence) noexcept {
    return enum_label_or_unknown(confidence, kEvidenceConfidenceLabels);
}

std::string_view CommandLineApplication::to_string(PreflightRisk risk) noexcept {
    return enum_label_or_unknown(risk, kPreflightRiskLabels);
}

std::string_view CommandLineApplication::to_string(ActionCandidateState state) noexcept {
    return enum_label_or_unknown(state, kActionCandidateStateLabels);
}

std::string_view CommandLineApplication::to_string(ActionTargetScope target_scope) noexcept {
    return enum_label_or_unknown(target_scope, kActionTargetScopeLabels);
}

std::string CommandLineApplication::format_evidence_item(const CapabilityEvidenceItem& item) {
    return "subject=" + std::string(to_string(item.subject)) +
           "; source=" + std::string(to_string(item.source)) +
           "; confidence=" + std::string(to_string(item.confidence)) +
           "; summary=" + item.summary;
}

std::string CommandLineApplication::format_action_candidate(const ActionCandidate& candidate) {
    return "method=" + std::string(to_string(candidate.method)) +
           "; state=" + std::string(to_string(candidate.state)) +
           "; scope=" + std::string(to_string(candidate.target_scope)) +
           "; summary=" + candidate.summary;
}

std::string CommandLineApplication::format_action_blocker(const ActionCandidate& candidate, std::string_view blocker) {
    return "method=" + std::string(to_string(candidate.method)) +
           "; summary=" + std::string(blocker);
}

int CommandLineApplication::run_inspect(const CommandRequest& request) const {
    const InspectionReport report = inspect_target(request.path);
    if (request.json) {
        print_json_inspection_report(report);
        if (!report.ok) {
            return to_exit_code(ExitCode::ExecutionFailure);
        }

        return report.recommendation == StrategyRecommendation::Refuse
            ? to_exit_code(ExitCode::Rejected)
            : to_exit_code(ExitCode::Success);
    }

    if (!report.ok) {
        error_output_ << "Inspect failed: " << report.message << '\n';
        return to_exit_code(ExitCode::ExecutionFailure);
    }

    print_inspection_report(report, request.detail);
    return report.recommendation == StrategyRecommendation::Refuse
        ? to_exit_code(ExitCode::Rejected)
        : to_exit_code(ExitCode::Success);
}

int CommandLineApplication::run_wipe_file(const CommandRequest& request) const {
    const WipeResult result = wipe_file(request.path, request.options);
    if (!result.ok) {
        error_output_ << "Wipe failed: " << result.message << '\n';
        return to_exit_code(ExitCode::ExecutionFailure);
    }

    output_ << result.message << '\n';
    return to_exit_code(ExitCode::Success);
}

int CommandLineApplication::run_wipe_directory(const CommandRequest& request) const {
    const WipeResult result = wipe_directory(request.path, request.options, request.dry_run, request.yes);
    if (!result.ok) {
        error_output_ << "Wipe-dir failed: " << result.message << '\n';
        return to_exit_code(ExitCode::ExecutionFailure);
    }

    output_ << result.message << '\n';
    return to_exit_code(ExitCode::Success);
}

void CommandLineApplication::print_inspection_report(const InspectionReport& report, bool detail) const {
    write_field(output_, "path", report.canonical_path);
    write_field(output_, "target-kind", to_string(report.target_kind));
    write_field(output_, "storage-kind", to_string(report.storage_kind));
    write_field(output_, "recommendation", to_string(report.recommendation));
    if (!report.volume_name.empty()) {
        write_field(output_, "volume", report.volume_name);
    }
    write_field(output_, "dangerous", report.dangerous ? "yes"sv : "no"sv);
    write_field(output_, "summary", report.message);
    for (const auto& warning : report.warnings) {
        write_field(output_, "warning", warning);
    }

    if (detail) {
        print_detailed_inspection_report(report);
    }
}

void CommandLineApplication::print_json_inspection_report(const InspectionReport& report) const {
    using ordered_json = nlohmann::ordered_json;

    const auto string_array = [](const auto& values) {
        ordered_json array = ordered_json::array();
        for (const auto& value : values) {
            array.push_back(value);
        }

        return array;
    };

    const auto evidence_items = [this](const std::vector<CapabilityEvidenceItem>& items) {
        ordered_json array = ordered_json::array();
        for (const auto& item : items) {
            ordered_json object = ordered_json::object();
            object["subject"] = to_string(item.subject);
            object["source"] = to_string(item.source);
            object["confidence"] = to_string(item.confidence);
            object["summary"] = item.summary;
            array.push_back(std::move(object));
        }

        return array;
    };

    const auto action_candidates = [this, &string_array](const std::vector<ActionCandidate>& candidates) {
        ordered_json array = ordered_json::array();
        for (const auto& candidate : candidates) {
            ordered_json object = ordered_json::object();
            object["method"] = to_string(candidate.method);
            object["state"] = to_string(candidate.state);
            object["target_scope"] = to_string(candidate.target_scope);
            object["summary"] = candidate.summary;
            object["blockers"] = string_array(candidate.blockers);
            array.push_back(std::move(object));
        }

        return array;
    };

    ordered_json device_capabilities = ordered_json::object();
    device_capabilities["bus_kind"] = to_string(report.device_capabilities.bus_kind);
    device_capabilities["trim_support"] = to_string(report.device_capabilities.trim_support);
    device_capabilities["device_sanitize_review"] = to_string(report.device_capabilities.device_sanitize_review);
    device_capabilities["crypto_erase_review"] = to_string(report.device_capabilities.crypto_erase_review);
    device_capabilities["is_removable_media"] = report.device_capabilities.is_removable_media;
    device_capabilities["usb_bridge_suspected"] = report.device_capabilities.usb_bridge_suspected;
    device_capabilities["evidence"] = string_array(report.device_capabilities.evidence);
    device_capabilities["evidence_items"] = evidence_items(report.device_capabilities.evidence_items);

    ordered_json erase_path_advice = ordered_json::object();
    erase_path_advice["preferred_method"] = to_string(report.erase_path_advice.preferred_method);
    erase_path_advice["reasons"] = string_array(report.erase_path_advice.reasons);
    erase_path_advice["risk_flags"] = ordered_json::array();
    for (const auto risk : report.erase_path_advice.risk_flags) {
        erase_path_advice["risk_flags"].push_back(to_string(risk));
    }
    erase_path_advice["action_candidates"] = action_candidates(report.erase_path_advice.action_candidates);

    ordered_json inspection_report = ordered_json::object();
    inspection_report["ok"] = report.ok;
    inspection_report["dangerous"] = report.dangerous;
    inspection_report["target_kind"] = to_string(report.target_kind);
    inspection_report["storage_kind"] = to_string(report.storage_kind);
    inspection_report["recommendation"] = to_string(report.recommendation);
    inspection_report["device_capabilities"] = std::move(device_capabilities);
    inspection_report["erase_path_advice"] = std::move(erase_path_advice);
    inspection_report["canonical_path"] = report.canonical_path;
    inspection_report["volume_name"] = report.volume_name;
    inspection_report["message"] = report.message;
    inspection_report["warnings"] = string_array(report.warnings);

    output_ << inspection_report.dump() << '\n';
}

void CommandLineApplication::print_detailed_inspection_report(const InspectionReport& report) const {
    write_field(output_, "device-bus", to_string(report.device_capabilities.bus_kind));
    write_field(output_, "trim-support", to_string(report.device_capabilities.trim_support));
    write_field(output_, "device-sanitize-review", to_string(report.device_capabilities.device_sanitize_review));
    write_field(output_, "crypto-erase-review", to_string(report.device_capabilities.crypto_erase_review));
    write_field(output_, "removable-media", report.device_capabilities.is_removable_media ? "yes"sv : "no"sv);
    write_field(output_, "usb-bridge-suspected", report.device_capabilities.usb_bridge_suspected ? "yes"sv : "no"sv);
    write_field(output_, "preferred-erase-method", to_string(report.erase_path_advice.preferred_method));

    print_capability_evidence(report.device_capabilities);
    print_preflight_advice(report.erase_path_advice);
}

void CommandLineApplication::print_capability_evidence(const DeviceCapabilities& capabilities) const {
    if (!capabilities.evidence_items.empty()) {
        for (const auto& item : capabilities.evidence_items) {
            write_field(output_, "capability-evidence", format_evidence_item(item));
        }
    } else {
        for (const auto& evidence : capabilities.evidence) {
            write_field(output_, "capability-evidence", evidence);
        }
    }
}

void CommandLineApplication::print_preflight_advice(const ErasePathAdvice& advice) const {
    for (const auto risk : advice.risk_flags) {
        write_field(output_, "preflight-risk", to_string(risk));
    }

    for (const auto& candidate : advice.action_candidates) {
        write_field(output_, "preflight-action", format_action_candidate(candidate));
        for (const auto& blocker : candidate.blockers) {
            write_field(output_, "preflight-blocker", format_action_blocker(candidate, blocker));
        }
    }

    for (const auto& reason : advice.reasons) {
        write_field(output_, "erase-advice", reason);
    }
}

} // namespace securewipe::app