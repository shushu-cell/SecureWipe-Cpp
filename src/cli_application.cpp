#include "internal/cli_application.h"

#include <CLI/CLI.hpp>

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

void write_json_string(std::ostream& output, std::string_view value) {
    static constexpr std::string_view kHexDigits = "0123456789abcdef";

    output << '"';
    for (const unsigned char character : value) {
        switch (character) {
        case '"':
            output << "\\\"";
            break;
        case '\\':
            output << "\\\\";
            break;
        case '\b':
            output << "\\b";
            break;
        case '\f':
            output << "\\f";
            break;
        case '\n':
            output << "\\n";
            break;
        case '\r':
            output << "\\r";
            break;
        case '\t':
            output << "\\t";
            break;
        default:
            if (character < 0x20U) {
                output << "\\u00"
                       << kHexDigits[(character >> 4U) & 0x0FU]
                       << kHexDigits[character & 0x0FU];
            } else {
                output << static_cast<char>(character);
            }
            break;
        }
    }
    output << '"';
}

void write_json_key(std::ostream& output, std::string_view key) {
    write_json_string(output, key);
    output << ':';
}

template <typename Range, typename Writer>
void write_json_array(std::ostream& output, const Range& values, Writer&& writer) {
    output << '[';

    bool is_first = true;
    for (const auto& value : values) {
        if (!is_first) {
            output << ',';
        }

        writer(value);
        is_first = false;
    }

    output << ']';
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
    const auto write_boolean = [this](bool value) {
        output_ << (value ? "true" : "false");
    };

    const auto write_string = [this](std::string_view value) {
        write_json_string(output_, value);
    };

    const auto write_string_array = [this, &write_string](const auto& values) {
        write_json_array(output_, values, [&write_string](std::string_view value) {
            write_string(value);
        });
    };

    const auto write_evidence_item = [this, &write_string](const CapabilityEvidenceItem& item) {
        output_ << '{';
        write_json_key(output_, "subject");
        write_string(to_string(item.subject));
        output_ << ',';
        write_json_key(output_, "source");
        write_string(to_string(item.source));
        output_ << ',';
        write_json_key(output_, "confidence");
        write_string(to_string(item.confidence));
        output_ << ',';
        write_json_key(output_, "summary");
        write_string(item.summary);
        output_ << '}';
    };

    const auto write_action_candidate = [this, &write_string, &write_string_array](const ActionCandidate& candidate) {
        output_ << '{';
        write_json_key(output_, "method");
        write_string(to_string(candidate.method));
        output_ << ',';
        write_json_key(output_, "state");
        write_string(to_string(candidate.state));
        output_ << ',';
        write_json_key(output_, "target_scope");
        write_string(to_string(candidate.target_scope));
        output_ << ',';
        write_json_key(output_, "summary");
        write_string(candidate.summary);
        output_ << ',';
        write_json_key(output_, "blockers");
        write_string_array(candidate.blockers);
        output_ << '}';
    };

    const auto write_device_capabilities = [this, &write_boolean, &write_string, &write_string_array, &write_evidence_item](
                                               const DeviceCapabilities& capabilities) {
        output_ << '{';
        write_json_key(output_, "bus_kind");
        write_string(to_string(capabilities.bus_kind));
        output_ << ',';
        write_json_key(output_, "trim_support");
        write_string(to_string(capabilities.trim_support));
        output_ << ',';
        write_json_key(output_, "device_sanitize_review");
        write_string(to_string(capabilities.device_sanitize_review));
        output_ << ',';
        write_json_key(output_, "crypto_erase_review");
        write_string(to_string(capabilities.crypto_erase_review));
        output_ << ',';
        write_json_key(output_, "is_removable_media");
        write_boolean(capabilities.is_removable_media);
        output_ << ',';
        write_json_key(output_, "usb_bridge_suspected");
        write_boolean(capabilities.usb_bridge_suspected);
        output_ << ',';
        write_json_key(output_, "evidence");
        write_string_array(capabilities.evidence);
        output_ << ',';
        write_json_key(output_, "evidence_items");
        write_json_array(output_, capabilities.evidence_items, [&write_evidence_item](const CapabilityEvidenceItem& item) {
            write_evidence_item(item);
        });
        output_ << '}';
    };

    const auto write_erase_path_advice = [this, &write_string, &write_string_array, &write_action_candidate](const ErasePathAdvice& advice) {
        output_ << '{';
        write_json_key(output_, "preferred_method");
        write_string(to_string(advice.preferred_method));
        output_ << ',';
        write_json_key(output_, "reasons");
        write_string_array(advice.reasons);
        output_ << ',';
        write_json_key(output_, "risk_flags");
        write_json_array(output_, advice.risk_flags, [this, &write_string](PreflightRisk risk) {
            write_string(to_string(risk));
        });
        output_ << ',';
        write_json_key(output_, "action_candidates");
        write_json_array(output_, advice.action_candidates, [&write_action_candidate](const ActionCandidate& candidate) {
            write_action_candidate(candidate);
        });
        output_ << '}';
    };

    output_ << '{';
    write_json_key(output_, "ok");
    write_boolean(report.ok);
    output_ << ',';
    write_json_key(output_, "dangerous");
    write_boolean(report.dangerous);
    output_ << ',';
    write_json_key(output_, "target_kind");
    write_string(to_string(report.target_kind));
    output_ << ',';
    write_json_key(output_, "storage_kind");
    write_string(to_string(report.storage_kind));
    output_ << ',';
    write_json_key(output_, "recommendation");
    write_string(to_string(report.recommendation));
    output_ << ',';
    write_json_key(output_, "device_capabilities");
    write_device_capabilities(report.device_capabilities);
    output_ << ',';
    write_json_key(output_, "erase_path_advice");
    write_erase_path_advice(report.erase_path_advice);
    output_ << ',';
    write_json_key(output_, "canonical_path");
    write_string(report.canonical_path);
    output_ << ',';
    write_json_key(output_, "volume_name");
    write_string(report.volume_name);
    output_ << ',';
    write_json_key(output_, "message");
    write_string(report.message);
    output_ << ',';
    write_json_key(output_, "warnings");
    write_string_array(report.warnings);
    output_ << "}\n";
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