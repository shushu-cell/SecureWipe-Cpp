#include "internal/cli_application.h"
#include "internal/inspection_report_json_formatter.h"

#include <CLI/CLI.hpp>

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

std::string CommandLineApplication::format_evidence_item(const CapabilityEvidenceItem& item) {
    return "subject=" + std::string(detail::to_string(item.subject)) +
           "; source=" + std::string(detail::to_string(item.source)) +
           "; confidence=" + std::string(detail::to_string(item.confidence)) +
           "; summary=" + item.summary;
}

std::string CommandLineApplication::format_action_candidate(const ActionCandidate& candidate) {
    return "method=" + std::string(detail::to_string(candidate.method)) +
           "; state=" + std::string(detail::to_string(candidate.state)) +
           "; scope=" + std::string(detail::to_string(candidate.target_scope)) +
           "; summary=" + candidate.summary;
}

std::string CommandLineApplication::format_action_blocker(const ActionCandidate& candidate, std::string_view blocker) {
    return "method=" + std::string(detail::to_string(candidate.method)) +
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
    write_field(output_, "target-kind", detail::to_string(report.target_kind));
    write_field(output_, "storage-kind", detail::to_string(report.storage_kind));
    write_field(output_, "recommendation", detail::to_string(report.recommendation));
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
    detail::write_json_inspection_report(output_, report);
}

void CommandLineApplication::print_detailed_inspection_report(const InspectionReport& report) const {
    write_field(output_, "device-bus", detail::to_string(report.device_capabilities.bus_kind));
    write_field(output_, "trim-support", detail::to_string(report.device_capabilities.trim_support));
    write_field(output_, "device-sanitize-review", detail::to_string(report.device_capabilities.device_sanitize_review));
    write_field(output_, "crypto-erase-review", detail::to_string(report.device_capabilities.crypto_erase_review));
    write_field(output_, "removable-media", report.device_capabilities.is_removable_media ? "yes"sv : "no"sv);
    write_field(output_, "usb-bridge-suspected", report.device_capabilities.usb_bridge_suspected ? "yes"sv : "no"sv);
    write_field(output_, "preferred-erase-method", detail::to_string(report.erase_path_advice.preferred_method));

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
        write_field(output_, "preflight-risk", detail::to_string(risk));
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