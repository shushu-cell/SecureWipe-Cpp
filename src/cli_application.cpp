#include "internal/cli_application.h"

#include <charconv>
#include <ostream>
#include <string_view>

namespace securewipe::app {

using namespace std::literals;

CommandLineApplication::CommandLineApplication(std::ostream& output, std::ostream& error_output)
    : output_(output), error_output_(error_output) {
}

int CommandLineApplication::run(const std::vector<std::string>& args) const {
    const ParseResult parse_result = parse(args);
    if (!parse_result.ok) {
        if (!parse_result.error_message.empty()) {
            error_output_ << parse_result.error_message << "\n\n";
        }
        print_help(error_output_);
        return to_exit_code(parse_result.exit_code);
    }

    switch (parse_result.request.kind) {
    case CommandKind::Help:
        print_help(output_);
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
    if (args.empty()) {
        return make_parse_success(CommandRequest{});
    }

    const std::string_view command = args[0];
    if (command == "--help"sv || command == "-h"sv) {
        return make_parse_success(CommandRequest{});
    }

    if (command == "inspect"sv) {
        if (args.size() != 2) {
            return make_parse_error("Error: inspect requires exactly one <path> argument");
        }

        CommandRequest request;
        request.kind = CommandKind::Inspect;
        request.path = args[1];
        return make_parse_success(std::move(request));
    }

    if (command != "wipe"sv && command != "wipe-dir"sv) {
        return make_parse_error("Unknown command: " + std::string(command));
    }

    if (args.size() < 2) {
        return make_parse_error("Error: missing <path>");
    }

    CommandRequest request;
    request.kind = command == "wipe"sv ? CommandKind::WipeFile : CommandKind::WipeDirectory;
    request.path = args[1];

    for (std::size_t index = 2; index < args.size(); ++index) {
        const std::string_view option = args[index];
        if (option == "--passes"sv) {
            if (index + 1 >= args.size()) {
                return make_parse_error("Error: --passes requires a positive integer value");
            }

            int passes = 0;
            if (!try_parse_positive_int(args[index + 1], passes)) {
                return make_parse_error("Error: --passes requires a positive integer value");
            }

            request.options.passes = passes;
            ++index;
            continue;
        }

        if (option == "--pattern"sv) {
            if (index + 1 >= args.size()) {
                return make_parse_error("Error: --pattern requires one of zeros|random");
            }

            if (!try_parse_pattern(args[index + 1], request.options.pattern)) {
                return make_parse_error("Error: unknown pattern: " + args[index + 1]);
            }

            ++index;
            continue;
        }

        if (option == "--dry-run"sv) {
            request.dry_run = true;
            continue;
        }

        if (option == "--yes"sv) {
            request.yes = true;
            continue;
        }

        return make_parse_error("Error: unknown option: " + std::string(option));
    }

    if (request.kind == CommandKind::WipeFile && (request.dry_run || request.yes)) {
        return make_parse_error("Error: --dry-run and --yes are only valid with wipe-dir");
    }

    return make_parse_success(std::move(request));
}

CommandLineApplication::ParseResult CommandLineApplication::make_parse_success(CommandRequest request) {
    ParseResult result;
    result.ok = true;
    result.request = std::move(request);
    return result;
}

CommandLineApplication::ParseResult CommandLineApplication::make_parse_error(std::string message) {
    ParseResult result;
    result.exit_code = ExitCode::Rejected;
    result.error_message = std::move(message);
    return result;
}

int CommandLineApplication::to_exit_code(ExitCode exit_code) noexcept {
    return static_cast<int>(exit_code);
}

void CommandLineApplication::print_help(std::ostream& output) {
    output <<
R"(SecureWipe-Cpp

Usage:
  securewipe --help
  securewipe inspect <path>
  securewipe wipe <path> [--passes N] [--pattern zeros|random]
  securewipe wipe-dir <dir> [--passes N] [--pattern zeros|random] [--dry-run] [--yes]

Examples:
  securewipe inspect test.txt
  securewipe wipe test.txt --passes 1 --pattern zeros
  securewipe wipe-dir ./tmp --dry-run
  securewipe wipe-dir ./tmp --passes 1 --pattern zeros --yes
)";
}

void CommandLineApplication::write_field(std::ostream& output, std::string_view key, std::string_view value) {
    output << key << ": " << value << '\n';
}

bool CommandLineApplication::try_parse_positive_int(std::string_view text, int& value) {
    const char* begin = text.data();
    const char* end = text.data() + text.size();
    const auto [ptr, error] = std::from_chars(begin, end, value);
    return error == std::errc() && ptr == end && value > 0;
}

bool CommandLineApplication::try_parse_pattern(std::string_view text, Pattern& pattern) {
    if (text == "zeros"sv) {
        pattern = Pattern::Zeros;
        return true;
    }
    if (text == "random"sv) {
        pattern = Pattern::Random;
        return true;
    }
    return false;
}

const char* CommandLineApplication::to_string(TargetKind kind) {
    switch (kind) {
    case TargetKind::Missing:
        return "missing";
    case TargetKind::RegularFile:
        return "regular-file";
    case TargetKind::Directory:
        return "directory";
    case TargetKind::Symlink:
        return "symlink";
    case TargetKind::Other:
        return "other";
    }
    return "unknown";
}

const char* CommandLineApplication::to_string(StorageKind kind) {
    switch (kind) {
    case StorageKind::Unknown:
        return "unknown";
    case StorageKind::FixedDisk:
        return "fixed-disk";
    case StorageKind::RotationalDisk:
        return "rotational-disk";
    case StorageKind::SolidState:
        return "solid-state";
    case StorageKind::RemovableDisk:
        return "removable-disk";
    case StorageKind::NetworkShare:
        return "network-share";
    }
    return "unknown";
}

const char* CommandLineApplication::to_string(StrategyRecommendation recommendation) {
    switch (recommendation) {
    case StrategyRecommendation::None:
        return "none";
    case StrategyRecommendation::Refuse:
        return "refuse";
    case StrategyRecommendation::BestEffortFileOverwrite:
        return "best-effort-file-overwrite";
    case StrategyRecommendation::BestEffortDirectoryWipe:
        return "best-effort-directory-wipe";
    case StrategyRecommendation::ReviewBeforeWipe:
        return "review-before-wipe";
    }
    return "unknown";
}

int CommandLineApplication::run_inspect(const CommandRequest& request) const {
    const InspectionReport report = inspect_target(request.path);
    if (!report.ok) {
        error_output_ << "Inspect failed: " << report.message << '\n';
        return to_exit_code(ExitCode::ExecutionFailure);
    }

    print_inspection_report(report);
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

void CommandLineApplication::print_inspection_report(const InspectionReport& report) const {
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
}

} // namespace securewipe::app