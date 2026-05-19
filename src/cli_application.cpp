#include "cli_application.h"

#include <charconv>
#include <ostream>
#include <system_error>

namespace securewipe::app {

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
        return parse_result.exit_code;
    }

    switch (parse_result.request.kind) {
    case CommandKind::Help:
        print_help(output_);
        return 0;
    case CommandKind::Inspect:
        return run_inspect(parse_result.request);
    case CommandKind::WipeFile:
        return run_wipe_file(parse_result.request);
    case CommandKind::WipeDirectory:
        return run_wipe_directory(parse_result.request);
    }

    error_output_ << "Error: unsupported command\n";
    return 2;
}

CommandLineApplication::ParseResult CommandLineApplication::parse(const std::vector<std::string>& args) {
    ParseResult result;
    result.ok = true;

    if (args.empty() || args[0] == "--help" || args[0] == "-h") {
        result.request.kind = CommandKind::Help;
        return result;
    }

    const std::string& command = args[0];
    if (command == "inspect") {
        if (args.size() != 2) {
            result.ok = false;
            result.exit_code = 2;
            result.error_message = "Error: inspect requires exactly one <path> argument";
            return result;
        }

        result.request.kind = CommandKind::Inspect;
        result.request.path = args[1];
        return result;
    }

    if (command != "wipe" && command != "wipe-dir") {
        result.ok = false;
        result.exit_code = 2;
        result.error_message = "Unknown command: " + command;
        return result;
    }

    if (args.size() < 2) {
        result.ok = false;
        result.exit_code = 2;
        result.error_message = "Error: missing <path>";
        return result;
    }

    result.request.kind = command == "wipe" ? CommandKind::WipeFile : CommandKind::WipeDirectory;
    result.request.path = args[1];

    for (std::size_t index = 2; index < args.size(); ++index) {
        const std::string& option = args[index];
        if (option == "--passes") {
            if (index + 1 >= args.size()) {
                result.ok = false;
                result.exit_code = 2;
                result.error_message = "Error: --passes requires a positive integer value";
                return result;
            }

            int passes = 0;
            if (!try_parse_positive_int(args[index + 1], passes)) {
                result.ok = false;
                result.exit_code = 2;
                result.error_message = "Error: --passes requires a positive integer value";
                return result;
            }

            result.request.options.passes = passes;
            ++index;
            continue;
        }

        if (option == "--pattern") {
            if (index + 1 >= args.size()) {
                result.ok = false;
                result.exit_code = 2;
                result.error_message = "Error: --pattern requires one of zeros|random";
                return result;
            }

            if (!try_parse_pattern(args[index + 1], result.request.options.pattern)) {
                result.ok = false;
                result.exit_code = 2;
                result.error_message = "Error: unknown pattern: " + args[index + 1];
                return result;
            }

            ++index;
            continue;
        }

        if (option == "--dry-run") {
            result.request.dry_run = true;
            continue;
        }

        if (option == "--yes") {
            result.request.yes = true;
            continue;
        }

        result.ok = false;
        result.exit_code = 2;
        result.error_message = "Error: unknown option: " + option;
        return result;
    }

    if (result.request.kind == CommandKind::WipeFile && (result.request.dry_run || result.request.yes)) {
        result.ok = false;
        result.exit_code = 2;
        result.error_message = "Error: --dry-run and --yes are only valid with wipe-dir";
        return result;
    }

    return result;
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

bool CommandLineApplication::try_parse_positive_int(const std::string& text, int& value) {
    const char* begin = text.data();
    const char* end = text.data() + text.size();
    const auto [ptr, error] = std::from_chars(begin, end, value);
    return error == std::errc() && ptr == end && value > 0;
}

bool CommandLineApplication::try_parse_pattern(const std::string& text, Pattern& pattern) {
    if (text == "zeros") {
        pattern = Pattern::Zeros;
        return true;
    }
    if (text == "random") {
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
        return 1;
    }

    print_inspection_report(report);
    return report.recommendation == StrategyRecommendation::Refuse ? 2 : 0;
}

int CommandLineApplication::run_wipe_file(const CommandRequest& request) const {
    const WipeResult result = wipe_file(request.path, request.options);
    if (!result.ok) {
        error_output_ << "Wipe failed: " << result.message << '\n';
        return 1;
    }

    output_ << result.message << '\n';
    return 0;
}

int CommandLineApplication::run_wipe_directory(const CommandRequest& request) const {
    const WipeResult result = wipe_directory(request.path, request.options, request.dry_run, request.yes);
    if (!result.ok) {
        error_output_ << "Wipe-dir failed: " << result.message << '\n';
        return 1;
    }

    output_ << result.message << '\n';
    return 0;
}

void CommandLineApplication::print_inspection_report(const InspectionReport& report) const {
    output_ << "path: " << report.canonical_path << '\n';
    output_ << "target-kind: " << to_string(report.target_kind) << '\n';
    output_ << "storage-kind: " << to_string(report.storage_kind) << '\n';
    output_ << "recommendation: " << to_string(report.recommendation) << '\n';
    if (!report.volume_name.empty()) {
        output_ << "volume: " << report.volume_name << '\n';
    }
    output_ << "dangerous: " << (report.dangerous ? "yes" : "no") << '\n';
    output_ << "summary: " << report.message << '\n';
    for (const auto& warning : report.warnings) {
        output_ << "warning: " << warning << '\n';
    }
}

} // namespace securewipe::app