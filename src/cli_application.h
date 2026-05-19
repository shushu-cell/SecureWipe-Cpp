#pragma once

#include <iosfwd>
#include <string>
#include <vector>

#include "secure_wipe.h"

namespace securewipe::app {

class CommandLineApplication final {
public:
    CommandLineApplication(std::ostream& output, std::ostream& error_output);

    int run(const std::vector<std::string>& args) const;

private:
    enum class CommandKind {
        Help,
        Inspect,
        WipeFile,
        WipeDirectory
    };

    struct CommandRequest {
        CommandKind kind = CommandKind::Help;
        std::string path;
        WipeOptions options;
        bool dry_run = false;
        bool yes = false;
    };

    struct ParseResult {
        bool ok = false;
        int exit_code = 0;
        std::string error_message;
        CommandRequest request;
    };

    static ParseResult parse(const std::vector<std::string>& args);
    static void print_help(std::ostream& output);
    static bool try_parse_positive_int(const std::string& text, int& value);
    static bool try_parse_pattern(const std::string& text, Pattern& pattern);
    static const char* to_string(TargetKind kind);
    static const char* to_string(StorageKind kind);
    static const char* to_string(StrategyRecommendation recommendation);

    int run_inspect(const CommandRequest& request) const;
    int run_wipe_file(const CommandRequest& request) const;
    int run_wipe_directory(const CommandRequest& request) const;
    void print_inspection_report(const InspectionReport& report) const;

    std::ostream& output_;
    std::ostream& error_output_;
};

} // namespace securewipe::app