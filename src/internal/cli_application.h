#pragma once

#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

#include "secure_wipe.h"

namespace securewipe::app {

class CommandLineApplication final {
public:
    CommandLineApplication(std::ostream& output, std::ostream& error_output);

    int run(const std::vector<std::string>& args) const;

private:
    enum class ExitCode : int {
        Success = 0,
        ExecutionFailure = 1,
        Rejected = 2
    };

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
        bool detail = false;
        bool dry_run = false;
        bool yes = false;
    };

    struct ParseResult {
        bool ok = false;
        ExitCode exit_code = ExitCode::Success;
        std::string error_message;
        std::string help_text;
        CommandRequest request;
    };

    [[nodiscard]] static ParseResult parse(const std::vector<std::string>& args);
    [[nodiscard]] static int to_exit_code(ExitCode exit_code) noexcept;
    static void write_field(std::ostream& output, std::string_view key, std::string_view value);
    [[nodiscard]] static std::string_view to_string(TargetKind kind) noexcept;
    [[nodiscard]] static std::string_view to_string(StorageKind kind) noexcept;
    [[nodiscard]] static std::string_view to_string(StrategyRecommendation recommendation) noexcept;
    [[nodiscard]] static std::string_view to_string(DeviceBusKind bus_kind) noexcept;
    [[nodiscard]] static std::string_view to_string(CapabilityState state) noexcept;
    [[nodiscard]] static std::string_view to_string(EraseMethod method) noexcept;
    [[nodiscard]] static std::string_view to_string(EvidenceSubject subject) noexcept;
    [[nodiscard]] static std::string_view to_string(EvidenceSource source) noexcept;
    [[nodiscard]] static std::string_view to_string(EvidenceConfidence confidence) noexcept;
    [[nodiscard]] static std::string_view to_string(PreflightRisk risk) noexcept;
    [[nodiscard]] static std::string_view to_string(ActionCandidateState state) noexcept;
    [[nodiscard]] static std::string_view to_string(ActionTargetScope target_scope) noexcept;
    [[nodiscard]] static std::string format_evidence_item(const CapabilityEvidenceItem& item);
    [[nodiscard]] static std::string format_action_candidate(const ActionCandidate& candidate);
    [[nodiscard]] static std::string format_action_blocker(const ActionCandidate& candidate, std::string_view blocker);

    int run_inspect(const CommandRequest& request) const;
    int run_wipe_file(const CommandRequest& request) const;
    int run_wipe_directory(const CommandRequest& request) const;
    void print_inspection_report(const InspectionReport& report, bool detail) const;
    void print_detailed_inspection_report(const InspectionReport& report) const;

    std::ostream& output_;
    std::ostream& error_output_;
};

} // namespace securewipe::app