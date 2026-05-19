#include <iostream>
#include <string>
#include <vector>
#include "secure_wipe.h"

static const char* to_string(securewipe::TargetKind kind) {
    switch (kind) {
    case securewipe::TargetKind::Missing:
        return "missing";
    case securewipe::TargetKind::RegularFile:
        return "regular-file";
    case securewipe::TargetKind::Directory:
        return "directory";
    case securewipe::TargetKind::Symlink:
        return "symlink";
    case securewipe::TargetKind::Other:
        return "other";
    }
    return "unknown";
}

static const char* to_string(securewipe::StorageKind kind) {
    switch (kind) {
    case securewipe::StorageKind::Unknown:
        return "unknown";
    case securewipe::StorageKind::FixedDisk:
        return "fixed-disk";
    case securewipe::StorageKind::RotationalDisk:
        return "rotational-disk";
    case securewipe::StorageKind::SolidState:
        return "solid-state";
    case securewipe::StorageKind::RemovableDisk:
        return "removable-disk";
    case securewipe::StorageKind::NetworkShare:
        return "network-share";
    }
    return "unknown";
}

static const char* to_string(securewipe::StrategyRecommendation recommendation) {
    switch (recommendation) {
    case securewipe::StrategyRecommendation::None:
        return "none";
    case securewipe::StrategyRecommendation::Refuse:
        return "refuse";
    case securewipe::StrategyRecommendation::BestEffortFileOverwrite:
        return "best-effort-file-overwrite";
    case securewipe::StrategyRecommendation::BestEffortDirectoryWipe:
        return "best-effort-directory-wipe";
    case securewipe::StrategyRecommendation::ReviewBeforeWipe:
        return "review-before-wipe";
    }
    return "unknown";
}

static void print_help() {
    std::cout <<
R"(SecureWipe-Cpp (prototype)

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

static int inspect_command(const std::string& path) {
    const auto report = securewipe::inspect_target(path);
    if (!report.ok) {
        std::cerr << "Inspect failed: " << report.message << "\n";
        return 1;
    }

    std::cout << "path: " << report.canonical_path << "\n";
    std::cout << "target-kind: " << to_string(report.target_kind) << "\n";
    std::cout << "storage-kind: " << to_string(report.storage_kind) << "\n";
    std::cout << "recommendation: " << to_string(report.recommendation) << "\n";
    if (!report.volume_name.empty()) {
        std::cout << "volume: " << report.volume_name << "\n";
    }
    std::cout << "dangerous: " << (report.dangerous ? "yes" : "no") << "\n";
    std::cout << "summary: " << report.message << "\n";
    for (const auto& warning : report.warnings) {
        std::cout << "warning: " << warning << "\n";
    }

    return report.recommendation == securewipe::StrategyRecommendation::Refuse ? 2 : 0;
}

int main(int argc, char* argv[]) {
    std::vector<std::string> args(argv + 1, argv + argc);

    if (args.empty() || args[0] == "--help" || args[0] == "-h") {
        print_help();
        return 0;
    }

    const std::string cmd = args[0];
    if (cmd == "inspect") {
        if (args.size() != 2) {
            std::cerr << "Error: inspect requires exactly one <path> argument\n\n";
            print_help();
            return 2;
        }
        return inspect_command(args[1]);
    }

    if (cmd == "wipe" || cmd == "wipe-dir") {
        if (args.size() < 2) {
            std::cerr << "Error: missing <path>\n\n";
            print_help();
            return 2;
        }
        const std::string path = args[1];

        securewipe::WipeOptions opt;
        bool dry_run = false;
        bool yes = false;

        for (size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--passes" && i + 1 < args.size()) {
                opt.passes = std::stoi(args[i + 1]);
                ++i;
            } else if (args[i] == "--pattern" && i + 1 < args.size()) {
                const auto& p = args[i + 1];
                if (p == "zeros") opt.pattern = securewipe::Pattern::Zeros;
                else if (p == "random") opt.pattern = securewipe::Pattern::Random;
                else {
                    std::cerr << "Error: unknown pattern: " << p << "\n";
                    return 2;
                }
                ++i;
            } else if (args[i] == "--dry-run") {
                dry_run = true;
            } else if (args[i] == "--yes") {
                yes = true;
            } else {
                std::cerr << "Error: unknown option: " << args[i] << "\n";
                return 2;
            }
        }

        if (cmd == "wipe") {
            auto res = securewipe::wipe_file(path, opt);
            if (!res.ok) {
                std::cerr << "Wipe failed: " << res.message << "\n";
                return 1;
            }
            std::cout << res.message << "\n";
            return 0;
        }

        // wipe-dir
        auto res = securewipe::wipe_directory(path, opt, dry_run, yes);
        if (!res.ok) {
            std::cerr << "Wipe-dir failed: " << res.message << "\n";
            return 1;
        }
        std::cout << res.message << "\n";
        return 0;
    }

    std::cerr << "Unknown command: " << cmd << "\n\n";
    print_help();
    return 2;
}