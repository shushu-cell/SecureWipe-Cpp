#include <iostream>
#include <string>
#include <vector>
#include "secure_wipe.h"
static void print_help() {
    std::cout <<
R"(SecureWipe-Cpp (prototype)

Usage:
  securewipe --help
  securewipe wipe <path> [--passes N] [--pattern zeros|random]
  securewipe wipe-dir <dir> [--passes N] [--pattern zeros|random] [--dry-run] [--yes]

Examples:
  securewipe wipe test.txt --passes 1 --pattern zeros
  securewipe wipe-dir ./tmp --dry-run
  securewipe wipe-dir ./tmp --passes 1 --pattern zeros --yes
)";
}

int main(int argc, char* argv[]) {
    std::vector<std::string> args(argv + 1, argv + argc);

    if (args.empty() || args[0] == "--help" || args[0] == "-h") {
        print_help();
        return 0;
    }

    const std::string cmd = args[0];
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