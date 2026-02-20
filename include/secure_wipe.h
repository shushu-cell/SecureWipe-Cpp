#pragma once
#include <cstddef>
#include <string>

namespace securewipe {

enum class Pattern {
    Zeros,
    Random
};

struct WipeOptions {
    int passes = 1;                 // overwrite passes
    Pattern pattern = Pattern::Zeros;
    std::size_t block_size = 1 << 20; // 1 MiB
};

struct WipeResult {
    bool ok = false;
    std::string message;  // error or info
};

WipeResult wipe_file(const std::string& path, const WipeOptions& opt);
WipeResult wipe_directory(const std::string& dir, const WipeOptions& opt, bool dry_run, bool yes);
} // namespace securewipe