#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

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

enum class TargetKind {
    Missing,
    RegularFile,
    Directory,
    Symlink,
    Other
};

enum class StorageKind {
    Unknown,
    FixedDisk,
    RotationalDisk,
    SolidState,
    RemovableDisk,
    NetworkShare
};

enum class StrategyRecommendation {
    None,
    Refuse,
    BestEffortFileOverwrite,
    BestEffortDirectoryWipe,
    ReviewBeforeWipe
};

struct [[nodiscard]] WipeResult {
    bool ok = false;
    bool dry_run = false;
    std::uint64_t files_total = 0;
    std::uint64_t files_wiped = 0;
    std::uint64_t files_failed = 0;
    std::string message;  // error or info
};

struct [[nodiscard]] InspectionReport {
    bool ok = false;
    bool dangerous = false;
    TargetKind target_kind = TargetKind::Missing;
    StorageKind storage_kind = StorageKind::Unknown;
    StrategyRecommendation recommendation = StrategyRecommendation::None;
    std::string canonical_path;
    std::string volume_name;
    std::string message;
    std::vector<std::string> warnings;
};

[[nodiscard]] InspectionReport inspect_target(std::string_view path);
[[nodiscard]] WipeResult wipe_file(std::string_view path, const WipeOptions& opt);
[[nodiscard]] WipeResult wipe_directory(std::string_view dir, const WipeOptions& opt, bool dry_run, bool yes);
} // namespace securewipe