#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>

#include "secure_wipe.h"

namespace fs = std::filesystem;

namespace {

class TempDir {
public:
    TempDir() {
        const auto seed = std::random_device{}();
        path_ = fs::temp_directory_path() /
                ("securewipe-tests-" + std::to_string(static_cast<unsigned long long>(seed)));
        fs::create_directories(path_);
    }

    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }

    const fs::path& path() const {
        return path_;
    }

private:
    fs::path path_;
};

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void write_text_file(const fs::path& path, const std::string& contents) {
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("Failed to create test file: " + path.string());
    }
    output << contents;
}

void test_inspect_regular_file() {
    TempDir temp;
    const fs::path file = temp.path() / "sample.txt";
    write_text_file(file, "secret");

    const auto report = securewipe::inspect_target(file.string());
    require(report.ok, "inspect_target should succeed for a regular file");
    require(report.target_kind == securewipe::TargetKind::RegularFile,
            "inspect_target should classify regular files correctly");
    require(!report.canonical_path.empty(), "inspect_target should return a canonical path");
    require(!report.warnings.empty(), "inspect_target should surface media or filesystem caveats");
}

void test_wipe_file_removes_target() {
    TempDir temp;
    const fs::path file = temp.path() / "erase-me.bin";
    write_text_file(file, std::string(4096, 'A'));

    securewipe::WipeOptions options;
    options.passes = 1;
    options.pattern = securewipe::Pattern::Zeros;
    options.block_size = 128;

    const auto result = securewipe::wipe_file(file.string(), options);
    require(result.ok, "wipe_file should succeed for a temporary file");
    require(!fs::exists(file), "wipe_file should remove the target file");
    require(result.files_wiped == 1, "wipe_file should report one wiped file");
}

void test_wipe_directory_dry_run_preserves_files() {
    TempDir temp;
    const fs::path dir = temp.path() / "folder";
    fs::create_directories(dir / "nested");
    write_text_file(dir / "root.txt", "alpha");
    write_text_file(dir / "nested" / "child.txt", "beta");

    securewipe::WipeOptions options;
    const auto result = securewipe::wipe_directory(dir.string(), options, true, false);
    require(result.ok, "wipe_directory dry-run should succeed");
    require(result.dry_run, "wipe_directory should mark dry-run results");
    require(result.files_total == 2, "wipe_directory dry-run should count all regular files");
    require(fs::exists(dir / "root.txt"), "dry-run must not delete files");
    require(fs::exists(dir / "nested" / "child.txt"), "dry-run must preserve nested files");
}

void test_dangerous_root_is_refused() {
    const fs::path root = fs::current_path().root_path();
    const auto report = securewipe::inspect_target(root.string());
    require(report.ok, "inspect_target should inspect the filesystem root");
    require(report.target_kind == securewipe::TargetKind::Directory,
            "root path should be classified as a directory");
    require(report.dangerous, "filesystem root must be classified as dangerous");
    require(report.recommendation == securewipe::StrategyRecommendation::Refuse,
            "filesystem root must be refused");
}

} // namespace

int main() {
    try {
        test_inspect_regular_file();
        test_wipe_file_removes_target();
        test_wipe_directory_dry_run_preserves_files();
        test_dangerous_root_is_refused();
        std::cout << "All tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Test failure: " << error.what() << '\n';
        return 1;
    }
}