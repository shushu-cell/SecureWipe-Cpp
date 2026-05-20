#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "src/internal/cli_application.h"
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

std::string read_field_value(const std::string& report, std::string_view field_name) {
    const std::string prefix = std::string(field_name) + ": ";
    const auto line_begin = report.find(prefix);
    if (line_begin == std::string::npos) {
        throw std::runtime_error("Missing report field: " + std::string(field_name));
    }

    const auto value_begin = line_begin + prefix.size();
    const auto line_end = report.find('\n', value_begin);
    return report.substr(value_begin, line_end == std::string::npos ? std::string::npos : line_end - value_begin);
}

bool matches_any(std::string_view value, std::initializer_list<std::string_view> candidates) {
    for (const auto candidate : candidates) {
        if (value == candidate) {
            return true;
        }
    }

    return false;
}

bool contains(std::string_view text, std::string_view needle) {
    return text.find(needle) != std::string_view::npos;
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

void test_inspect_missing_path() {
    TempDir temp;
    const auto report = securewipe::inspect_target((temp.path() / "missing.txt").string());
    require(!report.ok, "inspect_target should fail for a missing path");
    require(report.target_kind == securewipe::TargetKind::Missing,
            "missing paths should keep the default target kind");
    require(report.message == "Path does not exist", "missing path message should be explicit");
}

void test_cli_without_arguments_prints_generated_help() {
    std::ostringstream output;
    std::ostringstream error_output;
    securewipe::app::CommandLineApplication application(output, error_output);

    const int exit_code = application.run({});
    require(exit_code == 0, "CLI without arguments should print help and succeed");
    require(error_output.str().empty(), "CLI help should not emit stderr");

    const std::string help = output.str();
        require(contains(help, "securewipe [OPTIONS] [SUBCOMMAND]"),
            "CLI11 should generate a command synopsis");
        require(contains(help, "SUBCOMMANDS:"),
            "CLI11 should generate a subcommand section");
    require(contains(help, "inspect"), "CLI11 help should list the inspect subcommand");
    require(contains(help, "wipe-dir"), "CLI11 help should list the wipe-dir subcommand");
    require(contains(help, "Examples:"), "CLI11 help should include the configured examples footer");
}

void test_cli_inspect_reports_stable_labels() {
    TempDir temp;
    const fs::path file = temp.path() / "sample.txt";
    write_text_file(file, "secret");

    std::ostringstream output;
    std::ostringstream error_output;
    securewipe::app::CommandLineApplication application(output, error_output);

    const int exit_code = application.run({"inspect", file.string()});
    require(exit_code == 0, "CLI inspect should succeed for a regular file");
    require(error_output.str().empty(), "CLI inspect should not emit stderr on success");

    const std::string report = output.str();
    require(read_field_value(report, "target-kind") == "regular-file",
            "CLI inspect should render TargetKind::RegularFile with a stable label");

    const std::string storage_kind = read_field_value(report, "storage-kind");
    require(matches_any(storage_kind,
                        {"unknown", "fixed-disk", "rotational-disk", "solid-state", "removable-disk", "network-share"}),
            "CLI inspect should render storage kinds using the supported label set");

    const std::string recommendation = read_field_value(report, "recommendation");
    require(matches_any(recommendation,
                        {"best-effort-file-overwrite", "review-before-wipe", "refuse"}),
            "CLI inspect should render recommendations using the supported label set");
}

void test_cli_inspect_refusal_uses_refuse_label() {
    std::ostringstream output;
    std::ostringstream error_output;
    securewipe::app::CommandLineApplication application(output, error_output);

    const fs::path root = fs::current_path().root_path();
    const int exit_code = application.run({"inspect", root.string()});
    require(exit_code == 2, "CLI inspect should reject dangerous root targets");
    require(error_output.str().empty(), "CLI inspect should print refusal reports to stdout, not stderr");

    const std::string report = output.str();
    require(read_field_value(report, "target-kind") == "directory",
            "CLI inspect should render root paths as directories");
    require(read_field_value(report, "recommendation") == "refuse",
            "CLI inspect should render StrategyRecommendation::Refuse with a stable label");
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

void test_wipe_file_rejects_zero_block_size() {
    TempDir temp;
    const fs::path file = temp.path() / "invalid.bin";
    write_text_file(file, "payload");

    securewipe::WipeOptions options;
    options.block_size = 0;

    const auto result = securewipe::wipe_file(file.string(), options);
    require(!result.ok, "wipe_file should reject zero-sized blocks");
    require(result.message == "block_size must be >= 1", "invalid block size should be explained");
    require(fs::exists(file), "wipe_file should leave the file intact on invalid options");
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

void test_wipe_directory_requires_confirmation() {
    TempDir temp;
    const fs::path dir = temp.path() / "folder";
    fs::create_directories(dir);
    write_text_file(dir / "root.txt", "alpha");

    securewipe::WipeOptions options;
    const auto result = securewipe::wipe_directory(dir.string(), options, false, false);
    require(!result.ok, "wipe_directory should require confirmation before execution");
    require(result.message.find("requires --dry-run") != std::string::npos,
            "wipe_directory should explain the confirmation requirement");
    require(fs::exists(dir / "root.txt"), "wipe_directory should not delete files without confirmation");
}

void test_wipe_directory_executes_when_confirmed() {
    TempDir temp;
    const fs::path dir = temp.path() / "folder";
    fs::create_directories(dir / "nested");
    write_text_file(dir / "root.txt", "alpha");
    write_text_file(dir / "nested" / "child.txt", "beta");

    securewipe::WipeOptions options;
    options.block_size = 64;

    const auto result = securewipe::wipe_directory(dir.string(), options, false, true);
    require(result.ok, "wipe_directory should succeed after confirmation");
    require(result.files_total == 2, "wipe_directory should count the files it processed");
    require(result.files_wiped == 2, "wipe_directory should report both files as wiped");
    require(!fs::exists(dir / "root.txt"), "confirmed wipe_directory should remove the root file");
    require(!fs::exists(dir / "nested" / "child.txt"), "confirmed wipe_directory should remove nested files");
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
        test_inspect_missing_path();
        test_cli_without_arguments_prints_generated_help();
        test_cli_inspect_reports_stable_labels();
        test_cli_inspect_refusal_uses_refuse_label();
        test_wipe_file_removes_target();
        test_wipe_file_rejects_zero_block_size();
        test_wipe_directory_dry_run_preserves_files();
        test_wipe_directory_requires_confirmation();
        test_wipe_directory_executes_when_confirmed();
        test_dangerous_root_is_refused();
        std::cout << "All tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Test failure: " << error.what() << '\n';
        return 1;
    }
}