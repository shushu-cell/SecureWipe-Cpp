#pragma once

#include <cstdio>
#include <filesystem>
#include <iosfwd>
#include <random>
#include <string>
#include <vector>

#include "secure_wipe.h"

namespace securewipe::detail {

namespace fs = std::filesystem;

struct DirectoryScan {
    std::vector<fs::path> files;
    std::vector<fs::path> directories;
};

class PathInspector final {
public:
    InspectionReport inspect(const std::string& path) const;
    InspectionReport inspect(const fs::path& path) const;
    fs::path resolve_path(const fs::path& path) const;

private:
    static fs::path canonical_or_absolute(const fs::path& path);
    static bool paths_equal(const fs::path& left, const fs::path& right);
    static bool is_root_path(const fs::path& path);
    static std::string environment_value(const char* name);
    static std::string filesystem_hint_for_path(const fs::path& path);
    static StorageKind detect_storage_kind(const fs::path& path);
    static bool is_dangerous_directory(const fs::path& path);
    static bool is_probably_ssd_unsafe(StorageKind storage_kind) noexcept;
};

class NativeFile final {
public:
    explicit NativeFile(const fs::path& path);
    ~NativeFile() noexcept;

    NativeFile(const NativeFile&) = delete;
    NativeFile& operator=(const NativeFile&) = delete;
    NativeFile(NativeFile&& other) noexcept;
    NativeFile& operator=(NativeFile&& other) noexcept;

    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] const std::string& open_error() const noexcept;
    [[nodiscard]] std::string seek_to_start();
    [[nodiscard]] std::string write(const unsigned char* buffer, std::size_t size);
    [[nodiscard]] std::string flush();
    [[nodiscard]] std::string close();

private:
    static std::string last_error(const char* prefix);
    std::FILE* handle_ = nullptr;
    std::string open_error_;
};

class FileWiper final {
public:
    explicit FileWiper(const PathInspector& inspector);

    WipeResult wipe(const std::string& path, const WipeOptions& options) const;
    WipeResult wipe(const fs::path& path, const WipeOptions& options) const;

private:
    static fs::path rename_candidate(const fs::path& path, int attempt);
    static void fill_buffer(
        std::vector<unsigned char>& buffer,
        std::size_t chunk,
        Pattern pattern,
        std::mt19937_64& rng);
    static bool obscure_name_best_effort(fs::path& path);
    static std::string success_message(const InspectionReport& report);

    const PathInspector& inspector_;
};

class DirectoryWiper final {
public:
    DirectoryWiper(
        const PathInspector& inspector,
        const FileWiper& file_wiper,
        std::ostream& output,
        std::ostream& error_output);

    WipeResult wipe(const std::string& path, const WipeOptions& options, bool dry_run, bool yes) const;

private:
    [[nodiscard]] DirectoryScan scan(const fs::path& root) const;
    void print_dry_run(const DirectoryScan& scan) const;
    void remove_empty_directories(const std::vector<fs::path>& directories) const;

    const PathInspector& inspector_;
    const FileWiper& file_wiper_;
    std::ostream& output_;
    std::ostream& error_output_;
};

class SecureWipeFacade final {
public:
    SecureWipeFacade(std::ostream& output, std::ostream& error_output);

    InspectionReport inspect(const std::string& path) const;
    WipeResult wipe_file(const std::string& path, const WipeOptions& options) const;
    WipeResult wipe_directory(const std::string& path, const WipeOptions& options, bool dry_run, bool yes) const;

private:
    PathInspector inspector_;
    FileWiper file_wiper_;
    DirectoryWiper directory_wiper_;
};

} // namespace securewipe::detail