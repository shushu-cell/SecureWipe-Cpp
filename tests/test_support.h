#pragma once

#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>

namespace test_support {

namespace fs = std::filesystem;

class TempDir {
public:
    TempDir();
    ~TempDir();

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    [[nodiscard]] const fs::path& path() const noexcept {
        return path_;
    }

private:
    fs::path path_;
};

inline TempDir::TempDir() {
    const auto seed = std::random_device{}();
    path_ = fs::temp_directory_path() /
            ("securewipe-tests-" + std::to_string(static_cast<unsigned long long>(seed)));
    fs::create_directories(path_);
}

inline TempDir::~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
}

inline void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

inline void write_text_file(const fs::path& path, std::string_view contents) {
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("Failed to create test file: " + path.string());
    }

    output << contents;
}

inline std::string read_field_value(const std::string& report, std::string_view field_name) {
    const std::string prefix = std::string(field_name) + ": ";
    const auto line_begin = report.find(prefix);
    if (line_begin == std::string::npos) {
        throw std::runtime_error("Missing report field: " + std::string(field_name));
    }

    const auto value_begin = line_begin + prefix.size();
    const auto line_end = report.find('\n', value_begin);
    return report.substr(value_begin, line_end == std::string::npos ? std::string::npos : line_end - value_begin);
}

inline bool matches_any(std::string_view value, std::initializer_list<std::string_view> candidates) {
    for (const auto candidate : candidates) {
        if (value == candidate) {
            return true;
        }
    }

    return false;
}

inline bool contains(std::string_view text, std::string_view needle) {
    return text.find(needle) != std::string_view::npos;
}

} // namespace test_support