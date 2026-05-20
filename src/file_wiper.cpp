#include "internal/secure_wipe_engine.h"

#include <algorithm>

namespace securewipe::detail {

namespace {

WipeResult make_error_result(std::string message) {
    WipeResult result;
    result.message = std::move(message);
    return result;
}

std::string validate_options(const WipeOptions& options) {
    if (options.passes < 1) {
        return "passes must be >= 1";
    }

    if (options.block_size == 0) {
        return "block_size must be >= 1";
    }

    return {};
}

} // namespace

FileWiper::FileWiper(const PathInspector& inspector)
    : inspector_(inspector) {
}

WipeResult FileWiper::wipe(const std::string& path, const WipeOptions& options) const {
    return wipe(fs::path(path), options);
}

WipeResult FileWiper::wipe(const fs::path& path, const WipeOptions& options) const {
    const InspectionReport inspection = inspector_.inspect(path);
    if (!inspection.ok) {
        return make_error_result(inspection.message);
    }

    if (inspection.target_kind != TargetKind::RegularFile) {
        return make_error_result("Path is not a regular file");
    }

    if (const std::string options_error = validate_options(options); !options_error.empty()) {
        return make_error_result(options_error);
    }

    const fs::path file_path = inspector_.resolve_path(path);
    std::error_code ec;
    const auto file_size = fs::file_size(file_path, ec);
    if (ec) {
        return make_error_result("Failed to get file size: " + ec.message());
    }

    NativeFile file(file_path);
    if (!file.is_open()) {
        return make_error_result(file.open_error());
    }

    std::vector<unsigned char> buffer(options.block_size, 0);
    std::mt19937_64 rng(std::random_device{}());
    for (int pass = 0; pass < options.passes; ++pass) {
        if (const auto error = file.seek_to_start(); !error.empty()) {
            return make_error_result(error);
        }

        std::uintmax_t remaining = file_size;
        while (remaining > 0) {
            const std::size_t chunk = static_cast<std::size_t>(
                std::min<std::uintmax_t>(remaining, buffer.size()));
            fill_buffer(buffer, chunk, options.pattern, rng);
            if (const auto error = file.write(buffer.data(), chunk); !error.empty()) {
                return make_error_result(error);
            }
            remaining -= chunk;
        }

        if (const auto error = file.flush(); !error.empty()) {
            return make_error_result(error);
        }
    }

    if (const auto error = file.close(); !error.empty()) {
        return make_error_result(error);
    }

    fs::resize_file(file_path, 0, ec);
    if (ec) {
        return make_error_result("Failed to truncate file before deletion: " + ec.message());
    }

    fs::path delete_path = file_path;
    obscure_name_best_effort(delete_path);
    ec.clear();
    if (!fs::remove(delete_path, ec) || ec) {
        return make_error_result(
            "Failed to delete file: " + (ec ? ec.message() : std::string("unknown error")));
    }

    WipeResult result;
    result.ok = true;
    result.files_total = 1;
    result.files_wiped = 1;
    result.message = success_message(inspection);
    return result;
}

fs::path FileWiper::rename_candidate(const fs::path& path, int attempt) {
    const std::string stem = path.stem().string();
    const std::string extension = path.extension().string();
    std::string scrambled(stem.empty() ? 8 : stem.size(), 'x');
    if (attempt > 0) scrambled += std::to_string(attempt);
    return path.parent_path() / (scrambled + extension);
}

void FileWiper::fill_buffer(
    std::vector<unsigned char>& buffer,
    std::size_t chunk,
    Pattern pattern,
    std::mt19937_64& rng) {
    if (pattern == Pattern::Zeros) {
        std::fill(
            buffer.begin(),
            buffer.begin() + static_cast<std::ptrdiff_t>(chunk),
            static_cast<unsigned char>(0));
        return;
    }

    std::uniform_int_distribution<int> distribution(0, 255);
    std::generate_n(
        buffer.begin(),
        static_cast<std::ptrdiff_t>(chunk),
        [&distribution, &rng]() {
            return static_cast<unsigned char>(distribution(rng));
        });
}

bool FileWiper::obscure_name_best_effort(fs::path& path) {
    std::error_code ec;
    for (int attempt = 0; attempt < 8; ++attempt) {
        const fs::path candidate = rename_candidate(path, attempt);
        if (candidate == path) continue;

        ec.clear();
        fs::rename(path, candidate, ec);
        if (!ec) {
            path = candidate;
            return true;
        }
    }

    return false;
}

std::string FileWiper::success_message(const InspectionReport& report) {
    if (report.recommendation == StrategyRecommendation::ReviewBeforeWipe) {
        return "Wiped and deleted successfully (best-effort only; inspect warnings for media caveats)";
    }
    return "Wiped and deleted successfully";
}

} // namespace securewipe::detail