#pragma once

#if defined(__linux__)

#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace securewipe::detail {

namespace fs = std::filesystem;

struct LinuxMountEntry {
    std::string source;
    std::string mount_point;
    std::string mount_type;
};

inline std::string decode_linux_mount_field(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index + 3 < value.size() && value.compare(index, 4, "\\040") == 0) {
            result.push_back(' ');
            index += 3;
            continue;
        }

        result.push_back(value[index]);
    }

    return result;
}

inline std::optional<LinuxMountEntry> find_best_linux_mount_entry(const fs::path& path) {
    std::ifstream mounts("/proc/self/mounts");
    if (!mounts) {
        return std::nullopt;
    }

    std::error_code ec;
    const fs::path resolved = fs::weakly_canonical(path, ec);
    const std::string resolved_string = (!ec ? resolved : fs::absolute(path, ec)).string();

    std::optional<LinuxMountEntry> best_match;
    std::string line;
    while (std::getline(mounts, line)) {
        std::istringstream input(line);
        LinuxMountEntry entry;
        if (!(input >> entry.source >> entry.mount_point >> entry.mount_type)) {
            continue;
        }

        entry.mount_point = decode_linux_mount_field(entry.mount_point);
        if (resolved_string.rfind(entry.mount_point, 0) != 0) {
            continue;
        }

        if (best_match && entry.mount_point.size() < best_match->mount_point.size()) {
            continue;
        }

        best_match = std::move(entry);
    }

    return best_match;
}

inline std::string normalize_linux_block_device_name(std::string_view source) {
    std::string device_name = fs::path(source).filename().string();
    if (device_name.rfind("nvme", 0) == 0 || device_name.rfind("mmcblk", 0) == 0) {
        const std::size_t partition_marker = device_name.find('p');
        if (partition_marker != std::string::npos) {
            device_name = device_name.substr(0, partition_marker);
        }
        return device_name;
    }

    while (!device_name.empty() && std::isdigit(static_cast<unsigned char>(device_name.back())) != 0) {
        device_name.pop_back();
    }

    return device_name;
}

} // namespace securewipe::detail

#endif