#include "secure_wipe.h"
#include <iostream>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>  // fsync
#endif

namespace fs = std::filesystem;

namespace securewipe {

static std::string errstr(const char* prefix) {
    return std::string(prefix) + ": " + std::strerror(errno);
}

static bool flush_to_disk(std::ofstream& ofs) {
    ofs.flush();
    if (!ofs) return false;

#if defined(__unix__) || defined(__APPLE__)
    // Best-effort: ensure data reaches disk.
    // Note: This is not a cryptographic guarantee, and SSD/TRIM may limit effectiveness.
    int fd = -1;
    // Hack: get fd from ofstream is non-standard; we can't portably do it.
    // We'll rely on flush() here. (On Windows we can use FlushFileBuffers.)
    (void)fd;
#endif
    return true;
}

WipeResult wipe_file(const std::string& path, const WipeOptions& opt) {
    WipeResult r;

    std::error_code ec;
    if (!fs::exists(path, ec)) {
        r.ok = false;
        r.message = "Path does not exist";
        return r;
    }
    if (!fs::is_regular_file(path, ec)) {
        r.ok = false;
        r.message = "Path is not a regular file (directories not supported in MVP)";
        return r;
    }

    const auto file_size = fs::file_size(path, ec);
    if (ec) {
        r.ok = false;
        r.message = "Failed to get file size: " + ec.message();
        return r;
    }

    if (opt.passes <= 0) {
        r.ok = false;
        r.message = "passes must be >= 1";
        return r;
    }

    std::vector<unsigned char> buf(opt.block_size);

    std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 255);

    for (int pass = 1; pass <= opt.passes; ++pass) {
        std::ofstream ofs(path, std::ios::binary | std::ios::in | std::ios::out);
        if (!ofs) {
            r.ok = false;
            r.message = errstr("Failed to open file for overwrite");
            return r;
        }

        std::uintmax_t remaining = file_size;
        while (remaining > 0) {
            std::size_t chunk = static_cast<std::size_t>(
                std::min<std::uintmax_t>(remaining, buf.size()));

            if (opt.pattern == Pattern::Zeros) {
                std::fill(buf.begin(), buf.begin() + chunk, 0x00);
            } else {
                for (std::size_t i = 0; i < chunk; ++i) {
                    buf[i] = static_cast<unsigned char>(dist(rng));
                }
            }

            ofs.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(chunk));
            if (!ofs) {
                r.ok = false;
                r.message = errstr("Write failed during overwrite");
                return r;
            }
            remaining -= chunk;
        }

        if (!flush_to_disk(ofs)) {
            r.ok = false;
            r.message = "Flush failed";
            return r;
        }
    }

    // Remove the file after overwrite
    if (!fs::remove(path, ec) || ec) {
        r.ok = false;
        r.message = "Failed to delete file: " + (ec ? ec.message() : std::string("unknown error"));
        return r;
    }

    r.ok = true;
    r.message = "Wiped and deleted successfully";
    return r;
}

static bool is_dangerous_dir(const fs::path& p) {
    std::error_code ec;
    fs::path canon = fs::weakly_canonical(p, ec);
    if (ec) canon = fs::absolute(p, ec);
    if (ec) return true;

    // Refuse root
    if (canon == fs::path("/")) return true;

    // Common macOS system dirs (hard refuse)
    const fs::path sys1("/System");
    const fs::path sys2("/Library");
    const fs::path sys3("/Applications");
    if (canon == sys1 || canon == sys2 || canon == sys3) return true;

    // Refuse wiping the user's home directory root (best-effort)
    const char* home = std::getenv("HOME");
    if (home) {
        std::error_code ec2;
        fs::path homep = fs::weakly_canonical(fs::path(home), ec2);
        if (!ec2 && canon == homep) return true;
    }

    return false;
}

WipeResult wipe_directory(const std::string& dir, const WipeOptions& opt, bool dry_run, bool yes) {
    WipeResult r;
    std::error_code ec;

    fs::path d(dir);
    if (!fs::exists(d, ec) || ec) {
        r.ok = false;
        r.message = "Directory does not exist";
        return r;
    }
    if (!fs::is_directory(d, ec) || ec) {
        r.ok = false;
        r.message = "Path is not a directory";
        return r;
    }

    if (is_dangerous_dir(d)) {
        r.ok = false;
        r.message = "Refusing to wipe a dangerous directory. Choose a safer target.";
        return r;
    }

    // Safety model:
    // - default is dry-run (list files)
    // - to actually wipe, user must pass --yes
    if (!dry_run && !yes) {
        r.ok = false;
        r.message = "Safety stop: wipe-dir requires --dry-run (preview) or --yes (execute).";
        return r;
    }

    std::uint64_t total_files = 0;
    std::uint64_t wiped_files = 0;
    std::uint64_t failed_files = 0;

    // First pass: enumerate files (skip symlinks)
    for (auto it = fs::recursive_directory_iterator(d, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) continue;

        const fs::path p = it->path();

        // Avoid following symlinks to prevent escaping the directory
        std::error_code ec2;
        if (fs::is_symlink(p, ec2)) {
            continue;
        }

        if (fs::is_regular_file(p, ec2) && !ec2) {
            ++total_files;
            if (dry_run) {
                std::cout << "[DRY-RUN] would wipe: " << p.string() << "\n";
            }
        }
    }

    if (dry_run) {
        r.ok = true;
        r.message = "Dry-run complete. Files to wipe: " + std::to_string(total_files) +
                    ". Re-run with --yes to execute.";
        return r;
    }

    // Execute: wipe files
    for (auto it = fs::recursive_directory_iterator(d, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) continue;

        const fs::path p = it->path();

        std::error_code ec2;
        if (fs::is_symlink(p, ec2)) {
            continue;
        }

        if (fs::is_regular_file(p, ec2) && !ec2) {
            auto res = wipe_file(p.string(), opt);
            if (res.ok) ++wiped_files;
            else {
                ++failed_files;
                std::cerr << "[FAIL] " << p.string() << " : " << res.message << "\n";
            }
        }
    }

    // Optional cleanup: attempt to remove empty directories (bottom-up)
    // We do best-effort; failures are OK.
    // Note: recursive_directory_iterator is top-down, so we can collect dirs and remove reversed.
    std::vector<fs::path> dirs;
    for (auto it = fs::recursive_directory_iterator(d, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) continue;
        std::error_code ec3;
        if (fs::is_directory(it->path(), ec3) && !ec3) dirs.push_back(it->path());
    }
    for (auto it = dirs.rbegin(); it != dirs.rend(); ++it) {
        std::error_code ec4;
        fs::remove(*it, ec4); // removes only if empty
    }

    r.ok = (failed_files == 0);
    r.message = "wipe-dir complete. total=" + std::to_string(total_files) +
                ", wiped=" + std::to_string(wiped_files) +
                ", failed=" + std::to_string(failed_files);
    return r;
}

} // namespace securewipe