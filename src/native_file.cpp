#include "internal/secure_wipe_engine.h"

#include <cerrno>
#include <cstring>
#include <utility>

#if defined(_WIN32)
#define NOMINMAX
#include <io.h>
#include <windows.h>
#endif

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

namespace securewipe::detail {

NativeFile::NativeFile(const fs::path& path) {
#if defined(_WIN32)
    if (_wfopen_s(&handle_, path.c_str(), L"r+b") != 0 || handle_ == nullptr) {
        open_error_ = last_error("Failed to open file for overwrite");
    }
#else
    handle_ = std::fopen(path.c_str(), "r+b");
    if (handle_ == nullptr) {
        open_error_ = last_error("Failed to open file for overwrite");
    }
#endif
}

NativeFile::~NativeFile() noexcept {
    if (handle_ != nullptr) {
        std::fclose(handle_);
    }
}

NativeFile::NativeFile(NativeFile&& other) noexcept
    : handle_(other.handle_),
      open_error_(std::move(other.open_error_)) {
    other.handle_ = nullptr;
}

NativeFile& NativeFile::operator=(NativeFile&& other) noexcept {
    if (this == &other) return *this;

    if (handle_ != nullptr) {
        std::fclose(handle_);
    }

    handle_ = other.handle_;
    open_error_ = std::move(other.open_error_);
    other.handle_ = nullptr;
    return *this;
}

bool NativeFile::is_open() const noexcept {
    return handle_ != nullptr;
}

const std::string& NativeFile::open_error() const noexcept {
    return open_error_;
}

std::string NativeFile::seek_to_start() {
    if (handle_ == nullptr) return "File handle is not open";
    if (std::fseek(handle_, 0, SEEK_SET) == 0) return {};
    return last_error("Failed to seek during overwrite");
}

std::string NativeFile::write(const unsigned char* buffer, std::size_t size) {
    if (handle_ == nullptr) return "File handle is not open";
    if (std::fwrite(buffer, 1, size, handle_) == size) return {};
    return last_error("Write failed during overwrite");
}

std::string NativeFile::flush() {
    if (handle_ == nullptr) return "File handle is not open";
    if (std::fflush(handle_) != 0) return last_error("Flush failed");

#if defined(_WIN32)
    const int fd = _fileno(handle_);
    if (fd < 0) return last_error("Flush failed");

    const intptr_t handle_value = _get_osfhandle(fd);
    if (handle_value == -1) return last_error("Flush failed");
    if (FlushFileBuffers(reinterpret_cast<HANDLE>(handle_value)) != 0) return {};
    return last_error("Flush failed");
#elif defined(__unix__) || defined(__APPLE__)
    const int fd = fileno(handle_);
    if (fd < 0) return last_error("Flush failed");
    if (fsync(fd) == 0) return {};
    return last_error("Flush failed");
#else
    return {};
#endif
}

std::string NativeFile::close() {
    if (handle_ == nullptr) return {};

    if (std::fclose(handle_) != 0) {
        handle_ = nullptr;
        return last_error("Failed to close file after overwrite");
    }

    handle_ = nullptr;
    return {};
}

std::string NativeFile::last_error(const char* prefix) {
#if defined(_WIN32)
    char buffer[256] = {};
    strerror_s(buffer, sizeof(buffer), errno);
    return std::string(prefix) + ": " + buffer;
#else
    return std::string(prefix) + ": " + std::strerror(errno);
#endif
}

} // namespace securewipe::detail