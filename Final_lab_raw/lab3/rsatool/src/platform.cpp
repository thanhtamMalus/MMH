// platform.cpp — Platform-specific implementations
#include <rsatool/platform.hpp>
#include <rsatool/errors.hpp>

#include <array>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <random>
#include <sstream>
#include <string>

#ifdef _WIN32
#  include <windows.h>
#  include <aclapi.h>
#else
#  include <sys/stat.h>
#endif

namespace rsatool::platform {

void restrict_private_file(const std::filesystem::path& path) {
#ifdef _WIN32
    // On Windows, print a warning. Full ACL restriction is complex.
    // The file is written without inheriting parent ACLs is preferred,
    // but as documented in README, we emit a one-line warning.
    (void)path;
    fprintf(stderr,
        "warning: Windows: private key file created but permissions are not "
        "restricted to the current user. Store it securely.\n");
#else
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::permissions(path,
        fs::perms::owner_read | fs::perms::owner_write,
        fs::perm_options::replace,
        ec);
    if (ec) {
        // Non-fatal: warn but do not abort
        fprintf(stderr, "warning: could not set private key permissions: %s\n",
                ec.message().c_str());
    }
#endif
}

std::string utc_iso8601() {
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t t = system_clock::to_time_t(now);

    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif

    std::array<char, 32> buf{};
    std::strftime(buf.data(), buf.size(), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return std::string(buf.data());
}

std::filesystem::path from_utf8(const std::string& utf8) {
#ifdef _WIN32
    // Convert UTF-8 to wstring for Windows path
    if (utf8.empty()) return {};
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(),
                                   static_cast<int>(utf8.size()), nullptr, 0);
    if (wlen <= 0) return std::filesystem::path(utf8);
    std::wstring wstr(static_cast<std::size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(),
                        static_cast<int>(utf8.size()), wstr.data(), wlen);
    return std::filesystem::path(wstr);
#else
    return std::filesystem::path(utf8);
#endif
}

std::filesystem::path temp_path_for(const std::filesystem::path& target) {
    // Generate a unique temp file in the same directory as target
    auto dir = target.parent_path();
    if (dir.empty()) dir = ".";

    // Use a random suffix
    std::random_device rd;
    std::uniform_int_distribution<uint32_t> dist;
    std::ostringstream oss;
    oss << target.filename().string() << ".tmp." << dist(rd);
    return dir / oss.str();
}

} // namespace rsatool::platform

