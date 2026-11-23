// platform.hpp — Platform-specific helpers (file permissions, timestamps, paths)
#pragma once
#include <filesystem>
#include <string>

namespace rsatool::platform {

/// Restrict a private key file: chmod 0600 on POSIX, warning on Windows.
void restrict_private_file(const std::filesystem::path& path);

/// Return current UTC time as ISO-8601 string, e.g. "2025-01-01T12:00:00Z".
std::string utc_iso8601();

/// Convert a UTF-8 string to a filesystem path (handles Windows wide-char).
std::filesystem::path from_utf8(const std::string& utf8);

/// Return a unique temp path in the same directory as target.
std::filesystem::path temp_path_for(const std::filesystem::path& target);

} // namespace rsatool::platform

