#include <rsalab/util.hpp>

#include <fstream>

// Read entire file into SecureBuffer (implementation - same as inline, kept for clarity)
SecureBuffer read_file_impl(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw rsalab::IoError("Cannot open file for reading: " + path);
    }
    std::streamsize size = file.tellg();
    if (size < 0) {
        file.close();
        throw rsalab::IoError("Cannot determine file size: " + path);
    }
    file.seekg(0, std::ios::beg);
    SecureBuffer buffer(static_cast<std::size_t>(size));
    if (size > 0) {
        file.read(reinterpret_cast<char*>(buffer.data()), size);
        if (static_cast<std::streamsize>(file.gcount()) != size) {
            file.close();
            throw rsalab::IoError("Failed to read entire file: " + path);
        }
    }
    file.close();
    return buffer;
}

// Write SecureBuffer to file (implementation)
bool write_file_impl(const std::string& path, const rsalab::SecureBuffer& data) {
    std::string tmp_path = path + ".tmp";
    std::ofstream file(tmp_path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (file.fail()) {
        file.close();
        std::remove(tmp_path.c_str());
        return false;
    }
    file.close();

    // Atomic rename
#ifdef _WIN32
    if (!MoveFileExA(tmp_path.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        std::remove(tmp_path.c_str());
        return false;
    }
#else
    if (std::rename(tmp_path.c_str(), path.c_str()) != 0) {
        std::remove(tmp_path.c_str());
        return false;
    }
#endif
    return true;
}

// Exported functions that are declared inline in header but also have definitions in .cpp
// These are kept for separation of concerns; the inline versions in the header take precedence
// but the .cpp definitions provide the single definition rule compliance.