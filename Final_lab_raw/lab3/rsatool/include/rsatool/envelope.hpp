// envelope.hpp — Container format: [4-byte big-endian header_len][header JSON][payload]
// Header is AAD-bound to AES-GCM ciphertext.
#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include <rsatool/secure.hpp>

namespace rsatool::envelope {

/// Supported encryption modes in envelope header
inline constexpr char MODE_HYBRID[] = "RSA-OAEP-AES-GCM";
inline constexpr char MODE_DIRECT[] = "RSA-OAEP";
inline constexpr std::size_t MAX_HEADER_LEN = 65536;  // 64 KiB limit

/// Encrypt a file (or memory buffer) and write the envelope to output.
/// mode_hint: "auto" (default), "direct", or "hybrid".
/// encode_name: "raw", "hex", or "base64" for the whole output file.
void encrypt_file(
    const std::filesystem::path& in_path,
    const std::filesystem::path& out_path,
    const std::filesystem::path& pub_key_path,
    const std::string& label,
    const std::string& encode_name,
    const std::string& mode_hint);

/// Decrypt an envelope file and write plaintext to output.
void decrypt_file(
    const std::filesystem::path& in_path,
    const std::filesystem::path& out_path,
    const std::filesystem::path& priv_key_path,
    const std::string& label,
    const std::string& encode_name);

/// Serialize header to canonical bytes for AAD (excludes "tag" field for hybrid,
/// uses full header for direct). Deterministic: sorted keys, no whitespace.
std::vector<uint8_t> make_aad_bytes(const std::string& header_json);

} // namespace rsatool::envelope

