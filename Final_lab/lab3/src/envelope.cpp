// envelope.cpp — Container format: [4B big-endian header_len][header JSON][payload]
// AAD-bound header: canonical header (without "tag") is passed as GCM AAD.
#include "envelope.hpp"
#include "errors.hpp"
#include "keys.hpp"
#include "oaep.hpp"
#include "hybrid.hpp"
#include "codec.hpp"
#include "platform.hpp"
#include "secure.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace rsatool::envelope {

// ── Utilities ─────────────────────────────────────────────────────────────────

static uint32_t read_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           (static_cast<uint32_t>(p[3]));
}

static void write_be32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(v & 0xFF);
}

// ── AAD ───────────────────────────────────────────────────────────────────────

std::vector<uint8_t> make_aad_bytes(const std::string& header_json) {
    // The AAD is the exact header JSON bytes as-is (what was written to the file)
    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(header_json.data()),
        reinterpret_cast<const uint8_t*>(header_json.data()) + header_json.size());
}

// ── Build canonical header JSON for hybrid (without "tag") ────────────────────

static std::string make_hybrid_header_no_tag(
    int rsa_modulus_bits,
    const std::string& wrapped_key_b64,
    const std::string& iv_b64)
{
    // Deterministic: sorted keys (nlohmann sorts by default? No, use object)
    // We control the field order manually for determinism
    nlohmann::json j;
    j["hash"]        = "SHA-256";
    j["iv"]          = iv_b64;
    j["mode"]        = MODE_HYBRID;
    j["rsa_modulus"] = rsa_modulus_bits;
    j["wrapped_key"] = wrapped_key_b64;
    // No "tag" field — that's added after GCM finalization
    return j.dump();  // nlohmann sorts keys alphabetically for objects
}

// ── Encrypt ───────────────────────────────────────────────────────────────────

void encrypt_file(
    const std::filesystem::path& in_path,
    const std::filesystem::path& out_path,
    const std::filesystem::path& pub_key_path,
    const std::string& label,
    const std::string& encode_name,
    const std::string& mode_hint)
{
    auto enc = codec::parse_encoding(encode_name);

    // Load public key
    auto pub_key = keys::load_key(pub_key_path, false);
    int bits = keys::key_bits(pub_key.get());
    std::size_t mLen = oaep::max_plaintext_len(bits);
    std::size_t modulus_bytes = static_cast<std::size_t>(bits / 8);

    // Read input file
    std::ifstream ifs(in_path, std::ios::binary);
    if (!ifs) throw FormatError("error: cannot open input file: " + in_path.string());

    std::vector<uint8_t> plaintext(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>());
    ifs.close();

    // Determine mode
    bool use_hybrid;
    if (mode_hint == "hybrid") {
        use_hybrid = true;
    } else if (mode_hint == "direct") {
        if (plaintext.size() > mLen) {
            throw UsageError(
                "error: plaintext too long for direct RSA-OAEP in --mode direct "
                "(" + std::to_string(plaintext.size()) + " > " +
                std::to_string(mLen) + " bytes)");
        }
        use_hybrid = false;
    } else {
        // "auto": choose based on length
        use_hybrid = (plaintext.size() > mLen);
    }

    // Prepare output bytes
    std::vector<uint8_t> envelope_bytes;

    if (!use_hybrid) {
        // ── Direct RSA-OAEP mode ──────────────────────────────────────────────
        auto ct = oaep::encrypt(pub_key.get(), plaintext.data(), plaintext.size(), label);

        // Header JSON (direct mode: wrapped_key = OAEP ciphertext in base64)
        nlohmann::json header;
        header["hash"]        = "SHA-256";
        header["mode"]        = MODE_DIRECT;
        header["rsa_modulus"] = bits;
        header["wrapped_key"] = codec::encode(ct, codec::Encoding::Base64);

        std::string header_str = header.dump();

        // Write: [4B header_len][header][payload=empty for direct]
        // For direct mode: no AES payload; payload is empty
        uint32_t hlen = static_cast<uint32_t>(header_str.size());
        envelope_bytes.resize(4 + hlen);
        write_be32(envelope_bytes.data(), hlen);
        std::memcpy(envelope_bytes.data() + 4, header_str.data(), hlen);
        // No payload bytes for direct mode

    } else {
        // ── Hybrid mode ───────────────────────────────────────────────────────
        // Step 1: Generate ephemeral AES key + IV, encrypt plaintext with AES-GCM
        // We need the header_no_tag first to serve as AAD
        // But we don't know wrapped_key or iv yet...
        // Approach: generate AES key & IV first, build header without tag, use as AAD

        // Generate fresh AES key & IV
        SecureBuffer aes_key(hybrid::AES_KEY_BYTES);
        {
            if (RAND_bytes(aes_key.data(), static_cast<int>(hybrid::AES_KEY_BYTES)) != 1) {
                ERR_clear_error();
                throw CryptoError("error: RAND_bytes failed");
            }
        }

        std::vector<uint8_t> iv(hybrid::AES_IV_BYTES);
        {
            if (RAND_bytes(iv.data(), static_cast<int>(hybrid::AES_IV_BYTES)) != 1) {
                ERR_clear_error();
                throw CryptoError("error: RAND_bytes failed");
            }
        }

        // Wrap AES key with RSA-OAEP
        auto wrapped_key = oaep::encrypt(pub_key.get(),
                                          aes_key.data(), aes_key.size(), label);

        // Build header_no_tag for AAD
        std::string iv_b64  = codec::encode(iv, codec::Encoding::Base64);
        std::string wk_b64  = codec::encode(wrapped_key, codec::Encoding::Base64);
        std::string header_no_tag = make_hybrid_header_no_tag(bits, wk_b64, iv_b64);

        auto aad = make_aad_bytes(header_no_tag);

        // AES-GCM encrypt plaintext with the generated key & IV
        // We call hybrid::encrypt_mem but need to supply our own key/IV
        // So we use EVP directly (same as in hybrid.cpp but with our key)
        // Actually let's use the low-level directly:
        hybrid::EncryptResult res = [&]() {
            // Temporarily piggyback by calling EVP directly (same as hybrid::encrypt_mem
            // but with our pre-generated key & IV)
            using namespace hybrid;
            ERR_clear_error();

            UniqueEVPCIPHERCTX ctx(EVP_CIPHER_CTX_new());
            if (!ctx) throw CryptoError();

            if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0)
                throw CryptoError();

            if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                                     static_cast<int>(AES_IV_BYTES), nullptr) <= 0)
                throw CryptoError();

            if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                                    aes_key.data(), iv.data()) <= 0)
                throw CryptoError();

            if (!aad.empty()) {
                int aad_out = 0;
                if (EVP_EncryptUpdate(ctx.get(), nullptr, &aad_out,
                                       aad.data(), static_cast<int>(aad.size())) <= 0)
                    throw CryptoError();
            }

            std::vector<uint8_t> ct(plaintext.size() + AES_TAG_BYTES);
            std::size_t off = 0, rem = plaintext.size();
            while (rem > 0) {
                std::size_t chunk = (rem > CHUNK_SIZE) ? CHUNK_SIZE : rem;
                int out_len = 0;
                if (EVP_EncryptUpdate(ctx.get(), ct.data() + off, &out_len,
                                       plaintext.data() + (plaintext.size() - rem),
                                       static_cast<int>(chunk)) <= 0)
                    throw CryptoError();
                off += static_cast<std::size_t>(out_len);
                rem -= chunk;
            }
            int final_len = 0;
            if (EVP_EncryptFinal_ex(ctx.get(), ct.data() + off, &final_len) <= 0)
                throw CryptoError();
            off += static_cast<std::size_t>(final_len);
            ct.resize(off);

            std::vector<uint8_t> tag(AES_TAG_BYTES);
            if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                                     static_cast<int>(AES_TAG_BYTES), tag.data()) <= 0)
                throw CryptoError();

            EncryptResult r;
            r.key = std::move(aes_key);
            r.iv  = std::move(iv);
            r.tag = std::move(tag);
            r.ciphertext = std::move(ct);
            return r;
        }();

        // Now build complete header with tag
        nlohmann::json header;
        header["hash"]        = "SHA-256";
        header["iv"]          = iv_b64;
        header["mode"]        = MODE_HYBRID;
        header["rsa_modulus"] = bits;
        header["tag"]         = codec::encode(res.tag, codec::Encoding::Base64);
        header["wrapped_key"] = wk_b64;

        std::string header_str = header.dump();

        uint32_t hlen = static_cast<uint32_t>(header_str.size());
        envelope_bytes.resize(4 + hlen + res.ciphertext.size());
        write_be32(envelope_bytes.data(), hlen);
        std::memcpy(envelope_bytes.data() + 4, header_str.data(), hlen);
        std::memcpy(envelope_bytes.data() + 4 + hlen,
                     res.ciphertext.data(), res.ciphertext.size());
    }

    // Apply output encoding and write to file (safe overwrite)
    auto tmp = platform::temp_path_for(out_path);
    bool ok = false;
    try {
        std::ofstream ofs(tmp, std::ios::binary);
        if (!ofs) throw FormatError("error: cannot write output file: " + tmp.string());

        std::string encoded = codec::encode(envelope_bytes, enc);
        ofs.write(encoded.data(), static_cast<std::streamsize>(encoded.size()));
        ofs.close();

        std::filesystem::rename(tmp, out_path);
        ok = true;
    } catch (...) {
        if (!ok) {
            std::error_code ec;
            std::filesystem::remove(tmp, ec);
        }
        throw;
    }
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

void decrypt_file(
    const std::filesystem::path& in_path,
    const std::filesystem::path& out_path,
    const std::filesystem::path& priv_key_path,
    const std::string& label,
    const std::string& encode_name)
{
    auto enc = codec::parse_encoding(encode_name);

    // Load private key
    auto priv_key = keys::load_key(priv_key_path, true);
    int key_bits_val = keys::key_bits(priv_key.get());
    std::size_t modulus_bytes = static_cast<std::size_t>(key_bits_val / 8);

    // Read and decode input file
    std::ifstream ifs(in_path, std::ios::binary);
    if (!ifs) throw FormatError("error: cannot open input file: " + in_path.string());

    std::vector<uint8_t> raw_data(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>());
    ifs.close();

    if (raw_data.empty()) throw FormatError("error: malformed envelope (empty file)");

    std::vector<uint8_t> envelope_bytes = codec::decode(raw_data, enc);

    // Parse envelope: [4B header_len][header JSON][payload]
    if (envelope_bytes.size() < 4)
        throw FormatError("error: malformed envelope (too short)");

    uint32_t hlen = read_be32(envelope_bytes.data());

    if (hlen > MAX_HEADER_LEN)
        throw FormatError("error: malformed envelope (header_len exceeds maximum)");

    if (envelope_bytes.size() < 4 + static_cast<std::size_t>(hlen))
        throw FormatError("error: malformed envelope (truncated header)");

    std::string header_str(
        reinterpret_cast<const char*>(envelope_bytes.data() + 4), hlen);

    const uint8_t* payload = envelope_bytes.data() + 4 + hlen;
    std::size_t payload_len = envelope_bytes.size() - 4 - hlen;

    // Parse and validate header JSON
    nlohmann::json header;
    try {
        header = nlohmann::json::parse(header_str);
    } catch (...) {
        throw FormatError("error: malformed envelope (invalid header JSON)");
    }

    // Validate required fields
    auto require_field = [&](const std::string& f) {
        if (!header.contains(f))
            throw FormatError("error: malformed envelope (missing field: " + f + ")");
    };

    require_field("mode");
    require_field("rsa_modulus");
    require_field("hash");
    require_field("wrapped_key");

    std::string mode = header["mode"].get<std::string>();
    int rsa_modulus  = header["rsa_modulus"].get<int>();
    std::string hash = header["hash"].get<std::string>();

    // Validate values
    if (hash != "SHA-256")
        throw FormatError("error: malformed envelope (unsupported hash: " + hash + ")");

    if (rsa_modulus != key_bits_val)
        throw FormatError("error: malformed envelope (rsa_modulus mismatch)");

    // Decode wrapped_key
    std::string wk_b64 = header["wrapped_key"].get<std::string>();
    std::vector<uint8_t> wrapped_key = codec::decode(wk_b64, codec::Encoding::Base64);
    if (wrapped_key.size() != modulus_bytes)
        throw FormatError("error: malformed envelope (wrapped_key length mismatch)");

    // Check for unknown fields (fail closed)
    if (mode == MODE_DIRECT) {
        for (auto& [k, v] : header.items()) {
            if (k != "mode" && k != "rsa_modulus" && k != "hash" && k != "wrapped_key")
                throw FormatError("error: malformed envelope (unexpected field in direct mode: " + k + ")");
        }
    } else if (mode == MODE_HYBRID) {
        require_field("iv");
        require_field("tag");
        for (auto& [k, v] : header.items()) {
            if (k != "mode" && k != "rsa_modulus" && k != "hash" &&
                k != "wrapped_key" && k != "iv" && k != "tag")
                throw FormatError("error: malformed envelope (unexpected field: " + k + ")");
        }
    } else {
        throw FormatError("error: malformed envelope (unknown mode: " + mode + ")");
    }

    // Build temp output file
    auto tmp = platform::temp_path_for(out_path);
    bool ok = false;

    try {
        if (mode == MODE_DIRECT) {
            // ── Direct RSA-OAEP decrypt ───────────────────────────────────────
            if (payload_len != 0)
                throw FormatError("error: malformed envelope (direct mode has unexpected payload)");

            // Decrypt wrapped_key (which IS the ciphertext in direct mode)
            SecureBuffer plaintext = oaep::decrypt(
                priv_key.get(),
                wrapped_key.data(), wrapped_key.size(),
                label);

            std::ofstream ofs(tmp, std::ios::binary);
            if (!ofs) throw FormatError("error: cannot write output: " + tmp.string());
            ofs.write(reinterpret_cast<const char*>(plaintext.data()),
                       static_cast<std::streamsize>(plaintext.size()));
            ofs.close();

        } else {
            // ── Hybrid decrypt ────────────────────────────────────────────────
            std::string iv_b64  = header["iv"].get<std::string>();
            std::string tag_b64 = header["tag"].get<std::string>();

            std::vector<uint8_t> iv  = codec::decode(iv_b64,  codec::Encoding::Base64);
            std::vector<uint8_t> tag = codec::decode(tag_b64, codec::Encoding::Base64);

            if (iv.size() != hybrid::AES_IV_BYTES)
                throw FormatError("error: malformed envelope (iv must be 12 bytes)");
            if (tag.size() != hybrid::AES_TAG_BYTES)
                throw FormatError("error: malformed envelope (tag must be 16 bytes)");

            // Unwrap AES key
            SecureBuffer aes_key = oaep::decrypt(
                priv_key.get(),
                wrapped_key.data(), wrapped_key.size(),
                label);

            if (aes_key.size() != hybrid::AES_KEY_BYTES)
                throw CryptoError();

            // Reconstruct header_no_tag for AAD (same as during encryption)
            std::string iv_b64_canon  = header["iv"].get<std::string>();
            std::string wk_b64_canon  = header["wrapped_key"].get<std::string>();
            // Build the same no-tag header JSON
            nlohmann::json aad_hdr;
            aad_hdr["hash"]        = "SHA-256";
            aad_hdr["iv"]          = iv_b64_canon;
            aad_hdr["mode"]        = MODE_HYBRID;
            aad_hdr["rsa_modulus"] = rsa_modulus;
            aad_hdr["wrapped_key"] = wk_b64_canon;
            std::string aad_str = aad_hdr.dump();
            auto aad = make_aad_bytes(aad_str);

            // AES-GCM decrypt (decrypt-then-release)
            SecureBuffer plaintext = hybrid::decrypt_mem(
                payload, payload_len,
                aes_key.data(),
                iv.data(),
                tag.data(),
                aad);

            std::ofstream ofs(tmp, std::ios::binary);
            if (!ofs) throw FormatError("error: cannot write output: " + tmp.string());
            ofs.write(reinterpret_cast<const char*>(plaintext.data()),
                       static_cast<std::streamsize>(plaintext.size()));
            ofs.close();
        }

        std::filesystem::rename(tmp, out_path);
        ok = true;

    } catch (...) {
        if (!ok) {
            std::error_code ec;
            std::filesystem::remove(tmp, ec);
        }
        throw;
    }
}

} // namespace rsatool::envelope

