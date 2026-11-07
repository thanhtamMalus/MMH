// keys.cpp — RSA key generation and loading via EVP API
// No RSA_* low-level functions. PEM/DER auto-detection.
#include <rsatool/keys.hpp>
#include <rsatool/errors.hpp>
#include <rsatool/platform.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace rsatool::keys {

void validate_bits(int bits) {
    if (bits != BITS_3072 && bits != BITS_4096) {
        throw UsageError(
            "error: unsupported RSA modulus size " + std::to_string(bits) +
            " bits. Only 3072 and 4096 are accepted.");
    }
}

UniqueEVPPKEY generate_key(int bits) {
    validate_bits(bits);
    ERR_clear_error();

    UniqueEVPPKEYCTX ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr));
    if (!ctx) throw CryptoError("error: EVP_PKEY_CTX_new_from_name failed");

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
        throw CryptoError("error: EVP_PKEY_keygen_init failed");

    // Set modulus bits
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_uint("bits",
            const_cast<unsigned int*>(reinterpret_cast<const unsigned int*>(&bits))),
        OSSL_PARAM_construct_end()
    };
    // Use EVP_PKEY_CTX_set_rsa_keygen_bits for compat
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0)
        throw CryptoError("error: EVP_PKEY_CTX_set_rsa_keygen_bits failed");

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0)
        throw CryptoError("error: RSA key generation failed");

    return UniqueEVPPKEY(raw);
}

int key_bits(const EVP_PKEY* key) {
    if (!key) throw FormatError("error: null key");

    int id = EVP_PKEY_get_base_id(key);
    if (id != EVP_PKEY_RSA) {
        throw FormatError("error: not an RSA key");
    }

    // Get key size in bytes, convert to bits
    int key_size = static_cast<int>(EVP_PKEY_get_size(key));
    int bits = key_size * 8;

    if (bits != BITS_3072 && bits != BITS_4096) {
        throw FormatError(
            "error: unsupported RSA modulus " + std::to_string(bits) +
            " bits. Only 3072 and 4096 are accepted.");
    }
    return bits;
}

// ── File I/O helpers ──────────────────────────────────────────────────────────

static void safe_write_file(const std::filesystem::path& path,
                             const std::function<void(BIO*)>& write_fn) {
    auto tmp = platform::temp_path_for(path);
    bool ok = false;

    UniqueBIO bio(BIO_new_file(tmp.string().c_str(), "wb"));
    if (!bio) {
        throw FormatError("error: cannot open temp file for writing: " + tmp.string());
    }

    try {
        write_fn(bio.get());
        bio.reset();  // flush/close before rename
        std::filesystem::rename(tmp, path);
        ok = true;
    } catch (...) {
        bio.reset();
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        throw;
    }
    (void)ok;
}

void write_public_pem(const EVP_PKEY* key, const std::filesystem::path& path) {
    safe_write_file(path, [&](BIO* bio) {
        if (PEM_write_bio_PUBKEY(bio, const_cast<EVP_PKEY*>(key)) <= 0)
            throw CryptoError("error: failed to write public PEM");
    });
}

void write_private_pem(const EVP_PKEY* key, const std::filesystem::path& path) {
    safe_write_file(path, [&](BIO* bio) {
        if (PEM_write_bio_PrivateKey(bio, const_cast<EVP_PKEY*>(key),
                                     nullptr, nullptr, 0, nullptr, nullptr) <= 0)
            throw CryptoError("error: failed to write private PEM");
    });
    platform::restrict_private_file(path);
}

void write_public_der(const EVP_PKEY* key, const std::filesystem::path& path) {
    safe_write_file(path, [&](BIO* bio) {
        if (i2d_PUBKEY_bio(bio, const_cast<EVP_PKEY*>(key)) <= 0)
            throw CryptoError("error: failed to write public DER");
    });
}

void write_private_der(const EVP_PKEY* key, const std::filesystem::path& path) {
    safe_write_file(path, [&](BIO* bio) {
        if (i2d_PrivateKey_bio(bio, const_cast<EVP_PKEY*>(key)) <= 0)
            throw CryptoError("error: failed to write private DER");
    });
    platform::restrict_private_file(path);
}

void write_meta_json(const std::filesystem::path& dir, int bits) {
    auto meta_path = dir / "meta.json";
    auto tmp = platform::temp_path_for(meta_path);

    nlohmann::json j;
    j["creation_time"] = platform::utc_iso8601();
    j["modulus_bits"]  = bits;
    j["hash"]          = "SHA-256";

    {
        std::ofstream ofs(tmp, std::ios::binary);
        if (!ofs) throw FormatError("error: cannot write meta.json");
        ofs << j.dump(2) << "\n";
    }
    std::filesystem::rename(tmp, meta_path);
}

// ── Key loading ───────────────────────────────────────────────────────────────

UniqueEVPPKEY load_key(const std::filesystem::path& path, bool is_private) {
    // Read entire file into memory (avoid FILE* on Windows)
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) throw FormatError("error: cannot open key file: " + path.string());

    std::vector<uint8_t> buf(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>());
    ifs.close();

    if (buf.empty()) throw FormatError("error: key file is empty: " + path.string());

    // Auto-detect PEM vs DER: PEM starts with "-----"
    bool is_pem = (buf.size() >= 5 &&
                   buf[0] == '-' && buf[1] == '-' && buf[2] == '-');

    EVP_PKEY* key = nullptr;
    ERR_clear_error();

    if (is_pem) {
        UniqueBIO bio(BIO_new_mem_buf(buf.data(), static_cast<int>(buf.size())));
        if (!bio) throw CryptoError();

        if (is_private) {
            key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
        } else {
            key = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
        }
    } else {
        // Try DER
        UniqueBIO bio(BIO_new_mem_buf(buf.data(), static_cast<int>(buf.size())));
        if (!bio) throw CryptoError();

        if (is_private) {
            key = d2i_PrivateKey_bio(bio.get(), nullptr);
        } else {
            key = d2i_PUBKEY_bio(bio.get(), nullptr);
        }
    }

    if (!key) {
        ERR_clear_error();
        throw FormatError("error: failed to load key from: " + path.string());
    }

    UniqueEVPPKEY pkey(key);

    // Validate it's RSA and supported size
    if (EVP_PKEY_get_base_id(pkey.get()) != EVP_PKEY_RSA) {
        throw FormatError("error: key is not RSA: " + path.string());
    }
    key_bits(pkey.get());  // throws if unsupported size

    return pkey;
}

} // namespace rsatool::keys

