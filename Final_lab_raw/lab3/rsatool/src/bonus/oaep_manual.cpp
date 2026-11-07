// oaep_manual.cpp — Bonus A: Manual OAEP implementation using EVP_Digest + raw RSA
// Implements MGF1(SHA-256), seed/DB masking, and constant-time decoding.
// Cross-tested: manual encode -> OpenSSL decrypt, OpenSSL encrypt -> manual decode.
//
// SECURITY NOTE: Non-constant-time OAEP decoding enables Manger's padding oracle
// (see report/report.md for detailed explanation).
#include <rsatool/secure.hpp>
#include <rsatool/errors.hpp>
#include <rsatool/keys.hpp>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

// ── MGF1-SHA256 ───────────────────────────────────────────────────────────────
// MGF1(seed, len) = Hash(seed || counter_be) until len bytes produced.
static void mgf1_sha256(const uint8_t* seed, std::size_t seed_len,
                         uint8_t* out, std::size_t out_len) {
    // SHA-256 output size
    constexpr std::size_t H = 32;
    std::size_t offset = 0;
    for (uint32_t counter = 0; offset < out_len; ++counter) {
        // counter as 4-byte big-endian
        uint8_t C[4] = {
            uint8_t(counter >> 24), uint8_t(counter >> 16),
            uint8_t(counter >> 8),  uint8_t(counter)
        };

        rsatool::UniqueEVPMDCTX ctx(EVP_MD_CTX_new());
        if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) <= 0)
            throw rsatool::CryptoError("MGF1: DigestInit failed");
        if (EVP_DigestUpdate(ctx.get(), seed, seed_len) <= 0 ||
            EVP_DigestUpdate(ctx.get(), C, 4) <= 0)
            throw rsatool::CryptoError("MGF1: DigestUpdate failed");

        uint8_t hash[H];
        unsigned int hlen = 0;
        if (EVP_DigestFinal_ex(ctx.get(), hash, &hlen) <= 0)
            throw rsatool::CryptoError("MGF1: DigestFinal failed");

        std::size_t to_copy = (offset + H > out_len) ? (out_len - offset) : H;
        std::memcpy(out + offset, hash, to_copy);
        offset += to_copy;
    }
}

// ── OAEP Hash (SHA-256 of label) ─────────────────────────────────────────────
static std::array<uint8_t, 32> hash_label(const std::string& label) {
    std::array<uint8_t, 32> h{};
    rsatool::UniqueEVPMDCTX ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) <= 0)
        throw rsatool::CryptoError("hash_label failed");
    if (!label.empty()) {
        if (EVP_DigestUpdate(ctx.get(), label.data(), label.size()) <= 0)
            throw rsatool::CryptoError("hash_label update failed");
    }
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), h.data(), &len) <= 0)
        throw rsatool::CryptoError("hash_label final failed");
    return h;
}

// ── Manual OAEP Encode (PS + DB + seed masking) ───────────────────────────────
// Output: EM = 0x00 || maskedSeed || maskedDB (k bytes)
static std::vector<uint8_t> oaep_encode(
    const uint8_t* M, std::size_t mLen,
    int modulus_bits,
    const std::string& label)
{
    std::size_t k    = static_cast<std::size_t>(modulus_bits / 8);
    std::size_t hLen = 32;  // SHA-256
    std::size_t dbLen = k - hLen - 1;

    if (mLen > dbLen - hLen - 1) {
        throw rsatool::UsageError("oaep_encode: message too long");
    }

    // 1. lHash = Hash(label)
    auto lHash = hash_label(label);

    // 2. Build DB = lHash || PS || 0x01 || M
    rsatool::SecureBuffer DB(dbLen, 0);
    std::memcpy(DB.data(), lHash.data(), hLen);
    // PS: zeros (already zeroed)
    DB[dbLen - mLen - 1] = 0x01;
    std::memcpy(DB.data() + dbLen - mLen, M, mLen);

    // 3. Random seed (hLen bytes)
    rsatool::SecureBuffer seed(hLen);
    if (RAND_bytes(seed.data(), static_cast<int>(hLen)) != 1)
        throw rsatool::CryptoError("RAND_bytes failed");

    // 4. maskedDB = DB XOR MGF1(seed, dbLen)
    std::vector<uint8_t> dbMask(dbLen);
    mgf1_sha256(seed.data(), hLen, dbMask.data(), dbLen);
    std::vector<uint8_t> maskedDB(dbLen);
    for (std::size_t i = 0; i < dbLen; ++i)
        maskedDB[i] = DB[i] ^ dbMask[i];

    // 5. maskedSeed = seed XOR MGF1(maskedDB, hLen)
    std::vector<uint8_t> seedMask(hLen);
    mgf1_sha256(maskedDB.data(), dbLen, seedMask.data(), hLen);
    std::vector<uint8_t> maskedSeed(hLen);
    for (std::size_t i = 0; i < hLen; ++i)
        maskedSeed[i] = seed[i] ^ seedMask[i];

    // 6. EM = 0x00 || maskedSeed || maskedDB
    std::vector<uint8_t> EM(k, 0);
    EM[0] = 0x00;
    std::memcpy(EM.data() + 1, maskedSeed.data(), hLen);
    std::memcpy(EM.data() + 1 + hLen, maskedDB.data(), dbLen);
    return EM;
}

// ── Manual OAEP Decode (constant-time) ───────────────────────────────────────
// CONSTANT-TIME: no early return on secret-dependent branches; use bitmask.
static rsatool::SecureBuffer oaep_decode(
    const uint8_t* EM, std::size_t k,
    const std::string& label)
{
    constexpr std::size_t hLen = 32;
    std::size_t dbLen = k - hLen - 1;

    // 1. Check leading zero (constant-time: accumulate into error mask)
    uint8_t err = 0;
    err |= EM[0];  // must be 0x00

    // 2. lHash = Hash(label)
    auto lHash = hash_label(label);

    // 3. Split
    const uint8_t* maskedSeed = EM + 1;
    const uint8_t* maskedDB   = EM + 1 + hLen;

    // 4. seed = maskedSeed XOR MGF1(maskedDB, hLen)
    std::vector<uint8_t> seedMask(hLen);
    mgf1_sha256(maskedDB, dbLen, seedMask.data(), hLen);
    rsatool::SecureBuffer seed(hLen);
    for (std::size_t i = 0; i < hLen; ++i)
        seed[i] = maskedSeed[i] ^ seedMask[i];

    // 5. DB = maskedDB XOR MGF1(seed, dbLen)
    std::vector<uint8_t> dbMask(dbLen);
    mgf1_sha256(seed.data(), hLen, dbMask.data(), dbLen);
    rsatool::SecureBuffer DB(dbLen);
    for (std::size_t i = 0; i < dbLen; ++i)
        DB[i] = maskedDB[i] ^ dbMask[i];

    // 6. Check lHash (constant-time compare)
    uint8_t lhash_ok = 0;
    for (std::size_t i = 0; i < hLen; ++i)
        lhash_ok |= DB[i] ^ lHash[i];
    err |= lhash_ok;

    // 7. Find 0x01 separator (constant-time: scan without early exit)
    // Accumulate: once we see 0x01, record position; never branch.
    std::size_t msg_start = dbLen;  // default: not found
    uint8_t found = 0;
    for (std::size_t i = hLen; i < dbLen; ++i) {
        // PS must be 0x00 until 0x01
        uint8_t is_one  = (DB[i] == 0x01) ? 0xFF : 0x00;
        uint8_t is_zero = (DB[i] == 0x00) ? 0xFF : 0x00;
        // non-zero, non-one in PS region (before 0x01) is an error
        uint8_t in_ps = ~found;
        err |= (in_ps & ~is_one & ~is_zero);
        // Record first 0x01 position (constant-time)
        if (!found && DB[i] == 0x01) {
            msg_start = i + 1;
            found = 0xFF;
        }
    }
    err |= (found ^ 0xFF);  // error if 0x01 never found

    // Check error flag — single combined failure path
    if (err != 0) {
        throw rsatool::CryptoError();  // Generic "error: decryption failed"
    }

    std::size_t mLen = dbLen - msg_start;
    rsatool::SecureBuffer M(mLen);
    std::memcpy(M.data(), DB.data() + msg_start, mLen);
    return M;
}

// ── Raw RSA via EVP (no padding) ──────────────────────────────────────────────
static std::vector<uint8_t> raw_rsa_public(const EVP_PKEY* pub, const uint8_t* in, std::size_t len) {
    ERR_clear_error();
    rsatool::UniqueEVPPKEYCTX ctx(
        EVP_PKEY_CTX_new_from_pkey(nullptr, const_cast<EVP_PKEY*>(pub), nullptr));
    if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) <= 0) throw rsatool::CryptoError();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_NO_PADDING) <= 0) throw rsatool::CryptoError();

    std::size_t out_len = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &out_len, in, len) <= 0) throw rsatool::CryptoError();
    std::vector<uint8_t> out(out_len);
    if (EVP_PKEY_encrypt(ctx.get(), out.data(), &out_len, in, len) <= 0) throw rsatool::CryptoError();
    out.resize(out_len);
    return out;
}

static rsatool::SecureBuffer raw_rsa_private(const EVP_PKEY* priv, const uint8_t* in, std::size_t len) {
    ERR_clear_error();
    rsatool::UniqueEVPPKEYCTX ctx(
        EVP_PKEY_CTX_new_from_pkey(nullptr, const_cast<EVP_PKEY*>(priv), nullptr));
    if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) <= 0) throw rsatool::CryptoError();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_NO_PADDING) <= 0) throw rsatool::CryptoError();

    std::size_t out_len = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &out_len, in, len) <= 0) throw rsatool::CryptoError();
    rsatool::SecureBuffer out(out_len);
    if (EVP_PKEY_decrypt(ctx.get(), out.data(), &out_len, in, len) <= 0) throw rsatool::CryptoError();
    out.resize(out_len);
    return out;
}

// ── Public API: manual OAEP encrypt/decrypt ───────────────────────────────────

static std::vector<uint8_t> manual_oaep_encrypt(
    const EVP_PKEY* pub, const uint8_t* M, std::size_t mLen,
    const std::string& label = "")
{
    int bits = rsatool::keys::key_bits(pub);
    auto EM = oaep_encode(M, mLen, bits, label);
    return raw_rsa_public(pub, EM.data(), EM.size());
}

static rsatool::SecureBuffer manual_oaep_decrypt(
    const EVP_PKEY* priv, const uint8_t* ct, std::size_t ctLen,
    const std::string& label = "")
{
    int bits = rsatool::keys::key_bits(priv);
    std::size_t k = static_cast<std::size_t>(bits / 8);

    auto EM = raw_rsa_private(priv, ct, ctLen);
    if (EM.size() != k) throw rsatool::CryptoError();

    return oaep_decode(EM.data(), k, label);
}

// ── Cross-tests ───────────────────────────────────────────────────────────────

static void check(bool cond, const char* msg) {
    if (!cond) {
        std::cerr << "FAIL: " << msg << "\n";
        std::exit(1);
    }
}

int main() {
    std::cout << "=== Bonus A: Manual OAEP Cross-Test ===\n\n";

    auto key = rsatool::keys::generate_key(3072);
    std::vector<uint8_t> M = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
    std::string label = "bonus-label";

    // ── Test 1: manual encode -> OpenSSL decrypt ──────────────────────────────
    {
        auto ct = manual_oaep_encrypt(key.get(), M.data(), M.size(), label);
        auto pt = rsatool::oaep::decrypt(key.get(), ct.data(), ct.size(), label);
        check(pt.size() == M.size() &&
              std::equal(M.begin(), M.end(), pt.begin()),
              "manual encode -> OpenSSL decrypt");
        std::cout << "[PASS] Manual encode -> OpenSSL decrypt\n";
    }

    // ── Test 2: OpenSSL encrypt -> manual decode ──────────────────────────────
    {
        auto ct = rsatool::oaep::encrypt(key.get(), M.data(), M.size(), label);
        auto pt = manual_oaep_decrypt(key.get(), ct.data(), ct.size(), label);
        check(pt.size() == M.size() &&
              std::equal(M.begin(), M.end(), pt.begin()),
              "OpenSSL encrypt -> manual decode");
        std::cout << "[PASS] OpenSSL encrypt -> manual decode\n";
    }

    // ── Test 3: manual round trip ─────────────────────────────────────────────
    {
        auto pt = rsatool::rand_vec(100);  // need this helper or inline
        // inline rand
        std::vector<uint8_t> rnd(100);
        RAND_bytes(rnd.data(), 100);

        auto ct  = manual_oaep_encrypt(key.get(), rnd.data(), rnd.size(), "");
        auto dec = manual_oaep_decrypt(key.get(), ct.data(), ct.size(), "");
        check(dec.size() == rnd.size() &&
              std::equal(rnd.begin(), rnd.end(), dec.begin()),
              "manual round trip (100 bytes, no label)");
        std::cout << "[PASS] Manual round trip (100 bytes, no label)\n";
    }

    // ── Test 4: wrong label -> must fail ─────────────────────────────────────
    {
        auto ct = manual_oaep_encrypt(key.get(), M.data(), M.size(), "correct");
        bool threw = false;
        try {
            manual_oaep_decrypt(key.get(), ct.data(), ct.size(), "wrong");
        } catch (const rsatool::CryptoError&) { threw = true; }
        check(threw, "manual decode: wrong label must throw CryptoError");
        std::cout << "[PASS] Wrong label -> CryptoError\n";
    }

    std::cout << "\nAll bonus tests passed.\n";
    return 0;
}

