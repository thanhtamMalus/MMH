#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>

#include "aescore.h"
#include "container.h"
#include "minijson.h"
#include "ops.h"
#include "util.h"

using namespace aescore;

namespace {

Bytes H(const std::string& s) {
  Bytes b;
  REQUIRE(util::from_hex(s, b, true));
  return b;
}

const char* kPt128 =
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
const char* kKey128 = "2b7e151628aed2a6abf7158809cf4f3c";

Bytes sample_message() {
  std::string s = "Xin chao the gioi - xin chào thế giới ✓ 你好 ";
  std::string r;
  while (r.size() < 200) r += s;
  return util::to_bytes(r);
}

Bytes key_for(Mode m) { return random_bytes(m == Mode::XTS ? 64 : 32); }

const Mode kAllModes[] = {Mode::ECB, Mode::CBC, Mode::OFB, Mode::CFB, Mode::CTR, Mode::XTS, Mode::CCM, Mode::GCM};

// true only if decryption succeeds AND returns exactly `expect`
bool decrypts_to(const DecryptOptions& o, const Bytes& file, const Bytes& expect) {
  try {
    return decrypt_buffer(o, file).plaintext == expect;
  } catch (const CryptoError&) {
    return false;
  }
}

std::string temp_name(const std::string& n) {
  return (std::filesystem::temp_directory_path() / ("aestool_test_" + n)).string();
}

}  // namespace

TEST_CASE("NIST SP 800-38A AES-128 known answers", "[kat]") {
  CipherParams p;
  p.key = H(kKey128);
  p.padding = false;
  const Bytes pt = H(kPt128);
  const Bytes iv = H("000102030405060708090a0b0c0d0e0f");

  SECTION("ECB") {
    p.mode = Mode::ECB;
    const Bytes ct = H("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4");
    REQUIRE(encrypt_raw(p, pt).ct == ct);
    REQUIRE(decrypt_raw(p, ct, Bytes()) == pt);
  }
  SECTION("CBC") {
    p.mode = Mode::CBC;
    p.iv = iv;
    const Bytes ct = H("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7");
    REQUIRE(encrypt_raw(p, pt).ct == ct);
    REQUIRE(decrypt_raw(p, ct, Bytes()) == pt);
  }
  SECTION("CFB128") {
    p.mode = Mode::CFB;
    p.iv = iv;
    const Bytes ct = H("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6");
    REQUIRE(encrypt_raw(p, pt).ct == ct);
  }
  SECTION("OFB") {
    p.mode = Mode::OFB;
    p.iv = iv;
    const Bytes ct = H("3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e");
    REQUIRE(encrypt_raw(p, pt).ct == ct);
  }
  SECTION("CTR") {
    p.mode = Mode::CTR;
    p.iv = H("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    const Bytes ct = H("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee");
    REQUIRE(encrypt_raw(p, pt).ct == ct);
  }
}

TEST_CASE("NIST GCM and CCM known answers", "[kat]") {
  SECTION("GCM test case 2") {
    CipherParams p;
    p.mode = Mode::GCM;
    p.key = Bytes(16, 0);
    p.iv = Bytes(12, 0);
    const EncResult r = encrypt_raw(p, Bytes(16, 0));
    REQUIRE(r.ct == H("0388dace60b6a392f328c2b971b2fe78"));
    REQUIRE(r.tag == H("ab6e47d42cec13bdf53a67b21257bddf"));
  }
  SECTION("CCM SP800-38C example 1") {
    CipherParams p;
    p.mode = Mode::CCM;
    p.key = H("404142434445464748494a4b4c4d4e4f");
    p.iv = H("10111213141516");
    p.aad = H("0001020304050607");
    p.tag_len = 4;
    const EncResult r = encrypt_raw(p, H("20212223"));
    REQUIRE(r.ct == H("7162015b"));
    REQUIRE(r.tag == H("4dac255d"));
    REQUIRE(decrypt_raw(p, r.ct, r.tag) == H("20212223"));
  }
}

TEST_CASE("round trip for every mode (UTF-8 payload)", "[roundtrip]") {
  const Bytes msg = sample_message();
  for (Mode m : kAllModes) {
    CAPTURE(mode_name(m));
    EncryptOptions e;
    e.mode = m;
    e.key = key_for(m);
    const EncryptResult er = encrypt_buffer(e, msg);
    DecryptOptions d;
    d.key = e.key;
    d.has_mode = true;
    d.mode = m;
    REQUIRE(decrypt_buffer(d, er.output).plaintext == msg);
  }
}

TEST_CASE("AAD round trip and AAD mismatch", "[aead]") {
  for (Mode m : {Mode::CCM, Mode::GCM}) {
    EncryptOptions e;
    e.mode = m;
    e.key = key_for(m);
    e.aad = util::to_bytes("header-v1");
    const Bytes msg = sample_message();
    const EncryptResult er = encrypt_buffer(e, msg);
    DecryptOptions d;
    d.key = e.key;
    REQUIRE(decrypt_buffer(d, er.output).plaintext == msg);   // AAD taken from header
    d.has_aad = true;
    d.aad = util::to_bytes("header-v2");
    REQUIRE_THROWS_AS(decrypt_buffer(d, er.output), AuthError);
  }
}

TEST_CASE("negative: wrong key and wrong IV give wrong plaintext", "[negative]") {
  const Bytes msg = sample_message();
  for (Mode m : {Mode::ECB, Mode::CBC, Mode::OFB, Mode::CFB, Mode::CTR, Mode::XTS}) {
    CAPTURE(mode_name(m));
    EncryptOptions e;
    e.mode = m;
    e.key = key_for(m);
    const EncryptResult er = encrypt_buffer(e, msg);

    DecryptOptions bad_key;
    bad_key.key = key_for(m);
    REQUIRE_FALSE(decrypts_to(bad_key, er.output, msg));

    if (m != Mode::ECB) {
      DecryptOptions bad_iv;
      bad_iv.key = e.key;
      bad_iv.has_iv = true;
      bad_iv.iv = random_bytes(16);
      REQUIRE_FALSE(decrypts_to(bad_iv, er.output, msg));
    }
  }
}

TEST_CASE("negative: tampered ciphertext", "[negative]") {
  const Bytes msg = sample_message();
  SECTION("non-AEAD: output is corrupted") {
    for (Mode m : {Mode::CBC, Mode::OFB, Mode::CFB, Mode::CTR, Mode::XTS}) {
      EncryptOptions e;
      e.mode = m;
      e.key = key_for(m);
      Bytes f = encrypt_buffer(e, msg).output;
      f[f.size() - 5] ^= 0x01;
      DecryptOptions d;
      d.key = e.key;
      REQUIRE_FALSE(decrypts_to(d, f, msg));
    }
  }
  SECTION("AEAD: authentication fails, no plaintext") {
    for (Mode m : {Mode::CCM, Mode::GCM}) {
      EncryptOptions e;
      e.mode = m;
      e.key = key_for(m);
      Bytes f = encrypt_buffer(e, msg).output;
      f[f.size() - 5] ^= 0x01;
      DecryptOptions d;
      d.key = e.key;
      REQUIRE_THROWS_AS(decrypt_buffer(d, f), AuthError);
    }
  }
  SECTION("AEAD: invalid tag is rejected") {
    for (Mode m : {Mode::CCM, Mode::GCM}) {
      EncryptOptions e;
      e.mode = m;
      e.key = key_for(m);
      const Bytes f = encrypt_buffer(e, msg).output;
      container::Parsed ps;
      std::string err;
      REQUIRE(container::parse(f, ps, err));
      Bytes ct(f.begin() + static_cast<std::ptrdiff_t>(ps.ct_offset), f.end());
      ps.h.tag[0] ^= 0x80;
      DecryptOptions d;
      d.key = e.key;
      REQUIRE_THROWS_AS(decrypt_buffer(d, container::pack(ps.h, ct)), AuthError);
    }
  }
}

TEST_CASE("negative: invalid IV / key lengths are rejected", "[negative]") {
  EncryptOptions e;
  e.mode = Mode::GCM;
  e.key = key_for(Mode::GCM);
  e.has_iv = true;
  e.iv = Bytes(8, 1);
  REQUIRE_THROWS_AS(encrypt_buffer(e, sample_message()), UsageError);

  e.mode = Mode::CBC;
  e.iv = Bytes(15, 1);
  REQUIRE_THROWS_AS(encrypt_buffer(e, sample_message()), UsageError);

  e.mode = Mode::CCM;
  e.iv = Bytes(6, 1);
  REQUIRE_THROWS_AS(encrypt_buffer(e, sample_message()), UsageError);

  e.mode = Mode::CBC;
  e.has_iv = false;
  e.key = Bytes(17, 1);
  REQUIRE_THROWS_AS(encrypt_buffer(e, sample_message()), UsageError);

  e.mode = Mode::ECB;
  e.key = Bytes(16, 1);
  e.has_iv = true;
  e.iv = Bytes(16, 1);
  REQUIRE_THROWS_AS(encrypt_buffer(e, sample_message()), UsageError);   // ECB takes no IV
}

TEST_CASE("malformed containers fail closed", "[negative]") {
  DecryptOptions d;
  d.key = Bytes(32, 7);
  REQUIRE_THROWS_AS(decrypt_buffer(d, Bytes()), FormatError);
  REQUIRE_THROWS_AS(decrypt_buffer(d, random_bytes(100)), FormatError);

  EncryptOptions e;
  e.mode = Mode::GCM;
  e.key = d.key;
  Bytes f = encrypt_buffer(e, sample_message()).output;
  Bytes truncated(f.begin(), f.end() - 3);
  REQUIRE_THROWS_AS(decrypt_buffer(d, truncated), FormatError);
  Bytes trailing = f;
  trailing.push_back(0);
  REQUIRE_THROWS_AS(decrypt_buffer(d, trailing), FormatError);
  Bytes wrong_mode = f;
  wrong_mode[5] = 3;   // mode id -> OFB while AEAD flag is set
  REQUIRE_THROWS_AS(decrypt_buffer(d, wrong_mode), FormatError);
}

TEST_CASE("ECB size limit and override", "[policy]") {
  EncryptOptions e;
  e.mode = Mode::ECB;
  e.key = Bytes(32, 3);
  const Bytes big(16 * 1024 + 1, 'a');
  REQUIRE_THROWS_AS(encrypt_buffer(e, big), UsageError);
  e.allow_ecb = true;
  REQUIRE_NOTHROW(encrypt_buffer(e, big));
  e.allow_ecb = false;
  REQUIRE_NOTHROW(encrypt_buffer(e, Bytes(16 * 1024, 'a')));   // exactly 16 KiB is allowed
}

TEST_CASE("nonce reuse detection (CTR/CCM/GCM)", "[policy]") {
  const std::string out = temp_name("nonce.bin");
  const std::string sc = temp_name("nonce.json");
  std::error_code ec;
  std::filesystem::remove(out, ec);
  std::filesystem::remove(sc, ec);

  for (Mode m : {Mode::CTR, Mode::CCM, Mode::GCM}) {
    CAPTURE(mode_name(m));
    std::filesystem::remove(out, ec);
    EncryptOptions e;
    e.mode = m;
    e.key = key_for(m);
    e.has_iv = true;
    e.iv = Bytes(m == Mode::CTR ? 16 : 12, 0x42);
    e.out_path = out;
    const EncryptResult r1 = encrypt_buffer(e, sample_message());
    std::string err;
    REQUIRE(util::write_file_atomic(out, r1.output, err, false));
    // same key + same nonce + same output file => refused
    REQUIRE_THROWS_AS(encrypt_buffer(e, sample_message()), UsageError);
    // different nonce => fine
    e.iv[0] ^= 1;
    REQUIRE_NOTHROW(encrypt_buffer(e, sample_message()));
    // different key, same nonce => fine
    e.iv[0] ^= 1;
    e.key = key_for(m);
    REQUIRE_NOTHROW(encrypt_buffer(e, sample_message()));
  }
  std::filesystem::remove(out, ec);

  // sidecar detection
  EncryptOptions s;
  s.mode = Mode::GCM;
  s.key = key_for(Mode::GCM);
  s.has_iv = true;
  s.iv = Bytes(12, 9);
  s.out_path = out;
  s.sidecar_path = sc;
  const EncryptResult r = encrypt_buffer(s, sample_message());
  std::string err;
  REQUIRE(util::write_file_atomic(sc, util::to_bytes(r.sidecar), err, false));
  REQUIRE_THROWS_AS(encrypt_buffer(s, sample_message()), UsageError);
  std::filesystem::remove(sc, ec);
}

TEST_CASE("sidecar mode round trip", "[sidecar]") {
  EncryptOptions e;
  e.mode = Mode::GCM;
  e.key = key_for(Mode::GCM);
  e.aad = util::to_bytes("meta");
  e.sidecar_path = "unused.json";
  const Bytes msg = sample_message();
  const EncryptResult r = encrypt_buffer(e, msg);
  REQUIRE(r.output.size() == msg.size());   // raw ciphertext only
  DecryptOptions d;
  d.key = e.key;
  d.sidecar_mode = true;
  d.sidecar_json = r.sidecar;
  REQUIRE(decrypt_buffer(d, r.output).plaintext == msg);
}

TEST_CASE("strict hex/base64 decoding", "[util]") {
  Bytes b;
  REQUIRE(util::from_hex("00ff10", b));
  REQUIRE(b == Bytes({0x00, 0xff, 0x10}));
  REQUIRE_FALSE(util::from_hex("0", b));
  REQUIRE_FALSE(util::from_hex("zz", b));
  REQUIRE_FALSE(util::from_hex("00 ff", b, false));
  REQUIRE(util::from_hex("00 ff", b, true));

  const Bytes data = util::to_bytes("any carnal pleas");
  REQUIRE(util::from_base64(util::to_base64(data), b));
  REQUIRE(b == data);
  REQUIRE(util::to_base64(util::to_bytes("Ma")) == "TWE=");
  REQUIRE_FALSE(util::from_base64("TWE", b));
  REQUIRE_FALSE(util::from_base64("T=E=", b));
  REQUIRE_FALSE(util::from_base64("TW!=", b));

  REQUIRE(util::is_valid_utf8(util::to_bytes("chào ✓")));
  REQUIRE_FALSE(util::is_valid_utf8(Bytes({0xC0, 0xAF})));   // overlong
  REQUIRE_FALSE(util::is_valid_utf8(Bytes({0xFF})));
}

TEST_CASE("minijson", "[util]") {
  minijson::Value v;
  std::string err;
  REQUIRE(minijson::parse("{\"a\": [1, 2.5, true, null], \"b\": \"x\\u00e9\"}", v, err));
  REQUIRE(v.get("b")->s == "x\xC3\xA9");
  REQUIRE(v.get("a")->arr.size() == 4);
  REQUIRE_FALSE(minijson::parse("{\"a\": }", v, err));
  REQUIRE_FALSE(minijson::parse("[1,2", v, err));
  REQUIRE_FALSE(minijson::parse("{} trailing", v, err));
}
