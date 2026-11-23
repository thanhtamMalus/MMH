#pragma once
// Output container ("AEST" header) and JSON sidecar.
//
// Binary layout (all integers big-endian):
//   "AEST" | ver(1)=1 | mode(1) | key_len(1) | flags(1: bit0=AEAD) | key_id(8)
//   | iv_len(1) | iv | aad_len(4) | aad | tag_len(1) | tag | ct_len(8) | ciphertext
#include <string>

#include "aescore.h"

namespace container {

using aescore::Bytes;
using aescore::Mode;

struct Header {
  Mode mode = Mode::GCM;
  uint8_t key_len = 0;   // bytes (XTS: 32 or 64)
  Bytes key_id;          // 8 bytes (may be empty in sidecars written by others)
  Bytes iv;
  Bytes aad;
  Bytes tag;
};

struct Parsed {
  Header h;
  size_t ct_offset = 0;
  size_t ct_len = 0;
};

Bytes pack(const Header& h, const Bytes& ciphertext);
// Parses only the header (used to inspect existing outputs for nonce reuse).
bool parse_header_prefix(const Bytes& data, Header& h, size_t& header_len, uint64_t& ct_len, std::string& err);
// Strict full parse: length field must match the remaining bytes exactly.
bool parse(const Bytes& data, Parsed& out, std::string& err);

std::string make_sidecar_json(const Header& h);
bool parse_sidecar_json(const std::string& text, Header& h, std::string& err);

}  // namespace container
