#include "aes/aes128.hpp"
#include "aes/ctr.hpp"
#include "aes/util.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <cctype>

namespace aes {

struct BlockVector {
    std::string name;
    std::string key_hex;
    std::string pt_hex;
    std::string ct_hex;
};

struct CtrVector {
    std::string name;
    std::string key_hex;
    std::string iv_hex;
    std::string pt_hex;
    std::string ct_hex;
};

// Minimal, resilient parser for flat KAT JSON schema
class SimpleKatParser {
public:
    static bool parse(
        const std::string& content,
        std::vector<BlockVector>& block_vecs,
        std::vector<CtrVector>& ctr_vecs
    ) {
        size_t pos = 0;
        skip_ws(content, pos);
        if (pos >= content.size() || content[pos] != '{') return false;
        pos++;

        while (pos < content.size()) {
            skip_ws(content, pos);
            if (pos < content.size() && content[pos] == '}') break;

            std::string key = parse_string(content, pos);
            skip_ws(content, pos);
            if (pos >= content.size() || content[pos] != ':') return false;
            pos++; // skip ':'
            skip_ws(content, pos);

            if (key == "aes128_block") {
                if (!parse_block_array(content, pos, block_vecs)) return false;
            } else if (key == "aes128_ctr") {
                if (!parse_ctr_array(content, pos, ctr_vecs)) return false;
            } else {
                // Skip unknown value (object, array, string, etc.)
                skip_value(content, pos);
            }

            skip_ws(content, pos);
            if (pos < content.size() && content[pos] == ',') {
                pos++;
            }
        }
        return true;
    }

private:
    static void skip_ws(const std::string& s, size_t& pos) {
        while (pos < s.size() && (std::isspace(static_cast<unsigned char>(s[pos])) || s[pos] == '\r')) {
            pos++;
        }
    }

    static std::string parse_string(const std::string& s, size_t& pos) {
        skip_ws(s, pos);
        if (pos >= s.size() || s[pos] != '"') return "";
        pos++; // skip '"'
        std::string result;
        while (pos < s.size()) {
            char c = s[pos++];
            if (c == '"') break;
            if (c == '\\' && pos < s.size()) {
                c = s[pos++];
            }
            result.push_back(c);
        }
        return result;
    }

    static void skip_value(const std::string& s, size_t& pos) {
        skip_ws(s, pos);
        if (pos >= s.size()) return;
        if (s[pos] == '"') {
            parse_string(s, pos);
        } else if (s[pos] == '[' || s[pos] == '{') {
            char open = s[pos++];
            char close = (open == '[') ? ']' : '}';
            int depth = 1;
            while (pos < s.size() && depth > 0) {
                if (s[pos] == open) depth++;
                else if (s[pos] == close) depth--;
                else if (s[pos] == '"') {
                    parse_string(s, pos);
                    continue;
                }
                pos++;
            }
        } else {
            while (pos < s.size() && s[pos] != ',' && s[pos] != '}' && s[pos] != ']' && !std::isspace(static_cast<unsigned char>(s[pos]))) {
                pos++;
            }
        }
    }

    static bool parse_block_array(const std::string& s, size_t& pos, std::vector<BlockVector>& vecs) {
        skip_ws(s, pos);
        if (pos >= s.size() || s[pos] != '[') return false;
        pos++;

        while (pos < s.size()) {
            skip_ws(s, pos);
            if (pos < s.size() && s[pos] == ']') {
                pos++;
                break;
            }
            if (s[pos] != '{') return false;
            pos++;

            BlockVector bv;
            while (pos < s.size()) {
                skip_ws(s, pos);
                if (pos < s.size() && s[pos] == '}') {
                    pos++;
                    break;
                }
                std::string k = parse_string(s, pos);
                skip_ws(s, pos);
                if (pos >= s.size() || s[pos] != ':') return false;
                pos++;
                std::string val = parse_string(s, pos);

                if (k == "name") bv.name = val;
                else if (k == "key") bv.key_hex = val;
                else if (k == "plaintext") bv.pt_hex = val;
                else if (k == "ciphertext") bv.ct_hex = val;

                skip_ws(s, pos);
                if (pos < s.size() && s[pos] == ',') pos++;
            }
            vecs.push_back(bv);

            skip_ws(s, pos);
            if (pos < s.size() && s[pos] == ',') pos++;
        }
        return true;
    }

    static bool parse_ctr_array(const std::string& s, size_t& pos, std::vector<CtrVector>& vecs) {
        skip_ws(s, pos);
        if (pos >= s.size() || s[pos] != '[') return false;
        pos++;

        while (pos < s.size()) {
            skip_ws(s, pos);
            if (pos < s.size() && s[pos] == ']') {
                pos++;
                break;
            }
            if (s[pos] != '{') return false;
            pos++;

            CtrVector cv;
            while (pos < s.size()) {
                skip_ws(s, pos);
                if (pos < s.size() && s[pos] == '}') {
                    pos++;
                    break;
                }
                std::string k = parse_string(s, pos);
                skip_ws(s, pos);
                if (pos >= s.size() || s[pos] != ':') return false;
                pos++;
                std::string val = parse_string(s, pos);

                if (k == "name") cv.name = val;
                else if (k == "key") cv.key_hex = val;
                else if (k == "iv") cv.iv_hex = val;
                else if (k == "plaintext") cv.pt_hex = val;
                else if (k == "ciphertext") cv.ct_hex = val;

                skip_ws(s, pos);
                if (pos < s.size() && s[pos] == ',') pos++;
            }
            vecs.push_back(cv);

            skip_ws(s, pos);
            if (pos < s.size() && s[pos] == ',') pos++;
        }
        return true;
    }
};

int run_kat_from_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[KAT Error] Cannot open vector file: " << filepath << std::endl;
        return 3; // IOError
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    std::vector<BlockVector> block_vecs;
    std::vector<CtrVector> ctr_vecs;

    if (!SimpleKatParser::parse(content, block_vecs, ctr_vecs)) {
        std::cerr << "[KAT Error] Failed to parse JSON in " << filepath << std::endl;
        return 5; // KatFailure
    }

    bool all_passed = true;
    size_t total_tests = 0;
    size_t passed_tests = 0;

    std::cout << "=== Running Known Answer Tests (KAT) ===" << std::endl;

    // 1. AES-128 Block Cipher Tests
    for (const auto& bv : block_vecs) {
        total_tests++;
        std::vector<uint8_t> key, pt, ct;
        if (!util::from_hex(bv.key_hex, key) || key.size() != 16 ||
            !util::from_hex(bv.pt_hex, pt) || pt.size() != 16 ||
            !util::from_hex(bv.ct_hex, ct) || ct.size() != 16) {
            std::cout << "  [FAIL] " << bv.name << " (Invalid hex/length in test vector)" << std::endl;
            all_passed = false;
            continue;
        }

        uint8_t round_keys[176];
        key_expansion_128(key.data(), round_keys);

        uint8_t actual_ct[16];
        encrypt_block_128(pt.data(), actual_ct, round_keys);

        if (std::memcmp(actual_ct, ct.data(), 16) == 0) {
            std::cout << "  [PASS] Block: " << bv.name << std::endl;
            passed_tests++;
        } else {
            std::cout << "  [FAIL] Block: " << bv.name << std::endl;
            std::cout << "         Expected: " << bv.ct_hex << std::endl;
            std::cout << "         Actual:   " << util::to_hex(actual_ct, 16) << std::endl;
            all_passed = false;
        }
        platform::secure_zero(round_keys, sizeof(round_keys));
    }

    // 2. AES-128 CTR Mode Tests (Test both encrypt and decrypt)
    for (const auto& cv : ctr_vecs) {
        total_tests++;
        std::vector<uint8_t> key, iv, pt, ct;
        if (!util::from_hex(cv.key_hex, key) || key.size() != 16 ||
            !util::from_hex(cv.iv_hex, iv) || iv.size() != 16 ||
            !util::from_hex(cv.pt_hex, pt) ||
            !util::from_hex(cv.ct_hex, ct) || pt.size() != ct.size()) {
            std::cout << "  [FAIL] " << cv.name << " (Invalid hex/length in test vector)" << std::endl;
            all_passed = false;
            continue;
        }

        std::vector<uint8_t> actual_ct(pt.size());
        CtrStatus enc_status = ctr_crypt_buffer(
            pt.data(), actual_ct.data(), pt.size(),
            key.data(), iv.data(), SBoxMode::Table, 128
        );

        std::vector<uint8_t> actual_pt(ct.size());
        CtrStatus dec_status = ctr_crypt_buffer(
            ct.data(), actual_pt.data(), ct.size(),
            key.data(), iv.data(), SBoxMode::Table, 128
        );

        bool enc_match = (enc_status == CtrStatus::Success) && (std::memcmp(actual_ct.data(), ct.data(), ct.size()) == 0);
        bool dec_match = (dec_status == CtrStatus::Success) && (std::memcmp(actual_pt.data(), pt.data(), pt.size()) == 0);

        if (enc_match && dec_match) {
            std::cout << "  [PASS] CTR:   " << cv.name << std::endl;
            passed_tests++;
        } else {
            std::cout << "  [FAIL] CTR:   " << cv.name << std::endl;
            if (!enc_match) {
                std::cout << "         Enc Expected: " << cv.ct_hex << std::endl;
                std::cout << "         Enc Actual:   " << util::to_hex(actual_ct.data(), actual_ct.size()) << std::endl;
            }
            if (!dec_match) {
                std::cout << "         Dec Expected: " << cv.pt_hex << std::endl;
                std::cout << "         Dec Actual:   " << util::to_hex(actual_pt.data(), actual_pt.size()) << std::endl;
            }
            all_passed = false;
        }
    }

    std::cout << "=== KAT Result: " << passed_tests << "/" << total_tests << " Passed ===" << std::endl;
    return all_passed ? 0 : 5;
}

} // namespace aes
