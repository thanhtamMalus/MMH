#pragma once
// Small strict JSON parser (RFC 8259 subset: full syntax, depth limit 64). Header-only.
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace minijson {

struct Value {
  enum Type { Null, Bool, Number, String, Array, Object };
  Type type = Null;
  bool b = false;
  double n = 0;
  std::string s;
  std::vector<Value> arr;
  std::vector<std::string> keys;  // object members (parallel arrays)
  std::vector<Value> vals;

  const Value* get(const std::string& k) const {
    if (type != Object) return nullptr;
    for (size_t i = 0; i < keys.size(); ++i)
      if (keys[i] == k) return &vals[i];
    return nullptr;
  }
};

class Parser {
 public:
  explicit Parser(const std::string& t) : t_(t) {}

  void parse(Value& out) {
    if (t_.size() >= 3 && t_.compare(0, 3, "\xEF\xBB\xBF") == 0) i_ = 3;
    ws();
    value(out, 0);
    ws();
    if (i_ != t_.size()) fail("unexpected trailing characters");
  }

 private:
  const std::string& t_;
  size_t i_ = 0;

  [[noreturn]] void fail(const std::string& m) const {
    throw std::runtime_error("JSON error at offset " + std::to_string(i_) + ": " + m);
  }
  void ws() {
    while (i_ < t_.size() && (t_[i_] == ' ' || t_[i_] == '\t' || t_[i_] == '\n' || t_[i_] == '\r')) ++i_;
  }
  char peek() const {
    if (i_ >= t_.size()) fail("unexpected end of input");
    return t_[i_];
  }
  void expect(char c) {
    if (peek() != c) fail(std::string("expected '") + c + "'");
    ++i_;
  }
  void lit(const char* w) {
    const size_t n = std::strlen(w);
    if (t_.compare(i_, n, w) != 0) fail("invalid literal");
    i_ += n;
  }

  static void put_utf8(std::string& o, unsigned cp) {
    if (cp < 0x80) o.push_back(static_cast<char>(cp));
    else if (cp < 0x800) {
      o.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      o.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
      o.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      o.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      o.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      o.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      o.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      o.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      o.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }

  unsigned hex4() {
    unsigned v = 0;
    for (int k = 0; k < 4; ++k) {
      const char c = peek();
      ++i_;
      v <<= 4;
      if (c >= '0' && c <= '9') v |= static_cast<unsigned>(c - '0');
      else if (c >= 'a' && c <= 'f') v |= static_cast<unsigned>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v |= static_cast<unsigned>(c - 'A' + 10);
      else fail("bad \\u escape");
    }
    return v;
  }

  std::string str() {
    expect('"');
    std::string o;
    for (;;) {
      const char c = peek();
      ++i_;
      if (c == '"') break;
      if (static_cast<unsigned char>(c) < 0x20) fail("control character in string");
      if (c != '\\') {
        o.push_back(c);
        continue;
      }
      const char e = peek();
      ++i_;
      switch (e) {
        case '"': o.push_back('"'); break;
        case '\\': o.push_back('\\'); break;
        case '/': o.push_back('/'); break;
        case 'b': o.push_back('\b'); break;
        case 'f': o.push_back('\f'); break;
        case 'n': o.push_back('\n'); break;
        case 'r': o.push_back('\r'); break;
        case 't': o.push_back('\t'); break;
        case 'u': {
          unsigned cp = hex4();
          if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (peek() != '\\') fail("lone high surrogate");
            ++i_;
            if (peek() != 'u') fail("lone high surrogate");
            ++i_;
            const unsigned lo = hex4();
            if (lo < 0xDC00 || lo > 0xDFFF) fail("invalid low surrogate");
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
          } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            fail("lone low surrogate");
          }
          put_utf8(o, cp);
          break;
        }
        default: fail("invalid escape");
      }
    }
    return o;
  }

  void value(Value& v, int depth) {
    if (depth > 64) fail("nesting too deep");
    const char c = peek();
    if (c == '{') {
      v.type = Value::Object;
      ++i_;
      ws();
      if (peek() == '}') { ++i_; return; }
      for (;;) {
        ws();
        if (peek() != '"') fail("object key must be a string");
        std::string k = str();
        ws();
        expect(':');
        ws();
        Value x;
        value(x, depth + 1);
        v.keys.push_back(std::move(k));
        v.vals.push_back(std::move(x));
        ws();
        const char d = peek();
        ++i_;
        if (d == ',') continue;
        if (d == '}') return;
        fail("expected ',' or '}'");
      }
    } else if (c == '[') {
      v.type = Value::Array;
      ++i_;
      ws();
      if (peek() == ']') { ++i_; return; }
      for (;;) {
        ws();
        Value x;
        value(x, depth + 1);
        v.arr.push_back(std::move(x));
        ws();
        const char d = peek();
        ++i_;
        if (d == ',') continue;
        if (d == ']') return;
        fail("expected ',' or ']'");
      }
    } else if (c == '"') {
      v.type = Value::String;
      v.s = str();
    } else if (c == 't') {
      lit("true");
      v.type = Value::Bool;
      v.b = true;
    } else if (c == 'f') {
      lit("false");
      v.type = Value::Bool;
      v.b = false;
    } else if (c == 'n') {
      lit("null");
      v.type = Value::Null;
    } else {
      const size_t st = i_;
      while (i_ < t_.size() && std::strchr("+-0123456789.eE", t_[i_]) != nullptr) ++i_;
      if (st == i_) fail("unexpected character");
      const std::string num = t_.substr(st, i_ - st);
      char* end = nullptr;
      v.n = std::strtod(num.c_str(), &end);
      if (end == nullptr || *end != '\0') fail("bad number");
      v.type = Value::Number;
    }
  }
};

inline bool parse(const std::string& text, Value& out, std::string& err) {
  try {
    Parser p(text);
    p.parse(out);
    return true;
  } catch (const std::exception& e) {
    err = e.what();
    return false;
  }
}

}  // namespace minijson
