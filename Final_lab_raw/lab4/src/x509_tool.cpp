// x509_tool.cpp - Lab 4 section 3: X.509 parsing + signature verification (OpenSSL EVP/X509 API)
#include "common.hpp"
#include "x509_tool.hpp"

#include <fstream>
#include <memory>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {

template <class T, void (*F)(T*)> struct Deleter { void operator()(T* p) const { if (p) F(p); } };
using X509Ptr = std::unique_ptr<X509, Deleter<X509, X509_free>>;
using BioPtr  = std::unique_ptr<BIO, Deleter<BIO, BIO_free_all>>;
using BnPtr   = std::unique_ptr<BIGNUM, Deleter<BIGNUM, BN_free>>;
using GnPtr   = std::unique_ptr<GENERAL_NAMES, Deleter<GENERAL_NAMES, GENERAL_NAMES_free>>;

std::string read_all(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) throw IoError("Cannot open file: " + path);
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

std::string bio_string(BIO* b) {
  char* p = nullptr;
  long n = BIO_get_mem_data(b, &p);
  return std::string(p ? p : "", n > 0 ? static_cast<size_t>(n) : 0);
}

std::string name_str(const X509_NAME* n) {
  BioPtr b(BIO_new(BIO_s_mem()));
  X509_NAME_print_ex(b.get(), n, 0, XN_FLAG_RFC2253 | ASN1_STRFLGS_UTF8_CONVERT);
  return bio_string(b.get());
}

std::string time_str(const ASN1_TIME* t) {
  BioPtr b(BIO_new(BIO_s_mem()));
  ASN1_TIME_print(b.get(), t);
  return bio_string(b.get());
}

std::string oid_str(const ASN1_OBJECT* o) {
  char buf[128];
  OBJ_obj2txt(buf, sizeof buf, o, 1);
  return buf;
}

// Load PEM first, then DER. Sets `trailing` when DER has bytes after the certificate.
X509Ptr load_cert(const std::string& path, bool& trailing, std::string& err) {
  std::string data = read_all(path);
  trailing = false;
  if (data.empty()) { err = "empty file"; return nullptr; }
  {
    BioPtr bio(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));
    X509Ptr c(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (c) return c;
  }
  ERR_clear_error();
  const unsigned char* p = reinterpret_cast<const unsigned char*>(data.data());
  const unsigned char* start = p;
  X509Ptr c(d2i_X509(nullptr, &p, static_cast<long>(data.size())));
  if (!c) { err = "not a valid PEM or DER X.509 certificate"; ERR_clear_error(); return nullptr; }
  trailing = static_cast<size_t>(p - start) != data.size();
  return c;
}

std::string key_usage_str(uint32_t ku) {
  if (ku == UINT32_MAX) return "(extension absent)";
  static const struct { uint32_t bit; const char* n; } t[] = {
    {0x0080, "digitalSignature"}, {0x0040, "nonRepudiation"}, {0x0020, "keyEncipherment"},
    {0x0010, "dataEncipherment"}, {0x0008, "keyAgreement"},   {0x0004, "keyCertSign"},
    {0x0002, "cRLSign"},          {0x0001, "encipherOnly"},   {0x8000, "decipherOnly"}};
  std::string s;
  for (auto& e : t) if (ku & e.bit) { if (!s.empty()) s += ", "; s += e.n; }
  return s.empty() ? "(none)" : s;
}

std::string eku_str(uint32_t x) {
  if (x == UINT32_MAX) return "(extension absent)";
  static const struct { uint32_t bit; const char* n; } t[] = {
    {XKU_SSL_SERVER, "serverAuth"}, {XKU_SSL_CLIENT, "clientAuth"}, {XKU_SMIME, "emailProtection"},
    {XKU_CODE_SIGN, "codeSigning"}, {XKU_OCSP_SIGN, "OCSPSigning"}, {XKU_TIMESTAMP, "timeStamping"},
    {XKU_ANYEKU, "anyExtendedKeyUsage"}};
  std::string s;
  for (auto& e : t) if (x & e.bit) { if (!s.empty()) s += ", "; s += e.n; }
  return s.empty() ? "(none of the well-known purposes)" : s;
}

std::string ip_str(const ASN1_OCTET_STRING* ip) {
  const unsigned char* d = ASN1_STRING_get0_data(ip);
  int n = ASN1_STRING_length(ip);
  std::ostringstream o;
  if (n == 4) { o << int(d[0]) << '.' << int(d[1]) << '.' << int(d[2]) << '.' << int(d[3]); }
  else if (n == 16) {
    for (int i = 0; i < 16; i += 2) { if (i) o << ':'; o << std::hex << ((d[i] << 8) | d[i + 1]); }
  } else o << "(" << n << " bytes)";
  return o.str();
}

} // namespace

int x509_analyze(const std::string& cert_path, const std::string& issuer_path,
                 bool check_time, std::string& report) {
  std::ostringstream R;
  bool fail = false;
  auto FAIL = [&](const std::string& why) { fail = true; R << "  [FAIL] " << why << "\n"; };
  auto OKAY = [&](const std::string& what) { R << "  [ OK ] " << what << "\n"; };
  auto WARN = [&](const std::string& what) { R << "  [WARN] " << what << "\n"; };

  R << "=== X.509 CERTIFICATE ANALYSIS ===\n";
  R << "File: " << cert_path << "\n";

  bool trailing = false;
  std::string err;
  X509Ptr cert = load_cert(cert_path, trailing, err);
  if (!cert) {
    R << "\n[FAIL] Cannot parse certificate: " << err << "\nVERDICT: FAIL (fail closed)\n";
    report = R.str();
    return 1;
  }

  // --- Identity ---
  R << "\n-- Identity --\n";
  R << "Version:  v" << (X509_get_version(cert.get()) + 1) << "\n";
  {
    BnPtr bn(ASN1_INTEGER_to_BN(X509_get0_serialNumber(cert.get()), nullptr));
    char* hx = bn ? BN_bn2hex(bn.get()) : nullptr;
    R << "Serial:   " << (hx ? hx : "?") << "\n";
    if (hx) OPENSSL_free(hx);
  }
  const X509_NAME* subj = X509_get_subject_name(cert.get());
  const X509_NAME* iss  = X509_get_issuer_name(cert.get());
  R << "Subject:  " << name_str(subj) << "\n";
  R << "Issuer:   " << name_str(iss) << "\n";
  const bool self_issued = X509_NAME_cmp(subj, iss) == 0;

  // --- Validity ---
  R << "\n-- Validity --\n";
  const ASN1_TIME* nb = X509_get0_notBefore(cert.get());
  const ASN1_TIME* na = X509_get0_notAfter(cert.get());
  R << "Not Before: " << time_str(nb) << "\n";
  R << "Not After:  " << time_str(na) << "\n";
  if (check_time) {
    if (X509_cmp_current_time(nb) > 0) FAIL("certificate is not yet valid");
    else if (X509_cmp_current_time(na) < 0) FAIL("certificate has expired");
    else OKAY("current time is inside the validity period");
  } else WARN("time check disabled (--no-time-check)");

  // --- Subject Public Key Info ---
  R << "\n-- Subject Public Key Info --\n";
  auto* pk = X509_get0_pubkey(cert.get());
  if (!pk) {
    FAIL("cannot decode the subject public key");
  } else {
    int base = EVP_PKEY_get_base_id(pk);
    R << "Algorithm: " << OBJ_nid2ln(base) << " (OID " << oid_str(OBJ_nid2obj(base)) << ")\n";
    R << "Key size:  " << EVP_PKEY_get_bits(pk) << " bits\n";
    if (base == EVP_PKEY_EC) {
      char grp[80] = {0};
      size_t gl = 0;
      if (EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME, grp, sizeof grp, &gl))
        R << "Parameters: curve = " << grp << "\n";
    } else if (base == EVP_PKEY_RSA || base == EVP_PKEY_RSA_PSS) {
      BIGNUM* e = nullptr;
      if (EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_E, &e)) {
        char* hx = BN_bn2dec(e);
        R << "Parameters: public exponent e = " << (hx ? hx : "?") << "\n";
        if (hx) OPENSSL_free(hx);
        BN_free(e);
      }
      if (EVP_PKEY_get_bits(pk) < 2048) WARN("RSA key shorter than 2048 bits");
    }
  }

  // --- Signature algorithm + TBS consistency ---
  R << "\n-- Signature --\n";
  const ASN1_BIT_STRING* sig = nullptr;
  const X509_ALGOR* outer = nullptr;
  X509_get0_signature(&sig, &outer, cert.get());
  const X509_ALGOR* inner = X509_get0_tbs_sigalg(cert.get());
  int sig_nid = X509_get_signature_nid(cert.get());
  R << "Signature algorithm: " << OBJ_nid2ln(sig_nid) << " (OID "
    << oid_str(OBJ_nid2obj(sig_nid)) << ")\n";
  R << "Signature length:    " << (sig ? ASN1_STRING_length(sig) : 0) << " bytes\n";

  if (trailing) FAIL("trailing bytes after the DER certificate (structure integrity)");
  if (!sig || ASN1_STRING_length(sig) == 0) FAIL("empty signature value");
  if (!outer || !inner || X509_ALGOR_cmp(outer, inner) != 0)
    FAIL("signatureAlgorithm in TBSCertificate differs from outer signatureAlgorithm (algorithm inconsistency)");
  else OKAY("TBS signature algorithm == outer signature algorithm");

  int md_nid = NID_undef, pk_nid = NID_undef;
  if (OBJ_find_sigid_algs(sig_nid, &md_nid, &pk_nid)) {
    if (md_nid != NID_undef) R << "Digest: " << OBJ_nid2ln(md_nid) << ", key type: " << OBJ_nid2ln(pk_nid) << "\n";
    if (md_nid == NID_md5 || md_nid == NID_md2 || md_nid == NID_md4 || md_nid == NID_sha1)
      FAIL(std::string("weak/banned signature hash: ") + OBJ_nid2ln(md_nid) + " (MD5/SHA-1 are rejected)");
    else OKAY("signature hash is not MD5/SHA-1");
  } else {
    FAIL("unknown signature algorithm OID");
  }

  // --- Extensions ---
  R << "\n-- Extensions --\n";
  R << "Key Usage:          " << key_usage_str(X509_get_key_usage(cert.get())) << "\n";
  R << "Extended Key Usage: " << eku_str(X509_get_extended_key_usage(cert.get())) << "\n";
  R << "CA (basicConstraints): " << (X509_check_ca(cert.get()) ? "yes" : "no") << "\n";
  {
    GnPtr gens(static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert.get(), NID_subject_alt_name, nullptr, nullptr)));
    if (!gens) R << "Subject Alternative Names: (extension absent)\n";
    else {
      R << "Subject Alternative Names:\n";
      for (int i = 0; i < sk_GENERAL_NAME_num(gens.get()); ++i) {
        const GENERAL_NAME* g = sk_GENERAL_NAME_value(gens.get(), i);
        switch (g->type) {
          case GEN_DNS:   R << "  DNS:" << std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(g->d.dNSName)), ASN1_STRING_length(g->d.dNSName)) << "\n"; break;
          case GEN_EMAIL: R << "  email:" << std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(g->d.rfc822Name)), ASN1_STRING_length(g->d.rfc822Name)) << "\n"; break;
          case GEN_URI:   R << "  URI:" << std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(g->d.uniformResourceIdentifier)), ASN1_STRING_length(g->d.uniformResourceIdentifier)) << "\n"; break;
          case GEN_IPADD: R << "  IP:" << ip_str(g->d.iPAddress) << "\n"; break;
          default:        R << "  (type " << g->type << ")\n";
        }
      }
    }
  }

  // --- Signature verification ---
  R << "\n-- Signature verification --\n";
  if (!issuer_path.empty()) {
    bool tr2 = false; std::string e2;
    X509Ptr issuer = load_cert(issuer_path, tr2, e2);
    if (!issuer) FAIL("cannot parse issuer certificate: " + e2);
    else {
      R << "Issuer cert: " << issuer_path << "  (" << name_str(X509_get_subject_name(issuer.get())) << ")\n";
      if (X509_NAME_cmp(X509_get_subject_name(issuer.get()), iss) != 0)
        FAIL("issuer certificate subject does not match this certificate's issuer name");
      auto* ipk = X509_get0_pubkey(issuer.get());
      if (!ipk) FAIL("cannot decode issuer public key");
      else {
        int r = X509_verify(cert.get(), ipk);
        if (r == 1) OKAY("signature VALID under the issuer public key");
        else FAIL("signature INVALID under the issuer public key (certificate altered or wrong issuer)");
      }
    }
  } else if (self_issued && pk) {
    int r = X509_verify(cert.get(), pk);
    if (r == 1) {
      OKAY("self-signed: signature VALID under the certificate's own public key");
      WARN("self-signed certificate proves integrity only, NOT trust (no chain to a trusted root)");
    } else FAIL("self-signed signature INVALID (certificate altered)");
  } else {
    FAIL("issuer public key not provided (use --issuer CA.pem): signature cannot be verified -> fail closed");
  }
  ERR_clear_error();

  R << "\nVERDICT: " << (fail ? "FAIL" : "PASS") << "\n";
  report = R.str();
  return fail ? 1 : 0;
}
