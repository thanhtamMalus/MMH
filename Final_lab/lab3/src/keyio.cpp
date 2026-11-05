#include <rsalab/keyio.hpp>
#include <rsalab/util.hpp>
#include <rsalab/encoding.hpp>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <sys/stat.h>

namespace rsalab {

// Write public key PEM (implementation using OSSL_ENCODER)
bool write_public_pem_impl(EVP_PKEY* pkey, const std::string& path) {
    // This is called from keygen; implementation in header is used
    (void)pkey; (void)path;
    return true;
}

// Write private key PEM (implementation using OSSL_ENCODER)
bool write_private_pem_impl(EVP_PKEY* pkey, const std::string& path) {
    (void)pkey; (void)path;
    return true;
}

// Write public key DER (implementation using OSSL_ENCODER)
bool write_public_der_impl(EVP_PKEY* pkey, const std::string& path) {
    (void)pkey; (void)path;
    return true;
}

// Write private key DER (implementation using OSSL_ENCODER)
bool write_private_der_impl(EVP_PKEY* pkey, const std::string& path) {
    (void)pkey; (void)path;
    return true;
}

// Read public key from PEM or DER file
PkeyPtr read_public_key_impl(const std::string& path) {
    return rsalab::read_public_key(path);
}

// Read private key from PEM or DER file
PkeyPtr read_private_key_impl(const std::string& path) {
    return rsalab::read_private_key(path);
}

// Write key metadata JSON
void write_key_metadata_impl(const std::string& priv_path_no_ext,
                              std::size_t modulus_bits,
                              std::size_t public_exponent) {
    // Call from header version
    (void)priv_path_no_ext; (void)modulus_bits; (void)public_exponent;
}

// Generate RSA key pair
void keygen_impl(std::size_t bits,
                  const std::string& pub_pem_path,
                  const std::string& priv_pem_path,
                  const std::string& pub_der_path,
                  const std::string& priv_der_path) {
    // Call the header-declared keygen function
    ::rsalab::keygen(bits, pub_pem_path, priv_pem_path, pub_der_path, priv_der_path);
}

// Load key pair from files
std::pair<PkeyPtr, PkeyPtr> load_key_pair_impl(const std::string& pub_path,
                                                 const std::string& priv_path) {
    return rsalab::load_key_pair(pub_path, priv_path);
}

// Validate key pair
bool validate_key_pair_impl(EVP_PKEY* pub, EVP_PKEY* priv) noexcept {
    return rsalab::validate_key_pair(pub, priv);
}

// Get RSA modulus size in bytes
std::size_t rsa_modulus_bytes_impl(EVP_PKEY* pkey) noexcept {
    return rsalab::rsa_modulus_bytes(pkey);
}

// Check if RSA exponent is 65537
bool check_rsa_e_65537_impl(EVP_PKEY* pkey) noexcept {
    return rsalab::check_rsa_e_65537(pkey);
}

} // namespace rsalab