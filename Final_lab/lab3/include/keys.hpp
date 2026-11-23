// keys.hpp — RSA key generation and loading (EVP_PKEY, PEM/DER)
#pragma once
#include <filesystem>
#include "secure.hpp"

namespace rsatool::keys {

/// Supported RSA modulus sizes (bits).
inline constexpr int BITS_3072 = 3072;
inline constexpr int BITS_4096 = 4096;

/// Validate that bits is 3072 or 4096. Throws UsageError otherwise.
void validate_bits(int bits);

/// Generate a new RSA key pair with the given modulus size.
/// Returns a unique_ptr to the EVP_PKEY; throws CryptoError on failure.
UniqueEVPPKEY generate_key(int bits);

/// Load an RSA key from file (PEM or DER, auto-detected).
/// is_private: true for private key, false for public key.
/// Throws FormatError / CryptoError on failure.
UniqueEVPPKEY load_key(const std::filesystem::path& path, bool is_private);

/// Return the RSA modulus size in bits. Throws if not an RSA key or unsupported size.
int key_bits(const EVP_PKEY* key);

/// Write the public key to PEM file (safe overwrite).
void write_public_pem(const EVP_PKEY* key, const std::filesystem::path& path);

/// Write the private key to PEM file (safe overwrite), then restrict permissions.
void write_private_pem(const EVP_PKEY* key, const std::filesystem::path& path);

/// Write the public key to DER file (safe overwrite).
void write_public_der(const EVP_PKEY* key, const std::filesystem::path& path);

/// Write the private key to DER file (safe overwrite), then restrict permissions.
void write_private_der(const EVP_PKEY* key, const std::filesystem::path& path);

/// Write meta.json (creation_time, modulus_bits, hash) next to the key files.
void write_meta_json(const std::filesystem::path& dir, int bits);

} // namespace rsatool::keys

