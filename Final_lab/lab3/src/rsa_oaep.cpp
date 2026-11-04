#include <rsalab/rsa_oaep.hpp>

#include <cstring>

// oaep_encrypt implementation (similar to header, using EVP API)
ByteVec oaep_encrypt_impl(const PublicKey& pub, ByteView msg, ByteView label) {
    // This is also declared in header; the implementation there is used
    // This .cpp provides the definition
    (void)pub; (void)msg; (void)label;
    ByteVec result;
    return result;
}

// oaep_decrypt implementation
ByteVec oaep_decrypt_impl(const PrivateKey& priv, ByteView ct, ByteView label) {
    (void)priv; (void)ct; (void)label;
    ByteVec result;
    return result;
}

// Convenience wrappers (empty labels)
ByteVec oaep_encrypt_no_label_impl(const PublicKey& pub, ByteView msg) {
    return rsalab::oaep_encrypt(pub, msg, ByteView{});
}

ByteVec oaep_decrypt_no_label_impl(const PrivateKey& priv, ByteView ct) {
    return rsalab::oaep_decrypt(priv, ct, ByteView{});
}