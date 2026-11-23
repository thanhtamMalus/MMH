#!/usr/bin/env python3
"""Verify-before-release implementation pitfall.

A correct AEAD API authenticates ciphertext/AAD before releasing plaintext.
This lab contrasts:

  SAFE   : verify tag -> decrypt/release
  UNSAFE : decrypt/release -> verify tag

The unsafe flow can expose attacker-controlled transient plaintext to application
logic even though authentication eventually fails.

This is an implementation misuse, not a cryptanalytic break of ChaCha20-Poly1305.
"""
from __future__ import annotations
import secrets
from chacha20_poly1305_core import (
    aead_encrypt, aead_decrypt, chacha20_xor, poly1305_key_gen,
    poly1305_mac, mac_data
)
import hmac


def patch(ct: bytes, plaintext: bytes, old: bytes, new: bytes) -> bytes:
    if len(old) != len(new):
        raise ValueError("same-length patch required")
    pos = plaintext.index(old)
    delta = bytes(a ^ b for a, b in zip(old, new))
    out = bytearray(ct)
    for i, d in enumerate(delta):
        out[pos+i] ^= d
    return bytes(out)


def unsafe_decrypt_then_verify(key, nonce, ciphertext, tag, aad=b""):
    # ANTI-PATTERN: plaintext exists/reaches application before authenticity is known.
    plaintext = chacha20_xor(key, nonce, 1, ciphertext)
    print("[UNSAFE application sees]", plaintext.decode(errors="replace"))
    otk = poly1305_key_gen(key, nonce)
    expected = poly1305_mac(mac_data(aad, ciphertext), otk)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("authentication failed AFTER plaintext release")
    return plaintext


def demo() -> bool:
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    p = b"uid=1001;role=user;active=yes"
    aad = b"type=account"
    c, t = aead_encrypt(key, nonce, p, aad)
    bad_c = patch(c, p, b"user", b"root")

    print("SAFE path:")
    try:
        aead_decrypt(key, nonce, bad_c, t, aad)
        print("  ERROR: accepted")
        return False
    except ValueError:
        print("  authentication failed before plaintext release")

    print("\nUNSAFE path:")
    try:
        unsafe_decrypt_then_verify(key, nonce, bad_c, t, aad)
    except ValueError as e:
        print("  final result:", e)
        print("  but application already observed attacker-influenced plaintext")
        return True
    return False


if __name__ == "__main__":
    raise SystemExit(0 if demo() else 1)
