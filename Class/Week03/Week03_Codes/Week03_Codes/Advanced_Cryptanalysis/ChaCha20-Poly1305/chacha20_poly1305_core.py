#!/usr/bin/env python3
"""Minimal RFC 8439 ChaCha20-Poly1305 core for Week 3 cryptanalysis labs.

Educational implementation only. Production software should use a vetted library.
"""
from __future__ import annotations
import hmac
import struct

MASK32 = 0xFFFFFFFF
P1305 = (1 << 130) - 5
R_MASK = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
M128 = 1 << 128
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)

RFC_KEY = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f"
)
RFC_NONCE = bytes.fromhex("070000004041424344454647")
RFC_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
RFC_PLAINTEXT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
    b"for the future, sunscreen would be it."
)
RFC_CIPHERTEXT = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "6116"
)
RFC_TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")


def rotl32(x: int, n: int) -> int:
    x &= MASK32
    return ((x << n) & MASK32) | (x >> (32 - n))


def quarter_round(x: list[int], a: int, b: int, c: int, d: int) -> None:
    x[a] = (x[a] + x[b]) & MASK32
    x[d] = rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & MASK32
    x[b] = rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & MASK32
    x[d] = rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & MASK32
    x[b] = rotl32(x[b] ^ x[c], 7)


def inner_block(x: list[int]) -> None:
    quarter_round(x, 0, 4, 8, 12)
    quarter_round(x, 1, 5, 9, 13)
    quarter_round(x, 2, 6, 10, 14)
    quarter_round(x, 3, 7, 11, 15)
    quarter_round(x, 0, 5, 10, 15)
    quarter_round(x, 1, 6, 11, 12)
    quarter_round(x, 2, 7, 8, 13)
    quarter_round(x, 3, 4, 9, 14)


def validate_key_nonce(key: bytes, nonce: bytes) -> None:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    validate_key_nonce(key, nonce)
    if not 0 <= counter <= MASK32:
        raise ValueError("counter out of range")
    state = [*CONSTANTS, *struct.unpack("<8I", key), counter, *struct.unpack("<3I", nonce)]
    x = state.copy()
    for _ in range(10):
        inner_block(x)
    x = [(x[i] + state[i]) & MASK32 for i in range(16)]
    return struct.pack("<16I", *x)


def chacha20_xor(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    blocks = (len(data) + 63) // 64
    if blocks and counter + blocks - 1 > MASK32:
        raise ValueError("counter would wrap")
    out = bytearray()
    for j in range(blocks):
        z = chacha20_block(key, counter + j, nonce)
        chunk = data[64*j:64*(j+1)]
        out.extend(a ^ b for a, b in zip(chunk, z))
    return bytes(out)


def pad16(data: bytes) -> bytes:
    r = len(data) % 16
    return b"" if r == 0 else b"\x00" * (16 - r)


def mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return (
        aad + pad16(aad)
        + ciphertext + pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )


def poly1305_accumulator(message: bytes, r: int) -> int:
    h = 0
    for off in range(0, len(message), 16):
        block = message[off:off+16]
        n = int.from_bytes(block + b"\x01", "little")
        h = ((h + n) * r) % P1305
    return h


def poly1305_mac_rs(message: bytes, r: int, s: int) -> bytes:
    h = poly1305_accumulator(message, r)
    return ((h + s) % M128).to_bytes(16, "little")


def poly1305_mac(message: bytes, one_time_key: bytes) -> bytes:
    if len(one_time_key) != 32:
        raise ValueError("Poly1305 one-time key must be 32 bytes")
    r = int.from_bytes(one_time_key[:16], "little") & R_MASK
    s = int.from_bytes(one_time_key[16:], "little")
    return poly1305_mac_rs(message, r, s)


def poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    return chacha20_block(key, 0, nonce)[:32]


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    validate_key_nonce(key, nonce)
    otk = poly1305_key_gen(key, nonce)
    ciphertext = chacha20_xor(key, nonce, 1, plaintext)
    tag = poly1305_mac(mac_data(aad, ciphertext), otk)
    return ciphertext, tag


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    validate_key_nonce(key, nonce)
    if len(tag) != 16:
        raise ValueError("tag must be 16 bytes")
    otk = poly1305_key_gen(key, nonce)
    expected = poly1305_mac(mac_data(aad, ciphertext), otk)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("authentication failed")
    return chacha20_xor(key, nonce, 1, ciphertext)


def selftest(verbose: bool = False) -> bool:
    c, t = aead_encrypt(RFC_KEY, RFC_NONCE, RFC_PLAINTEXT, RFC_AAD)
    ok = (c == RFC_CIPHERTEXT and t == RFC_TAG)
    try:
        p = aead_decrypt(RFC_KEY, RFC_NONCE, RFC_CIPHERTEXT, RFC_TAG, RFC_AAD)
        ok = ok and p == RFC_PLAINTEXT
    except Exception:
        ok = False
    if verbose:
        print("RFC 8439 ChaCha20-Poly1305:", "PASS" if ok else "FAIL")
    return ok
