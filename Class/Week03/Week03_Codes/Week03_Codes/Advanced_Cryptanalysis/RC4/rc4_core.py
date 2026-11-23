#!/usr/bin/env python3
"""Minimal RC4 implementation used only for Week 3 cryptanalysis labs."""

from __future__ import annotations


def rc4_keystream(key: bytes, n: int, drop: int = 0) -> bytes:
    if not key:
        raise ValueError("RC4 key must not be empty")
    if n < 0 or drop < 0:
        raise ValueError("n and drop must be non-negative")

    S = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) & 0xFF
        S[i], S[j] = S[j], S[i]

    out = bytearray()
    i = j = 0
    needed = n + drop
    for t in range(needed):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        z = S[(S[i] + S[j]) & 0xFF]
        if t >= drop:
            out.append(z)
    return bytes(out)


def rc4_crypt(key: bytes, data: bytes, drop: int = 0) -> bytes:
    z = rc4_keystream(key, len(data), drop=drop)
    return bytes(a ^ b for a, b in zip(data, z))


def selftest() -> None:
    # RFC 6229, key 01 02 03 04 05, first 16 output bytes.
    key = bytes.fromhex("0102030405")
    expected = bytes.fromhex("b2396305f03dc027ccc3524a0a1118a8")
    got = rc4_keystream(key, 16)
    if got != expected:
        raise AssertionError(f"RC4 self-test failed: {got.hex()} != {expected.hex()}")


if __name__ == "__main__":
    selftest()
    print("RC4 RFC 6229 self-test: PASS")
