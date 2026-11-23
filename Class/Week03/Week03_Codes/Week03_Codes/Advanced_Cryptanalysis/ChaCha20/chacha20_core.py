#!/usr/bin/env python3
"""Minimal IETF ChaCha20 core plus reduced-round helpers for teaching labs."""
from __future__ import annotations
import struct

MASK32 = 0xFFFFFFFF
CONSTANT = b"expand 32-byte k"


def rotl32(x: int, n: int) -> int:
    return ((x << n) & MASK32) | (x >> (32 - n))


def quarter_round(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & MASK32
    s[d] ^= s[a]; s[d] = rotl32(s[d], 16)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] ^= s[c]; s[b] = rotl32(s[b], 12)
    s[a] = (s[a] + s[b]) & MASK32
    s[d] ^= s[a]; s[d] = rotl32(s[d], 8)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] ^= s[c]; s[b] = rotl32(s[b], 7)


def initial_state(key: bytes, counter: int, nonce: bytes) -> list[int]:
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("IETF ChaCha20 nonce must be 12 bytes")
    if not 0 <= counter <= 0xFFFFFFFF:
        raise ValueError("counter must fit 32 bits")
    return list(struct.unpack("<4I", CONSTANT)) + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))


def round_pair(state: list[int]) -> None:
    # Column round
    quarter_round(state, 0, 4, 8, 12)
    quarter_round(state, 1, 5, 9, 13)
    quarter_round(state, 2, 6, 10, 14)
    quarter_round(state, 3, 7, 11, 15)
    # Diagonal round
    quarter_round(state, 0, 5, 10, 15)
    quarter_round(state, 1, 6, 11, 12)
    quarter_round(state, 2, 7, 8, 13)
    quarter_round(state, 3, 4, 9, 14)


def reduced_state(key: bytes, counter: int, nonce: bytes, rounds: int) -> list[int]:
    """State after an even number of ChaCha rounds, before feed-forward."""
    if rounds < 0 or rounds % 2:
        raise ValueError("rounds must be a nonnegative even number")
    s = initial_state(key, counter, nonce)
    for _ in range(rounds // 2):
        round_pair(s)
    return s


def chacha_block(key: bytes, counter: int, nonce: bytes, rounds: int = 20) -> bytes:
    """ChaCha block with feed-forward; rounds may be reduced for lab experiments."""
    init = initial_state(key, counter, nonce)
    s = init.copy()
    if rounds < 0 or rounds % 2:
        raise ValueError("rounds must be a nonnegative even number")
    for _ in range(rounds // 2):
        round_pair(s)
    out = [((s[i] + init[i]) & MASK32) for i in range(16)]
    return struct.pack("<16I", *out)


def chacha_xor(key: bytes, nonce: bytes, counter: int, data: bytes, rounds: int = 20) -> bytes:
    out = bytearray()
    ctr = counter
    for off in range(0, len(data), 64):
        block = data[off:off+64]
        ks = chacha_block(key, ctr, nonce, rounds)
        out.extend(bytes(a ^ b for a, b in zip(block, ks)))
        ctr = (ctr + 1) & MASK32
    return bytes(out)


def state_to_bytes(state: list[int]) -> bytes:
    return struct.pack("<16I", *state)


def hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("inputs must have equal length")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def rfc8439_selftest() -> bool:
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    got = chacha_block(key, 1, nonce)
    exp = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    return got == exp

if __name__ == "__main__":
    print("RFC 8439 block test:", "PASS" if rfc8439_selftest() else "FAIL")
