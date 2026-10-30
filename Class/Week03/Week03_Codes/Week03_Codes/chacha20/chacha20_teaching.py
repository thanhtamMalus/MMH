#!/usr/bin/env python3
"""
ChaCha20 Teaching Code — Week 3: Stream Ciphers and Cryptanalysis

This version exposes IETF ChaCha20 (RFC 8439) step by step:
  1) State construction
  2) Quarter round (ARX: Add, Rotate, XOR)
  3) Column + diagonal rounds
  4) 10 double-rounds = 20 rounds
  5) Feed-forward addition of the original state
  6) Little-endian serialization to a 64-byte keystream block
  7) XOR encryption/decryption and block-counter progression

ChaCha20 ONLY — no Poly1305.
Educational/demo use only.
"""

from __future__ import annotations

import argparse
import base64
import struct
from typing import Sequence

MASK32 = 0xFFFFFFFF
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)

RFC_KEY = bytes(range(32))
RFC_BLOCK_NONCE = bytes.fromhex("000000090000004a00000000")
RFC_BLOCK_COUNTER = 1
RFC_BLOCK_EXPECTED = bytes.fromhex(
    "10f1e7e4d13b5915500fdd1fa32071c4"
    "c7d1f4c733c068030422aa9ac3d46c4e"
    "d2826446079faa0914c2d705d98b02a2"
    "b5129cd1de164eb9cbd083e8a2503c4e"
)
RFC_ENC_NONCE = bytes.fromhex("000000000000004a00000000")
RFC_ENC_COUNTER = 1
RFC_PLAINTEXT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
    b"for the future, sunscreen would be it."
)
RFC_CIPHERTEXT = bytes.fromhex(
    "6e2e359a2568f98041ba0728dd0d6981"
    "e97e7aec1d4360c20a27afccfd9fae0b"
    "f91b65c5524733ab8f593dabcd62b357"
    "1639d624e65152ab8f530c359f0861d8"
    "07ca0dbf500d6a6156a38e088a22b65e"
    "52bc514d16ccf806818ce91ab7793736"
    "5af90bbf74a35be6b40b8eedf2785e42"
    "874d"
)


def algorithm_overview() -> str:
    return r"""
CHACHA20 ALGORITHM OVERVIEW — IETF VARIANT (RFC 8439)
=====================================================
Inputs:
  K       : 256-bit key (32 bytes)
  N       : 96-bit nonce (12 bytes)
  counter : 32-bit initial block counter
  data    : arbitrary-length plaintext/ciphertext

State: 16 little-endian 32-bit words

   0: constant   1: constant   2: constant   3: constant
   4: key[0]     5: key[1]     6: key[2]     7: key[3]
   8: key[4]     9: key[5]    10: key[6]    11: key[7]
  12: counter   13: nonce[0]  14: nonce[1]  15: nonce[2]

Quarter round QR(a,b,c,d) — ARX operations, modulo 2^32:
  a += b; d ^= a; d = ROTL(d,16)
  c += d; b ^= c; b = ROTL(b,12)
  a += b; d ^= a; d = ROTL(d, 8)
  c += d; b ^= c; b = ROTL(b, 7)

One double-round = one column round + one diagonal round:
  Columns : QR(0,4,8,12), QR(1,5,9,13), QR(2,6,10,14), QR(3,7,11,15)
  Diagonal: QR(0,5,10,15), QR(1,6,11,12), QR(2,7,8,13), QR(3,4,9,14)

ChaCha20 block function:
  initial <- state
  working <- initial
  repeat 10 times: inner_block(working)     # 20 rounds total
  output_words[i] <- working[i] + initial[i] mod 2^32
  serialize output_words little-endian      # 64-byte keystream block

Stream encryption/decryption:
  Z_j = ChaCha20_block(K, counter+j, N)
  C_j = P_j XOR Z_j
  P_j = C_j XOR Z_j

Important correctness points:
  * The feed-forward addition of the INITIAL state is mandatory.
  * Serialization is LITTLE-ENDIAN word-by-word.
  * The nonce stays fixed for a message; the block counter increments per 64 bytes.
  * Stand-alone ChaCha20 does NOT reserve counter 0. The initial counter is explicit
    and can normally be 0 or 1. This package defaults to 1 only for convenience.
  * Never repeat a nonce with the same key.
  * ChaCha20 alone is unauthenticated: ciphertext modification is not detected.
""".strip()


def parse_hex(text: str) -> bytes:
    cleaned = "".join(text.split()).replace(":", "").replace("-", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) % 2:
        raise ValueError("hex input must contain an even number of digits")
    return bytes.fromhex(cleaned)


def decode_value(text: str, fmt: str) -> bytes:
    if fmt == "text":
        return text.encode("utf-8")
    if fmt == "hex":
        return parse_hex(text)
    if fmt == "base64":
        return base64.b64decode(text, validate=True)
    raise ValueError(f"unsupported format: {fmt}")


def encode_value(data: bytes, fmt: str) -> str:
    if fmt == "hex":
        return data.hex()
    if fmt == "base64":
        return base64.b64encode(data).decode("ascii")
    if fmt == "text":
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return "<not valid UTF-8; use hex/base64>"
    raise ValueError(f"unsupported format: {fmt}")


def rotl32(x: int, n: int) -> int:
    x &= MASK32
    return ((x << n) & MASK32) | (x >> (32 - n))


def print_words(words: Sequence[int], title: str | None = None) -> None:
    if title:
        print(title)
    for r in range(4):
        print("  " + "  ".join(f"{words[4*r+c]:08x}" for c in range(4)))


def quarter_round(x: list[int], a: int, b: int, c: int, d: int) -> None:
    x[a] = (x[a] + x[b]) & MASK32
    x[d] = rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & MASK32
    x[b] = rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & MASK32
    x[d] = rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & MASK32
    x[b] = rotl32(x[b] ^ x[c], 7)


def quarter_round_trace(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    print("\nQUARTER ROUND TRACE")
    print(f"start: a={a:08x} b={b:08x} c={c:08x} d={d:08x}")

    a = (a + b) & MASK32
    print(f"1a  a = a+b mod 2^32          -> {a:08x}")
    d = d ^ a
    print(f"1b  d = d XOR a               -> {d:08x}")
    d = rotl32(d, 16)
    print(f"1c  d = ROTL(d,16)            -> {d:08x}")

    c = (c + d) & MASK32
    print(f"2a  c = c+d mod 2^32          -> {c:08x}")
    b = b ^ c
    print(f"2b  b = b XOR c               -> {b:08x}")
    b = rotl32(b, 12)
    print(f"2c  b = ROTL(b,12)            -> {b:08x}")

    a = (a + b) & MASK32
    print(f"3a  a = a+b mod 2^32          -> {a:08x}")
    d = d ^ a
    print(f"3b  d = d XOR a               -> {d:08x}")
    d = rotl32(d, 8)
    print(f"3c  d = ROTL(d,8)             -> {d:08x}")

    c = (c + d) & MASK32
    print(f"4a  c = c+d mod 2^32          -> {c:08x}")
    b = b ^ c
    print(f"4b  b = b XOR c               -> {b:08x}")
    b = rotl32(b, 7)
    print(f"4c  b = ROTL(b,7)             -> {b:08x}")
    print(f"end  : a={a:08x} b={b:08x} c={c:08x} d={d:08x}")
    return a, b, c, d


def inner_block(x: list[int]) -> None:
    quarter_round(x, 0, 4, 8, 12)
    quarter_round(x, 1, 5, 9, 13)
    quarter_round(x, 2, 6, 10, 14)
    quarter_round(x, 3, 7, 11, 15)
    quarter_round(x, 0, 5, 10, 15)
    quarter_round(x, 1, 6, 11, 12)
    quarter_round(x, 2, 7, 8, 13)
    quarter_round(x, 3, 4, 9, 14)


def validate_inputs(key: bytes, nonce: bytes, counter: int) -> None:
    if len(key) != 32:
        raise ValueError(f"key must be exactly 32 bytes; got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"nonce must be exactly 12 bytes; got {len(nonce)}")
    if not 0 <= counter <= MASK32:
        raise ValueError("counter must be in 0..2^32-1")


def initial_state(key: bytes, counter: int, nonce: bytes) -> list[int]:
    validate_inputs(key, nonce, counter)
    return [*CONSTANTS, *struct.unpack("<8I", key), counter, *struct.unpack("<3I", nonce)]


def chacha20_block(
    key: bytes,
    counter: int,
    nonce: bytes,
    *,
    verbose: int = 0,
    trace_double_rounds: int = 0,
) -> bytes:
    state = initial_state(key, counter, nonce)
    working = state.copy()

    if verbose:
        print("\n[Block function]")
        print(f"counter = {counter} (0x{counter:08x})")
        print_words(state, "Initial 4x4 state (32-bit words):")
        if verbose >= 2:
            print("\nState components:")
            print("  words  0..3 : constants 'expand 32-byte k'")
            print("  words  4..11: 256-bit key read little-endian")
            print("  word      12: 32-bit block counter")
            print("  words 13..15: 96-bit nonce read little-endian")

    for dr in range(1, 11):
        inner_block(working)
        if dr <= trace_double_rounds:
            print_words(working, f"\nAfter double-round {dr} (rounds {2*dr-1} and {2*dr}):")

    if verbose >= 2:
        print_words(working, "\nState after 20 rounds, BEFORE feed-forward:")

    final_words = [(working[i] + state[i]) & MASK32 for i in range(16)]
    if verbose:
        print_words(final_words, "\nAfter feed-forward: working + initial mod 2^32:")

    block = struct.pack("<16I", *final_words)
    if verbose:
        print("\nSerialized 64-byte block (little-endian):")
        print("  " + block.hex(" "))
    return block


def chacha20_keystream(
    key: bytes,
    nonce: bytes,
    counter: int,
    n: int,
    *,
    verbose: int = 0,
    trace_double_rounds: int = 0,
) -> bytes:
    validate_inputs(key, nonce, counter)
    if n < 0:
        raise ValueError("length must be non-negative")
    blocks = (n + 63) // 64
    if blocks and counter + blocks - 1 > MASK32:
        raise ValueError("data length causes 32-bit counter wrap")

    out = bytearray()
    for j in range(blocks):
        c = counter + j
        if verbose:
            print(f"\n=== Keystream block {j}: counter={c} ===")
        out.extend(
            chacha20_block(
                key,
                c,
                nonce,
                verbose=verbose,
                trace_double_rounds=trace_double_rounds if j == 0 else 0,
            )
        )
    return bytes(out[:n])


def chacha20_crypt(
    key: bytes,
    nonce: bytes,
    counter: int,
    data: bytes,
    *,
    verbose: int = 0,
    trace_double_rounds: int = 0,
) -> bytes:
    z = chacha20_keystream(
        key, nonce, counter, len(data), verbose=verbose, trace_double_rounds=trace_double_rounds
    )
    if verbose:
        print("\n[XOR stage]")
        print(f"Data      : {data.hex()}")
        print(f"Keystream : {z.hex()}")
    result = bytes(a ^ b for a, b in zip(data, z))
    if verbose:
        print(f"Result    : {result.hex()}")
    return result


def selftest(verbose: bool = True) -> bool:
    tests: list[tuple[str, bool]] = []

    qr_actual = quarter_round_values(0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567)
    qr_expected = (0xEA2A92F4, 0xCB1CF8CE, 0x4581472E, 0x5881C4BB)
    tests.append(("RFC 8439 quarter-round", qr_actual == qr_expected))

    block_actual = chacha20_block(RFC_KEY, RFC_BLOCK_COUNTER, RFC_BLOCK_NONCE)
    tests.append(("RFC 8439 block function", block_actual == RFC_BLOCK_EXPECTED))

    enc_actual = chacha20_crypt(RFC_KEY, RFC_ENC_NONCE, RFC_ENC_COUNTER, RFC_PLAINTEXT)
    tests.append(("RFC 8439 encryption", enc_actual == RFC_CIPHERTEXT))

    dec_actual = chacha20_crypt(RFC_KEY, RFC_ENC_NONCE, RFC_ENC_COUNTER, RFC_CIPHERTEXT)
    tests.append(("RFC 8439 decryption", dec_actual == RFC_PLAINTEXT))

    if verbose:
        print("RFC 8439 SELF-TESTS")
        print("=" * 40)
        for name, ok in tests:
            print(f"{name:28s}: {'PASS' if ok else 'FAIL'}")
    return all(ok for _, ok in tests)


def quarter_round_values(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    x = [a, b, c, d]
    quarter_round(x, 0, 1, 2, 3)
    return tuple(x)  # type: ignore[return-value]


def add_crypto_args(p: argparse.ArgumentParser, *, payload: bool = True) -> None:
    p.add_argument("--key", required=True, help="32-byte key in hex")
    p.add_argument("--nonce", required=True, help="12-byte nonce in hex")
    p.add_argument("--counter", type=lambda s: int(s, 0), default=1,
                   help="initial 32-bit block counter, decimal or 0x... [default: 1]")
    if payload:
        p.add_argument("--input", required=True, help="input data")
        p.add_argument("--input-format", choices=["text", "hex", "base64"], default="text")
        p.add_argument("--output-format", choices=["text", "hex", "base64"], default="hex")
    p.add_argument("--verbose", type=int, choices=[0, 1, 2], default=1,
                   help="0=quiet, 1=state/block overview, 2=include pre-feed-forward state")
    p.add_argument("--trace-double-rounds", type=int, choices=range(0, 11), default=0,
                   metavar="N", help="print first N double-round states (0..10)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Step-by-step IETF ChaCha20 teaching implementation — no Poly1305.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python chacha20_teaching.py overview
  python chacha20_teaching.py selftest
  python chacha20_teaching.py quarter-test --trace

  python chacha20_teaching.py block \\
    --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \\
    --nonce 000000090000004a00000000 --counter 1 --verbose 2 --trace-double-rounds 1

  python chacha20_teaching.py encrypt \\
    --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \\
    --nonce 000000000000004a00000000 --counter 1 \\
    --input "Hello ChaCha20" --input-format text --output-format hex
""",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("overview", help="print algorithm overview")
    sub.add_parser("selftest", help="run RFC 8439 self-tests")

    p_qr = sub.add_parser("quarter-test", help="show/check the RFC quarter-round vector")
    p_qr.add_argument("--trace", action="store_true", help="print every primitive ARX step")

    p_block = sub.add_parser("block", help="generate one 64-byte ChaCha20 block")
    add_crypto_args(p_block, payload=False)

    p_enc = sub.add_parser("encrypt", help="encrypt data")
    add_crypto_args(p_enc, payload=True)
    p_enc.set_defaults(default_in="text", default_out="hex")

    p_dec = sub.add_parser("decrypt", help="decrypt data")
    add_crypto_args(p_dec, payload=True)
    p_dec.set_defaults(default_in="hex", default_out="text")

    p_ks = sub.add_parser("keystream", help="generate N keystream bytes")
    add_crypto_args(p_ks, payload=False)
    p_ks.add_argument("--n", type=int, required=True)
    p_ks.add_argument("--output-format", choices=["hex", "base64"], default="hex")
    return parser


def parse_key_nonce(args: argparse.Namespace) -> tuple[bytes, bytes]:
    key = parse_hex(args.key)
    nonce = parse_hex(args.nonce)
    validate_inputs(key, nonce, args.counter)
    return key, nonce


def main() -> int:
    args = build_parser().parse_args()

    if args.command == "overview":
        print(algorithm_overview())
        return 0
    if args.command == "selftest":
        return 0 if selftest() else 1
    if args.command == "quarter-test":
        initial = (0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567)
        expected = (0xEA2A92F4, 0xCB1CF8CE, 0x4581472E, 0x5881C4BB)
        actual = quarter_round_trace(*initial) if args.trace else quarter_round_values(*initial)
        print("\nExpected:", " ".join(f"{v:08x}" for v in expected))
        print("Actual  :", " ".join(f"{v:08x}" for v in actual))
        print("PASS" if actual == expected else "FAIL")
        return 0 if actual == expected else 1

    key, nonce = parse_key_nonce(args)

    if args.command == "block":
        out = chacha20_block(
            key, args.counter, nonce,
            verbose=args.verbose,
            trace_double_rounds=args.trace_double_rounds,
        )
        print("\nBlock (hex):", out.hex())
        return 0

    if args.command == "keystream":
        out = chacha20_keystream(
            key, nonce, args.counter, args.n,
            verbose=args.verbose,
            trace_double_rounds=args.trace_double_rounds,
        )
        print("\nKeystream:", encode_value(out, args.output_format))
        return 0

    data = decode_value(args.input, args.input_format)
    out = chacha20_crypt(
        key, nonce, args.counter, data,
        verbose=args.verbose,
        trace_double_rounds=args.trace_double_rounds,
    )
    print("\nOutput:", encode_value(out, args.output_format))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
