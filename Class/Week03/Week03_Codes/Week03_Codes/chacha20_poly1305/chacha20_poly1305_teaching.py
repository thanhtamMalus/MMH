#!/usr/bin/env python3
"""
ChaCha20-Poly1305 Teaching Code — Week 3

Detailed, step-by-step implementation of the IETF ChaCha20-Poly1305 AEAD
construction in RFC 8439.  The program exposes:
  1) ChaCha20 state and ARX quarter round
  2) ChaCha20 block 0 -> Poly1305 one-time key
  3) ChaCha20 counter 1+ -> ciphertext
  4) Poly1305 r/s split and clamping
  5) AEAD MAC-input construction
  6) Poly1305 accumulation modulo 2^130-5
  7) Tag verification before decryption

Educational/demo use only.  For production use a vetted cryptographic library.
"""

from __future__ import annotations

import argparse
import base64
import hmac
import struct
from typing import Sequence

MASK32 = 0xFFFFFFFF
P1305 = (1 << 130) - 5
R_MASK = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)

# RFC 8439, Section 2.8.2 AEAD construction example
RFC_AEAD_KEY = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f"
)
RFC_AEAD_NONCE = bytes.fromhex("070000004041424344454647")
RFC_AEAD_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
RFC_AEAD_PLAINTEXT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
    b"for the future, sunscreen would be it."
)
RFC_AEAD_CIPHERTEXT = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "6116"
)
RFC_AEAD_TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

# RFC 8439, Section 2.5.2 raw Poly1305 example
RFC_POLY_KEY = bytes.fromhex(
    "85d6be7857556d337f4452fe42d506a8"
    "0103808afb0db2fd4abff6af4149f51b"
)
RFC_POLY_MSG = b"Cryptographic Forum Research Group"
RFC_POLY_TAG = bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")


def algorithm_overview() -> str:
    return r"""
CHACHA20-POLY1305 AEAD — ALGORITHM OVERVIEW (RFC 8439)
======================================================
Inputs
  K   : 256-bit key (32 bytes)
  N   : 96-bit nonce (12 bytes)
  P   : plaintext
  A   : optional Additional Authenticated Data (AAD)

Encryption
-----------
A. Derive the Poly1305 one-time key
     block0 = ChaCha20_Block(K, counter=0, N)
     otk    = block0[0:32]

B. Encrypt with ChaCha20 beginning at counter 1
     C = P XOR ChaCha20_Keystream(K, counter=1, N)

C. Build the exact Poly1305 input
     M = A || pad16(A)
         || C || pad16(C)
         || LE64(len(A)) || LE64(len(C))

D. Authenticate
     T = Poly1305(M, otk)                    # 16-byte tag

Output
     (C, T)

Decryption
----------
  1. Re-derive otk from ChaCha20 counter 0.
  2. Recompute T' over A and received C.
  3. Compare T' and T in constant time.
  4. Only if T' == T, decrypt C using counter 1+.

POLY1305 CORE
-------------
Split 32-byte one-time key into r || s, each 16 bytes.
Clamp r:
     r = LE128(r_bytes) & 0x0ffffffc0ffffffc0ffffffc0fffffff

For every message chunk m_i of at most 16 bytes:
     n_i = LE(m_i || 0x01)
     h   = ((h + n_i) * r) mod (2^130 - 5)

Final tag:
     tag = (h + s) mod 2^128

CRITICAL SECURITY RULES
-----------------------
* Counter 0 is reserved here for the Poly1305 one-time key.
* Payload encryption begins at counter 1.
* The (key, nonce) pair MUST be unique.
* Reusing a nonce repeats BOTH the ChaCha20 keystream and the Poly1305 one-time key.
* AAD is authenticated but not encrypted.
* A valid tag does not mean the plaintext is secret from an endpoint holding the key;
  it means ciphertext/AAD integrity and origin authentication under the shared key.
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


def inner_block(x: list[int]) -> None:
    # Column round
    quarter_round(x, 0, 4, 8, 12)
    quarter_round(x, 1, 5, 9, 13)
    quarter_round(x, 2, 6, 10, 14)
    quarter_round(x, 3, 7, 11, 15)
    # Diagonal round
    quarter_round(x, 0, 5, 10, 15)
    quarter_round(x, 1, 6, 11, 12)
    quarter_round(x, 2, 7, 8, 13)
    quarter_round(x, 3, 4, 9, 14)


def validate_key_nonce(key: bytes, nonce: bytes) -> None:
    if len(key) != 32:
        raise ValueError(f"key must be exactly 32 bytes; got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"nonce must be exactly 12 bytes; got {len(nonce)}")


def initial_state(key: bytes, counter: int, nonce: bytes) -> list[int]:
    validate_key_nonce(key, nonce)
    if not 0 <= counter <= MASK32:
        raise ValueError("counter must be in 0..2^32-1")
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
        print(f"\n[ChaCha20 block] counter={counter}")
        print_words(state, "Initial state:")

    for dr in range(1, 11):
        inner_block(working)
        if dr <= trace_double_rounds:
            print_words(working, f"\nAfter double-round {dr}:")

    if verbose >= 2:
        print_words(working, "\nAfter 20 rounds, before feed-forward:")

    final_words = [(working[i] + state[i]) & MASK32 for i in range(16)]
    if verbose:
        print_words(final_words, "\nAfter feed-forward:")

    block = struct.pack("<16I", *final_words)
    if verbose:
        print("Serialized 64 bytes:", block.hex())
    return block


def chacha20_xor(
    key: bytes,
    nonce: bytes,
    counter: int,
    data: bytes,
    *,
    verbose: int = 0,
    trace_double_rounds: int = 0,
) -> bytes:
    validate_key_nonce(key, nonce)
    blocks = (len(data) + 63) // 64
    if blocks and counter + blocks - 1 > MASK32:
        raise ValueError("message too long: 32-bit counter would wrap")

    out = bytearray()
    for j in range(blocks):
        if verbose:
            print(f"\n=== Payload block {j}; counter={counter+j} ===")
        z = chacha20_block(
            key,
            counter + j,
            nonce,
            verbose=verbose,
            trace_double_rounds=trace_double_rounds if j == 0 else 0,
        )
        chunk = data[64*j : 64*(j+1)]
        result = bytes(a ^ b for a, b in zip(chunk, z))
        if verbose:
            print("Input     :", chunk.hex())
            print("Keystream :", z[:len(chunk)].hex())
            print("Output    :", result.hex())
        out.extend(result)
    return bytes(out)


def clamp_r(r_bytes: bytes) -> int:
    if len(r_bytes) != 16:
        raise ValueError("r must be 16 bytes before clamping")
    return int.from_bytes(r_bytes, "little") & R_MASK


def poly1305_mac(
    message: bytes,
    one_time_key: bytes,
    *,
    verbose: int = 0,
    trace_blocks: int = 0,
) -> bytes:
    if len(one_time_key) != 32:
        raise ValueError("Poly1305 one-time key must be exactly 32 bytes")

    raw_r = int.from_bytes(one_time_key[:16], "little")
    r = raw_r & R_MASK
    s = int.from_bytes(one_time_key[16:], "little")
    h = 0

    if verbose:
        print("\n[Poly1305]")
        print("one-time key :", one_time_key.hex())
        print(f"r raw        : {raw_r:032x}")
        print(f"r clamped    : {r:032x}")
        print(f"s            : {s:032x}")
        print(f"p            : 2^130 - 5 = {P1305}")

    block_no = 0
    for offset in range(0, len(message), 16):
        block_no += 1
        block = message[offset : offset + 16]
        n = int.from_bytes(block + b"\x01", "little")
        before = h
        h = ((h + n) * r) % P1305
        if trace_blocks and block_no <= trace_blocks:
            print(f"\nPoly1305 block {block_no}")
            print("  bytes      :", block.hex())
            print(f"  n=m||01 LE : {n:x}")
            print(f"  h before   : {before:x}")
            print(f"  h after    : {h:x}")

    tag_int = (h + s) % (1 << 128)
    tag = tag_int.to_bytes(16, "little")
    if verbose:
        print(f"\nh final      : {h:x}")
        print(f"(h+s) mod 2^128: {tag_int:032x}")
        print("tag (LE bytes):", tag.hex())
    return tag


def pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return b"" if rem == 0 else b"\x00" * (16 - rem)


def poly1305_key_gen(
    key: bytes,
    nonce: bytes,
    *,
    verbose: int = 0,
    trace_double_rounds: int = 0,
) -> bytes:
    if verbose:
        print("\nSTEP 1 — derive Poly1305 one-time key using ChaCha20 counter 0")
    block0 = chacha20_block(
        key, 0, nonce, verbose=verbose, trace_double_rounds=trace_double_rounds
    )
    otk = block0[:32]
    if verbose:
        print("Poly1305 one-time key = first 32 bytes of block 0")
        print("OTK:", otk.hex())
    return otk


def aead_mac_data(aad: bytes, ciphertext: bytes, *, verbose: int = 0) -> bytes:
    aad_pad = pad16(aad)
    ct_pad = pad16(ciphertext)
    lengths = struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext))
    result = aad + aad_pad + ciphertext + ct_pad + lengths

    if verbose:
        print("\nSTEP 3 — construct Poly1305 AEAD input")
        print(f"AAD ({len(aad)} bytes)            : {aad.hex()}")
        print(f"pad16(AAD) ({len(aad_pad)} bytes)     : {aad_pad.hex() or '<empty>'}")
        print(f"Ciphertext ({len(ciphertext)} bytes)     : {ciphertext.hex()}")
        print(f"pad16(ciphertext) ({len(ct_pad)} bytes): {ct_pad.hex() or '<empty>'}")
        print("LE64(len(AAD))               :", struct.pack("<Q", len(aad)).hex())
        print("LE64(len(ciphertext))        :", struct.pack("<Q", len(ciphertext)).hex())
        print(f"Total MAC input ({len(result)} bytes) : {result.hex()}")
    return result


def chacha20_poly1305_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
    *,
    verbose: int = 0,
    trace_double_rounds: int = 0,
    trace_poly_blocks: int = 0,
) -> tuple[bytes, bytes]:
    validate_key_nonce(key, nonce)

    if verbose:
        print("\n" + "=" * 72)
        print("CHACHA20-POLY1305 ENCRYPTION")
        print("=" * 72)
        print("Key       :", key.hex())
        print("Nonce     :", nonce.hex())
        print("AAD       :", aad.hex())
        print("Plaintext :", plaintext.hex())

    otk = poly1305_key_gen(
        key, nonce, verbose=verbose, trace_double_rounds=trace_double_rounds
    )

    if verbose:
        print("\nSTEP 2 — encrypt payload with ChaCha20 starting at counter 1")
    ciphertext = chacha20_xor(
        key,
        nonce,
        1,
        plaintext,
        verbose=verbose,
        trace_double_rounds=trace_double_rounds,
    )

    mac_input = aead_mac_data(aad, ciphertext, verbose=verbose)

    if verbose:
        print("\nSTEP 4 — Poly1305 authentication")
    tag = poly1305_mac(
        mac_input,
        otk,
        verbose=verbose,
        trace_blocks=trace_poly_blocks,
    )

    if verbose:
        print("\nFINAL OUTPUT")
        print("Ciphertext:", ciphertext.hex())
        print("Tag       :", tag.hex())
    return ciphertext, tag


def chacha20_poly1305_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
    *,
    verbose: int = 0,
    trace_double_rounds: int = 0,
    trace_poly_blocks: int = 0,
) -> bytes:
    validate_key_nonce(key, nonce)
    if len(tag) != 16:
        raise ValueError("authentication tag must be exactly 16 bytes")

    if verbose:
        print("\n" + "=" * 72)
        print("CHACHA20-POLY1305 DECRYPTION")
        print("=" * 72)
        print("IMPORTANT: authenticate first; decrypt only if the tag is valid.")

    otk = poly1305_key_gen(
        key, nonce, verbose=verbose, trace_double_rounds=trace_double_rounds
    )
    mac_input = aead_mac_data(aad, ciphertext, verbose=verbose)
    expected = poly1305_mac(
        mac_input,
        otk,
        verbose=verbose,
        trace_blocks=trace_poly_blocks,
    )

    if verbose:
        print("\nSTEP 4 — constant-time tag verification")
        print("Received :", tag.hex())
        print("Expected :", expected.hex())

    if not hmac.compare_digest(expected, tag):
        if verbose:
            print("Authentication: FAIL — plaintext is NOT released")
        raise ValueError("authentication failed")

    if verbose:
        print("Authentication: PASS")
        print("\nSTEP 5 — decrypt ciphertext using ChaCha20 counter 1+")

    plaintext = chacha20_xor(
        key,
        nonce,
        1,
        ciphertext,
        verbose=verbose,
        trace_double_rounds=trace_double_rounds,
    )
    if verbose:
        print("Plaintext:", plaintext.hex())
    return plaintext


def selftest(verbose: bool = True) -> bool:
    tests: list[tuple[str, bool]] = []

    # Raw Poly1305 vector
    poly = poly1305_mac(RFC_POLY_MSG, RFC_POLY_KEY)
    tests.append(("RFC 8439 Poly1305", poly == RFC_POLY_TAG))

    # Complete AEAD vector
    ct, tag = chacha20_poly1305_encrypt(
        RFC_AEAD_KEY, RFC_AEAD_NONCE, RFC_AEAD_PLAINTEXT, RFC_AEAD_AAD
    )
    tests.append(("RFC 8439 AEAD ciphertext", ct == RFC_AEAD_CIPHERTEXT))
    tests.append(("RFC 8439 AEAD tag", tag == RFC_AEAD_TAG))

    pt = chacha20_poly1305_decrypt(
        RFC_AEAD_KEY, RFC_AEAD_NONCE, RFC_AEAD_CIPHERTEXT, RFC_AEAD_TAG, RFC_AEAD_AAD
    )
    tests.append(("RFC 8439 AEAD decryption", pt == RFC_AEAD_PLAINTEXT))

    # Negative integrity test
    modified = bytearray(RFC_AEAD_CIPHERTEXT)
    modified[0] ^= 1
    rejected = False
    try:
        chacha20_poly1305_decrypt(
            RFC_AEAD_KEY, RFC_AEAD_NONCE, bytes(modified), RFC_AEAD_TAG, RFC_AEAD_AAD
        )
    except ValueError:
        rejected = True
    tests.append(("Modified ciphertext rejected", rejected))

    if verbose:
        print("RFC 8439 SELF-TESTS")
        print("=" * 48)
        for name, ok in tests:
            print(f"{name:34s}: {'PASS' if ok else 'FAIL'}")
    return all(ok for _, ok in tests)


def add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--key", required=True, help="32-byte key in hex")
    p.add_argument("--nonce", required=True, help="12-byte nonce in hex")
    p.add_argument("--aad", default="", help="AAD value [default: empty]")
    p.add_argument("--aad-format", choices=["text", "hex", "base64"], default="text")
    p.add_argument("--verbose", type=int, choices=[0, 1, 2], default=1)
    p.add_argument("--trace-double-rounds", type=int, choices=range(0, 11), default=0, metavar="N")
    p.add_argument("--trace-poly-blocks", type=int, default=0, metavar="N",
                   help="show first N Poly1305 accumulator blocks")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Step-by-step ChaCha20-Poly1305 AEAD teaching implementation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python chacha20_poly1305_teaching.py overview
  python chacha20_poly1305_teaching.py selftest
  python chacha20_poly1305_teaching.py rfc-demo --verbose 1 --trace-poly-blocks 2

  python chacha20_poly1305_teaching.py encrypt \\
    --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \\
    --nonce 000000000000000000000002 \\
    --aad "header" --aad-format text \\
    --input "Hello AEAD" --input-format text
""",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("overview", help="print algorithm overview")
    sub.add_parser("selftest", help="run RFC 8439 self-tests")

    p_demo = sub.add_parser("rfc-demo", help="trace the complete RFC 8439 AEAD example")
    p_demo.add_argument("--verbose", type=int, choices=[1, 2], default=1)
    p_demo.add_argument("--trace-double-rounds", type=int, choices=range(0, 11), default=0, metavar="N")
    p_demo.add_argument("--trace-poly-blocks", type=int, default=3, metavar="N")

    p_poly = sub.add_parser("poly1305-test", help="trace the raw RFC 8439 Poly1305 vector")
    p_poly.add_argument("--trace-blocks", type=int, default=3)

    p_enc = sub.add_parser("encrypt", help="encrypt and authenticate")
    add_common_args(p_enc)
    p_enc.add_argument("--input", required=True)
    p_enc.add_argument("--input-format", choices=["text", "hex", "base64"], default="text")
    p_enc.add_argument("--output-format", choices=["hex", "base64"], default="hex")

    p_dec = sub.add_parser("decrypt", help="authenticate then decrypt")
    add_common_args(p_dec)
    p_dec.add_argument("--input", required=True, help="ciphertext")
    p_dec.add_argument("--input-format", choices=["hex", "base64"], default="hex")
    p_dec.add_argument("--tag", required=True, help="16-byte tag in hex")
    p_dec.add_argument("--output-format", choices=["text", "hex", "base64"], default="text")
    return parser


def parse_common(args: argparse.Namespace) -> tuple[bytes, bytes, bytes]:
    key = parse_hex(args.key)
    nonce = parse_hex(args.nonce)
    aad = decode_value(args.aad, args.aad_format)
    validate_key_nonce(key, nonce)
    return key, nonce, aad


def main() -> int:
    args = build_parser().parse_args()

    if args.command == "overview":
        print(algorithm_overview())
        return 0
    if args.command == "selftest":
        return 0 if selftest() else 1
    if args.command == "poly1305-test":
        print("RFC 8439 raw Poly1305 test")
        print("Message:", RFC_POLY_MSG)
        actual = poly1305_mac(
            RFC_POLY_MSG, RFC_POLY_KEY, verbose=1, trace_blocks=args.trace_blocks
        )
        print("Expected:", RFC_POLY_TAG.hex())
        print("Actual  :", actual.hex())
        print("PASS" if actual == RFC_POLY_TAG else "FAIL")
        return 0 if actual == RFC_POLY_TAG else 1
    if args.command == "rfc-demo":
        ct, tag = chacha20_poly1305_encrypt(
            RFC_AEAD_KEY,
            RFC_AEAD_NONCE,
            RFC_AEAD_PLAINTEXT,
            RFC_AEAD_AAD,
            verbose=args.verbose,
            trace_double_rounds=args.trace_double_rounds,
            trace_poly_blocks=args.trace_poly_blocks,
        )
        print("\nRFC EXPECTED CIPHERTEXT:", RFC_AEAD_CIPHERTEXT.hex())
        print("RFC ACTUAL CIPHERTEXT  :", ct.hex())
        print("RFC EXPECTED TAG       :", RFC_AEAD_TAG.hex())
        print("RFC ACTUAL TAG         :", tag.hex())
        ok = ct == RFC_AEAD_CIPHERTEXT and tag == RFC_AEAD_TAG
        print("PASS" if ok else "FAIL")
        return 0 if ok else 1

    key, nonce, aad = parse_common(args)

    if args.command == "encrypt":
        pt = decode_value(args.input, args.input_format)
        ct, tag = chacha20_poly1305_encrypt(
            key,
            nonce,
            pt,
            aad,
            verbose=args.verbose,
            trace_double_rounds=args.trace_double_rounds,
            trace_poly_blocks=args.trace_poly_blocks,
        )
        print("\nCiphertext:", encode_value(ct, args.output_format))
        print("Tag (hex) :", tag.hex())
        print("Combined  :", (ct + tag).hex())
        return 0

    if args.command == "decrypt":
        ct = decode_value(args.input, args.input_format)
        tag = parse_hex(args.tag)
        try:
            pt = chacha20_poly1305_decrypt(
                key,
                nonce,
                ct,
                tag,
                aad,
                verbose=args.verbose,
                trace_double_rounds=args.trace_double_rounds,
                trace_poly_blocks=args.trace_poly_blocks,
            )
        except ValueError as exc:
            print(f"ERROR: {exc}")
            return 2
        print("\nPlaintext:", encode_value(pt, args.output_format))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
