#!/usr/bin/env python3
"""
RC4 Teaching Code — Week 3: Stream Ciphers and Cryptanalysis

This version exposes the algorithm step by step:
    1) KSA: Key Scheduling Algorithm
    2) PRGA: Pseudo-Random Generation Algorithm
    3) XOR encryption/decryption

It also includes the RFC 6229 40-bit test vector used in the Week 3 slides.

Educational use only. RC4 is obsolete and must not be used for real security.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from typing import Iterable


RFC6229_KEY = bytes.fromhex("0102030405")
RFC6229_FIRST16 = bytes.fromhex("b2396305f03dc027ccc3524a0a1118a8")


@dataclass
class KSAStep:
    i: int
    j_before: int
    s_i_before: int
    key_index: int
    key_byte: int
    j_after: int
    s_i_after: int
    s_j_after: int


@dataclass
class PRGAStep:
    number: int
    i: int
    j: int
    s_i: int
    s_j: int
    t: int
    z: int


def algorithm_overview() -> str:
    return r"""
RC4 ALGORITHM OVERVIEW
======================
State:
  S is a permutation of {0,1,...,255}.
  i and j are byte-sized indices; arithmetic is modulo 256.
  K[0..L-1] is a non-empty byte key.

Phase 1 — KSA (no keystream bytes are output):
  S <- [0,1,...,255]
  j <- 0
  for i = 0..255:
      j <- (j + S[i] + K[i mod L]) mod 256
      swap S[i], S[j]

Phase 2 — PRGA (one keystream byte Z per iteration):
  i <- 0; j <- 0
  repeat:
      i <- (i + 1) mod 256
      j <- (j + S[i]) mod 256
      swap S[i], S[j]
      t <- (S[i] + S[j]) mod 256
      Z <- S[t]

Encryption / decryption:
  C = P XOR Z
  P = C XOR Z

Important:
  * KSA constructs the key-dependent permutation; it does NOT output data.
  * PRGA MUTATES S after every byte.
  * RC4 has no built-in nonce and no authentication.
  * RC4 is obsolete; this code is for algorithm/cryptanalysis teaching only.
""".strip()


def state_preview(s: list[int], width: int = 16) -> str:
    head = " ".join(f"{x:02x}" for x in s[:width])
    return f"S[0:{width}] = {head}"


def parse_hex(text: str) -> bytes:
    cleaned = "".join(text.split()).replace(":", "").replace("-", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) % 2:
        raise ValueError("hex input must have an even number of digits")
    return bytes.fromhex(cleaned)


def parse_value(text: str, is_hex: bool) -> bytes:
    return parse_hex(text) if is_hex else text.encode("utf-8")


def rc4_ksa(
    key: bytes,
    *,
    verbose: int = 0,
    ksa_steps: int = 0,
    dump_s_every: int = 0,
) -> list[int]:
    if not key:
        raise ValueError("key must not be empty")
    if len(key) > 256:
        raise ValueError("use a key of 1..256 bytes for this teaching implementation")

    s = list(range(256))
    j = 0

    if verbose:
        print("\n[KSA] Initialize S as the identity permutation; j = 0")
        print(state_preview(s))
        print(f"Key length L = {len(key)} byte(s)")
        print(f"Key bytes      = {key.hex(' ')}")

    for i in range(256):
        j_before = j
        s_i_before = s[i]
        key_index = i % len(key)
        key_byte = key[key_index]
        j = (j + s[i] + key_byte) % 256
        s[i], s[j] = s[j], s[i]

        if verbose >= 2 and i < ksa_steps:
            print(
                f"KSA {i:3d}: j = ({j_before:3d} + {s_i_before:3d} + "
                f"K[{key_index}]={key_byte:3d}) mod 256 = {j:3d}; "
                f"swap S[{i}] <-> S[{j}]"
            )
            if verbose >= 3:
                print("          " + state_preview(s))

        if dump_s_every and (i + 1) % dump_s_every == 0:
            print(f"[KSA snapshot after {i + 1:3d} iterations] {state_preview(s)}")

    if verbose:
        print("[KSA] Complete: S is now a key-dependent permutation.")
        print(state_preview(s))
    return s


def rc4_prga(
    s: list[int],
    n: int,
    *,
    verbose: int = 0,
    detail_bytes: int = 0,
    start_number: int = 1,
) -> bytes:
    if n < 0:
        raise ValueError("n must be non-negative")

    i = j = 0
    out = bytearray()

    if verbose:
        print("\n[PRGA] Initialize i = 0, j = 0 and use the KSA output state.")

    for number in range(1, n + 1):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        t = (s[i] + s[j]) % 256
        z = s[t]
        out.append(z)

        if verbose >= 2 and number <= detail_bytes:
            print(
                f"PRGA {start_number + number - 1:3d}: i={i:3d}, j={j:3d}, "
                f"swap -> S[i]={s[i]:3d}, S[j]={s[j]:3d}; "
                f"t=({s[i]}+{s[j]}) mod 256={t:3d}; Z=S[t]={z:3d} (0x{z:02x})"
            )
            if verbose >= 3:
                print("           " + state_preview(s))

    return bytes(out)


def rc4_keystream(
    key: bytes,
    n: int,
    *,
    drop_n: int = 0,
    verbose: int = 0,
    ksa_steps: int = 0,
    dump_s_every: int = 0,
    prga_bytes: int = 0,
) -> bytes:
    if drop_n < 0:
        raise ValueError("drop_n must be non-negative")

    s = rc4_ksa(
        key,
        verbose=verbose,
        ksa_steps=ksa_steps,
        dump_s_every=dump_s_every,
    )

    total = drop_n + n
    stream = rc4_prga(
        s,
        total,
        verbose=verbose,
        detail_bytes=min(prga_bytes, total),
    )

    if drop_n and verbose:
        print(f"\n[drop-N] Discarded the first {drop_n} generated byte(s).")
    return stream[drop_n:]


def rc4_crypt(key: bytes, data: bytes, **kwargs) -> tuple[bytes, bytes]:
    z = rc4_keystream(key, len(data), **kwargs)
    out = bytes(x ^ y for x, y in zip(data, z))
    return out, z


def selftest(verbose: bool = True) -> bool:
    actual = rc4_keystream(RFC6229_KEY, 16)
    ok = actual == RFC6229_FIRST16
    if verbose:
        print("RFC 6229 RC4 self-test")
        print(f"Key      : {RFC6229_KEY.hex(' ')}")
        print(f"Expected : {RFC6229_FIRST16.hex(' ')}")
        print(f"Actual   : {actual.hex(' ')}")
        print(f"Result   : {'PASS' if ok else 'FAIL'}")
    return ok


def add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--key", required=True, help="key as UTF-8 text; with --hex, key is hex")
    parser.add_argument("--hex", action="store_true", help="interpret key and payload as hexadecimal bytes")
    parser.add_argument("--verbose", type=int, choices=[0, 1, 2, 3], default=0,
                        help="0=quiet, 1=phase overview, 2=steps, 3=steps+state previews")
    parser.add_argument("--ksa-steps", type=int, default=8,
                        help="number of early KSA iterations to print at verbose >= 2")
    parser.add_argument("--dump-s-every", type=int, default=0,
                        help="dump S preview every N KSA iterations; 0 disables")
    parser.add_argument("--prga-bytes", type=int, default=8,
                        help="number of early PRGA bytes to explain at verbose >= 2")
    parser.add_argument("--drop-n", type=int, default=0,
                        help="historical RC4-dropN experiment: discard first N bytes")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Step-by-step RC4 teaching implementation (educational use only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples used by the Week 3 slides:
  python rc4_teaching.py overview
  python rc4_teaching.py selftest

  python rc4_teaching.py encrypt \\
      --key 736563726574 --pt 48656c6c6f --hex \\
      --verbose 3 --ksa-steps 8 --dump-s-every 64

  python rc4_teaching.py keystream \\
      --key secret --n 20 --verbose 2 \\
      --prga-bytes 10 --drop-n 256
""",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("overview", help="print the RC4 algorithm overview")
    sub.add_parser("selftest", help="run the RFC 6229 validation vector")

    p_ksa = sub.add_parser("ksa", help="run KSA and inspect the resulting state")
    add_common_options(p_ksa)

    p_ks = sub.add_parser("keystream", help="generate and inspect RC4 keystream bytes")
    add_common_options(p_ks)
    p_ks.add_argument("--n", type=int, required=True, help="number of bytes to return after drop-N")

    p_enc = sub.add_parser("encrypt", help="encrypt plaintext")
    add_common_options(p_enc)
    p_enc.add_argument("--pt", required=True, help="plaintext; UTF-8 by default, hex with --hex")

    p_dec = sub.add_parser("decrypt", help="decrypt ciphertext")
    add_common_options(p_dec)
    p_dec.add_argument("--ct", required=True, help="ciphertext; UTF-8 by default, hex with --hex")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "overview":
        print(algorithm_overview())
        return

    if args.command == "selftest":
        raise SystemExit(0 if selftest() else 1)

    key = parse_value(args.key, args.hex)

    if args.command == "ksa":
        s = rc4_ksa(
            key,
            verbose=args.verbose,
            ksa_steps=args.ksa_steps,
            dump_s_every=args.dump_s_every,
        )
        print("\nFinal KSA state (all 256 bytes, hex):")
        print(" ".join(f"{x:02x}" for x in s))
        return

    kwargs = dict(
        drop_n=args.drop_n,
        verbose=args.verbose,
        ksa_steps=args.ksa_steps,
        dump_s_every=args.dump_s_every,
        prga_bytes=args.prga_bytes,
    )

    if args.command == "keystream":
        z = rc4_keystream(key, args.n, **kwargs)
        print(f"\nReturned keystream ({len(z)} bytes): {z.hex(' ')}")
        return

    if args.command == "encrypt":
        pt = parse_value(args.pt, args.hex)
        ct, z = rc4_crypt(key, pt, **kwargs)
        print("\n[XOR] C = P XOR Z")
        print(f"P : {pt.hex(' ')}")
        print(f"Z : {z.hex(' ')}")
        print(f"C : {ct.hex(' ')}")
        print(f"C (Base64): {base64.b64encode(ct).decode('ascii')}")
        return

    if args.command == "decrypt":
        ct = parse_value(args.ct, args.hex)
        pt, z = rc4_crypt(key, ct, **kwargs)
        print("\n[XOR] P = C XOR Z")
        print(f"C : {ct.hex(' ')}")
        print(f"Z : {z.hex(' ')}")
        print(f"P : {pt.hex(' ')}")
        try:
            print(f"P (UTF-8): {pt.decode('utf-8')}")
        except UnicodeDecodeError:
            print("P (UTF-8): <not valid UTF-8>")


if __name__ == "__main__":
    main()
