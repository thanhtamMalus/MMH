#!/usr/bin/env python3
"""
RC4 repeated-plaintext recovery laboratory.

RC4's second output byte is biased toward zero:

    Pr[Z_2 = 0] ~= 1/128 > 1/256.

If the same plaintext byte P_2 is encrypted many times under INDEPENDENT RC4 keys:

    C_2 = P_2 XOR Z_2

then C_2 equals P_2 unusually often because Z_2 = 0 unusually often.
Therefore the most frequent observed second ciphertext byte is a simple maximum-
frequency estimate of the second plaintext byte.

This is a deliberately small teaching version of the statistical principle used by
RC4 plaintext-recovery attacks against repeatedly encrypted data. It does not
recover any key and does not attack network traffic.
"""

from __future__ import annotations
import argparse
import base64
import collections
import secrets
from pathlib import Path
from rc4_core import rc4_crypt, selftest


def parse_plaintext(s: str) -> bytes:
    if s.startswith("hex:"):
        return bytes.fromhex("".join(s[4:].split()))
    if s.startswith("base64:"):
        return base64.b64decode(s[7:])
    if s.startswith("file:"):
        return Path(s[5:]).read_bytes()
    if s.startswith("text:"):
        return s[5:].encode()
    return s.encode()


def generate_ciphertexts(plaintext: bytes, sessions: int, key_len: int):
    for _ in range(sessions):
        key = secrets.token_bytes(key_len)
        yield rc4_crypt(key, plaintext)


def recover_second_byte(ciphertexts) -> tuple[int, collections.Counter]:
    counts = collections.Counter()
    used = 0
    for c in ciphertexts:
        if len(c) < 2:
            continue
        counts[c[1]] += 1
        used += 1
    if not used:
        raise ValueError("No ciphertext contains a second byte")
    guess, _ = counts.most_common(1)[0]
    return guess, counts


def save_hex_lines(path: Path, ciphertexts):
    with path.open("w", encoding="utf-8") as f:
        for c in ciphertexts:
            f.write(c.hex() + "\n")


def load_hex_lines(path: Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            yield bytes.fromhex(line)


def main():
    ap = argparse.ArgumentParser(description="Recover the second byte of a repeatedly encrypted RC4 plaintext using its keystream bias.")
    ap.add_argument("--plaintext", default="text:Secret cookie", help="Simulation plaintext: text:, hex:, base64:, or file:")
    ap.add_argument("--sessions", type=int, default=50000)
    ap.add_argument("--key-len", type=int, default=16)
    ap.add_argument("--save-ciphertexts", help="Save simulated ciphertexts as hex lines")
    ap.add_argument("--analyze", help="Instead of simulating, analyze a file of ciphertext hex lines")
    args = ap.parse_args()

    selftest()

    known_plaintext = None
    if args.analyze:
        ciphertexts = list(load_hex_lines(Path(args.analyze)))
    else:
        known_plaintext = parse_plaintext(args.plaintext)
        if len(known_plaintext) < 2:
            raise SystemExit("plaintext must contain at least two bytes")
        ciphertexts = list(generate_ciphertexts(known_plaintext, args.sessions, args.key_len))
        if args.save_ciphertexts:
            save_hex_lines(Path(args.save_ciphertexts), ciphertexts)
            print(f"[+] Saved {len(ciphertexts):,} ciphertexts to {args.save_ciphertexts}")

    guess, counts = recover_second_byte(ciphertexts)
    top = counts.most_common(8)

    print("RC4 repeated-plaintext statistical recovery")
    print(f"ciphertexts analyzed: {sum(counts.values()):,}")
    print("Most frequent ciphertext values at byte position 2:")
    for rank, (b, c) in enumerate(top, start=1):
        print(f"  {rank:>2}. 0x{b:02x}  count={c:,}")

    print(f"\nRecovered plaintext-byte guess P2 = 0x{guess:02x}")
    printable = chr(guess) if 32 <= guess <= 126 else "."
    print(f"ASCII view: {printable!r}")

    if known_plaintext is not None:
        actual = known_plaintext[1]
        print(f"Actual P2: 0x{actual:02x} ({chr(actual) if 32 <= actual <= 126 else '.'!r})")
        print("Result:", "PASS" if guess == actual else "not recovered at this sample size")
        if guess != actual:
            print("Try increasing --sessions; statistical recovery is probabilistic.")


if __name__ == "__main__":
    main()
