#!/usr/bin/env python3
"""Tag-truncation guessing lab.

RFC 8439 ChaCha20-Poly1305 uses a 128-bit tag. This program illustrates how an
application that *improperly truncates* authentication tags reduces resistance to
online guessing attacks.

This is not a break of the standard 128-bit construction. The brute-force simulator
is intentionally limited to small classroom tag sizes.
"""
from __future__ import annotations
import argparse
import math
import random
import secrets


def success_probability(bits: int, guesses: int) -> float:
    p = 2.0 ** (-bits)
    return 1.0 - (1.0 - p) ** guesses


def expected_guesses(bits: int) -> float:
    return 2.0 ** bits


def one_trial(bits: int, max_guesses: int) -> int | None:
    target = secrets.randbits(bits)
    for g in range(1, max_guesses + 1):
        if secrets.randbits(bits) == target:
            return g
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bits", type=int, default=16, help="simulated truncated tag bits")
    ap.add_argument("--guesses", type=int, default=100000)
    ap.add_argument("--trials", type=int, default=20)
    args = ap.parse_args()

    if not 1 <= args.bits <= 128:
        raise SystemExit("bits must be 1..128")

    print(f"Tag bits                 : {args.bits}")
    print(f"Random-guess success/try : 2^-{args.bits} = {2.0**(-args.bits):.6e}")
    print(f"Expected guesses         : {expected_guesses(args.bits):.6g}")
    print(f"P(success in {args.guesses} guesses): {success_probability(args.bits,args.guesses):.6g}")

    if args.bits > 24:
        print("\nSimulation skipped for >24 bits; analytical result shown above.")
        print("Standard ChaCha20-Poly1305 uses a 128-bit tag.")
        return

    wins = 0
    samples = []
    for _ in range(args.trials):
        g = one_trial(args.bits, args.guesses)
        if g is not None:
            wins += 1
            samples.append(g)
    print(f"\nMonte Carlo trials       : {args.trials}")
    print(f"Successful trials        : {wins}")
    if samples:
        print(f"Mean guesses among wins  : {sum(samples)/len(samples):.1f}")
    print("\nLesson: truncating tags is an application-level security degradation, not a weakness of RFC 8439's full 128-bit tag.")


if __name__ == "__main__":
    main()
