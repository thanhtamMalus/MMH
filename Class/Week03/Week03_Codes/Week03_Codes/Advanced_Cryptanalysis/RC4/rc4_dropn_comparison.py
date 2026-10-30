#!/usr/bin/env python3
"""
Compare the visible RC4 second-byte zero bias before and after discarding bytes.

This is a teaching experiment, not a claim that RC4-dropN makes RC4 modern or safe.
Dropping early output was historically proposed as a mitigation for some early
keystream biases, but RC4 as a construction was ultimately prohibited in TLS.
"""

from __future__ import annotations
import argparse
import math
import secrets
from rc4_core import rc4_keystream, selftest


def measure(samples: int, key_len: int, drop: int) -> tuple[int, float, float]:
    count = 0
    for _ in range(samples):
        key = secrets.token_bytes(key_len)
        z2 = rc4_keystream(key, 2, drop=drop)[1]
        count += (z2 == 0)
    p = count / samples
    p0 = 1 / 256
    sigma = math.sqrt(samples * p0 * (1 - p0))
    z = (count - samples * p0) / sigma
    return count, p, z


def main():
    ap = argparse.ArgumentParser(description="Compare RC4 early-byte bias for several drop-N settings.")
    ap.add_argument("--samples", type=int, default=30000)
    ap.add_argument("--key-len", type=int, default=16)
    ap.add_argument("--drops", default="0,256,768,1536", help="Comma-separated drop counts")
    args = ap.parse_args()

    selftest()
    drops = [int(x.strip()) for x in args.drops.split(",") if x.strip()]

    print("RC4-dropN comparison")
    print("NOTE: this only demonstrates one early-byte bias; it does NOT rehabilitate RC4.")
    print("drop       zero-count      Pr[measured byte=00]      z vs uniform")
    for drop in drops:
        c, p, z = measure(args.samples, args.key_len, drop)
        print(f"{drop:>5}       {c:>9}            {p:>10.7f}          {z:>8.3f}")


if __name__ == "__main__":
    main()
