#!/usr/bin/env python3
"""
RC4-versus-random statistical distinguisher.

We use the RC4 second-byte zero bias. Under a uniform random stream:

    H0: Pr[byte_2 = 0] = 1/256

For RC4, approximately:

    H1: Pr[Z_2 = 0] ~= 1/128

The program samples many independent streams and computes a binomial z-score.
This is a statistical distinguisher: it demonstrates non-random structure without
recovering any key.
"""

from __future__ import annotations
import argparse
import math
import secrets
from rc4_core import rc4_keystream, selftest


def sample_second_bytes(source: str, samples: int, key_len: int) -> list[int]:
    out = []
    if source == "rc4":
        for _ in range(samples):
            key = secrets.token_bytes(key_len)
            out.append(rc4_keystream(key, 2)[1])
    elif source == "random":
        for _ in range(samples):
            out.append(secrets.randbelow(256))
    else:
        raise ValueError(source)
    return out


def stats(values: list[int]):
    n = len(values)
    count0 = sum(v == 0 for v in values)
    p0 = 1 / 256
    mu = n * p0
    sigma = math.sqrt(n * p0 * (1 - p0))
    z = (count0 - mu) / sigma
    return count0, count0 / n, z


def main():
    ap = argparse.ArgumentParser(description="Distinguish RC4 from uniform random using the second-byte zero bias.")
    ap.add_argument("--source", choices=["rc4", "random"], default="rc4")
    ap.add_argument("--samples", type=int, default=50000)
    ap.add_argument("--key-len", type=int, default=16)
    ap.add_argument("--threshold", type=float, default=5.0, help="z-score threshold for calling the source non-uniform")
    args = ap.parse_args()

    selftest()
    values = sample_second_bytes(args.source, args.samples, args.key_len)
    count0, prob0, z = stats(values)

    print("RC4 statistical distinguisher")
    print(f"source used for lab      : {args.source}")
    print(f"number of independent streams: {args.samples:,}")
    print(f"byte-2 zero count        : {count0:,}")
    print(f"empirical Pr[byte2=0]    : {prob0:.7f}")
    print(f"uniform expectation      : {1/256:.7f}")
    print(f"RC4 classic approximation: {1/128:.7f}")
    print(f"z-score vs uniform       : {z:.3f}")

    verdict = "RC4-like / detectably non-uniform" if z >= args.threshold else "consistent with uniform at this threshold"
    print(f"verdict (threshold {args.threshold:g}): {verdict}")


if __name__ == "__main__":
    main()
