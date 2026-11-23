#!/usr/bin/env python3
"""
RC4 statistical-bias laboratory.

The classic Mantin-Shamir result says that the SECOND RC4 output byte Z_2
is biased toward 0x00:

    Pr[Z_2 = 0x00] ~= 1/128

instead of the uniform-random probability 1/256.

This program measures the bias empirically over many independent random keys.
It does not recover any secret key.
"""

from __future__ import annotations
import argparse
import csv
import math
import secrets
from pathlib import Path
from rc4_core import rc4_keystream, selftest


def collect(samples: int, positions: int, key_len: int, drop: int = 0):
    # counts[pos][byte]
    counts = [[0] * 256 for _ in range(positions)]
    for _ in range(samples):
        key = secrets.token_bytes(key_len)
        z = rc4_keystream(key, positions, drop=drop)
        for pos, b in enumerate(z):
            counts[pos][b] += 1
    return counts


def zscore_binomial(count: int, n: int, p: float = 1 / 256) -> float:
    mu = n * p
    sigma = math.sqrt(n * p * (1 - p))
    return (count - mu) / sigma if sigma else 0.0


def save_csv(path: Path, counts, samples: int):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["position_1_based", "byte_hex", "count", "probability"])
        for pos, row in enumerate(counts, start=1):
            for b, c in enumerate(row):
                w.writerow([pos, f"{b:02x}", c, c / samples])


def plot_second_byte(path: Path, counts, samples: int):
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("[!] matplotlib not installed; plot skipped")
        return

    row = counts[1] if len(counts) >= 2 else counts[0]
    xs = list(range(256))
    probs = [c / samples for c in row]
    plt.figure(figsize=(11, 4.5))
    plt.bar(xs, probs, width=1.0)
    plt.axhline(1 / 256, linestyle="--", linewidth=1, label="Uniform 1/256")
    plt.axhline(1 / 128, linestyle=":", linewidth=1, label="RC4 Z2=0 approx. 1/128")
    plt.xlabel("Keystream byte value")
    plt.ylabel("Empirical probability")
    plt.title("RC4 second output byte distribution")
    plt.legend()
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


def main():
    ap = argparse.ArgumentParser(description="Measure RC4 keystream biases over random keys.")
    ap.add_argument("--samples", type=int, default=50000)
    ap.add_argument("--positions", type=int, default=16)
    ap.add_argument("--key-len", type=int, default=16)
    ap.add_argument("--drop", type=int, default=0, help="Discard N RC4 bytes before measurement")
    ap.add_argument("--csv", default="rc4_bias_counts.csv")
    ap.add_argument("--plot", default="rc4_second_byte_bias.png")
    args = ap.parse_args()

    if args.samples <= 0 or args.positions <= 0 or args.key_len <= 0:
        raise SystemExit("samples, positions, and key length must be positive")

    selftest()
    counts = collect(args.samples, args.positions, args.key_len, args.drop)

    print("RC4 statistical-bias laboratory")
    print(f"samples={args.samples:,}, positions={args.positions}, key_len={args.key_len}, drop={args.drop}")
    print("Uniform expectation for any byte value: 1/256 = 0.00390625")

    print("\nZero-byte frequency by output position:")
    print("pos   count(00)    probability      z-score vs uniform")
    for pos, row in enumerate(counts, start=1):
        c = row[0]
        print(f"{pos:>3}   {c:>9}    {c/args.samples:>11.7f}      {zscore_binomial(c,args.samples):>8.3f}")

    if len(counts) >= 2:
        c2 = counts[1][0]
        p2 = c2 / args.samples
        print("\nKey teaching result:")
        print(f"  observed Pr[Z2=00] = {p2:.7f}")
        print(f"  uniform probability = {1/256:.7f}")
        print(f"  classic RC4 approximation = {1/128:.7f}")
        print(f"  z-score against uniform = {zscore_binomial(c2,args.samples):.3f}")

    csv_path = Path(args.csv)
    save_csv(csv_path, counts, args.samples)
    print(f"\n[+] Full distributions saved to {csv_path}")

    if args.plot:
        plot_path = Path(args.plot)
        plot_second_byte(plot_path, counts, args.samples)
        if plot_path.exists():
            print(f"[+] Plot saved to {plot_path}")


if __name__ == "__main__":
    main()
