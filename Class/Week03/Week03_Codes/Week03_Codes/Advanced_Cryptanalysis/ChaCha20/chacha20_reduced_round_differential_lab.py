#!/usr/bin/env python3
"""
Toy related-input differential-bias experiment for reduced-round ChaCha.

Purpose
-------
Show how cryptanalysts can look for non-random differential behavior in reduced
rounds. This script is intentionally a *laboratory distinguisher*, not a key-recovery
attack and not a practical attack on standardized 20-round ChaCha20.

Experiment
----------
For each random key K, compute two reduced-round ChaCha blocks with public inputs
that differ in one chosen bit (default: nonce bit 0):

    Y  = ChaCha_r(K, counter, nonce)
    Y' = ChaCha_r(K, counter, nonce XOR Delta)
    D  = Y XOR Y'

For each of the 512 output bits, estimate Pr[D_i = 1]. Under a simple random-
difference reference model, each bit should be near 1/2. A large deviation from
1/2 is a visible differential bias/distinguisher for that reduced-round experiment.

The program reports the largest observed absolute bias and the most biased bits.
Sampling noise is approximately O(1/sqrt(N)); use larger N for stronger evidence.
"""
from __future__ import annotations
import argparse, csv, secrets, math
from chacha20_core import chacha_block, rfc8439_selftest


def flip_bit_bytes(data: bytes, bit: int) -> bytes:
    if bit < 0 or bit >= len(data) * 8:
        raise ValueError("bit outside input")
    out = bytearray(data)
    byte_i, bit_i = divmod(bit, 8)
    out[byte_i] ^= 1 << bit_i
    return bytes(out)


def make_related(nonce: bytes, counter: int, target: str, bit: int):
    if target == "nonce":
        return flip_bit_bytes(nonce, bit), counter
    if target == "counter":
        if not 0 <= bit < 32:
            raise ValueError("counter bit must be 0..31")
        return nonce, counter ^ (1 << bit)
    raise ValueError(target)


def accumulate(rounds: int, samples: int, target: str, bit: int, nonce: bytes, counter: int):
    n2, c2 = make_related(nonce, counter, target, bit)
    ones = [0] * 512

    for _ in range(samples):
        key = secrets.token_bytes(32)
        y1 = chacha_block(key, counter, nonce, rounds)
        y2 = chacha_block(key, c2, n2, rounds)
        d = bytes(a ^ b for a, b in zip(y1, y2))
        for byte_index, value in enumerate(d):
            base = 8 * byte_index
            for b in range(8):
                ones[base + b] += (value >> b) & 1

    probs = [x / samples for x in ones]
    biases = [p - 0.5 for p in probs]
    return probs, biases


def main():
    ap = argparse.ArgumentParser(description="Toy differential-bias measurement for reduced-round ChaCha.")
    ap.add_argument("--rounds", default="2,4,6,8", help="Even round counts")
    ap.add_argument("--samples", type=int, default=3000)
    ap.add_argument("--target", choices=["nonce", "counter"], default="nonce")
    ap.add_argument("--bit", type=int, default=0)
    ap.add_argument("--nonce", default="000000000000000000000000")
    ap.add_argument("--counter", type=int, default=1)
    ap.add_argument("--top", type=int, default=8)
    ap.add_argument("--csv", default="chacha20_reduced_round_bias.csv")
    a = ap.parse_args()

    nonce = bytes.fromhex(a.nonce)
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    rounds_list = [int(x) for x in a.rounds.split(",") if x.strip()]

    print("RFC 8439 block self-test:", "PASS" if rfc8439_selftest() else "FAIL")
    print(f"Difference: flip {a.target} bit {a.bit}")
    print(f"Samples per round: {a.samples}")
    sigma = math.sqrt(0.25 / a.samples)
    print(f"Random-reference 1-sigma sampling scale: {sigma:.5f}\n")

    all_rows = []
    for r in rounds_list:
        probs, biases = accumulate(r, a.samples, a.target, a.bit, nonce, a.counter)
        order = sorted(range(512), key=lambda i: abs(biases[i]), reverse=True)
        best = order[0]
        print(f"Rounds {r:2d}: max |bias| = {abs(biases[best]):.6f} at output bit {best} "
              f"(Pr[D_i=1]={probs[best]:.6f}, z~{abs(biases[best])/sigma:.2f})")
        print("  Top bits:")
        for i in order[:a.top]:
            print(f"    bit {i:3d}: p={probs[i]:.6f}, bias={biases[i]:+.6f}")
        print()
        for i in range(512):
            all_rows.append((r, i, probs[i], biases[i], abs(biases[i]) / sigma))

    with open(a.csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rounds", "output_bit", "prob_difference_bit_1", "bias_from_half", "abs_z_approx"])
        w.writerows(all_rows)
    print("Saved CSV:", a.csv)
    print("\nSecurity interpretation:")
    print("  Visible low-round biases illustrate the method used in reduced-round analysis.")
    print("  This experiment is not evidence of a practical attack on standardized ChaCha20/20 rounds.")

if __name__ == "__main__":
    main()
