#!/usr/bin/env python3
"""Nonce collision / birthday-risk lab for ChaCha20-Poly1305.

The AEAD security rule is uniqueness of nonce per key. If an application chooses
96-bit nonces randomly, collisions follow the birthday phenomenon. This script
computes the collision probability analytically and can simulate smaller nonce
spaces so the effect is visible in class.
"""
from __future__ import annotations
import argparse
import math
import secrets


def collision_probability(bits: int, q: int) -> float:
    n = 2 ** bits
    if q <= 1:
        return 0.0
    # Stable approximation for large n. Exact product would be costly.
    x = q * (q - 1) / (2.0 * n)
    return -math.expm1(-x)


def q_for_probability(bits: int, probability: float) -> float:
    if not 0 < probability < 1:
        raise ValueError("probability must be in (0,1)")
    n = 2.0 ** bits
    return math.sqrt(2.0 * n * (-math.log1p(-probability)))


def simulate(bits: int, q: int, trials: int) -> float:
    if bits > 32:
        raise ValueError("simulation intentionally limited to <=32-bit toy nonce spaces")
    collisions = 0
    for _ in range(trials):
        seen = set()
        hit = False
        for _ in range(q):
            x = secrets.randbits(bits)
            if x in seen:
                hit = True
                break
            seen.add(x)
        collisions += int(hit)
    return collisions / trials


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--messages", type=int, default=1_000_000)
    ap.add_argument("--bits", type=int, default=96)
    ap.add_argument("--simulate-bits", type=int, default=16)
    ap.add_argument("--simulate-messages", type=int, default=300)
    ap.add_argument("--trials", type=int, default=200)
    args = ap.parse_args()

    p = collision_probability(args.bits, args.messages)
    print(f"Analytical nonce width     : {args.bits} bits")
    print(f"Messages under one key     : {args.messages:,}")
    print(f"Collision probability      : {p:.6e}")
    print(f"Messages for ~1% collision : {q_for_probability(args.bits,0.01):,.3g}")
    print(f"Messages for ~50% collision: {q_for_probability(args.bits,0.50):,.3g}")

    print("\nToy birthday simulation")
    pred = collision_probability(args.simulate_bits, args.simulate_messages)
    obs = simulate(args.simulate_bits, args.simulate_messages, args.trials)
    print(f"Nonce width                : {args.simulate_bits} bits")
    print(f"Messages/trial             : {args.simulate_messages}")
    print(f"Predicted collision P      : {pred:.4f}")
    print(f"Observed collision fraction: {obs:.4f}")
    print("\nLesson: ChaCha20-Poly1305 requires nonce uniqueness per key; deterministic/counter-based allocation avoids relying on collision luck.")


if __name__ == "__main__":
    main()
