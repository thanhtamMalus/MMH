#!/usr/bin/env python3
"""
ChaCha20 reduced-round diffusion / avalanche laboratory.

This is NOT a practical attack on full ChaCha20. It is an educational experiment
that measures how a one-bit input difference spreads as the number of rounds grows.

We compare two related inputs that differ in exactly one bit of the key, nonce, or
counter. For each selected even round count, the program reports:

  * Hamming distance of the internal 512-bit state before feed-forward;
  * Hamming distance of the 512-bit block output after feed-forward;
  * percentage of changed bits.

A well-diffused state should approach about half the bits changed. Low-round
structure is exactly what reduced-round differential cryptanalysis tries to exploit.
"""
from __future__ import annotations
import argparse, csv, secrets
from pathlib import Path
from chacha20_core import reduced_state, state_to_bytes, chacha_block, hamming_distance, rfc8439_selftest


def flip_bit_bytes(data: bytes, bit: int) -> bytes:
    if bit < 0 or bit >= len(data) * 8:
        raise ValueError("bit index outside byte string")
    out = bytearray(data)
    byte_i, bit_i = divmod(bit, 8)
    out[byte_i] ^= 1 << bit_i
    return bytes(out)


def related_inputs(key: bytes, nonce: bytes, counter: int, target: str, bit: int):
    k2, n2, c2 = key, nonce, counter
    if target == "key":
        k2 = flip_bit_bytes(key, bit)
    elif target == "nonce":
        n2 = flip_bit_bytes(nonce, bit)
    elif target == "counter":
        if not 0 <= bit < 32:
            raise ValueError("counter bit must be 0..31")
        c2 = counter ^ (1 << bit)
    else:
        raise ValueError(target)
    return k2, n2, c2


def run(rounds_list, target, bit, key, nonce, counter):
    k2, n2, c2 = related_inputs(key, nonce, counter, target, bit)
    rows = []
    for r in rounds_list:
        s1 = state_to_bytes(reduced_state(key, counter, nonce, r))
        s2 = state_to_bytes(reduced_state(k2, c2, n2, r))
        hd_state = hamming_distance(s1, s2)

        b1 = chacha_block(key, counter, nonce, r)
        b2 = chacha_block(k2, c2, n2, r)
        hd_out = hamming_distance(b1, b2)
        rows.append((r, hd_state, hd_state / 512.0, hd_out, hd_out / 512.0))
    return rows


def main():
    ap = argparse.ArgumentParser(description="Measure reduced-round ChaCha20 diffusion from a one-bit related input.")
    ap.add_argument("--rounds", default="0,2,4,6,8,12,20")
    ap.add_argument("--target", choices=["key", "nonce", "counter"], default="nonce")
    ap.add_argument("--bit", type=int, default=0, help="Bit to flip within selected input")
    ap.add_argument("--key", help="32-byte hex key; default random")
    ap.add_argument("--nonce", help="12-byte hex nonce; default random")
    ap.add_argument("--counter", type=int, default=1)
    ap.add_argument("--csv", default="chacha20_diffusion.csv")
    a = ap.parse_args()

    key = bytes.fromhex(a.key) if a.key else secrets.token_bytes(32)
    nonce = bytes.fromhex(a.nonce) if a.nonce else secrets.token_bytes(12)
    rounds_list = [int(x) for x in a.rounds.split(",") if x.strip()]

    print("RFC 8439 block self-test:", "PASS" if rfc8439_selftest() else "FAIL")
    print(f"Related input: flip {a.target} bit {a.bit}")
    print(f"Key   : {key.hex()}")
    print(f"Nonce : {nonce.hex()}")
    print(f"Counter: {a.counter}\n")

    rows = run(rounds_list, a.target, a.bit, key, nonce, a.counter)
    print("rounds | internal HD /512 | output HD /512")
    print("-------+------------------+---------------")
    for r, hds, ps, hdo, po in rows:
        print(f"{r:6d} | {hds:4d} ({ps:6.2%}) | {hdo:4d} ({po:6.2%})")

    with open(a.csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rounds", "internal_hamming", "internal_fraction", "output_hamming", "output_fraction"])
        w.writerows(rows)
    print(f"\nSaved CSV: {a.csv}")
    print("Interpretation: low-round non-random structure is a research target; this is not a full-ChaCha20 break.")

if __name__ == "__main__":
    main()
