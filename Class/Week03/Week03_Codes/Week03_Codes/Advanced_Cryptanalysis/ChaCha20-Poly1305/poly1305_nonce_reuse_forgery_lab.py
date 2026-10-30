#!/usr/bin/env python3
"""Poly1305 one-time-key reuse forgery lab for ChaCha20-Poly1305.

Purpose
-------
Demonstrate the *integrity* consequence of nonce reuse, beyond the confidentiality
keystream-reuse attack.

When the same (ChaCha20 key, nonce) is reused, counter 0 produces the same
Poly1305 one-time key (r,s). Reusing a Poly1305 one-time key is forbidden.

This educational attack recovers (r,s) from TWO valid records under a deliberately
restricted classroom setup:

  * same reused key+nonce,
  * empty AAD,
  * equal ciphertext length,
  * 1..16 ciphertext bytes.

For this case the RFC 8439 MAC input contains exactly two 16-byte Poly1305 blocks:

  block 1 = padded ciphertext
  block 2 = lengths

and the equal-length second block cancels between records, giving a relation in r^2.
We enumerate the small ambiguity introduced by the final mod 2^128 tag reduction,
recover the clamped r, derive s, and forge a valid tag for a modified ciphertext.

The attacker code itself uses no ChaCha20 secret key. In --demo mode a simulated
victim uses a secret key only to generate/verify records so students can see success.

Educational/authorized lab use only.
"""
from __future__ import annotations
import argparse
import secrets
from chacha20_poly1305_core import (
    P1305, R_MASK, M128, mac_data, poly1305_accumulator, poly1305_mac_rs,
    aead_encrypt, aead_decrypt
)


def sqrt_mod_p_3mod4(x: int) -> list[int]:
    """Square roots modulo p for p == 3 mod 4."""
    x %= P1305
    y = pow(x, (P1305 + 1) // 4, P1305)
    if (y * y) % P1305 != x:
        return []
    if y == 0:
        return [0]
    return [y, (-y) % P1305]


def recover_poly1305_rs(ct1: bytes, tag1: bytes, ct2: bytes, tag2: bytes) -> list[tuple[int, int]]:
    if not (1 <= len(ct1) <= 16 and len(ct1) == len(ct2)):
        raise ValueError("lab attack requires equal ciphertext lengths in 1..16 bytes")
    if len(tag1) != 16 or len(tag2) != 16:
        raise ValueError("tags must be 16 bytes")

    m1 = mac_data(b"", ct1)
    m2 = mac_data(b"", ct2)
    if len(m1) != 32 or len(m2) != 32:
        raise AssertionError("restricted lab should produce exactly two Poly1305 blocks")

    # First padded-ciphertext block interpreted with the Poly1305 appended 1 bit.
    n1 = int.from_bytes(m1[:16] + b"\x01", "little")
    n2 = int.from_bytes(m2[:16] + b"\x01", "little")
    dn = (n1 - n2) % P1305
    if dn == 0:
        raise ValueError("the two ciphertext first blocks must differ")
    dn_inv = pow(dn, -1, P1305)

    t1 = int.from_bytes(tag1, "little")
    t2 = int.from_bytes(tag2, "little")
    d0 = t1 - t2

    # h+s is less than about 5*2^128, hence the difference of hidden quotient
    # values lies in [-4,4]. Try all possible lifts of the observed tag difference.
    candidates: list[tuple[int, int]] = []
    seen = set()
    for q in range(-4, 5):
        lifted = d0 + q * M128
        r_squared = (lifted % P1305) * dn_inv % P1305

        for r in sqrt_mod_p_3mod4(r_squared):
            # A real Poly1305 r is a 128-bit value satisfying the clamp mask.
            if r >= M128 or (r & ~R_MASK) != 0:
                continue

            h1 = poly1305_accumulator(m1, r)
            s = (t1 - h1) % M128

            if poly1305_mac_rs(m1, r, s) != tag1:
                continue
            if poly1305_mac_rs(m2, r, s) != tag2:
                continue

            if (r, s) not in seen:
                seen.add((r, s))
                candidates.append((r, s))

    return candidates


def forge_tag(ciphertext: bytes, r: int, s: int) -> bytes:
    if not 1 <= len(ciphertext) <= 16:
        raise ValueError("restricted lab supports ciphertext length 1..16")
    return poly1305_mac_rs(mac_data(b"", ciphertext), r, s)


def controlled_patch(ct: bytes, known_plaintext: bytes, old: bytes, new: bytes) -> bytes:
    if len(old) != len(new):
        raise ValueError("old/new must have same length")
    offset = known_plaintext.index(old)
    delta = bytes(a ^ b for a, b in zip(old, new))
    out = bytearray(ct)
    for i, d in enumerate(delta):
        out[offset+i] ^= d
    return bytes(out)


def demo() -> bool:
    # Victim setup. The attack below never receives this key.
    victim_key = secrets.token_bytes(32)
    reused_nonce = secrets.token_bytes(12)

    p1 = b"role=user;id=01!"   # 16 bytes
    p2 = b"role=user;id=02?"   # 16 bytes
    assert len(p1) == len(p2) == 16

    c1, t1 = aead_encrypt(victim_key, reused_nonce, p1, b"")
    c2, t2 = aead_encrypt(victim_key, reused_nonce, p2, b"")

    print("Victim mistakenly reused one nonce for two records.")
    print("C1 =", c1.hex())
    print("T1 =", t1.hex())
    print("C2 =", c2.hex())
    print("T2 =", t2.hex())

    # Attacker: recover the reused Poly1305 one-time key from public C,T values.
    candidates = recover_poly1305_rs(c1, t1, c2, t2)
    print(f"\nRecovered candidate (r,s) pairs: {len(candidates)}")
    if len(candidates) != 1:
        print("Demo expected a unique candidate; aborting.")
        return False
    r, s = candidates[0]
    print("r =", f"{r:032x}")
    print("s =", f"{s:032x}")

    # Attacker knows the semantic layout of record 2 and performs the same
    # user -> root controlled ciphertext patch as in the bare-ChaCha20 lab.
    forged_c2 = controlled_patch(c2, p2, b"user", b"root")
    forged_t2 = forge_tag(forged_c2, r, s)

    print("\nForged C2 =", forged_c2.hex())
    print("Forged T2 =", forged_t2.hex())

    # Victim verifies with the real secret key. Acceptance proves the forgery.
    try:
        recovered = aead_decrypt(victim_key, reused_nonce, forged_c2, forged_t2, b"")
    except ValueError:
        print("Victim rejected forged record: FAIL")
        return False

    expected = p2.replace(b"user", b"root")
    print("Victim accepted plaintext:", recovered.decode())
    print("Expected forged plaintext:", expected.decode())
    ok = recovered == expected
    print("Result:", "PASS" if ok else "FAIL")
    return ok


def attacker_mode(args) -> int:
    c1 = bytes.fromhex(args.c1)
    t1 = bytes.fromhex(args.t1)
    c2 = bytes.fromhex(args.c2)
    t2 = bytes.fromhex(args.t2)
    target = bytes.fromhex(args.target)

    candidates = recover_poly1305_rs(c1, t1, c2, t2)
    print(f"Recovered candidates: {len(candidates)}")
    for i, (r, s) in enumerate(candidates, 1):
        print(f"[{i}] r={r:032x}")
        print(f"    s={s:032x}")
        print(f"    forged_tag={forge_tag(target, r, s).hex()}")
    return 0 if candidates else 2


def main():
    ap = argparse.ArgumentParser(description="Restricted Poly1305 nonce-reuse forgery teaching lab")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--c1", help="first ciphertext hex, 1..16 bytes")
    ap.add_argument("--t1", help="first tag hex")
    ap.add_argument("--c2", help="second equal-length ciphertext hex")
    ap.add_argument("--t2", help="second tag hex")
    ap.add_argument("--target", help="same-length target ciphertext hex to authenticate")
    args = ap.parse_args()

    if args.demo or not all([args.c1, args.t1, args.c2, args.t2, args.target]):
        raise SystemExit(0 if demo() else 1)
    raise SystemExit(attacker_mode(args))


if __name__ == "__main__":
    main()
