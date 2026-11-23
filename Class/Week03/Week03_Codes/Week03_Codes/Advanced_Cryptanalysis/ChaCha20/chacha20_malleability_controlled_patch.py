#!/usr/bin/env python3
"""
ChaCha20 malleability lab: controlled plaintext modification by editing ciphertext.

Bare ChaCha20 provides confidentiality but no integrity/authentication.
For C = P XOR Z, an attacker can choose a byte mask Delta and send

    C' = C XOR Delta

The receiver obtains

    P' = C' XOR Z = P XOR Delta.

If the attacker knows an original plaintext segment OLD and wants the same-length
segment NEW at the same offset, choose

    Delta = OLD XOR NEW

and XOR Delta into the ciphertext at that offset. No key is needed by the attacker.

This is a teaching demonstration of unauthenticated stream-cipher malleability.
It is NOT a break of the ChaCha20 keystream generator. ChaCha20-Poly1305 prevents
this attack when the authentication tag is correctly verified.
"""
from __future__ import annotations
import argparse, base64, secrets
from pathlib import Path
from chacha20_core import chacha_xor, rfc8439_selftest


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def parse_spec(spec: str) -> bytes:
    if ":" not in spec:
        return spec.encode("utf-8")
    kind, value = spec.split(":", 1)
    kind = kind.lower()
    if kind == "text":
        return value.encode("utf-8")
    if kind == "hex":
        return bytes.fromhex("".join(value.split()))
    if kind in ("base64", "b64"):
        return base64.b64decode(value)
    if kind in ("file", "bin", "binary"):
        return Path(value).read_bytes()
    # Windows path such as C:\...
    if len(kind) == 1 and kind.isalpha():
        return Path(spec).read_bytes()
    raise ValueError("Use text:, hex:, base64:, or file:")


def patch_ciphertext(ciphertext: bytes, offset: int, old: bytes, new: bytes) -> tuple[bytes, bytes]:
    if len(old) != len(new):
        raise ValueError("OLD and NEW must have equal byte length for an in-place XOR patch.")
    if offset < 0 or offset + len(old) > len(ciphertext):
        raise ValueError("Patch range is outside the ciphertext.")
    delta = xor_bytes(old, new)
    out = bytearray(ciphertext)
    for i, d in enumerate(delta):
        out[offset + i] ^= d
    return bytes(out), delta


def demo(plaintext_spec="text:uid=1001;role=user;expires=2026-12-31", old_spec="text:user", new_spec="text:root", offset_arg=None):
    print("=" * 78)
    print("CHACHA20 CONTROLLED CIPHERTEXT-MODIFICATION DEMO")
    print("Attacker modifies ciphertext WITHOUT knowing the key")
    print("=" * 78)
    print("RFC 8439 core self-test:", "PASS" if rfc8439_selftest() else "FAIL")

    p = parse_spec(plaintext_spec)
    old = parse_spec(old_spec)
    new = parse_spec(new_spec)
    if len(old) != len(new):
        raise ValueError("Demo OLD and NEW must have equal byte length")
    offset = p.find(old) if offset_arg is None else offset_arg
    if offset < 0:
        raise ValueError("OLD segment not found in demo plaintext; provide --demo-offset")

    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    counter = 1
    c = chacha_xor(key, nonce, counter, p)

    forged_c, delta = patch_ciphertext(c, offset, old, new)
    receiver_original = chacha_xor(key, nonce, counter, c)
    receiver_forged = chacha_xor(key, nonce, counter, forged_c)

    print("\nSender plaintext :", p.decode())
    print("Ciphertext (hex)  :", c.hex())
    print("\nAttacker knows original segment:", old)
    print("Attacker wants new segment       :", new)
    print("Offset                           :", offset)
    print("Delta = OLD XOR NEW              :", delta.hex())
    print("Forged ciphertext (hex)          :", forged_c.hex())
    print("\nReceiver decrypts original:", receiver_original.decode())
    print("Receiver decrypts forged  :", receiver_forged.decode())
    print("\nKey was used only by sender/receiver demo code; patch_ciphertext() never receives it.")


def interactive():
    print("=" * 78)
    print("CHACHA20 MALLEABILITY ATTACK — NO KEY REQUIRED")
    print("=" * 78)
    c = parse_spec(input("Ciphertext [hex:/base64:/file:]: ").strip())
    offset = int(input("Known plaintext segment byte offset: "))
    old = parse_spec(input("Known OLD segment [text:/hex:/base64:]: ").strip())
    new = parse_spec(input("Desired NEW segment, same length: ").strip())
    forged, delta = patch_ciphertext(c, offset, old, new)
    out = input("Output forged ciphertext file [forged_cipher.bin]: ").strip() or "forged_cipher.bin"
    Path(out).write_bytes(forged)
    print("Delta(hex):", delta.hex())
    print("Saved:", out)
    print("No secret key was used.")


def main():
    ap = argparse.ArgumentParser(description="Controlled plaintext modification of bare ChaCha20 by XOR-editing ciphertext.")
    ap.add_argument("--cipher", help="Ciphertext as hex:, base64:, or file:")
    ap.add_argument("--offset", type=int)
    ap.add_argument("--old", help="Known original plaintext bytes as text:/hex:/base64:")
    ap.add_argument("--new", help="Desired same-length bytes as text:/hex:/base64:")
    ap.add_argument("--output", default="forged_cipher.bin")
    ap.add_argument("--demo", action="store_true", help="Run self-contained sender/attacker/receiver demonstration")
    ap.add_argument("--demo-plaintext", default="text:uid=1001;role=user;expires=2026-12-31")
    ap.add_argument("--demo-old", default="text:user")
    ap.add_argument("--demo-new", default="text:root")
    ap.add_argument("--demo-offset", type=int)
    ap.add_argument("--interactive", action="store_true")
    a = ap.parse_args()

    if a.demo:
        demo(a.demo_plaintext, a.demo_old, a.demo_new, a.demo_offset); return
    if a.interactive or not (a.cipher is not None and a.offset is not None and a.old and a.new):
        interactive(); return

    c = parse_spec(a.cipher)
    old = parse_spec(a.old)
    new = parse_spec(a.new)
    forged, delta = patch_ciphertext(c, a.offset, old, new)
    Path(a.output).write_bytes(forged)
    print(f"[+] Delta(hex) = {delta.hex()}")
    print(f"[+] Forged ciphertext saved: {a.output}")
    print("[+] No key was used by the attacker.")

if __name__ == "__main__":
    main()
