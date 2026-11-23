#!/usr/bin/env python3
"""
ChaCha20-Poly1305 Warm-up Code — Week 3

Interactive educational program:
  * Encrypt or decrypt
  * Manual or random 256-bit key
  * Manual or random 96-bit nonce
  * Optional AAD (Additional Authenticated Data)
  * Text / hex / Base64 data entry

Implements the IETF ChaCha20-Poly1305 AEAD construction from RFC 8439.
No external cryptographic library is used so students can inspect the mechanics.

IMPORTANT: Educational/demo use only. In real applications use a vetted crypto library.
"""

from __future__ import annotations

import base64
import hmac
import secrets
import struct

MASK32 = 0xFFFFFFFF
P1305 = (1 << 130) - 5
R_MASK = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def rotl32(x: int, n: int) -> int:
    x &= MASK32
    return ((x << n) & MASK32) | (x >> (32 - n))


def quarter_round(x: list[int], a: int, b: int, c: int, d: int) -> None:
    x[a] = (x[a] + x[b]) & MASK32
    x[d] = rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & MASK32
    x[b] = rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & MASK32
    x[d] = rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & MASK32
    x[b] = rotl32(x[b] ^ x[c], 7)


def inner_block(x: list[int]) -> None:
    # Column round
    quarter_round(x, 0, 4, 8, 12)
    quarter_round(x, 1, 5, 9, 13)
    quarter_round(x, 2, 6, 10, 14)
    quarter_round(x, 3, 7, 11, 15)
    # Diagonal round
    quarter_round(x, 0, 5, 10, 15)
    quarter_round(x, 1, 6, 11, 12)
    quarter_round(x, 2, 7, 8, 13)
    quarter_round(x, 3, 4, 9, 14)


def validate_key_nonce(key: bytes, nonce: bytes) -> None:
    if len(key) != 32:
        raise ValueError(f"key must be exactly 32 bytes; got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"nonce must be exactly 12 bytes; got {len(nonce)}")


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    validate_key_nonce(key, nonce)
    if not 0 <= counter <= MASK32:
        raise ValueError("counter must be in 0..2^32-1")

    state = [*CONSTANTS, *struct.unpack("<8I", key), counter, *struct.unpack("<3I", nonce)]
    working = state.copy()
    for _ in range(10):
        inner_block(working)
    out = [(working[i] + state[i]) & MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20_xor(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    validate_key_nonce(key, nonce)
    blocks = (len(data) + 63) // 64
    if blocks and counter + blocks - 1 > MASK32:
        raise ValueError("message too long: 32-bit ChaCha20 counter would wrap")

    out = bytearray()
    for block_index in range(blocks):
        stream = chacha20_block(key, counter + block_index, nonce)
        chunk = data[64 * block_index : 64 * (block_index + 1)]
        out.extend(a ^ b for a, b in zip(chunk, stream))
    return bytes(out)


def poly1305_mac(message: bytes, one_time_key: bytes) -> bytes:
    if len(one_time_key) != 32:
        raise ValueError("Poly1305 one-time key must be 32 bytes")

    r = int.from_bytes(one_time_key[:16], "little") & R_MASK
    s = int.from_bytes(one_time_key[16:], "little")
    acc = 0

    for offset in range(0, len(message), 16):
        block = message[offset : offset + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r) % P1305

    tag = (acc + s) % (1 << 128)
    return tag.to_bytes(16, "little")


def pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return b"" if rem == 0 else b"\x00" * (16 - rem)


def poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    """RFC 8439: first 32 bytes of ChaCha20 block with counter = 0."""
    return chacha20_block(key, 0, nonce)[:32]


def aead_mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return (
        aad
        + pad16(aad)
        + ciphertext
        + pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )


def chacha20_poly1305_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b""
) -> tuple[bytes, bytes]:
    validate_key_nonce(key, nonce)
    otk = poly1305_key_gen(key, nonce)     # counter 0: authentication key only
    ciphertext = chacha20_xor(key, nonce, 1, plaintext)  # counter 1+: message
    tag = poly1305_mac(aead_mac_data(aad, ciphertext), otk)
    return ciphertext, tag


def chacha20_poly1305_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""
) -> bytes:
    validate_key_nonce(key, nonce)
    if len(tag) != 16:
        raise ValueError("authentication tag must be exactly 16 bytes")

    otk = poly1305_key_gen(key, nonce)
    expected = poly1305_mac(aead_mac_data(aad, ciphertext), otk)

    # Authenticate FIRST. Never return unauthenticated plaintext.
    if not hmac.compare_digest(expected, tag):
        raise ValueError("AUTHENTICATION FAILED: wrong key/nonce/AAD/tag or modified ciphertext")

    return chacha20_xor(key, nonce, 1, ciphertext)


def clean_hex(text: str) -> bytes:
    t = "".join(text.split()).replace(":", "").replace("-", "")
    if t.lower().startswith("0x"):
        t = t[2:]
    if len(t) % 2:
        raise ValueError("hex input must have an even number of digits")
    return bytes.fromhex(t)


def decode_data(text: str, fmt: str) -> bytes:
    if fmt == "text":
        return text.encode("utf-8")
    if fmt == "hex":
        return clean_hex(text)
    if fmt == "base64":
        return base64.b64decode(text, validate=True)
    raise ValueError("unsupported format")


def show_data(data: bytes) -> None:
    print("  Hex    :", data.hex())
    print("  Base64 :", base64.b64encode(data).decode("ascii"))
    try:
        print("  Text   :", data.decode("utf-8"))
    except UnicodeDecodeError:
        print("  Text   : <not valid UTF-8>")


def ask_format(prompt: str, default: str = "text") -> str:
    choices = {"1": "text", "2": "hex", "3": "base64"}
    print(f"{prompt}: 1=Text, 2=Hex, 3=Base64")
    ans = input(f"Choice [{default}]: ").strip().lower()
    if not ans:
        return default
    if ans in choices:
        return choices[ans]
    if ans in choices.values():
        return ans
    raise ValueError("invalid format choice")


def ask_key() -> bytes:
    print("\nKey source: 1=Manual hex, 2=Random 32-byte key")
    choice = input("Choice [2]: ").strip() or "2"
    if choice == "1":
        key = clean_hex(input("Enter 64 hex digits (32 bytes): ").strip())
    elif choice == "2":
        key = secrets.token_bytes(32)
        print("Generated key:", key.hex())
    else:
        raise ValueError("invalid key choice")
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    return key


def ask_nonce() -> bytes:
    print("\nNonce source: 1=Manual hex, 2=Random 12-byte nonce")
    choice = input("Choice [2]: ").strip() or "2"
    if choice == "1":
        nonce = clean_hex(input("Enter 24 hex digits (12 bytes): ").strip())
    elif choice == "2":
        nonce = secrets.token_bytes(12)
        print("Generated nonce:", nonce.hex())
    else:
        raise ValueError("invalid nonce choice")
    if len(nonce) != 12:
        raise ValueError("nonce must be exactly 12 bytes")
    return nonce


def ask_aad() -> bytes:
    use = input("\nUse AAD (Additional Authenticated Data)? [y/N]: ").strip().lower()
    if use not in {"y", "yes"}:
        return b""
    fmt = ask_format("AAD format", "text")
    return decode_data(input("AAD: "), fmt)


def print_concept() -> None:
    print(
        """
ChaCha20-Poly1305 AEAD — warm-up view
=====================================
1. ChaCha20 block counter 0 derives a 32-byte ONE-TIME Poly1305 key.
2. ChaCha20 counter 1,2,... encrypts the plaintext:
       C = P XOR keystream
3. Poly1305 authenticates:
       AAD || pad16 || C || pad16 || len(AAD) || len(C)
4. Decryption MUST verify the tag before releasing plaintext.

Security rule:
  NEVER reuse the same nonce with the same key.
  Nonce reuse repeats both the ChaCha20 keystream and Poly1305 one-time key.
""".strip()
    )


def main() -> int:
    print_concept()
    print("\nOperation: 1=Encrypt, 2=Decrypt")
    operation = input("Choice [1]: ").strip() or "1"

    try:
        key = ask_key()
        nonce = ask_nonce()
        aad = ask_aad()

        print("\nParameters")
        print("  Key   :", key.hex())
        print("  Nonce :", nonce.hex())
        print("  AAD   :", aad.hex() if aad else "<empty>")

        if operation == "1":
            fmt = ask_format("Plaintext format", "text")
            plaintext = decode_data(input("Plaintext: "), fmt)
            ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)

            print("\nCiphertext")
            show_data(ciphertext)
            print("\nAuthentication tag (16 bytes)")
            print("  Hex    :", tag.hex())
            print("\nCombined ciphertext || tag")
            print("  Hex    :", (ciphertext + tag).hex())

        elif operation == "2":
            fmt = ask_format("Ciphertext format", "hex")
            ciphertext = decode_data(input("Ciphertext: "), fmt)
            tag = clean_hex(input("Authentication tag (32 hex digits): ").strip())
            plaintext = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad)
            print("\nAuthentication: PASS")
            print("Plaintext")
            show_data(plaintext)
        else:
            raise ValueError("operation must be 1 or 2")

        return 0
    except Exception as exc:
        print(f"\nERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
