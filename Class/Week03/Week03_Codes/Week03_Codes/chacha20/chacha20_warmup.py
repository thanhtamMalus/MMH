#!/usr/bin/env python3
"""
ChaCha20 Warm-up — Week 3: Stream Ciphers and Cryptanalysis

Purpose
-------
An interactive first-contact program for the IETF ChaCha20 stream cipher
(RFC 8439 variant):
  * 256-bit key (32 bytes)
  * 96-bit nonce (12 bytes)
  * 32-bit block counter
  * 64-byte keystream blocks

Students can choose encryption or decryption, manually provide or randomly
create key/nonce values, and observe the XOR stream-cipher relation:

    C = P XOR Z        P = C XOR Z

This is ChaCha20 ONLY — no Poly1305 and therefore no authentication.
Educational/demo use only.
"""

from __future__ import annotations

import base64
import secrets
import struct

MASK32 = 0xFFFFFFFF
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


def validate_inputs(key: bytes, nonce: bytes, counter: int) -> None:
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be exactly 32 bytes (256 bits).")
    if len(nonce) != 12:
        raise ValueError("IETF ChaCha20 nonce must be exactly 12 bytes (96 bits).")
    if not 0 <= counter <= MASK32:
        raise ValueError("Counter must be in 0..2^32-1.")


def initial_state(key: bytes, counter: int, nonce: bytes) -> list[int]:
    validate_inputs(key, nonce, counter)
    return [
        *CONSTANTS,
        *struct.unpack("<8I", key),
        counter,
        *struct.unpack("<3I", nonce),
    ]


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = initial_state(key, counter, nonce)
    working = state.copy()
    for _ in range(10):  # 10 double-rounds = 20 rounds
        inner_block(working)
    result = [(working[i] + state[i]) & MASK32 for i in range(16)]
    return struct.pack("<16I", *result)


def chacha20_keystream(key: bytes, nonce: bytes, counter: int, n: int) -> bytes:
    validate_inputs(key, nonce, counter)
    if n < 0:
        raise ValueError("Requested keystream length must be non-negative.")
    blocks = (n + 63) // 64
    if blocks and counter + blocks - 1 > MASK32:
        raise ValueError("Message would make the 32-bit block counter wrap.")

    out = bytearray()
    for block_index in range(blocks):
        out.extend(chacha20_block(key, counter + block_index, nonce))
    return bytes(out[:n])


def chacha20_crypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    z = chacha20_keystream(key, nonce, counter, len(data))
    return bytes(a ^ b for a, b in zip(data, z))


def ask_choice(prompt: str, choices: dict[str, str]) -> str:
    while True:
        print(prompt)
        for token, description in choices.items():
            print(f"  {token}) {description}")
        value = input("> ").strip().lower()
        if value in choices:
            return value
        print("Invalid selection. Please try again.\n")


def parse_hex(text: str) -> bytes:
    cleaned = "".join(text.split()).replace(":", "").replace("-", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) % 2:
        raise ValueError("Hex input must contain an even number of digits.")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError("Invalid hexadecimal input.") from exc


def read_fixed_bytes(name: str, length: int, allow_text: bool, random_label: str) -> bytes:
    choices = {"1": f"manual hexadecimal {name}", "2": f"generate random {random_label}"}
    if allow_text:
        choices = {
            "1": f"manual UTF-8 text {name} (must encode to exactly {length} bytes)",
            "2": f"manual hexadecimal {name}",
            "3": f"generate random {random_label}",
        }

    mode = ask_choice(f"\n{name.capitalize()} source:", choices)
    if allow_text and mode == "1":
        value = input(f"{name.capitalize()} text: ").encode("utf-8")
    elif (allow_text and mode == "2") or (not allow_text and mode == "1"):
        while True:
            try:
                value = parse_hex(input(f"{name.capitalize()} hex: "))
                break
            except ValueError as exc:
                print(f"Input error: {exc}")
    else:
        value = secrets.token_bytes(length)
        print(f"Generated {name} (hex): {value.hex()}")

    if len(value) != length:
        raise ValueError(f"{name.capitalize()} must be exactly {length} bytes; got {len(value)}.")
    return value


def read_counter() -> int:
    while True:
        raw = input("Initial 32-bit block counter [1]: ").strip() or "1"
        try:
            value = int(raw, 0)
            if not 0 <= value <= MASK32:
                raise ValueError
            return value
        except ValueError:
            print("Enter an integer from 0 through 4294967295 (decimal or 0x...).")


def read_plaintext() -> bytes:
    mode = ask_choice("\nPlaintext input format:", {"1": "UTF-8 text", "2": "hexadecimal"})
    if mode == "1":
        return input("Plaintext: ").encode("utf-8")
    while True:
        try:
            return parse_hex(input("Plaintext hex: "))
        except ValueError as exc:
            print(f"Input error: {exc}")


def read_ciphertext() -> bytes:
    mode = ask_choice("\nCiphertext input format:", {"1": "hexadecimal", "2": "Base64"})
    if mode == "1":
        while True:
            try:
                return parse_hex(input("Ciphertext hex: "))
            except ValueError as exc:
                print(f"Input error: {exc}")
    while True:
        try:
            return base64.b64decode(input("Ciphertext Base64: ").strip(), validate=True)
        except Exception:
            print("Invalid Base64 input.")


def printable_utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return "<not valid UTF-8; use hex output>"


def run_once() -> None:
    print("\n" + "=" * 76)
    print("CHACHA20 WARM-UP — IETF ChaCha20, no Poly1305")
    print("C = P XOR Z       P = C XOR Z")
    print("Z = ChaCha20_stream(key, nonce, initial_counter)")
    print("=" * 76)

    op = ask_choice("\nSelect operation:", {"1": "encrypt", "2": "decrypt"})
    key = read_fixed_bytes("key", 32, True, "32-byte key")
    nonce = read_fixed_bytes("nonce", 12, False, "12-byte nonce")
    counter = read_counter()

    if op == "1":
        plaintext = read_plaintext()
        keystream = chacha20_keystream(key, nonce, counter, len(plaintext))
        ciphertext = bytes(p ^ z for p, z in zip(plaintext, keystream))
        print("\n--- Result ---")
        print(f"Key (hex)        : {key.hex()}")
        print(f"Nonce (hex)      : {nonce.hex()}")
        print(f"Initial counter  : {counter}")
        print(f"Plaintext (hex)  : {plaintext.hex()}")
        print(f"Keystream (hex)  : {keystream.hex()}")
        print(f"Ciphertext (hex) : {ciphertext.hex()}")
        print(f"Ciphertext (b64) : {base64.b64encode(ciphertext).decode('ascii')}")
    else:
        ciphertext = read_ciphertext()
        keystream = chacha20_keystream(key, nonce, counter, len(ciphertext))
        plaintext = bytes(c ^ z for c, z in zip(ciphertext, keystream))
        print("\n--- Result ---")
        print(f"Key (hex)        : {key.hex()}")
        print(f"Nonce (hex)      : {nonce.hex()}")
        print(f"Initial counter  : {counter}")
        print(f"Ciphertext (hex) : {ciphertext.hex()}")
        print(f"Keystream (hex)  : {keystream.hex()}")
        print(f"Plaintext (hex)  : {plaintext.hex()}")
        print(f"Plaintext (UTF-8): {printable_utf8(plaintext)}")

    print("\nKey observation:")
    print("  Encryption and decryption are the same XOR operation.")
    print("  The same (key, nonce, counter) produces the same keystream.")
    print("  NEVER reuse a nonce with the same key for different messages.")
    print("  ChaCha20 alone provides confidentiality only — no authentication/integrity.")


def main() -> None:
    print("ChaCha20 Warm-up — Week 3")
    print("RFC 8439 IETF ChaCha20: 32-byte key, 12-byte nonce, 32-bit counter.")
    print("This program intentionally excludes Poly1305.\n")
    while True:
        try:
            run_once()
        except (ValueError, KeyboardInterrupt) as exc:
            print(f"\nStopped/error: {exc}")
        again = input("\nRun another example? [y/N]: ").strip().lower()
        if again not in {"y", "yes"}:
            break


if __name__ == "__main__":
    main()
