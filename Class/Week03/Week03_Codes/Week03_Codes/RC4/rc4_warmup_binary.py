#!/usr/bin/env python3
"""
RC4 Warm-up — Week 3: Stream Ciphers and Cryptanalysis

Purpose
-------
A small interactive program for first contact with RC4. Students can:
  * choose encryption or decryption;
  * enter a key manually (text/hex) or generate a random key;
  * enter plaintext/ciphertext as UTF-8 text, hexadecimal bytes, or a binary file;
  * observe that encryption and decryption use the SAME XOR operation.

Educational use only. RC4 is obsolete and must not be used to protect real data.
"""

from __future__ import annotations

import base64
import secrets
from typing import Iterable


# ---------------------------------------------------------------------------
# RC4 core
# ---------------------------------------------------------------------------

def rc4_ksa(key: bytes) -> list[int]:
    """RC4 Key Scheduling Algorithm (KSA)."""
    if not key:
        raise ValueError("RC4 key must not be empty.")
    if len(key) > 256:
        raise ValueError("For this teaching program, use a key of 1..256 bytes.")

    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return s


def rc4_keystream(key: bytes, n: int) -> bytes:
    """Generate n RC4 keystream bytes using KSA followed by PRGA."""
    if n < 0:
        raise ValueError("Number of keystream bytes must be non-negative.")

    s = rc4_ksa(key)
    i = j = 0
    out = bytearray()
    for _ in range(n):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        t = (s[i] + s[j]) % 256
        out.append(s[t])
    return bytes(out)


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """Encrypt OR decrypt data: output = data XOR RC4_keystream."""
    z = rc4_keystream(key, len(data))
    return bytes(a ^ b for a, b in zip(data, z))


# ---------------------------------------------------------------------------
# Input/output helpers
# ---------------------------------------------------------------------------

def ask_choice(prompt: str, choices: dict[str, str]) -> str:
    """Read one menu choice. choices maps accepted token -> description."""
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
        raise ValueError("Hex input must contain an even number of hex digits.")
    return bytes.fromhex(cleaned)


def read_key() -> bytes:
    mode = ask_choice(
        "\nKey source:",
        {
            "1": "manual UTF-8 text key",
            "2": "manual hexadecimal key",
            "3": "generate a random key",
        },
    )

    if mode == "1":
        key = input("Key text: ").encode("utf-8")
    elif mode == "2":
        while True:
            try:
                key = parse_hex(input("Key hex: "))
                break
            except ValueError as exc:
                print(f"Input error: {exc}")
    else:
        while True:
            raw = input("Random key length in bytes [16]: ").strip() or "16"
            try:
                n = int(raw)
                if not 1 <= n <= 256:
                    raise ValueError
                key = secrets.token_bytes(n)
                print(f"Generated key (hex): {key.hex()}")
                break
            except ValueError:
                print("Enter an integer from 1 to 256.")

    if not key:
        raise ValueError("Key must not be empty.")
    if len(key) > 256:
        raise ValueError("Use a key of 1..256 bytes for this exercise.")
    return key


def read_binary_file(prompt: str) -> bytes:
    """Read all bytes from a binary file."""
    while True:
        path = input(prompt).strip()
        try:
            with open(path, "rb") as f:
                return f.read()
        except OSError as exc:
            print(f"File error: {exc}")


def read_plaintext() -> bytes:
    mode = ask_choice(
        "\nPlaintext input format:",
        {"1": "UTF-8 text", "2": "hexadecimal bytes", "3": "binary file"},
    )
    if mode == "1":
        return input("Plaintext: ").encode("utf-8")
    if mode == "2":
        while True:
            try:
                return parse_hex(input("Plaintext hex: "))
            except ValueError as exc:
                print(f"Input error: {exc}")
    return read_binary_file("Plaintext binary file path: ")


def read_ciphertext() -> bytes:
    mode = ask_choice(
        "\nCiphertext input format:",
        {"1": "hexadecimal", "2": "Base64", "3": "binary file"},
    )
    if mode == "1":
        while True:
            try:
                return parse_hex(input("Ciphertext hex: "))
            except ValueError as exc:
                print(f"Input error: {exc}")
    if mode == "2":
        while True:
            try:
                return base64.b64decode(input("Ciphertext Base64: ").strip(), validate=True)
            except Exception:
                print("Invalid Base64 input.")
    return read_binary_file("Ciphertext binary file path: ")


def printable_utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return "<not valid UTF-8; use the hex output>"


# ---------------------------------------------------------------------------
# Interactive warm-up
# ---------------------------------------------------------------------------

def run_once() -> None:
    print("\n" + "=" * 72)
    print("RC4 WARM-UP: encryption/decryption are the same XOR operation")
    print("C = P XOR Z       P = C XOR Z")
    print("=" * 72)

    operation = ask_choice(
        "\nSelect operation:",
        {"1": "encrypt", "2": "decrypt"},
    )
    key = read_key()

    if operation == "1":
        plaintext = read_plaintext()
        keystream = rc4_keystream(key, len(plaintext))
        ciphertext = bytes(p ^ z for p, z in zip(plaintext, keystream))

        print("\n--- Result ---")
        print(f"Key (hex)       : {key.hex()}")
        print(f"Plaintext (hex) : {plaintext.hex()}")
        print(f"Keystream (hex) : {keystream.hex()}")
        print(f"Ciphertext (hex): {ciphertext.hex()}")
        print(f"Ciphertext (b64): {base64.b64encode(ciphertext).decode('ascii')}")
    else:
        ciphertext = read_ciphertext()
        keystream = rc4_keystream(key, len(ciphertext))
        plaintext = bytes(c ^ z for c, z in zip(ciphertext, keystream))

        print("\n--- Result ---")
        print(f"Key (hex)       : {key.hex()}")
        print(f"Ciphertext (hex): {ciphertext.hex()}")
        print(f"Keystream (hex) : {keystream.hex()}")
        print(f"Plaintext (hex) : {plaintext.hex()}")
        print(f"Plaintext (UTF-8): {printable_utf8(plaintext)}")

    print("\nObservation: the same key generates the same keystream; XOR reverses itself.")


def main() -> None:
    print("RC4 Warm-up — Week 3")
    print("Educational use only: RC4 is obsolete and provides no authentication.\n")
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
