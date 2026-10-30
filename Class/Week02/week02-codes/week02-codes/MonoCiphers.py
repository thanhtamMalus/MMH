#!/usr/bin/env python3
import string
import random
from math import gcd
import argparse
from typing import Dict, List
import json

ALPHABET = string.ascii_uppercase
M = len(ALPHABET)

# --- 1. Simple Substitution Cipher ---
def generate_substitution_key():
    """Generate a random substitution key (dict)."""
    letters = list(ALPHABET)
    random.shuffle(letters)
    return dict(zip(ALPHABET, letters))

def parse_substitution_key(key_str: str):
    """
    Parse a 26-character key string into a substitution mapping.
    Example: "QWERTYUIOPASDFGHJKLZXCVBNM"
    """
    key_str = key_str.upper()
    if len(key_str) != 26 or len(set(key_str)) != 26:
        raise ValueError("Substitution key must contain 26 unique letters.")
    return dict(zip(ALPHABET, key_str))

def substitution_encrypt(text: str, key: dict) -> str:
    """Encrypt text using a substitution key (dict)."""
    return ''.join(key.get(ch, ch) for ch in text.upper())

def substitution_decrypt(cipher: str, key: dict) -> str:
    """Decrypt text using a substitution key (dict)."""
    inv_key = {v: k for k, v in key.items()}
    return ''.join(inv_key.get(ch, ch) for ch in cipher.upper())

# --- 2. Caesar Cipher (Shift) ---
def caesar(text: str, shift: int = 3, decrypt: bool = False) -> str:
    """
    Caesar cipher encryption/decryption.
    Key = shift (integer).
    """
    if not isinstance(shift, int):
        raise ValueError("Shift must be an integer.")
    shift = -shift if decrypt else shift
    return ''.join(
        ALPHABET[(ALPHABET.index(ch) + shift) % M] if ch in ALPHABET else ch
        for ch in text.upper()
    )

# --- 3. Atbash Cipher ---
def atbash(text):
    return ''.join(ALPHABET[M - 1 - ALPHABET.index(ch)] if ch in ALPHABET else ch for ch in text.upper())

# --- 4. Affine Cipher ---
def affine(text: str, a: int = 5, b: int = 8, decrypt: bool = False) -> str:
    """
    Affine cipher encryption/decryption.
    Key = (a, b) where gcd(a, 26) = 1.
    E(x) = (a*x + b) mod 26
    D(y) = a_inv * (y - b) mod 26
    """
    if gcd(a, M) != 1:
        raise ValueError(f"a={a} must be coprime with 26 for the Affine cipher.")

    if decrypt:
        a_inv = pow(a, -1, M)  # modular inverse of a mod 26
        return ''.join(
            ALPHABET[(a_inv * (ALPHABET.index(ch) - b)) % M] if ch in ALPHABET else ch
            for ch in text.upper()
        )
    else:
        return ''.join(
            ALPHABET[(a * ALPHABET.index(ch) + b) % M] if ch in ALPHABET else ch
            for ch in text.upper()
        )

def keyword_cipher(text: str, keyword: str = "SECRET", decrypt: bool = False, show_key: bool = False) -> str:
    """
    Keyword cipher: build substitution alphabet starting with keyword,
    then fill with remaining letters.
    Key = keyword (string, letters only).
    If show_key=True, also prints the substitution table.
    """
    # Clean keyword: uppercase, remove non-letters, drop duplicates
    keyword = ''.join(ch for ch in keyword.upper() if ch in ALPHABET)
    keyword = ''.join(sorted(set(keyword), key=keyword.index))
    
    # Build cipher alphabet
    rest = ''.join(ch for ch in ALPHABET if ch not in keyword)
    cipher_alphabet = keyword + rest

    # Build mappings
    mapping = dict(zip(ALPHABET, cipher_alphabet))
    inv_mapping = {v: k for k, v in mapping.items()}

    # Optionally display key matrix
    if show_key:
        print("Plain : " + " ".join(ALPHABET))
        print("Cipher: " + " ".join(cipher_alphabet))

    # Encrypt / Decrypt
    if decrypt:
        return ''.join(inv_mapping.get(ch, ch) for ch in text.upper())
    else:
        return ''.join(mapping.get(ch, ch) for ch in text.upper())

# --- 6. Homophonic Substitution (with JSON key option) ---
def load_homophonic_mapping(file_path: str = None):
    """
    Load homophonic mapping from a JSON file.
    If no file is given, use a default built-in mapping.
    """
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            mapping = json.load(f)
    else:
        # Default demo mapping (same as before)
        mapping = {
            'E': ['1', '!', 'Q', '9', 'X', '3'],
            'T': ['2', '$', 'Y', '+'],
            'A': ['@', '4', '7'],
            'O': ['0', 'O', '*'],
            'I': ['|', 'i', '8'],
            'N': ['~', 'n', '^'],
            'S': ['$', '5', '%'],
            'H': ['#', 'h', '&'],
            'R': ['R', '?', '4'],
            'D': ['D', ')'],
            'L': ['L', '/'],
            'C': ['C', '(', '['],
            'U': ['U', '_'],
            'M': ['M', '='],
            'W': ['W', '{'],
            'F': ['F', '}'],
            'G': ['G', ':'],
            'Y': ['Y', ';'],
            'P': ['P', '.'],
            'B': ['B', ','],
            'V': ['V', '<'],
            'K': ['K', '>'],
            'J': ['J', '`'],
            'X': ['X', '"'],
            'Q': ['Q', "'"],
            'Z': ['Z', '\\']
        }

    # Ensure all 26 letters exist (fallback self-mapping)
    for ch in ALPHABET:
        if ch not in mapping:
            mapping[ch] = [ch]
    return mapping

def homophonic_encrypt(text: str, mapping: dict) -> str:
    """Encrypt using homophonic substitution."""
    result = []
    for ch in text.upper():
        if ch in mapping:
            result.append(random.choice(mapping[ch]))
        else:
            result.append(ch)  # keep non-letters as is
    return ''.join(result)

def homophonic_decrypt(cipher: str, mapping: dict) -> str:
    """Decrypt homophonic ciphertext (many-to-one mapping)."""
    reverse = {}
    for k, vals in mapping.items():
        for v in vals:
            reverse[v] = k
    return ''.join(reverse.get(ch, ch) for ch in cipher)

# --- 7. Pigpen Cipher (with customizable symbols) ---

# Default simple placeholder Pigpen map (A=∆, B=⊡, ... etc.)
DEFAULT_PIGPEN_SYMBOLS = [
    "∆", "⊡", "□", "⊞", "⊟", "⊠", "◈", "◇", "◆", "◉", 
    "○", "◍", "◎", "●", "◐", "◑", "◒", "◓", "◔", "◕",
    "★", "✦", "✧", "✩", "✪", "✫"
]
DEFAULT_PIGPEN_MAP = dict(zip(ALPHABET, DEFAULT_PIGPEN_SYMBOLS))


def build_pigpen_map(custom_symbols: str = None):
    """
    Build Pigpen mapping. If custom_symbols is provided,
    it must contain 26 unique characters.
    """
    if custom_symbols:
        if len(custom_symbols) != 26:
            raise ValueError("Pigpen key must have exactly 26 symbols/characters.")
        return dict(zip(ALPHABET, list(custom_symbols)))
    else:
        return DEFAULT_PIGPEN_MAP


def pigpen_encrypt(text: str, mapping: dict) -> str:
    """Encrypt using Pigpen cipher with mapping."""
    return ''.join(mapping.get(ch, ch) for ch in text.upper())


def pigpen_decrypt(cipher: str, mapping: dict) -> str:
    """Decrypt Pigpen ciphertext (symbol-to-letter)."""
    inv = {v: k for k, v in mapping.items()}
    return ''.join(inv.get(ch, ch) for ch in cipher)


# --- 8. ROT-N Variants ---
def rotN(text, n=13):
    return ''.join(ALPHABET[(ALPHABET.index(ch) + n) % M] if ch in ALPHABET else ch for ch in text.upper())

# --- 9. Numeric Ciphers ---
def a1z26(text, decrypt=False):
    if decrypt:
        return ''.join(ALPHABET[int(p)-1] if p.isdigit() else p for p in text.split())
    else:
        return ' '.join(str(ALPHABET.index(ch) + 1) if ch in ALPHABET else ch for ch in text.upper())

# --- CLI Parser ---
def main():
    parser = argparse.ArgumentParser(description="Monoalphabetic Ciphers CLI Tool")
    parser.add_argument("cipher", choices=[
        "substitution", "caesar", "atbash", "affine", "keyword",
        "rot", "a1z26", "homophonic", "pigpen"
    ], help="Cipher to use")
    parser.add_argument("text", help="Input text")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt instead of encrypt")

    # Cipher-specific options
    parser.add_argument("--subkey", type=str, help="26-letter key for substitution cipher (e.g., QWERTYUIOPASDFGHJKLZXCVBNM)")
    parser.add_argument("--shift", type=int, default=3, help="Shift value (Caesar)")
    parser.add_argument("--a", type=int, default=5, help="Affine parameter a")
    parser.add_argument("--b", type=int, default=8, help="Affine parameter b")
    parser.add_argument("--keyword", type=str, default="SECRET", help="Keyword (Keyword cipher)")
    parser.add_argument("--showkey", action="store_true", 
                    help="Show the substitution table for keyword cipher")
    
    parser.add_argument("--homofile", type=str, help="Path to JSON file with homophonic mapping")
    parser.add_argument("--n", type=int, default=13, help="Rotation amount (ROT-N)")
    
    parser.add_argument("--pigpenkey", type=str, help="26-character custom Pigpen key (symbols or chars)")

    args = parser.parse_args()

    if args.cipher == "substitution":
        if not args.subkey:
            raise ValueError("Please provide --subkey for substitution cipher")
        key = parse_substitution_key(args.subkey)
        if args.decrypt:
            print(substitution_decrypt(args.text, key))
        else:
            print(substitution_encrypt(args.text, key))

    elif args.cipher == "caesar":
        print(caesar(args.text, shift=args.shift, decrypt=args.decrypt))

    elif args.cipher == "atbash":
        print(atbash(args.text))

    elif args.cipher == "affine":
        print(affine(args.text, a=args.a, b=args.b, decrypt=args.decrypt))

    elif args.cipher == "keyword":
        print(keyword_cipher(args.text, keyword=args.keyword, 
                            decrypt=args.decrypt, 
                            show_key=args.showkey))
    elif args.cipher == "rot":
        print(rotN(args.text, n=args.n))

    elif args.cipher == "a1z26":
        print(a1z26(args.text, decrypt=args.decrypt))

    elif args.cipher == "homophonic":
        # load mapping from file if provided, else use default
        mapping = load_homophonic_mapping(args.homofile)
        if args.decrypt:
            print(homophonic_decrypt(args.text, mapping))
        else:
            print(homophonic_encrypt(args.text, mapping))

    elif args.cipher == "pigpen":
        mapping = build_pigpen_map(args.pigpenkey)
        if args.decrypt:
            print(pigpen_decrypt(args.text, mapping))
        else:
            print(pigpen_encrypt(args.text, mapping))

if __name__ == "__main__":
    main()
