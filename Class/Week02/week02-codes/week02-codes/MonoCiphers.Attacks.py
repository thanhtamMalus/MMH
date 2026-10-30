#!/usr/bin/env python3
import argparse
import string
from math import gcd
import random
from collections import Counter

ALPHABET = string.ascii_uppercase
M = len(ALPHABET)

# ================================================================
# 1. BRUTE-FORCE ATTACKS
# ================================================================

def caesar_bruteforce(cipher):
    """Try all Caesar shifts and return possible plaintexts."""
    results = []
    for shift in range(1, 26):
        pt = ''.join(
            ALPHABET[(ALPHABET.index(ch) - shift) % M] if ch in ALPHABET else ch
            for ch in cipher.upper()
        )
        results.append((shift, pt))
    return results


def affine_bruteforce(cipher):
    """Try all valid (a, b) pairs for Affine cipher."""
    results = []
    for a in range(1, M):
        if gcd(a, M) != 1:
            continue
        a_inv = pow(a, -1, M)
        for b in range(M):
            pt = ''.join(
                ALPHABET[(a_inv * (ALPHABET.index(ch) - b)) % M] if ch in ALPHABET else ch
                for ch in cipher.upper()
            )
            results.append(((a, b), pt))
    return results


def rotN_bruteforce(cipher):
    """ROT-N attack = Caesar brute force."""
    return caesar_bruteforce(cipher)


# ================================================================
# 2. FREQUENCY ANALYSIS + INTERACTIVE ATTACK
# ================================================================

ENGLISH_FREQ = {
    'E': 12.0, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
    'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
    'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
    'P': 1.9, 'B': 1.5, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
    'Q': 0.10, 'Z': 0.07
}


def print_key_mapping_table(mapping):
    """Display mapping in a neat substitution table."""
    plain_letters = list(ALPHABET)
    row1 = " ".join(f"{letter:2}" for letter in plain_letters)
    row2 = " " + "--" + "+--"*(len(plain_letters)-1) + " "
    row3 = " ".join(f"{mapping[letter]:2}" for letter in plain_letters)
    print(row1)
    print(row2)
    print(row3)


def decrypt_with_mapping(cipher, mapping):
    """Decrypt using current mapping (case preserved)."""
    result = []
    for char in cipher:
        if char.isalpha():
            if char.isupper():
                result.append(mapping.get(char, char))
            else:
                result.append(mapping.get(char.upper(), char.upper()).lower())
        else:
            result.append(char)
    return ''.join(result)


def substitution_interactive_attack(cipher):
    """Interactive substitution attack with manual key refinement."""
    # Step 1: Frequency-based guess
    freq_order = [x for x, _ in Counter(cipher.upper()).most_common() if x in ALPHABET]
    eng_order = sorted(ENGLISH_FREQ, key=ENGLISH_FREQ.get, reverse=True)
    mapping = dict(zip(ALPHABET, ALPHABET))  # start with identity
    for i, letter in enumerate(freq_order):
        if i < len(eng_order):
            mapping[letter] = eng_order[i]

    # Fill unused letters
    unused = [ch for ch in ALPHABET if ch not in mapping.values()]
    for ch in ALPHABET:
        if ch not in mapping:
            mapping[ch] = unused.pop() if unused else ch

    print("=== Interactive Substitution Attack ===")
    print_key_mapping_table(mapping)
    print("\nInitial Decryption Guess:")
    print(decrypt_with_mapping(cipher, mapping))

    # Step 2: Interactive refinement loop
    while True:
        cmd = input("\n[command: swap/set/show/decrypt/quit] > ").strip().split()
        if not cmd:
            continue
        action = cmd[0].lower()

        if action == "quit":
            break
        elif action == "show":
            print_key_mapping_table(mapping)
        elif action == "decrypt":
            print(decrypt_with_mapping(cipher, mapping))
        elif action == "swap" and len(cmd) == 3:
            a, b = cmd[1].upper(), cmd[2].upper()
            for k, v in mapping.items():
                if v == a: mapping[k] = b
                elif v == b: mapping[k] = a
            print("Swapped:", a, "<->", b)
        elif action == "set" and len(cmd) == 3:
            ciph, plain = cmd[1].upper(), cmd[2].upper()
            mapping[ciph] = plain
            print(f"Set {ciph} -> {plain}")
        else:
            print("Invalid command. Try again.")

    print("\nFinal Decryption:")
    print(decrypt_with_mapping(cipher, mapping))
    print("\nFinal Key Mapping:")
    print_key_mapping_table(mapping)


# ================================================================
# CLI HANDLER
# ================================================================
def main():
    parser = argparse.ArgumentParser(description="Cryptanalysis CLI Tool (Monoalphabetic)")
    parser.add_argument("attack", choices=["caesar", "affine", "rot", "substitution"],
                        help="Attack type")
    parser.add_argument("ciphertext", help="Ciphertext to analyze")

    args = parser.parse_args()

    if args.attack == "caesar":
        print("=== Caesar Brute Force ===")
        for shift, pt in caesar_bruteforce(args.ciphertext):
            print(f"[Shift={shift}] {pt}")

    elif args.attack == "affine":
        print("=== Affine Brute Force ===")
        for (a, b), pt in affine_bruteforce(args.ciphertext):
            print(f"[a={a}, b={b}] {pt}")

    elif args.attack == "rot":
        print("=== ROT-N Brute Force ===")
        for shift, pt in rotN_bruteforce(args.ciphertext):
            print(f"[ROT-{shift}] {pt}")

    elif args.attack == "substitution":
        substitution_interactive_attack(args.ciphertext)


if __name__ == "__main__":
    main()
