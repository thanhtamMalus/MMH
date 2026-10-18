# -*- coding: utf-8 -*-
"""
CBC_weakness_demo.py

Teaching-only local demonstrations for weaknesses of non-authenticated AES-CBC.

Demos included:
    1) CBC IV malleability / first-block modification:
       Change only the IV so that the decrypted first plaintext block changes
       from one numeric value to another, without changing the ciphertext body.

    2) Padding-oracle attack against a deliberately vulnerable API:
       Recover plaintext from IV||ciphertext using only an oracle that says
       whether PKCS#7 padding is valid. This demo runs locally against a toy
       oracle object. Do not expose padding errors in real systems.

Mitigations shown:
    - Encrypt-then-MAC for CBC: verify HMAC before decrypting/unpadding.
    - Prefer AEAD modes such as AES-GCM, AES-CCM, or AES-GCM-SIV.
    - Return one generic error for all decryption failures.

Requires:
    pip install cryptography

This file is for a controlled classroom/lab environment only.
"""

from __future__ import annotations

import argparse
import hmac
import os
import random
import secrets
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except Exception as exc:  # pragma: no cover
    raise SystemExit(
        "Missing dependency: cryptography. Install with: pip install cryptography"
    ) from exc

BLOCK_SIZE = 16


# -----------------------------------------------------------------------------
# Basic byte / padding helpers
# -----------------------------------------------------------------------------
def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes requires equal-length byte strings")
    return bytes(x ^ y for x, y in zip(a, b))


def chunks(data: bytes, n: int = BLOCK_SIZE) -> Iterable[bytes]:
    for i in range(0, len(data), n):
        yield data[i:i + n]


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(padded: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not padded or len(padded) % block_size != 0:
        raise ValueError("Invalid padded length")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding length")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding bytes")
    return padded[:-pad_len]


def is_valid_pkcs7_padding(padded: bytes, block_size: int = BLOCK_SIZE) -> bool:
    try:
        pkcs7_unpad(padded, block_size)
        return True
    except ValueError:
        return False


def aes_cbc_encrypt_raw(key: bytes, iv: bytes, padded_plaintext: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes")
    if len(padded_plaintext) % BLOCK_SIZE != 0:
        raise ValueError("CBC input must be block-aligned")
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    ).encryptor()
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def aes_cbc_decrypt_raw(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("CBC ciphertext must be block-aligned")
    decryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def aes_cbc_encrypt(key: bytes, plaintext: bytes, iv: Optional[bytes] = None) -> bytes:
    iv = iv or secrets.token_bytes(BLOCK_SIZE)
    return iv + aes_cbc_encrypt_raw(key, iv, pkcs7_pad(plaintext))


def aes_cbc_decrypt(key: bytes, token: bytes) -> bytes:
    if len(token) < 2 * BLOCK_SIZE or len(token) % BLOCK_SIZE != 0:
        raise ValueError("CBC token must be IV || ciphertext and block-aligned")
    iv, ciphertext = token[:BLOCK_SIZE], token[BLOCK_SIZE:]
    padded = aes_cbc_decrypt_raw(key, iv, ciphertext)
    return pkcs7_unpad(padded)


def printable_block(block: bytes) -> str:
    return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in block)


# -----------------------------------------------------------------------------
# Demo 1: CBC IV malleability
# -----------------------------------------------------------------------------
def craft_iv_for_desired_first_block(
    original_iv: bytes,
    original_first_plaintext_block: bytes,
    desired_first_plaintext_block: bytes,
) -> bytes:
    """
    CBC first-block equation:
        P1 = D_K(C1) XOR IV

    Therefore, for a desired P1':
        IV' = IV XOR P1 XOR P1'
    """
    if not (len(original_iv) == len(original_first_plaintext_block) == len(desired_first_plaintext_block) == BLOCK_SIZE):
        raise ValueError("IV, original block, and desired block must each be 16 bytes")
    return xor_bytes(xor_bytes(original_iv, original_first_plaintext_block), desired_first_plaintext_block)


def demo_iv_malleability() -> None:
    print("\n" + "=" * 78)
    print("DEMO 1 — CBC IV malleability: change numeric plaintext by changing only IV")
    print("=" * 78)

    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)

    # Exactly 16 bytes. We put a numeric field in block 1 so IV tampering affects it.
    original_block1 = b"amount=00000100;"
    desired_block1 = b"amount=90000100;"
    suffix = b" receiver=Bob; note=non-authenticated CBC demo"
    plaintext = original_block1 + suffix

    token = aes_cbc_encrypt(key, plaintext, iv=iv)
    original_iv, ciphertext_body = token[:BLOCK_SIZE], token[BLOCK_SIZE:]

    tampered_iv = craft_iv_for_desired_first_block(original_iv, original_block1, desired_block1)
    tampered_token = tampered_iv + ciphertext_body

    recovered_original = aes_cbc_decrypt(key, token)
    recovered_tampered = aes_cbc_decrypt(key, tampered_token)

    print(f"Key                  : {key.hex()}")
    print(f"Original IV          : {original_iv.hex()}")
    print(f"Tampered IV          : {tampered_iv.hex()}")
    print(f"Ciphertext body same?: {ciphertext_body == tampered_token[BLOCK_SIZE:]}")
    print()
    print(f"Original block 1     : {original_block1!r}  ({printable_block(original_block1)})")
    print(f"Desired block 1      : {desired_block1!r}  ({printable_block(desired_block1)})")
    print()
    print(f"Recovered original   : {recovered_original!r}")
    print(f"Recovered tampered   : {recovered_tampered!r}")
    print()
    print("Observation:")
    print("  CBC encryption alone does not authenticate the IV or ciphertext.")
    print("  Because P1 = D(C1) XOR IV, changing IV changes the first plaintext block")
    print("  in a predictable way. No decryption error occurs because the padding block")
    print("  was not damaged.")


# -----------------------------------------------------------------------------
# Demo 2: Padding oracle attack
# -----------------------------------------------------------------------------
@dataclass
class VulnerableCBCService:
    """
    Deliberately vulnerable local service.

    The vulnerability is not CBC itself; it is exposing a decryption side channel:
    different behavior for valid vs invalid PKCS#7 padding.
    """
    key: bytes
    queries: int = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        return aes_cbc_encrypt(self.key, plaintext)

    def padding_oracle(self, token: bytes) -> bool:
        """Return True only if padding is valid. This boolean leak is the vulnerability."""
        self.queries += 1
        if len(token) < 2 * BLOCK_SIZE or len(token) % BLOCK_SIZE != 0:
            return False
        iv, ciphertext = token[:BLOCK_SIZE], token[BLOCK_SIZE:]
        try:
            padded = aes_cbc_decrypt_raw(self.key, iv, ciphertext)
            return is_valid_pkcs7_padding(padded)
        except Exception:
            return False


@dataclass
class SecureCBCServiceEtM:
    """
    Safer CBC wrapper using Encrypt-then-MAC.

    Layout:
        IV || ciphertext || HMAC-SHA256(IV || ciphertext)

    Decryption verifies the HMAC before CBC decryption and padding removal.
    An attacker cannot query padding validity without first forging the MAC.
    """
    enc_key: bytes
    mac_key: bytes

    def encrypt(self, plaintext: bytes) -> bytes:
        token = aes_cbc_encrypt(self.enc_key, plaintext)
        tag = hmac_sha256(self.mac_key, token)
        return token + tag

    def decrypt(self, sealed: bytes) -> bytes:
        if len(sealed) < 2 * BLOCK_SIZE + 32:
            raise ValueError("Invalid message")
        token, tag = sealed[:-32], sealed[-32:]
        expected = hmac_sha256(self.mac_key, token)
        if not hmac.compare_digest(tag, expected):
            # Important: generic error. Do not reveal MAC-vs-padding details.
            raise ValueError("Invalid message")
        return aes_cbc_decrypt(self.enc_key, token)

    def generic_oracle(self, sealed: bytes) -> bool:
        """A safe service does not reveal padding validity; it only accepts/rejects the whole message."""
        try:
            self.decrypt(sealed)
            return True
        except Exception:
            return False


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()


def recover_intermediate_block(
    oracle: Callable[[bytes], bool],
    prev_block: bytes,
    target_block: bytes,
    *,
    random_guess_order: bool = True,
    verbose: bool = False,
) -> bytes:
    """
    Recover I = D_K(C_i) for one target block C_i using a padding oracle.

    CBC relation:
        P_i = D_K(C_i) XOR C_{i-1}

    Padding-oracle attacks recover the intermediate value I = D_K(C_i), byte by
    byte, by manipulating C_{i-1}' and observing whether padding is valid.
    """
    if len(prev_block) != BLOCK_SIZE or len(target_block) != BLOCK_SIZE:
        raise ValueError("prev_block and target_block must be 16 bytes")

    intermediate = bytearray(BLOCK_SIZE)
    crafted = bytearray(BLOCK_SIZE)
    prefix = b"A" * BLOCK_SIZE  # one extra block so modified prev block is not IV-only special case

    for pad_len in range(1, BLOCK_SIZE + 1):
        idx = BLOCK_SIZE - pad_len

        # Force already-solved suffix bytes to decrypt to the current pad value.
        for j in range(idx + 1, BLOCK_SIZE):
            crafted[j] = intermediate[j] ^ pad_len

        guesses: List[int] = list(range(256))
        if random_guess_order:
            random.shuffle(guesses)

        found = False
        for guess in guesses:
            crafted[idx] = guess
            trial = prefix + bytes(crafted) + target_block
            if not oracle(trial):
                continue

            # For pad_len=1, avoid a common false positive where the original
            # last-byte padding accidentally remains valid. Flip another byte
            # outside the padding area and require the oracle to stay valid.
            if pad_len == 1:
                check = bytearray(crafted)
                check[idx - 1] ^= 0x01
                if not oracle(prefix + bytes(check) + target_block):
                    continue

            intermediate[idx] = guess ^ pad_len
            found = True
            if verbose:
                recovered_plain_byte = intermediate[idx] ^ prev_block[idx]
                print(
                    f"  byte {idx:02d}: I={intermediate[idx]:02x}, "
                    f"P={recovered_plain_byte:02x} ({chr(recovered_plain_byte)!r} if printable)"
                )
            break

        if not found:
            raise RuntimeError(f"Failed to recover byte index {idx}")

    return bytes(intermediate)


def padding_oracle_attack(
    token: bytes,
    oracle: Callable[[bytes], bool],
    *,
    random_guess_order: bool = True,
    verbose: bool = False,
) -> bytes:
    """Recover the full plaintext from IV||ciphertext using only the padding oracle."""
    if len(token) < 2 * BLOCK_SIZE or len(token) % BLOCK_SIZE != 0:
        raise ValueError("token must be IV || ciphertext and block-aligned")

    blocks = list(chunks(token, BLOCK_SIZE))
    recovered_padded = bytearray()

    print(f"Padding-oracle attack target has {len(blocks) - 1} ciphertext block(s).")
    for block_index in range(1, len(blocks)):
        prev_block = blocks[block_index - 1]
        target_block = blocks[block_index]
        if verbose:
            print(f"\nRecovering plaintext block {block_index}/{len(blocks) - 1}...")
        intermediate = recover_intermediate_block(
            oracle,
            prev_block,
            target_block,
            random_guess_order=random_guess_order,
            verbose=verbose,
        )
        plain_block = xor_bytes(intermediate, prev_block)
        recovered_padded.extend(plain_block)
        print(f"  recovered block {block_index}: {plain_block.hex()}  {printable_block(plain_block)}")

    return pkcs7_unpad(bytes(recovered_padded))


def demo_padding_oracle_attack(verbose: bool = False, deterministic: bool = False) -> None:
    print("\n" + "=" * 78)
    print("DEMO 2 — Randomized padding-oracle attack against vulnerable CBC")
    print("=" * 78)

    if deterministic:
        random.seed(7)
        key = bytes.fromhex("00112233445566778899aabbccddeeff")
    else:
        key = secrets.token_bytes(16)

    service = VulnerableCBCService(key=key)
    secret_plaintext = (
        b"user=student;amount=00000100;role=user;"
        b"CBC without authentication leaks through padding errors."
    )
    token = service.encrypt(secret_plaintext)

    print(f"Oracle AES key, hidden from attacker : {key.hex()}")
    print(f"Target token IV||ciphertext hex       : {token.hex()}")
    print(f"Target token length                  : {len(token)} bytes")
    print("Attacker is allowed to query only: padding_valid(modified_token) -> True/False")
    print()

    recovered = padding_oracle_attack(
        token,
        service.padding_oracle,
        random_guess_order=not deterministic,
        verbose=verbose,
    )

    print("\nRecovered plaintext:")
    print(recovered)
    print(f"Oracle queries used: {service.queries}")
    print(f"Attack success     : {recovered == secret_plaintext}")
    print()
    print("Why this works:")
    print("  CBC decryption computes P_i = D(C_i) XOR C_{i-1}.")
    print("  By modifying C_{i-1} and observing only valid/invalid padding, the attacker")
    print("  learns D(C_i) byte by byte, then XORs with the real previous block to recover P_i.")


def demo_mitigation() -> None:
    print("\n" + "=" * 78)
    print("MITIGATION — Encrypt-then-MAC blocks the padding oracle")
    print("=" * 78)

    enc_key = secrets.token_bytes(16)
    mac_key = secrets.token_bytes(32)
    service = SecureCBCServiceEtM(enc_key=enc_key, mac_key=mac_key)
    plaintext = b"amount=00000100; receiver=Bob; authenticated CBC wrapper"
    sealed = service.encrypt(plaintext)

    print(f"Sealed format: IV || ciphertext || HMAC-SHA256")
    print(f"Sealed length: {len(sealed)} bytes")
    print(f"Valid message accepted: {service.generic_oracle(sealed)}")

    tampered = bytearray(sealed)
    tampered[0] ^= 0x01  # attempt IV tampering
    print(f"Tampered IV accepted : {service.generic_oracle(bytes(tampered))}")

    tampered = bytearray(sealed)
    tampered[-33] ^= 0x01  # attempt ciphertext tampering before tag
    print(f"Tampered CT accepted : {service.generic_oracle(bytes(tampered))}")

    print()
    print("Mitigation rules:")
    print("  1. Prefer AEAD modes: AES-GCM, AES-CCM, AES-GCM-SIV.")
    print("  2. If CBC is required, use Encrypt-then-MAC: verify MAC before decrypt/unpad.")
    print("  3. Authenticate IV, ciphertext, mode/version, and AAD/context.")
    print("  4. Return one generic failure message; never expose padding-vs-MAC errors.")
    print("  5. Use constant-time tag comparison and avoid timing differences in errors.")


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local teaching demos for AES-CBC malleability and padding-oracle weaknesses.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--demo",
        choices=["iv", "oracle", "mitigation", "all"],
        default="all",
        help="Which demo to run.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print byte-by-byte padding-oracle recovery details.",
    )
    parser.add_argument(
        "--deterministic",
        action="store_true",
        help="Use a fixed key and deterministic guess order for repeatable classroom output.",
    )
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    if args.demo in {"iv", "all"}:
        demo_iv_malleability()
    if args.demo in {"oracle", "all"}:
        demo_padding_oracle_attack(verbose=args.verbose, deterministic=args.deterministic)
    if args.demo in {"mitigation", "all"}:
        demo_mitigation()


if __name__ == "__main__":
    main()
