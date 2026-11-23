"""
01_shared_prime_gcd.py
======================

RSA Cryptanalysis Lab 01 — Shared-Prime GCD Key-Recovery Attack

Teaching objective
------------------
Demonstrate that RSA moduli may be very large and still be catastrophically
weak when key generation reuses a prime:

    n1 = p*q1
    n2 = p*q2

An attacker who knows only the public moduli computes:

    g = gcd(n1, n2) = p

and then factors both moduli:

    q1 = n1 // g
    q2 = n2 // g

The script deliberately constructs this vulnerable condition for a LOCAL
classroom experiment. It does not scan or attack third-party keys.

OpenSSL role
------------
OpenSSL is used to:
  1. generate large cryptographic primes,
  2. generate normal RSA-2048 control keys,
  3. validate reconstructed vulnerable RSA private keys,
  4. perform a local OAEP encryption/decryption proof of key recovery.

Python big-integer arithmetic exposes the cryptanalytic reasoning.

Requirement
-----------
Place this file beside/in the lab tree that can import:

    openssl_config.py

Then run:

    python 01_shared_prime_gcd.py
"""

from __future__ import annotations

import math
import shutil
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from openssl_config import (
    OUTPUT_DIR,
    DEFAULT_PUBLIC_EXPONENT,
    run_openssl,
    run_openssl_text,
    generate_rsa_keypair,
    verify_private_key,
)


# =====================================================================
# LAB PARAMETERS
# =====================================================================

# Two ~2048-bit moduli are created from three independently generated
# 1024-bit primes, with p deliberately reused.
PRIME_BITS = 1024
E = DEFAULT_PUBLIC_EXPONENT

LAB_DIR = OUTPUT_DIR / "01_shared_prime_gcd"
CONTROL_DIR = LAB_DIR / "control"
VULN_DIR = LAB_DIR / "vulnerable"
RECOVERED_DIR = LAB_DIR / "recovered"

for directory in (LAB_DIR, CONTROL_DIR, VULN_DIR, RECOVERED_DIR):
    directory.mkdir(parents=True, exist_ok=True)


# =====================================================================
# DISPLAY HELPERS
# =====================================================================

def banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def print_bigint(name: str, value: int, preview: int = 72) -> None:
    """Print bit length plus a compact hexadecimal preview."""
    h = format(value, "x")
    if len(h) > preview:
        shown = h[:preview // 2] + "..." + h[-preview // 2:]
    else:
        shown = h

    print(f"{name:<10} bits={value.bit_length():4d}  0x{shown}")


def write_integer_report(path: Path, values: dict[str, int]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for name, value in values.items():
            f.write(f"{name}\n")
            f.write(f"bits = {value.bit_length()}\n")
            f.write(f"decimal = {value}\n")
            f.write(f"hex = {value:x}\n\n")


# =====================================================================
# OPENSSL PRIME GENERATION
# =====================================================================

def generate_prime(bits: int) -> int:
    """
    Generate a cryptographic prime with OpenSSL.

    OpenSSL prints the prime as a decimal integer.
    """
    text = run_openssl_text(
        ["prime", "-generate", "-bits", str(bits)],
        verbose=False,
    ).strip()

    p = int(text)

    # Local sanity checks.
    if p.bit_length() != bits:
        raise RuntimeError(
            f"OpenSSL generated an unexpected prime size: {p.bit_length()} bits"
        )

    return p


def generate_distinct_primes() -> tuple[int, int, int]:
    """Generate p, q1, q2 and ensure all three are distinct."""
    while True:
        p = generate_prime(PRIME_BITS)
        q1 = generate_prime(PRIME_BITS)
        q2 = generate_prime(PRIME_BITS)

        if len({p, q1, q2}) != 3:
            continue

        n1 = p * q1
        n2 = p * q2

        # Ensure e is invertible modulo lambda/phi for both keys.
        phi1 = (p - 1) * (q1 - 1)
        phi2 = (p - 1) * (q2 - 1)

        if math.gcd(E, phi1) == 1 and math.gcd(E, phi2) == 1:
            return p, q1, q2


# =====================================================================
# RSA PRIVATE-KEY RECONSTRUCTION
# =====================================================================

def reconstruct_private_key(
    p: int,
    q: int,
    e: int,
    output_path: Path,
) -> int:
    """
    Reconstruct a standards-compatible RSA private key from recovered factors.

    The cryptanalytic step is NOT delegated to this function:
    p and q must already have been recovered by the GCD attack.

    Python computes d and CRT parameters; the 'cryptography' package serializes
    them as PKCS#8 PEM so OpenSSL can validate/use the reconstructed key.
    """
    if p == q:
        raise ValueError("RSA requires distinct primes.")

    # Keep p > q only for consistent presentation; RSA itself does not require
    # this ordering at the mathematical level.
    if q > p:
        p, q = q, p

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)

    numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=p * q),
    )

    key = numbers.private_key()

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    output_path.write_bytes(pem)
    return d


# =====================================================================
# CONTROL EXPERIMENT
# =====================================================================

def create_control_keys() -> None:
    """
    Generate two normal OpenSSL RSA-2048 keys and show that their moduli
    should not share a non-trivial factor.
    """
    banner("CONTROL — INDEPENDENT OPENSSL RSA-2048 KEYS")

    c1_priv = CONTROL_DIR / "control1_private.pem"
    c1_pub = CONTROL_DIR / "control1_public.pem"
    c2_priv = CONTROL_DIR / "control2_private.pem"
    c2_pub = CONTROL_DIR / "control2_public.pem"

    generate_rsa_keypair(c1_priv, c1_pub, bits=2048, verbose=False)
    generate_rsa_keypair(c2_priv, c2_pub, bits=2048, verbose=False)

    def modulus_from_public_key(pub: Path) -> int:
        text = run_openssl_text(
            ["pkey", "-pubin", "-in", pub, "-text", "-noout"],
            verbose=False,
        )

        # More robustly obtain n via `pkey -pubin -modulus`.
        # Some OpenSSL versions do not expose -modulus for pkey, so use rsa.
        mod_text = run_openssl_text(
            ["rsa", "-pubin", "-in", pub, "-modulus", "-noout"],
            verbose=False,
        ).strip()

        _, hex_n = mod_text.split("=", 1)
        return int(hex_n, 16)

    n1 = modulus_from_public_key(c1_pub)
    n2 = modulus_from_public_key(c2_pub)
    g = math.gcd(n1, n2)

    print_bigint("control n1", n1)
    print_bigint("control n2", n2)
    print(f"\ngcd(control n1, control n2) = {g}")
    print("Expected result: 1")

    if g != 1:
        raise RuntimeError(
            "Unexpected shared factor between independently generated control keys."
        )


# =====================================================================
# VULNERABLE KEY GENERATION
# =====================================================================

def construct_vulnerable_moduli() -> tuple[int, int, int, int, int]:
    banner("SETUP — DELIBERATELY VULNERABLE LARGE RSA MODULI")

    print(
        f"Generating three independent {PRIME_BITS}-bit primes with OpenSSL...\n"
        "The lab deliberately reuses p in TWO RSA moduli."
    )

    p, q1, q2 = generate_distinct_primes()

    n1 = p * q1
    n2 = p * q2

    print_bigint("p", p)
    print_bigint("q1", q1)
    print_bigint("q2", q2)

    print("\nConstructed public moduli:")
    print_bigint("n1", n1)
    print_bigint("n2", n2)

    write_integer_report(
        VULN_DIR / "teacher_secret_parameters.txt",
        {"p": p, "q1": q1, "q2": q2},
    )

    # This is the attacker-visible dataset.
    write_integer_report(
        VULN_DIR / "attacker_public_moduli.txt",
        {"n1": n1, "n2": n2, "e": E},
    )

    print(
        "\n[Weakness]\n"
        "n1 = p*q1\n"
        "n2 = p*q2\n"
        "The same prime p was reused because of a simulated key-generation/RNG failure."
    )

    return p, q1, q2, n1, n2


# =====================================================================
# CRYPTANALYSIS
# =====================================================================

def gcd_attack(n1: int, n2: int) -> tuple[int, int, int]:
    banner("ATTACK — GCD OF PUBLIC MODULI")

    print("[Attacker knows only]")
    print_bigint("n1", n1)
    print_bigint("n2", n2)
    print(f"e          = {E}")

    print("\nComputing:")
    print("    g = gcd(n1, n2)")

    g = math.gcd(n1, n2)

    if g in (1, n1, n2):
        raise RuntimeError(
            "No useful shared prime was recovered. Lab construction failed."
        )

    rq1 = n1 // g
    rq2 = n2 // g

    print("\n[Recovered factors]")
    print_bigint("g = p", g)
    print_bigint("q1", rq1)
    print_bigint("q2", rq2)

    print("\nVerification:")
    print(f"g*q1 == n1 : {g * rq1 == n1}")
    print(f"g*q2 == n2 : {g * rq2 == n2}")

    write_integer_report(
        RECOVERED_DIR / "recovered_factors.txt",
        {"p": g, "q1": rq1, "q2": rq2},
    )

    return g, rq1, rq2


# =====================================================================
# KEY RECOVERY + OPENSSL VALIDATION
# =====================================================================

def recover_private_keys(
    p: int,
    q1: int,
    q2: int,
) -> tuple[Path, Path]:
    banner("KEY RECOVERY — RECONSTRUCT BOTH RSA PRIVATE KEYS")

    k1 = RECOVERED_DIR / "recovered_private1.pem"
    k2 = RECOVERED_DIR / "recovered_private2.pem"

    d1 = reconstruct_private_key(p, q1, E, k1)
    d2 = reconstruct_private_key(p, q2, E, k2)

    print_bigint("d1", d1)
    print_bigint("d2", d2)

    print("\nAsking OpenSSL to validate reconstructed private keys...")

    ok1 = verify_private_key(k1, verbose=False)
    ok2 = verify_private_key(k2, verbose=False)

    print(f"OpenSSL validates key 1: {ok1}")
    print(f"OpenSSL validates key 2: {ok2}")

    if not (ok1 and ok2):
        raise RuntimeError("OpenSSL rejected a reconstructed RSA private key.")

    # Export public keys from the recovered private keys.
    pub1 = RECOVERED_DIR / "recovered_public1.pem"
    pub2 = RECOVERED_DIR / "recovered_public2.pem"

    run_openssl(
        ["pkey", "-in", k1, "-pubout", "-out", pub1],
        verbose=False,
    )
    run_openssl(
        ["pkey", "-in", k2, "-pubout", "-out", pub2],
        verbose=False,
    )

    return k1, k2


# =====================================================================
# PROOF OF COMPROMISE — LOCAL OAEP ROUND TRIP
# =====================================================================

def prove_compromise(recovered_private: Path) -> None:
    banner("PROOF OF COMPROMISE — OPENSSL RSA-OAEP")

    recovered_public = RECOVERED_DIR / "recovered_public1.pem"
    message = LAB_DIR / "secret_message.txt"
    ciphertext = LAB_DIR / "ciphertext.bin"
    plaintext = LAB_DIR / "recovered_plaintext.txt"

    original = (
        "RSA Cryptanalysis Lab: possession of the recovered factors "
        "allows reconstruction of the private key."
    )
    message.write_text(original, encoding="utf-8")

    print("Encrypting with the recovered public key using RSA-OAEP/SHA-256...")

    run_openssl(
        [
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey", recovered_public,
            "-in", message,
            "-out", ciphertext,
            "-pkeyopt", "rsa_padding_mode:oaep",
            "-pkeyopt", "rsa_oaep_md:sha256",
            "-pkeyopt", "rsa_mgf1_md:sha256",
        ],
        verbose=False,
    )

    print("Decrypting with the private key reconstructed from the GCD attack...")

    run_openssl(
        [
            "pkeyutl",
            "-decrypt",
            "-inkey", recovered_private,
            "-in", ciphertext,
            "-out", plaintext,
            "-pkeyopt", "rsa_padding_mode:oaep",
            "-pkeyopt", "rsa_oaep_md:sha256",
            "-pkeyopt", "rsa_mgf1_md:sha256",
        ],
        verbose=False,
    )

    recovered = plaintext.read_text(encoding="utf-8")

    print(f"\nOriginal message : {original}")
    print(f"Recovered message: {recovered}")
    print(f"Recovery success : {recovered == original}")

    if recovered != original:
        raise RuntimeError("Recovered private key failed the OAEP proof.")


# =====================================================================
# SUMMARY
# =====================================================================

def summary(
    original_p: int,
    recovered_p: int,
    n1: int,
    n2: int,
) -> None:
    banner("ATTACK → WEAKNESS → CONSEQUENCE → COUNTERMEASURE")

    print(f"Modulus 1 size       : {n1.bit_length()} bits")
    print(f"Modulus 2 size       : {n2.bit_length()} bits")
    print(f"Recovered factor size: {recovered_p.bit_length()} bits")
    print(f"Recovered p correct  : {recovered_p == original_p}")

    print(
        "\nATTACK\n"
        "  Compute gcd(n1, n2).\n\n"
        "WEAKNESS\n"
        "  Two independently presented RSA public keys reuse one secret prime.\n"
        "  Typical root cause: defective randomness or faulty key generation.\n\n"
        "CONSEQUENCE\n"
        "  Both public moduli factor immediately; both private keys can be rebuilt.\n\n"
        "COUNTERMEASURE\n"
        "  Use well-tested CSPRNG-backed key generation; never reuse RSA primes;\n"
        "  validate key-generation systems and, where appropriate, audit public\n"
        "  key sets for accidental common factors.\n"
    )

    print(
        "CORE LESSON\n"
        "  Large RSA numbers do not compensate for broken key-generation entropy.\n"
        "  The mathematical hardness assumption is bypassed rather than solved."
    )


# =====================================================================
# MAIN
# =====================================================================

def main() -> None:
    banner("RSA CRYPTANALYSIS LAB 01 — SHARED-PRIME GCD ATTACK")
    print(
        "LOCAL EDUCATIONAL DEMONSTRATION\n"
        "This program deliberately creates its own vulnerable RSA parameters.\n"
        "It does not inspect or attack external keys."
    )

    # 1. Normal reference case.
    create_control_keys()

    # 2. Deliberately introduce one key-generation weakness.
    p, q1, q2, n1, n2 = construct_vulnerable_moduli()

    # 3. Attacker uses only public information.
    recovered_p, recovered_q1, recovered_q2 = gcd_attack(n1, n2)

    # 4. Rebuild private keys from recovered factors.
    key1, key2 = recover_private_keys(
        recovered_p,
        recovered_q1,
        recovered_q2,
    )

    # 5. Demonstrate practical consequence with OpenSSL OAEP.
    prove_compromise(key1)

    # 6. Teaching synthesis.
    summary(p, recovered_p, n1, n2)

    print(f"\nLab artifacts saved under:\n  {LAB_DIR}")


if __name__ == "__main__":
    main()
