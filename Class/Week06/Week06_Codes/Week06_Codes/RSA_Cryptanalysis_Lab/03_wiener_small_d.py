"""
03_wiener_small_d.py
====================

RSA Cryptanalysis Lab 03 — Wiener's Attack on RSA with a Small Private Exponent

Teaching objective
------------------
Construct a deliberately vulnerable ~2048-bit RSA public key (n, e) whose
private exponent d is abnormally small, then recover d using only public
information and Wiener's continued-fraction attack.

This is a LOCAL classroom demonstration. It creates its own vulnerable key
and does not attack third-party keys.

Mathematical idea
-----------------
RSA satisfies

    e*d - k*phi(n) = 1

so

    e / phi(n) ~= k / d.

Because phi(n) is close to n for balanced RSA primes,

    e / n ~= k / d.

If d is sufficiently small (classically, under Wiener's conditions,
roughly d < n^(1/4)/3), then k/d appears among the convergents of the
continued fraction expansion of e/n.

For a candidate (k, d):

    phi = (e*d - 1) / k
    s   = n - phi + 1 = p + q

and p,q are roots of

    x^2 - s*x + n = 0.

A perfect-square discriminant therefore validates the candidate.

OpenSSL role
------------
OpenSSL is used to:
  1. generate large 1024-bit primes p and q,
  2. validate the reconstructed vulnerable RSA private key,
  3. derive/inspect its public key,
  4. demonstrate a real RSA-OAEP/SHA-256 compromise.

Python big-integer arithmetic exposes the continued fractions and the
cryptanalytic reasoning.

Requirement
-----------
Place this file where it can import openssl_config.py.

The `cryptography` package is used only to serialize the deliberately
constructed/recovered RSA parameters into standard PEM files:

    pip install cryptography

Run:
    python 03_wiener_small_d.py
"""

from __future__ import annotations

import math
import secrets
import time
from pathlib import Path
from typing import Iterator

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from openssl_config import (
    OUTPUT_DIR,
    run_openssl,
    run_openssl_text,
    verify_private_key,
)


# =====================================================================
# LAB PARAMETERS
# =====================================================================

PRIME_BITS = 1024

# Choose d well below the classical Wiener scale n^(1/4)/3.
# For a ~2048-bit n, n^(1/4) is ~512 bits. A 384-bit d is therefore
# dramatically smaller while still being a genuinely huge integer.
TARGET_D_BITS = 384

LAB_DIR = OUTPUT_DIR / "03_wiener_small_d"
LAB_DIR.mkdir(parents=True, exist_ok=True)

TEACHER_SECRET = LAB_DIR / "teacher_secret_parameters.txt"
ATTACKER_INPUT = LAB_DIR / "attacker_public_key.txt"
RECOVERED_REPORT = LAB_DIR / "recovered_parameters.txt"

VULNERABLE_PRIVATE = LAB_DIR / "vulnerable_private.pem"
VULNERABLE_PUBLIC = LAB_DIR / "vulnerable_public.pem"
RECOVERED_PRIVATE = LAB_DIR / "recovered_private.pem"
RECOVERED_PUBLIC = LAB_DIR / "recovered_public.pem"


# =====================================================================
# DISPLAY / REPORT HELPERS
# =====================================================================

def banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def print_bigint(name: str, value: int, preview: int = 72) -> None:
    h = format(value, "x")
    if len(h) > preview:
        h = h[: preview // 2] + "..." + h[-preview // 2 :]
    print(f"{name:<14} bits={value.bit_length():4d}  0x{h}")


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

def generate_openssl_prime(bits: int) -> int:
    """Generate one cryptographic prime using OpenSSL."""
    text = run_openssl_text(
        ["prime", "-generate", "-bits", str(bits)],
        verbose=False,
    ).strip()

    p = int(text)
    if p.bit_length() != bits:
        raise RuntimeError(
            f"Unexpected OpenSSL prime size: {p.bit_length()} bits"
        )
    return p


def generate_balanced_distinct_primes() -> tuple[int, int]:
    """
    Generate independent same-size RSA primes.

    Wiener's classic setting assumes ordinary balanced RSA factors; the
    weakness introduced by this lab is SMALL d, not close-prime Fermat
    structure or shared-prime reuse.
    """
    while True:
        p = generate_openssl_prime(PRIME_BITS)
        q = generate_openssl_prime(PRIME_BITS)

        if p == q:
            continue

        n = p * q
        if n.bit_length() >= 2047:
            return p, q


# =====================================================================
# SMALL-d VULNERABLE KEY CONSTRUCTION
# =====================================================================

def choose_small_private_exponent(phi: int, n: int) -> int:
    """
    Choose an odd d satisfying:
        gcd(d, phi) = 1
        d < floor(n^(1/4))/3

    d is deliberately generated around TARGET_D_BITS.
    """
    fourth_root = math.isqrt(math.isqrt(n))
    bound = fourth_root // 3

    if (1 << (TARGET_D_BITS - 1)) >= bound:
        raise RuntimeError(
            "TARGET_D_BITS is not safely below the Wiener bound "
            "for the generated modulus."
        )

    while True:
        d = secrets.randbits(TARGET_D_BITS)
        d |= 1
        d |= 1 << (TARGET_D_BITS - 1)

        if d < bound and math.gcd(d, phi) == 1:
            return d


def rsa_private_numbers(
    p: int,
    q: int,
    d: int,
    e: int,
) -> rsa.RSAPrivateNumbers:
    """
    Build standard RSA private numbers.

    `cryptography` convention uses iqmp = q^{-1} mod p.
    """
    if q > p:
        p, q = q, p

    return rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=rsa.RSAPublicNumbers(e=e, n=p * q),
    )


def save_private_key(
    p: int,
    q: int,
    d: int,
    e: int,
    path: Path,
) -> None:
    key = rsa_private_numbers(p, q, d, e).private_key()
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def construct_vulnerable_key() -> tuple[int, int, int, int, int, int]:
    banner("SETUP — DELIBERATELY VULNERABLE LARGE RSA KEY")

    print(
        f"Generating two independent {PRIME_BITS}-bit primes with OpenSSL...\n"
        "The vulnerability will be introduced ONLY through an abnormally small d."
    )

    p, q = generate_balanced_distinct_primes()
    n = p * q
    phi = (p - 1) * (q - 1)

    d = choose_small_private_exponent(phi, n)
    e = pow(d, -1, phi)

    # ed - 1 is exactly divisible by phi.
    k = (e * d - 1) // phi

    fourth_root = math.isqrt(math.isqrt(n))
    wiener_reference_bound = fourth_root // 3

    print("\n[Teacher view — secret construction values]")
    print_bigint("p", p)
    print_bigint("q", q)
    print_bigint("n", n)
    print_bigint("phi(n)", phi)
    print_bigint("d", d)
    print_bigint("e", e)
    print_bigint("k", k)

    print("\n[Small-d diagnosis]")
    print(f"n^(1/4) bits        : {fourth_root.bit_length()}")
    print(f"d bits              : {d.bit_length()}")
    print(f"d < n^(1/4)/3       : {d < wiener_reference_bound}")

    if not (1 < e < n):
        raise RuntimeError(
            "Generated e is not in the expected RSA public-exponent range; "
            "regenerate the lab instance."
        )

    save_private_key(p, q, d, e, VULNERABLE_PRIVATE)

    if not verify_private_key(VULNERABLE_PRIVATE, verbose=False):
        raise RuntimeError("OpenSSL rejected the deliberately vulnerable RSA key.")

    run_openssl(
        [
            "pkey",
            "-in", VULNERABLE_PRIVATE,
            "-pubout",
            "-out", VULNERABLE_PUBLIC,
        ],
        verbose=False,
    )

    write_integer_report(
        TEACHER_SECRET,
        {
            "p": p,
            "q": q,
            "phi": phi,
            "d": d,
            "k": k,
        },
    )

    # Only public information is written to the attacker dataset.
    write_integer_report(
        ATTACKER_INPUT,
        {
            "n": n,
            "e": e,
        },
    )

    print("\n[Attacker-visible values]")
    print_bigint("n", n)
    print_bigint("e", e)
    print("The attacker is NOT given p, q, phi(n), d, or k.")

    return p, q, n, phi, e, d


# =====================================================================
# CONTINUED FRACTIONS
# =====================================================================

def continued_fraction(numerator: int, denominator: int) -> Iterator[int]:
    """
    Yield partial quotients of numerator/denominator.

    For Wiener's attack we expand e/n.
    """
    while denominator:
        a = numerator // denominator
        yield a
        numerator, denominator = denominator, numerator - a * denominator


def convergents(partials: Iterator[int]) -> Iterator[tuple[int, int]]:
    """
    Yield convergents h_i/k_i for a continued fraction.

    Recurrence:
        h_i = a_i*h_{i-1} + h_{i-2}
        k_i = a_i*k_{i-1} + k_{i-2}

    In Wiener's attack, each convergent is interpreted as candidate k/d.
    """
    h_m2, h_m1 = 0, 1
    k_m2, k_m1 = 1, 0

    for a in partials:
        h = a * h_m1 + h_m2
        k = a * k_m1 + k_m2

        yield h, k

        h_m2, h_m1 = h_m1, h
        k_m2, k_m1 = k_m1, k


# =====================================================================
# WIENER ATTACK
# =====================================================================

def wiener_attack(n: int, e: int) -> tuple[int, int, int, int, int]:
    """
    Recover (p, q, d, k, convergent_index) from public (n, e).

    Candidate convergent:
        k / d ~= e / n

    Validate candidate by reconstructing phi(n) and checking whether
    x^2 - (n-phi+1)x + n has integral roots.
    """
    banner("ATTACK — WIENER CONTINUED-FRACTION KEY RECOVERY")

    print("[Attacker knows only]")
    print_bigint("n", n)
    print_bigint("e", e)

    print(
        "\nCompute the continued fraction of e/n and examine convergents k/d.\n"
        "For each candidate:\n"
        "    phi_candidate = (e*d - 1) / k\n"
        "    s = n - phi_candidate + 1\n"
        "    Delta = s^2 - 4n\n"
        "A non-negative perfect-square Delta reveals p and q."
    )

    start = time.perf_counter()

    for index, (k_candidate, d_candidate) in enumerate(
        convergents(continued_fraction(e, n))
    ):
        if k_candidate == 0:
            continue

        ed_minus_1 = e * d_candidate - 1

        if ed_minus_1 % k_candidate != 0:
            continue

        phi_candidate = ed_minus_1 // k_candidate
        s = n - phi_candidate + 1

        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue

        t = math.isqrt(discriminant)
        if t * t != discriminant:
            continue

        if (s + t) % 2 != 0:
            continue

        p = (s + t) // 2
        q = (s - t) // 2

        if p > 1 and q > 1 and p * q == n:
            elapsed = time.perf_counter() - start

            if p > q:
                p, q = q, p

            print(
                f"\nSuccessful convergent index: {index}\n"
                f"Attack runtime             : {elapsed:.6f} s"
            )
            print_bigint("candidate k", k_candidate)
            print_bigint("recovered d", d_candidate)
            print_bigint("recovered p", p)
            print_bigint("recovered q", q)

            return p, q, d_candidate, k_candidate, index

    raise RuntimeError(
        "Wiener's attack did not recover the key. "
        "The generated instance may not satisfy the attack conditions."
    )


# =====================================================================
# RECONSTRUCT / VALIDATE RECOVERED KEY
# =====================================================================

def reconstruct_recovered_key(
    p: int,
    q: int,
    d: int,
    e: int,
) -> None:
    banner("KEY RECOVERY — BUILD A REAL PRIVATE KEY FROM THE ATTACK")

    save_private_key(p, q, d, e, RECOVERED_PRIVATE)

    print("Asking OpenSSL to validate the recovered private key...")
    valid = verify_private_key(RECOVERED_PRIVATE, verbose=False)
    print(f"OpenSSL private-key check: {valid}")

    if not valid:
        raise RuntimeError("OpenSSL rejected the Wiener-recovered private key.")

    run_openssl(
        [
            "pkey",
            "-in", RECOVERED_PRIVATE,
            "-pubout",
            "-out", RECOVERED_PUBLIC,
        ],
        verbose=False,
    )

    print(f"Recovered private key: {RECOVERED_PRIVATE}")
    print(f"Recovered public key : {RECOVERED_PUBLIC}")


# =====================================================================
# PRACTICAL PROOF OF COMPROMISE
# =====================================================================

def prove_compromise() -> None:
    banner("PROOF OF COMPROMISE — RSA-OAEP WITH THE WIENER-RECOVERED KEY")

    message_file = LAB_DIR / "message.txt"
    ciphertext_file = LAB_DIR / "ciphertext.bin"
    recovered_file = LAB_DIR / "recovered_message.txt"

    message = (
        "Wiener's attack recovered this deliberately weak RSA private key "
        "from public values n and e."
    )
    message_file.write_text(message, encoding="utf-8")

    # Encrypt exactly as a legitimate sender would: public key + OAEP.
    run_openssl(
        [
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey", VULNERABLE_PUBLIC,
            "-in", message_file,
            "-out", ciphertext_file,
            "-pkeyopt", "rsa_padding_mode:oaep",
            "-pkeyopt", "rsa_oaep_md:sha256",
            "-pkeyopt", "rsa_mgf1_md:sha256",
        ],
        verbose=False,
    )

    # Attacker decrypts using the reconstructed private key.
    run_openssl(
        [
            "pkeyutl",
            "-decrypt",
            "-inkey", RECOVERED_PRIVATE,
            "-in", ciphertext_file,
            "-out", recovered_file,
            "-pkeyopt", "rsa_padding_mode:oaep",
            "-pkeyopt", "rsa_oaep_md:sha256",
            "-pkeyopt", "rsa_mgf1_md:sha256",
        ],
        verbose=False,
    )

    recovered = recovered_file.read_text(encoding="utf-8")

    print(f"Original message : {message}")
    print(f"Recovered message: {recovered}")
    print(f"Recovery success : {message == recovered}")

    if recovered != message:
        raise RuntimeError("OAEP proof-of-compromise failed.")


# =====================================================================
# SUMMARY
# =====================================================================

def summary(
    original_p: int,
    original_q: int,
    n: int,
    e: int,
    original_d: int,
    recovered_p: int,
    recovered_q: int,
    recovered_d: int,
    convergent_index: int,
) -> None:
    banner("ATTACK → WEAKNESS → CONSEQUENCE → COUNTERMEASURE")

    factors_correct = (
        {original_p, original_q} == {recovered_p, recovered_q}
    )

    fourth_root = math.isqrt(math.isqrt(n))
    reference_bound = fourth_root // 3

    print(f"RSA modulus size          : {n.bit_length()} bits")
    print(f"Public exponent size      : {e.bit_length()} bits")
    print(f"Private exponent size     : {original_d.bit_length()} bits")
    print(f"n^(1/4) size              : {fourth_root.bit_length()} bits")
    print(f"d < n^(1/4)/3             : {original_d < reference_bound}")
    print(f"Successful convergent     : {convergent_index}")
    print(f"Recovered d correct       : {recovered_d == original_d}")
    print(f"Recovered factors correct : {factors_correct}")

    print(
        "\nATTACK\n"
        "  Continued-fraction expansion of the public ratio e/n.\n\n"
        "WEAKNESS\n"
        "  The private exponent d was deliberately chosen abnormally small.\n\n"
        "WHY IT WORKS\n"
        "  From e*d - k*phi(n)=1 and phi(n) close to n, k/d is an unusually\n"
        "  accurate rational approximation to e/n. Continued fractions expose\n"
        "  such approximations as convergents.\n\n"
        "CONSEQUENCE\n"
        "  Public values (n,e) are sufficient to recover d and then p,q for\n"
        "  this deliberately vulnerable key.\n\n"
        "COUNTERMEASURE\n"
        "  Do not choose a tiny RSA private exponent. Use established RSA key\n"
        "  generation implementations and standard parameter-generation rules.\n"
        "  The conventional small PUBLIC exponent e=65537 is not the weakness\n"
        "  demonstrated here."
    )

    print(
        "\nCORE LESSON\n"
        "  A large modulus alone does not guarantee RSA security. RSA parameter\n"
        "  relationships matter: making private operations faster by choosing\n"
        "  an excessively small d can destroy the intended hardness."
    )


# =====================================================================
# MAIN
# =====================================================================

def main() -> None:
    banner("RSA CRYPTANALYSIS LAB 03 — WIENER SMALL-d ATTACK")

    print(
        "LOCAL EDUCATIONAL DEMONSTRATION\n"
        "The program creates its own deliberately vulnerable ~2048-bit RSA key.\n"
        "No external key, certificate, host, or service is targeted."
    )

    # 1. Construct a balanced large RSA modulus but deliberately weak d.
    original_p, original_q, n, phi, e, original_d = construct_vulnerable_key()

    # 2. Attacker uses only public n,e.
    recovered_p, recovered_q, recovered_d, recovered_k, conv_index = (
        wiener_attack(n, e)
    )

    # 3. Confirm attack correctness.
    if recovered_d != original_d:
        raise RuntimeError("Recovered d does not match the hidden private exponent.")

    if {recovered_p, recovered_q} != {original_p, original_q}:
        raise RuntimeError("Recovered factors do not match the hidden factors.")

    write_integer_report(
        RECOVERED_REPORT,
        {
            "p": recovered_p,
            "q": recovered_q,
            "d": recovered_d,
            "k": recovered_k,
        },
    )

    # 4. Turn the recovered mathematical secret into a real PEM key.
    reconstruct_recovered_key(
        recovered_p,
        recovered_q,
        recovered_d,
        e,
    )

    # 5. Demonstrate practical decryption of standard OAEP ciphertext.
    prove_compromise()

    # 6. Teaching synthesis.
    summary(
        original_p,
        original_q,
        n,
        e,
        original_d,
        recovered_p,
        recovered_q,
        recovered_d,
        conv_index,
    )

    print(f"\nLab artifacts saved under:\n  {LAB_DIR}")


if __name__ == "__main__":
    main()
