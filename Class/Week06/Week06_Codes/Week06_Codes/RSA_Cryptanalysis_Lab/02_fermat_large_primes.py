"""
02_fermat_large_primes.py
=========================

RSA Cryptanalysis Lab 02 — Fermat Factorization with Large Close Primes

Purpose
-------
Demonstrate that a ~2048-bit RSA modulus can be easy to factor when its two
secret primes are deliberately chosen too close together.

For odd n = p*q, Fermat writes:

    n = a^2 - b^2 = (a-b)(a+b)

If p and q are close, then:

    a = (p+q)/2

lies very near ceil(sqrt(n)), so only a small number of search steps is needed.

This is a LOCAL classroom demonstration. It constructs its own vulnerable
parameters and does not attack external keys.

OpenSSL role
------------
OpenSSL is used to:
  1. generate the first 1024-bit prime p,
  2. validate the reconstructed RSA private key,
  3. derive the public key,
  4. prove compromise using RSA-OAEP/SHA-256.

Python exposes the actual Fermat cryptanalysis using arbitrary-precision
integer arithmetic.

Requirement
-----------
Place this file where it can import openssl_config.py.

The `cryptography` package is used only to serialize the recovered RSA
parameters into a standard PKCS#8 PEM private key:

    pip install cryptography

Run:
    python 02_fermat_large_primes.py
"""

from __future__ import annotations

import math
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from openssl_config import (
    OUTPUT_DIR,
    DEFAULT_PUBLIC_EXPONENT,
    run_openssl,
    run_openssl_text,
    verify_private_key,
)


# =====================================================================
# LAB PARAMETERS
# =====================================================================

PRIME_BITS = 1024
E = DEFAULT_PUBLIC_EXPONENT

# Target number of Fermat iterations.
#
# We deliberately construct q so that Fermat needs a visible but small
# search rather than succeeding immediately. 20,000 iterations is normally
# fast enough for a classroom demonstration with Python big integers.
TARGET_FERMAT_STEPS = 20_000

LAB_DIR = OUTPUT_DIR / "02_fermat_large_primes"
LAB_DIR.mkdir(parents=True, exist_ok=True)

TEACHER_SECRET = LAB_DIR / "teacher_secret_parameters.txt"
ATTACKER_INPUT = LAB_DIR / "attacker_public_modulus.txt"
RECOVERED_FACTORS = LAB_DIR / "recovered_factors.txt"
RECOVERED_PRIVATE = LAB_DIR / "recovered_private.pem"
RECOVERED_PUBLIC = LAB_DIR / "recovered_public.pem"


# =====================================================================
# DISPLAY HELPERS
# =====================================================================

def banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def print_bigint(name: str, value: int, preview: int = 72) -> None:
    h = format(value, "x")
    if len(h) > preview:
        h = h[: preview // 2] + "..." + h[-preview // 2 :]
    print(f"{name:<12} bits={value.bit_length():4d}  0x{h}")


def write_integer_report(path: Path, values: dict[str, int]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for name, value in values.items():
            f.write(f"{name}\n")
            f.write(f"bits = {value.bit_length()}\n")
            f.write(f"decimal = {value}\n")
            f.write(f"hex = {value:x}\n\n")


# =====================================================================
# INTEGER MATH
# =====================================================================

def ceil_sqrt(n: int) -> int:
    r = math.isqrt(n)
    return r if r * r == n else r + 1


def is_square(n: int) -> tuple[bool, int]:
    if n < 0:
        return False, 0
    r = math.isqrt(n)
    return r * r == n, r


# =====================================================================
# OPENSSL PRIME GENERATION
# =====================================================================

def generate_openssl_prime(bits: int) -> int:
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


def next_prime_openssl(start: int) -> int:
    """
    Ask OpenSSL to return the first prime >= start.

    `openssl prime <decimal>` reports whether the supplied number is prime;
    OpenSSL's CLI is not a next-prime oracle. Therefore we test odd candidates
    with OpenSSL until a prime is found. This is used only during deliberate
    vulnerable-key construction, not during the attack.
    """
    candidate = start | 1

    while True:
        result = run_openssl(
            ["prime", str(candidate)],
            check=False,
            verbose=False,
        )
        text = result.stdout.decode("utf-8", errors="replace").lower()

        if result.returncode == 0 and "is prime" in text:
            return candidate

        candidate += 2


# =====================================================================
# CONSTRUCT A LARGE BUT FERMAT-WEAK MODULUS
# =====================================================================

def construct_vulnerable_modulus() -> tuple[int, int, int, int]:
    banner("SETUP — CONSTRUCT A ~2048-BIT RSA MODULUS WITH CLOSE PRIMES")

    print(f"Generating p as a genuine {PRIME_BITS}-bit OpenSSL prime...")
    p = generate_openssl_prime(PRIME_BITS)

    # Fermat's iteration count is approximately:
    #
    #   ((q-p)^2) / (8*sqrt(n))
    #
    # for close p and q.
    #
    # Choose an initial gap so the expected number of iterations is near
    # TARGET_FERMAT_STEPS:
    #
    #   gap ~= sqrt(8 * p * steps)
    #
    estimated_gap = math.isqrt(8 * p * TARGET_FERMAT_STEPS)

    # Keep q in the same 1024-bit range and find a nearby prime.
    q_start = p + max(estimated_gap, 2)
    if q_start % 2 == 0:
        q_start += 1

    print(
        "Constructing q deliberately close to p.\n"
        f"Target Fermat search length: about {TARGET_FERMAT_STEPS:,} iterations."
    )
    q = next_prime_openssl(q_start)

    if q == p:
        raise RuntimeError("Vulnerable-key construction produced identical primes.")

    # Ensure RSA exponent is usable. If not, move to another nearby prime.
    while math.gcd(E, (p - 1) * (q - 1)) != 1:
        q = next_prime_openssl(q + 2)

    n = p * q

    if n.bit_length() < 2047:
        raise RuntimeError("Constructed modulus is unexpectedly small.")

    print("\n[Secret key-generation values — teacher view]")
    print_bigint("p", p)
    print_bigint("q", q)
    print_bigint("|q-p|", abs(q - p))
    print_bigint("n", n)

    write_integer_report(
        TEACHER_SECRET,
        {"p": p, "q": q, "gap": abs(q - p)},
    )

    write_integer_report(
        ATTACKER_INPUT,
        {"n": n, "e": E},
    )

    print(
        "\n[Attacker-visible public information]\n"
        f"n: {n.bit_length()} bits\n"
        f"e: {E}\n\n"
        "The attacker is NOT given p, q, or their distance."
    )

    return p, q, n, abs(q - p)


# =====================================================================
# FERMAT FACTORIZATION
# =====================================================================

def fermat_factor(
    n: int,
    *,
    max_steps: int = 1_000_000,
    progress_every: int = 5_000,
) -> tuple[int, int, int]:
    """
    Factor an odd integer n using Fermat's difference-of-squares method.

        a = ceil(sqrt(n))
        b^2 = a^2 - n

    Increment a until b^2 is a perfect square.
    """
    if n <= 0 or n % 2 == 0:
        raise ValueError("Fermat demo expects a positive odd modulus.")

    a = ceil_sqrt(n)

    # Avoid recomputing a*a from scratch conceptually:
    # when a -> a+1,
    #
    # (a+1)^2 - n = (a^2-n) + 2a + 1.
    b2 = a * a - n

    start = time.perf_counter()

    for step in range(max_steps + 1):
        square, b = is_square(b2)

        if square:
            p = a - b
            q = a + b

            if p > 1 and p * q == n:
                elapsed = time.perf_counter() - start
                print(
                    f"\nPerfect square found after {step:,} Fermat iterations "
                    f"({elapsed:.4f} s)."
                )
                return p, q, step

        if progress_every and step and step % progress_every == 0:
            print(f"  searched {step:,} candidate values of a...")

        # Update b^2 for next a.
        b2 += 2 * a + 1
        a += 1

    raise RuntimeError(
        f"Fermat factorization failed within {max_steps:,} iterations."
    )


def run_attack(n: int) -> tuple[int, int, int]:
    banner("ATTACK — FERMAT DIFFERENCE-OF-SQUARES FACTORIZATION")

    print("[Attacker knows]")
    print_bigint("n", n)
    print(f"e            = {E}")

    a0 = ceil_sqrt(n)

    print("\nStart from:")
    print("    a0 = ceil(sqrt(n))")
    print("    b^2 = a^2 - n")
    print("\nSearch until b^2 becomes a perfect square.")
    print("Then:")
    print("    p = a - b")
    print("    q = a + b")

    p, q, steps = fermat_factor(n)

    if p > q:
        p, q = q, p

    print("\n[Recovered factors]")
    print_bigint("p", p)
    print_bigint("q", q)
    print_bigint("|q-p|", q - p)

    print("\nVerification:")
    print(f"p*q == n       : {p * q == n}")
    print(f"p < sqrt(n) < q: {p < math.isqrt(n) < q}")

    write_integer_report(
        RECOVERED_FACTORS,
        {"p": p, "q": q, "iterations": steps},
    )

    return p, q, steps


# =====================================================================
# RECONSTRUCT PRIVATE KEY
# =====================================================================

def reconstruct_private_key(p: int, q: int, e: int) -> int:
    banner("KEY RECOVERY — RECONSTRUCT THE RSA PRIVATE KEY")

    # cryptography accepts standard RSA private-number representation.
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
        public_numbers=rsa.RSAPublicNumbers(
            e=e,
            n=p * q,
        ),
    )

    private_key = numbers.private_key()

    RECOVERED_PRIVATE.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    print_bigint("d", d)

    print("\nAsking OpenSSL to validate the reconstructed key...")
    ok = verify_private_key(RECOVERED_PRIVATE, verbose=False)
    print(f"OpenSSL private-key check: {ok}")

    if not ok:
        raise RuntimeError("OpenSSL rejected the reconstructed private key.")

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

    return d


# =====================================================================
# PRACTICAL PROOF WITH OAEP
# =====================================================================

def prove_compromise() -> None:
    banner("PROOF OF COMPROMISE — RSA-OAEP WITH THE RECOVERED KEY")

    message_file = LAB_DIR / "message.txt"
    cipher_file = LAB_DIR / "ciphertext.bin"
    recovered_file = LAB_DIR / "recovered_message.txt"

    message = (
        "Fermat factorization recovered the factors of this deliberately "
        "weak large RSA modulus."
    )
    message_file.write_text(message, encoding="utf-8")

    print("Encrypting with RSA-OAEP/SHA-256 using the reconstructed public key...")

    run_openssl(
        [
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey", RECOVERED_PUBLIC,
            "-in", message_file,
            "-out", cipher_file,
            "-pkeyopt", "rsa_padding_mode:oaep",
            "-pkeyopt", "rsa_oaep_md:sha256",
            "-pkeyopt", "rsa_mgf1_md:sha256",
        ],
        verbose=False,
    )

    print("Decrypting with the private key recovered by Fermat factorization...")

    run_openssl(
        [
            "pkeyutl",
            "-decrypt",
            "-inkey", RECOVERED_PRIVATE,
            "-in", cipher_file,
            "-out", recovered_file,
            "-pkeyopt", "rsa_padding_mode:oaep",
            "-pkeyopt", "rsa_oaep_md:sha256",
            "-pkeyopt", "rsa_mgf1_md:sha256",
        ],
        verbose=False,
    )

    recovered = recovered_file.read_text(encoding="utf-8")

    print(f"\nOriginal : {message}")
    print(f"Recovered: {recovered}")
    print(f"Success  : {message == recovered}")

    if message != recovered:
        raise RuntimeError("OAEP proof-of-compromise failed.")


# =====================================================================
# OPTIONAL CONTRAST: WHY ORDINARY RSA DOES NOT FALL QUICKLY TO FERMAT
# =====================================================================

def estimate_random_key_difficulty(n: int, p: int, q: int) -> None:
    """
    Explain the structural reason for the attack without attempting an
    infeasible search on a secure random RSA-2048 key.
    """
    banner("STRUCTURAL DIAGNOSIS")

    if p > q:
        p, q = q, p

    a0 = ceil_sqrt(n)
    target_a = (p + q) // 2
    exact_steps = target_a - a0

    print_bigint("|q-p|", q - p)
    print(f"Actual Fermat iterations required: {exact_steps:,}")

    print(
        "\nThe attack is fast here because p and q were deliberately chosen close.\n"
        "This demonstration does NOT imply that Fermat efficiently factors a\n"
        "normally generated RSA-2048 modulus with independent random primes."
    )


# =====================================================================
# SUMMARY
# =====================================================================

def summary(
    original_p: int,
    original_q: int,
    recovered_p: int,
    recovered_q: int,
    n: int,
    steps: int,
) -> None:
    banner("ATTACK → WEAKNESS → CONSEQUENCE → COUNTERMEASURE")

    expected = {original_p, original_q}
    recovered = {recovered_p, recovered_q}

    print(f"RSA modulus size       : {n.bit_length()} bits")
    print(f"Prime sizes            : {original_p.bit_length()}, {original_q.bit_length()} bits")
    print(f"Fermat iterations      : {steps:,}")
    print(f"Factors recovered      : {expected == recovered}")

    print(
        "\nATTACK\n"
        "  Express n as a difference of squares:\n"
        "      n = a^2 - b^2 = (a-b)(a+b)\n\n"
        "WEAKNESS\n"
        "  The RSA primes p and q are unusually close.\n\n"
        "WHY IT WORKS\n"
        "  For n=pq, the successful value a=(p+q)/2 lies close to sqrt(n)\n"
        "  when |p-q| is small. Fermat therefore needs very few increments.\n\n"
        "CONSEQUENCE\n"
        "  Factoring n reveals p and q, which permits reconstruction of d and\n"
        "  the complete RSA private key.\n\n"
        "COUNTERMEASURE\n"
        "  Generate RSA primes independently using a well-tested cryptographic\n"
        "  implementation and CSPRNG; enforce appropriate key-generation checks.\n"
    )

    print(
        "CORE LESSON\n"
        "  RSA security depends not only on modulus length but also on how its\n"
        "  secret factors are generated. A 2048-bit-looking modulus can still\n"
        "  contain exploitable mathematical structure."
    )


# =====================================================================
# MAIN
# =====================================================================

def main() -> None:
    banner("RSA CRYPTANALYSIS LAB 02 — FERMAT ATTACK ON LARGE CLOSE PRIMES")

    print(
        "LOCAL EDUCATIONAL DEMONSTRATION\n"
        "The script deliberately constructs its own vulnerable ~2048-bit RSA\n"
        "modulus. No external key or service is targeted."
    )

    # 1. Construct one deliberately weak large RSA modulus.
    original_p, original_q, n, gap = construct_vulnerable_modulus()

    # 2. Attacker factors n using only the public modulus.
    recovered_p, recovered_q, steps = run_attack(n)

    # 3. Verify that the recovered factors are the hidden factors.
    if {original_p, original_q} != {recovered_p, recovered_q}:
        raise RuntimeError("Recovered factors do not match the generated factors.")

    # 4. Recover a complete RSA private key.
    reconstruct_private_key(recovered_p, recovered_q, E)

    # 5. Demonstrate practical compromise using standard OAEP operations.
    prove_compromise()

    # 6. Explain why this specially structured modulus was vulnerable.
    estimate_random_key_difficulty(n, original_p, original_q)

    # 7. Teaching synthesis.
    summary(
        original_p,
        original_q,
        recovered_p,
        recovered_q,
        n,
        steps,
    )

    print(f"\nLab artifacts saved under:\n  {LAB_DIR}")


if __name__ == "__main__":
    main()
