"""
04_broadcast_e3.py
==================

RSA Cryptanalysis Lab 04 — Håstad-Style Broadcast Attack for e = 3

LOCAL EDUCATIONAL DEMONSTRATION ONLY.

Scenario
--------
The SAME small plaintext integer m is sent with textbook/raw RSA to three
different recipients:

    c1 = m^3 mod n1
    c2 = m^3 mod n2
    c3 = m^3 mod n3

where the public moduli are pairwise coprime and all public exponents are e=3.

If:

    m^3 < n1*n2*n3,

the Chinese Remainder Theorem reconstructs the ordinary integer m^3 exactly.
The attacker then takes the exact integer cube root and recovers m.

This does NOT break properly padded RSA-OAEP. The vulnerability is:
    same message + small e + deterministic/raw RSA + enough recipients.

OpenSSL role
------------
OpenSSL generates six large primes (two per recipient) and validates the
three deliberately constructed RSA private keys. Python exposes the CRT and
integer-root cryptanalysis.

Requires:
    openssl_config.py
    cryptography

Run:
    python 04_broadcast_e3.py
"""

from __future__ import annotations

import math
from pathlib import Path

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

E = 3
PRIME_BITS = 1024
RECIPIENTS = 3

LAB_DIR = OUTPUT_DIR / "04_broadcast_e3"
KEY_DIR = LAB_DIR / "keys"
LAB_DIR.mkdir(parents=True, exist_ok=True)
KEY_DIR.mkdir(parents=True, exist_ok=True)

ATTACKER_INPUT = LAB_DIR / "attacker_public_data.txt"
TEACHER_SECRET = LAB_DIR / "teacher_secret.txt"
RECOVERY_REPORT = LAB_DIR / "recovery_report.txt"


# =====================================================================
# DISPLAY HELPERS
# =====================================================================

def banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def print_bigint(name: str, x: int, preview: int = 72) -> None:
    h = format(x, "x")
    if len(h) > preview:
        h = h[:preview // 2] + "..." + h[-preview // 2:]
    print(f"{name:<12} bits={x.bit_length():4d}  0x{h}")


def write_values(path: Path, values: dict[str, int | str]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for name, value in values.items():
            f.write(f"{name} = {value}\n")


# =====================================================================
# LARGE PRIME / RSA KEY CONSTRUCTION
# =====================================================================

def openssl_prime(bits: int) -> int:
    """Generate a prime using the configured OpenSSL installation."""
    text = run_openssl_text(
        ["prime", "-generate", "-bits", str(bits)],
        verbose=False,
    ).strip()
    p = int(text)
    if p.bit_length() != bits:
        raise RuntimeError("Unexpected OpenSSL prime length.")
    return p


def generate_e3_key(index: int) -> tuple[int, int, int, int]:
    """
    Construct one ~2048-bit RSA key with public exponent e=3.

    For e=3 to be invertible modulo phi(n), neither p-1 nor q-1 may be
    divisible by 3. We therefore regenerate until gcd(3, phi)=1.
    """
    while True:
        p = openssl_prime(PRIME_BITS)
        q = openssl_prime(PRIME_BITS)

        if p == q:
            continue

        phi = (p - 1) * (q - 1)
        if math.gcd(E, phi) != 1:
            continue

        n = p * q
        d = pow(E, -1, phi)
        break

    # Normalize order for cryptography's private-number representation.
    pp, qq = (p, q) if p > q else (q, p)

    numbers = rsa.RSAPrivateNumbers(
        p=pp,
        q=qq,
        d=d,
        dmp1=d % (pp - 1),
        dmq1=d % (qq - 1),
        iqmp=pow(qq, -1, pp),
        public_numbers=rsa.RSAPublicNumbers(e=E, n=n),
    )

    private_key = numbers.private_key()

    priv = KEY_DIR / f"recipient{index}_private.pem"
    pub = KEY_DIR / f"recipient{index}_public.pem"

    priv.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    if not verify_private_key(priv, verbose=False):
        raise RuntimeError(f"OpenSSL rejected recipient {index} key.")

    run_openssl(
        ["pkey", "-in", priv, "-pubout", "-out", pub],
        verbose=False,
    )

    return p, q, n, d


def generate_three_keys():
    banner("SETUP — THREE LARGE RSA RECIPIENTS WITH e = 3")

    keys = []
    moduli = []

    for i in range(1, RECIPIENTS + 1):
        print(f"Generating recipient {i}...")
        p, q, n, d = generate_e3_key(i)

        # Extremely unlikely with independent prime generation, but explicitly
        # reject accidental common factors so this remains a broadcast attack,
        # not the shared-prime attack from Lab 01.
        if any(math.gcd(n, old_n) != 1 for old_n in moduli):
            print("Accidental shared factor detected; regenerating complete set.")
            return generate_three_keys()

        keys.append((p, q, n, d))
        moduli.append(n)

        print_bigint(f"n{i}", n)

    print("\nPairwise GCD checks:")
    for i in range(RECIPIENTS):
        for j in range(i + 1, RECIPIENTS):
            print(
                f"gcd(n{i+1}, n{j+1}) = "
                f"{math.gcd(moduli[i], moduli[j])}"
            )

    return keys


# =====================================================================
# MESSAGE ENCODING
# =====================================================================

def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def int_to_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


# =====================================================================
# TEXTBOOK RSA BROADCAST
# =====================================================================

def raw_rsa_encrypt(m: int, n: int, e: int = E) -> int:
    """
    Textbook RSA mathematical operation.

    Intentionally NO OAEP and NO randomized encoding.
    This is exactly the misuse being demonstrated.
    """
    if not 0 <= m < n:
        raise ValueError("RSA message representative must satisfy 0 <= m < n.")
    return pow(m, e, n)


def create_broadcast_ciphertexts(keys, message: bytes):
    banner("VULNERABLE OPERATION — SAME MESSAGE, RAW RSA, e = 3")

    m = bytes_to_int(message)
    moduli = [item[2] for item in keys]

    if any(m >= n for n in moduli):
        raise RuntimeError("Message integer is too large for a recipient modulus.")

    product_n = math.prod(moduli)

    print(f"Message text : {message.decode('utf-8')}")
    print_bigint("m", m)
    print(f"\ne = {E}")

    print("\nCritical broadcast condition:")
    print(f"m^3 < n1*n2*n3 : {m**3 < product_n}")

    if not m**3 < product_n:
        raise RuntimeError(
            "Chosen message does not satisfy the classroom broadcast condition."
        )

    ciphertexts = [
        raw_rsa_encrypt(m, n, E)
        for n in moduli
    ]

    print("\nPublic ciphertexts:")
    for i, c in enumerate(ciphertexts, 1):
        print_bigint(f"c{i}", c)

    # Teacher-only record.
    write_values(
        TEACHER_SECRET,
        {
            "message_utf8": message.decode("utf-8"),
            "m": m,
            **{
                f"recipient{i}_p": keys[i-1][0]
                for i in range(1, 4)
            },
            **{
                f"recipient{i}_q": keys[i-1][1]
                for i in range(1, 4)
            },
            **{
                f"recipient{i}_d": keys[i-1][3]
                for i in range(1, 4)
            },
        },
    )

    # This file contains exactly what the attacker needs.
    with ATTACKER_INPUT.open("w", encoding="utf-8") as f:
        f.write(f"e={E}\n")
        for i, (n, c) in enumerate(zip(moduli, ciphertexts), 1):
            f.write(f"n{i}={n}\n")
            f.write(f"c{i}={c}\n")

    return m, moduli, ciphertexts


# =====================================================================
# CHINESE REMAINDER THEOREM
# =====================================================================

def crt(residues: list[int], moduli: list[int]) -> tuple[int, int]:
    """
    Reconstruct x modulo N = product(n_i):

        x == residues[i] (mod moduli[i])

    Pairwise-coprime moduli are required.
    """
    if len(residues) != len(moduli):
        raise ValueError("Residue/modulus count mismatch.")

    N = math.prod(moduli)
    x = 0

    for c_i, n_i in zip(residues, moduli):
        N_i = N // n_i

        if math.gcd(N_i, n_i) != 1:
            raise ValueError("CRT requires pairwise-coprime moduli.")

        inverse = pow(N_i, -1, n_i)
        x = (x + c_i * N_i * inverse) % N

    return x, N


# =====================================================================
# EXACT INTEGER CUBE ROOT
# =====================================================================

def integer_cube_root(n: int) -> tuple[int, bool]:
    """
    Return (floor(cuberoot(n)), exact).

    Uses integer binary search only; no floating point is used, so the
    operation remains exact even for multi-thousand-bit integers.
    """
    if n < 0:
        raise ValueError("Expected a non-negative integer.")
    if n < 2:
        return n, True

    # 2^ceil(bitlen/3) is a safe upper bound.
    high = 1 << ((n.bit_length() + 2) // 3)
    low = 0

    while low + 1 < high:
        mid = (low + high) // 2
        cube = mid * mid * mid

        if cube == n:
            return mid, True
        if cube < n:
            low = mid
        else:
            high = mid

    return low, (low * low * low == n)


# =====================================================================
# BROADCAST ATTACK
# =====================================================================

def broadcast_attack(
    moduli: list[int],
    ciphertexts: list[int],
) -> tuple[int, bytes]:
    banner("ATTACK — CRT + EXACT INTEGER CUBE ROOT")

    print(
        "The attacker has three public pairs (ni, ci) with the same e=3.\n"
        "CRT reconstructs x satisfying:\n"
        "    x = m^3 (mod n1)\n"
        "    x = m^3 (mod n2)\n"
        "    x = m^3 (mod n3)"
    )

    x, N = crt(ciphertexts, moduli)

    print("\n[CRT reconstruction]")
    print_bigint("N", N)
    print_bigint("x", x)
    print(f"x < N : {x < N}")

    recovered_m, exact = integer_cube_root(x)

    print("\n[Integer cube root]")
    print(f"Exact cube root: {exact}")
    print_bigint("recovered m", recovered_m)

    if not exact:
        raise RuntimeError(
            "CRT result was not an exact cube; broadcast conditions were not met."
        )

    recovered_bytes = int_to_bytes(recovered_m)

    try:
        recovered_text = recovered_bytes.decode("utf-8")
    except UnicodeDecodeError:
        recovered_text = "<not valid UTF-8>"

    print(f"Recovered bytes: {recovered_bytes!r}")
    print(f"Recovered text : {recovered_text}")

    return recovered_m, recovered_bytes


# =====================================================================
# OAEP COUNTEREXAMPLE
# =====================================================================

def oaep_counterexample(message: bytes) -> None:
    """
    Show the countermeasure concept with normal OpenSSL-generated RSA keys.

    We intentionally do NOT reuse the e=3 constructed keys here. The point is
    that standardized randomized OAEP encoding makes encryptions of the same
    message differ before the RSA exponentiation.

    Two encryptions under the same normal public key are enough to demonstrate
    OAEP randomization.
    """
    banner("COUNTERMEASURE DEMO — RSA-OAEP RANDOMIZES THE MESSAGE")

    control_priv = LAB_DIR / "oaep_control_private.pem"
    control_pub = LAB_DIR / "oaep_control_public.pem"
    msg_file = LAB_DIR / "oaep_message.txt"
    c1_file = LAB_DIR / "oaep_ciphertext1.bin"
    c2_file = LAB_DIR / "oaep_ciphertext2.bin"

    # Use OpenSSL's standard RSA key generator for the secure comparison.
    run_openssl(
        [
            "genpkey",
            "-algorithm", "RSA",
            "-pkeyopt", "rsa_keygen_bits:2048",
            "-out", control_priv,
        ],
        verbose=False,
    )

    run_openssl(
        ["pkey", "-in", control_priv, "-pubout", "-out", control_pub],
        verbose=False,
    )

    msg_file.write_bytes(message)

    base_command = [
        "pkeyutl",
        "-encrypt",
        "-pubin",
        "-inkey", control_pub,
        "-in", msg_file,
        "-pkeyopt", "rsa_padding_mode:oaep",
        "-pkeyopt", "rsa_oaep_md:sha256",
        "-pkeyopt", "rsa_mgf1_md:sha256",
    ]

    run_openssl(base_command + ["-out", c1_file], verbose=False)
    run_openssl(base_command + ["-out", c2_file], verbose=False)

    c1 = c1_file.read_bytes()
    c2 = c2_file.read_bytes()

    print("Same plaintext encrypted twice with RSA-OAEP/SHA-256.")
    print(f"Ciphertext 1 length : {len(c1)} bytes")
    print(f"Ciphertext 2 length : {len(c2)} bytes")
    print(f"Ciphertexts equal   : {c1 == c2}")

    if c1 == c2:
        raise RuntimeError(
            "Unexpected identical OAEP ciphertexts; randomization demonstration failed."
        )

    print(
        "\nOAEP introduces randomized encoding, so the raw deterministic relation\n"
        "ci = m^3 mod ni for one common integer m is no longer the protocol model."
    )


# =====================================================================
# SUMMARY
# =====================================================================

def summary(
    original_m: int,
    recovered_m: int,
    moduli: list[int],
) -> None:
    banner("ATTACK → WEAKNESS → CONSEQUENCE → COUNTERMEASURE")

    print(f"Recipients             : {len(moduli)}")
    print(f"Public exponent        : {E}")
    print(
        "Modulus sizes          : "
        + ", ".join(f"{n.bit_length()} bits" for n in moduli)
    )
    print(f"Recovered m correct    : {recovered_m == original_m}")

    print(
        "\nATTACK\n"
        "  Chinese Remainder Theorem followed by an exact integer cube root.\n\n"
        "WEAKNESS\n"
        "  The identical plaintext representative m is encrypted for at least\n"
        "  e=3 pairwise-coprime RSA moduli using deterministic textbook RSA.\n\n"
        "WHY IT WORKS\n"
        "  CRT reconstructs m^3 modulo N=n1*n2*n3. When m^3 < N, this modular\n"
        "  value is the ordinary integer m^3 itself, so taking the cube root\n"
        "  reveals m without factoring any modulus or recovering any private key.\n\n"
        "CONSEQUENCE\n"
        "  Plaintext recovery from public keys and ciphertexts alone.\n\n"
        "COUNTERMEASURE\n"
        "  Never use textbook/raw RSA encryption. Use RSA-OAEP with appropriate\n"
        "  parameters, or preferably use RSA only as part of a standardized\n"
        "  hybrid-encryption construction."
    )

    print(
        "\nCORE LESSON\n"
        "  e=3 is not by itself the complete vulnerability. The failure comes\n"
        "  from combining a small exponent with deterministic raw RSA and\n"
        "  broadcasting the same plaintext to enough independent recipients."
    )


# =====================================================================
# MAIN
# =====================================================================

def main() -> None:
    banner("RSA CRYPTANALYSIS LAB 04 — BROADCAST ATTACK WITH e = 3")

    print(
        "LOCAL EDUCATIONAL DEMONSTRATION\n"
        "This script creates its own RSA recipients and vulnerable ciphertexts.\n"
        "It does not target external keys, certificates, hosts, or services."
    )

    # 1. Create three independent ~2048-bit RSA recipients with e=3.
    keys = generate_three_keys()

    # 2. Broadcast one identical small message using deliberately raw RSA.
    message = (
        b"Cryptography and Applications: same message, raw RSA, e=3."
    )
    original_m, moduli, ciphertexts = create_broadcast_ciphertexts(
        keys, message
    )

    # 3. Recover plaintext from public data using CRT + cube root.
    recovered_m, recovered_bytes = broadcast_attack(
        moduli, ciphertexts
    )

    if recovered_m != original_m or recovered_bytes != message:
        raise RuntimeError("Broadcast plaintext recovery failed.")

    write_values(
        RECOVERY_REPORT,
        {
            "recovered_m": recovered_m,
            "recovered_utf8": recovered_bytes.decode("utf-8"),
            "success": str(recovered_m == original_m),
        },
    )

    # 4. Contrast the vulnerable construction with randomized OAEP.
    oaep_counterexample(message)

    # 5. Teaching synthesis.
    summary(original_m, recovered_m, moduli)

    print(f"\nLab artifacts saved under:\n  {LAB_DIR}")


if __name__ == "__main__":
    main()
