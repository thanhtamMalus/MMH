"""
05_common_modulus.py
====================

RSA Cryptanalysis Lab 05 — Common-Modulus Attack

LOCAL EDUCATIONAL DEMONSTRATION ONLY.

Scenario
--------
Two different RSA public exponents are incorrectly used with the SAME modulus n
to encrypt the SAME plaintext representative m with textbook/raw RSA:

    c1 = m^e1 mod n
    c2 = m^e2 mod n

If gcd(e1, e2) = 1, the extended Euclidean algorithm gives integers a,b:

    a*e1 + b*e2 = 1

Hence, when the needed modular inverses exist,

    m = c1^a * c2^b mod n.

No factorization of n and no private key are required.

This lab deliberately creates this misuse locally. It is NOT an attack on
proper RSA-OAEP or on external systems.

OpenSSL role
------------
OpenSSL:
  * generates two large 1024-bit primes for a ~2048-bit modulus;
  * validates two private keys that share n but use different public exponents;
  * demonstrates randomized RSA-OAEP as the secure comparison.

Python exposes the common-modulus mathematics directly.

Requires:
    openssl_config.py
    cryptography

Run:
    python 05_common_modulus.py
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

PRIME_BITS = 1024

# Deliberately different, coprime public exponents.
# 17 and 65537 are both odd and gcd(17,65537)=1.
E1 = 17
E2 = 65537

LAB_DIR = OUTPUT_DIR / "05_common_modulus"
KEY_DIR = LAB_DIR / "keys"
LAB_DIR.mkdir(parents=True, exist_ok=True)
KEY_DIR.mkdir(parents=True, exist_ok=True)

PRIVATE1 = KEY_DIR / "private_e17.pem"
PUBLIC1 = KEY_DIR / "public_e17.pem"
PRIVATE2 = KEY_DIR / "private_e65537.pem"
PUBLIC2 = KEY_DIR / "public_e65537.pem"

TEACHER_SECRET = LAB_DIR / "teacher_secret_parameters.txt"
ATTACKER_INPUT = LAB_DIR / "attacker_public_data.txt"
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
    print(f"{name:<14} bits={x.bit_length():4d}  0x{h}")


def write_values(path: Path, values: dict[str, int | str]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for name, value in values.items():
            f.write(f"{name} = {value}\n")


# =====================================================================
# OPENSSL PRIME GENERATION
# =====================================================================

def openssl_prime(bits: int) -> int:
    text = run_openssl_text(
        ["prime", "-generate", "-bits", str(bits)],
        verbose=False,
    ).strip()

    p = int(text)
    if p.bit_length() != bits:
        raise RuntimeError(f"Unexpected prime size: {p.bit_length()} bits")
    return p


# =====================================================================
# EXTENDED EUCLIDEAN ALGORITHM
# =====================================================================

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Return (g,x,y) such that:

        a*x + b*y = g = gcd(a,b)
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return old_r, old_s, old_t


def mod_power_signed(base: int, exponent: int, modulus: int) -> int:
    """
    Compute base^exponent mod modulus for a signed exponent.

    Negative exponent:
        base^(-k) = (base^{-1})^k mod modulus

    Python's modular inverse is used explicitly to make the cryptanalytic
    requirement visible.
    """
    if exponent >= 0:
        return pow(base, exponent, modulus)

    inverse = pow(base, -1, modulus)
    return pow(inverse, -exponent, modulus)


# =====================================================================
# CONSTRUCT TWO KEYS SHARING THE SAME MODULUS
# =====================================================================

def save_rsa_private(
    p: int,
    q: int,
    e: int,
    d: int,
    path: Path,
) -> None:
    pp, qq = (p, q) if p > q else (q, p)

    numbers = rsa.RSAPrivateNumbers(
        p=pp,
        q=qq,
        d=d,
        dmp1=d % (pp - 1),
        dmq1=d % (qq - 1),
        iqmp=pow(qq, -1, pp),
        public_numbers=rsa.RSAPublicNumbers(
            e=e,
            n=pp * qq,
        ),
    )

    key = numbers.private_key()
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def construct_common_modulus_keys():
    banner("SETUP — TWO RSA PUBLIC KEYS SHARE ONE ~2048-BIT MODULUS")

    print(
        f"Generating two independent {PRIME_BITS}-bit primes with OpenSSL...\n"
        f"Public exponents: e1={E1}, e2={E2}"
    )

    while True:
        p = openssl_prime(PRIME_BITS)
        q = openssl_prime(PRIME_BITS)

        if p == q:
            continue

        phi = (p - 1) * (q - 1)

        if math.gcd(E1, phi) != 1:
            continue
        if math.gcd(E2, phi) != 1:
            continue

        n = p * q
        if n.bit_length() < 2047:
            continue

        break

    d1 = pow(E1, -1, phi)
    d2 = pow(E2, -1, phi)

    save_rsa_private(p, q, E1, d1, PRIVATE1)
    save_rsa_private(p, q, E2, d2, PRIVATE2)

    if not verify_private_key(PRIVATE1, verbose=False):
        raise RuntimeError("OpenSSL rejected the e1 private key.")
    if not verify_private_key(PRIVATE2, verbose=False):
        raise RuntimeError("OpenSSL rejected the e2 private key.")

    run_openssl(
        ["pkey", "-in", PRIVATE1, "-pubout", "-out", PUBLIC1],
        verbose=False,
    )
    run_openssl(
        ["pkey", "-in", PRIVATE2, "-pubout", "-out", PUBLIC2],
        verbose=False,
    )

    print("\n[Teacher view]")
    print_bigint("p", p)
    print_bigint("q", q)
    print_bigint("n", n)
    print_bigint("d1", d1)
    print_bigint("d2", d2)

    print("\n[Public-key structure]")
    print(f"Key 1: (n, e1={E1})")
    print(f"Key 2: (n, e2={E2})")
    print(f"gcd(e1,e2) = {math.gcd(E1,E2)}")

    write_values(
        TEACHER_SECRET,
        {
            "p": p,
            "q": q,
            "phi": phi,
            "d1": d1,
            "d2": d2,
        },
    )

    return p, q, n, d1, d2


# =====================================================================
# VULNERABLE TEXTBOOK RSA ENCRYPTION
# =====================================================================

def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def int_to_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def create_vulnerable_ciphertexts(n: int, message: bytes):
    banner("VULNERABLE OPERATION — SAME n, SAME m, DIFFERENT e")

    m = bytes_to_int(message)

    if not 1 < m < n:
        raise RuntimeError("Message representative must satisfy 1 < m < n.")

    # For the signed-exponent attack below, ciphertexts must be invertible
    # modulo n. For a normal short message and secret large p,q this is
    # overwhelmingly likely, but check explicitly.
    if math.gcd(m, n) != 1:
        raise RuntimeError(
            "Message is not invertible modulo n; choose another classroom message."
        )

    c1 = pow(m, E1, n)
    c2 = pow(m, E2, n)

    print(f"Message: {message.decode('utf-8')}")
    print_bigint("m", m)
    print_bigint("n", n)

    print("\nTextbook RSA ciphertexts:")
    print(f"c1 = m^{E1} mod n")
    print_bigint("c1", c1)
    print(f"c2 = m^{E2} mod n")
    print_bigint("c2", c2)

    print("\nInvertibility checks needed for negative Bézout exponents:")
    print(f"gcd(c1,n) = {math.gcd(c1,n)}")
    print(f"gcd(c2,n) = {math.gcd(c2,n)}")

    with ATTACKER_INPUT.open("w", encoding="utf-8") as f:
        f.write(f"n={n}\n")
        f.write(f"e1={E1}\n")
        f.write(f"c1={c1}\n")
        f.write(f"e2={E2}\n")
        f.write(f"c2={c2}\n")

    return m, c1, c2


# =====================================================================
# COMMON-MODULUS ATTACK
# =====================================================================

def common_modulus_attack(
    n: int,
    e1: int,
    e2: int,
    c1: int,
    c2: int,
) -> tuple[int, int, int]:
    banner("ATTACK — BÉZOUT COEFFICIENTS + MODULAR INVERSES")

    print("[Attacker knows only]")
    print_bigint("n", n)
    print(f"e1 = {e1}")
    print(f"e2 = {e2}")
    print_bigint("c1", c1)
    print_bigint("c2", c2)

    g, a, b = extended_gcd(e1, e2)

    print("\nExtended Euclidean algorithm:")
    print(f"gcd(e1,e2) = {g}")
    print(f"a = {a}")
    print(f"b = {b}")
    print(f"a*e1 + b*e2 = {a*e1 + b*e2}")

    if g != 1:
        raise RuntimeError(
            "This basic common-modulus recovery requires gcd(e1,e2)=1."
        )

    print(
        "\nTherefore:\n"
        "    c1^a * c2^b\n"
        "  = m^(a*e1 + b*e2)\n"
        "  = m mod n"
    )

    try:
        part1 = mod_power_signed(c1, a, n)
        part2 = mod_power_signed(c2, b, n)
    except ValueError as exc:
        raise RuntimeError(
            "A ciphertext requiring inversion is not invertible modulo n."
        ) from exc

    recovered_m = (part1 * part2) % n

    print("\n[Recovered plaintext representative]")
    print_bigint("m", recovered_m)

    recovered_bytes = int_to_bytes(recovered_m)
    try:
        recovered_text = recovered_bytes.decode("utf-8")
    except UnicodeDecodeError:
        recovered_text = "<not valid UTF-8>"

    print(f"Recovered bytes: {recovered_bytes!r}")
    print(f"Recovered text : {recovered_text}")

    return recovered_m, a, b


# =====================================================================
# OAEP COUNTEREXAMPLE
# =====================================================================

def oaep_counterexample(message: bytes) -> None:
    """
    Demonstrate the protocol-level fix: randomized encoding.

    We use a normal OpenSSL RSA-2048 key and encrypt the same plaintext twice
    with OAEP/SHA-256. The resulting ciphertexts differ.

    The common-modulus algebra depends on both ciphertexts corresponding to
    the SAME integer representative m. OAEP prevents that raw deterministic
    relationship from being the protocol model.
    """
    banner("COUNTERMEASURE DEMO — RSA-OAEP RANDOMIZATION")

    priv = LAB_DIR / "oaep_control_private.pem"
    pub = LAB_DIR / "oaep_control_public.pem"
    msg = LAB_DIR / "oaep_message.bin"
    c1_path = LAB_DIR / "oaep_ciphertext1.bin"
    c2_path = LAB_DIR / "oaep_ciphertext2.bin"

    run_openssl(
        [
            "genpkey",
            "-algorithm", "RSA",
            "-pkeyopt", "rsa_keygen_bits:2048",
            "-out", priv,
        ],
        verbose=False,
    )

    run_openssl(
        ["pkey", "-in", priv, "-pubout", "-out", pub],
        verbose=False,
    )

    msg.write_bytes(message)

    def encrypt(out_path: Path) -> None:
        run_openssl(
            [
                "pkeyutl",
                "-encrypt",
                "-pubin",
                "-inkey", pub,
                "-in", msg,
                "-out", out_path,
                "-pkeyopt", "rsa_padding_mode:oaep",
                "-pkeyopt", "rsa_oaep_md:sha256",
                "-pkeyopt", "rsa_mgf1_md:sha256",
            ],
            verbose=False,
        )

    encrypt(c1_path)
    encrypt(c2_path)

    oaep1 = c1_path.read_bytes()
    oaep2 = c2_path.read_bytes()

    print("Same plaintext encrypted twice with RSA-OAEP/SHA-256:")
    print(f"Ciphertext 1 length: {len(oaep1)} bytes")
    print(f"Ciphertext 2 length: {len(oaep2)} bytes")
    print(f"Ciphertexts equal  : {oaep1 == oaep2}")

    if oaep1 == oaep2:
        raise RuntimeError("Unexpected identical OAEP ciphertexts.")

    print(
        "\nOAEP maps the same application plaintext to randomized encoded message\n"
        "representatives. The raw common-m relation exploited above is therefore\n"
        "not how proper RSA encryption should be used."
    )


# =====================================================================
# SUMMARY
# =====================================================================

def summary(
    n: int,
    original_m: int,
    recovered_m: int,
    a: int,
    b: int,
) -> None:
    banner("ATTACK → WEAKNESS → CONSEQUENCE → COUNTERMEASURE")

    print(f"RSA modulus size       : {n.bit_length()} bits")
    print(f"e1                     : {E1}")
    print(f"e2                     : {E2}")
    print(f"gcd(e1,e2)             : {math.gcd(E1,E2)}")
    print(f"Bézout coefficient a   : {a}")
    print(f"Bézout coefficient b   : {b}")
    print(f"Recovered m correct    : {recovered_m == original_m}")

    print(
        "\nATTACK\n"
        "  Extended Euclidean algorithm + modular exponentiation/inversion.\n\n"
        "WEAKNESS\n"
        "  The same RSA modulus n and same raw plaintext representative m are\n"
        "  reused with two coprime public exponents.\n\n"
        "WHY IT WORKS\n"
        "  Bézout gives a*e1+b*e2=1, so\n"
        "      c1^a c2^b = m^(a*e1+b*e2) = m (mod n).\n"
        "  A negative coefficient is handled with a modular inverse.\n\n"
        "CONSEQUENCE\n"
        "  The plaintext is recovered without factoring n and without finding d.\n\n"
        "COUNTERMEASURE\n"
        "  Do not share one RSA modulus across independently parameterized keys.\n"
        "  Never use textbook/raw RSA encryption. Use standardized RSA-OAEP or\n"
        "  a modern standardized hybrid-encryption design."
    )

    print(
        "\nCORE LESSON\n"
        "  RSA security depends on protocol-level key and message handling, not\n"
        "  merely on the difficulty of factoring a 2048-bit modulus."
    )


# =====================================================================
# MAIN
# =====================================================================

def main() -> None:
    banner("RSA CRYPTANALYSIS LAB 05 — COMMON-MODULUS ATTACK")

    print(
        "LOCAL EDUCATIONAL DEMONSTRATION\n"
        "This program deliberately constructs its own vulnerable RSA scenario.\n"
        "No external key, certificate, host, or service is targeted."
    )

    # 1. Create one large n but two RSA key pairs with different coprime e.
    p, q, n, d1, d2 = construct_common_modulus_keys()

    # 2. Deliberately encrypt the same integer representative under both keys.
    message = (
        b"Cryptography and Applications: RSA common modulus demonstration."
    )
    original_m, c1, c2 = create_vulnerable_ciphertexts(n, message)

    # 3. Recover m from public data alone.
    recovered_m, a, b = common_modulus_attack(
        n, E1, E2, c1, c2
    )

    recovered_bytes = int_to_bytes(recovered_m)

    if recovered_m != original_m or recovered_bytes != message:
        raise RuntimeError("Common-modulus plaintext recovery failed.")

    write_values(
        RECOVERY_REPORT,
        {
            "a": a,
            "b": b,
            "recovered_m": recovered_m,
            "recovered_utf8": recovered_bytes.decode("utf-8"),
            "success": str(recovered_m == original_m),
        },
    )

    # 4. Show why proper randomized encoding changes the protocol model.
    oaep_counterexample(message)

    # 5. Teaching synthesis.
    summary(n, original_m, recovered_m, a, b)

    print(f"\nLab artifacts saved under:\n  {LAB_DIR}")


if __name__ == "__main__":
    main()
