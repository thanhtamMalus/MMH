"""
07_crt_fault_demo_v2.py
====================

RSA Cryptanalysis Lab 07 — RSA-CRT Fault Attack (Bellcore-style principle)

LOCAL EDUCATIONAL DEMONSTRATION ONLY.

Purpose
-------
Show that a mathematically sound RSA key can be compromised when an
implementation releases a faulty CRT-RSA signature.

For RSA n = p*q, CRT signing computes

    dP = d mod (p-1)
    dQ = d mod (q-1)

    sP = m^dP mod p
    sQ = m^dQ mod q

and recombines the two residues.

This lab deliberately injects a fault into ONE local CRT branch before
recombination. If S is the correct signature and S_fault is the faulty one,
then one prime still divides their difference:

    gcd(S - S_fault, n) = p   or   q

Thus one faulty output can expose a factor of n and therefore the complete
private key.

The lab also demonstrates the public-data Bellcore consistency test:

    gcd(S_fault^e - m, n)

which can reveal the surviving correct CRT branch without requiring the
correct signature S.

Countermeasure demonstrated
---------------------------
Verify a CRT-produced signature with the public operation BEFORE releasing it:

    S^e mod n == m

A deliberately faulted signature fails this check and is blocked.

OpenSSL role
------------
OpenSSL is used to:
  * generate a real RSA-2048 key,
  * expose/parse its RSA parameters for this local lab,
  * validate a private key reconstructed after factor recovery.

Python is used to make the CRT computation and controlled fault explicit.

Requires:
    openssl_config.py
    cryptography

Run:
    python 07_crt_fault_demo_v2.py
"""

from __future__ import annotations

import math
import re
from pathlib import Path
import io
from contextlib import redirect_stdout
from datetime import datetime

from docx import Document
from docx.shared import Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from openssl_config import (
    OUTPUT_DIR,
    generate_rsa_keypair,
    run_openssl,
    run_openssl_text,
    verify_private_key,
)

# =====================================================================
# LAB PARAMETERS / PATHS
# =====================================================================

RSA_BITS = 2048

LAB_DIR = OUTPUT_DIR / "07_crt_fault_demo"
LAB_DIR.mkdir(parents=True, exist_ok=True)

REPORT_DOCX = LAB_DIR / "07_crt_fault_demo_analysis.docx"

PRIVATE_KEY = LAB_DIR / "original_private.pem"
PUBLIC_KEY = LAB_DIR / "original_public.pem"
RECOVERED_PRIVATE = LAB_DIR / "recovered_private.pem"
RECOVERED_PUBLIC = LAB_DIR / "recovered_public.pem"

PUBLIC_REPORT = LAB_DIR / "attacker_public_data.txt"
RECOVERY_REPORT = LAB_DIR / "recovery_report.txt"


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
    print(f"{name:<16} bits={value.bit_length():4d}  0x{h}")


# =====================================================================
# OPENSSL PARAMETER EXTRACTION
# =====================================================================

def _hex_block_after(label: str, text: str) -> int:
    """
    Parse a colon-separated OpenSSL hex block appearing after `label:`.

    Example:
        prime1:
            00:ab:cd:...
        prime2:
            ...
    """
    lines = text.splitlines()

    start = None
    for i, line in enumerate(lines):
        if line.strip().lower() == f"{label.lower()}:":
            start = i + 1
            break

    if start is None:
        raise RuntimeError(f"Could not find OpenSSL field: {label}")

    parts = []
    for line in lines[start:]:
        stripped = line.strip()

        if not stripped:
            break

        # Parameter labels terminate the hex block.
        if re.match(r"^[A-Za-z][A-Za-z0-9]*(?:\s+[A-Za-z0-9]+)*:$", stripped):
            break

        if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:)*[0-9a-fA-F]{2}:?", stripped):
            break

        parts.append(stripped.rstrip(":").replace(":", ""))

    if not parts:
        raise RuntimeError(f"Could not parse OpenSSL hex value: {label}")

    return int("".join(parts), 16)


def extract_private_parameters(private_key: Path) -> tuple[int, int, int, int]:
    """
    Read n,e,d,p,q from the locally generated key using OpenSSL text output.

    We need p and q only to SIMULATE the internal CRT signing operation.
    The attacker section below is intentionally given only public information
    plus released signature values.
    """
    text = run_openssl_text(
        ["pkey", "-in", private_key, "-text", "-noout"],
        verbose=False,
    )

    n = _hex_block_after("modulus", text)
    d = _hex_block_after("privateExponent", text)
    p = _hex_block_after("prime1", text)
    q = _hex_block_after("prime2", text)

    e = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("publicexponent:"):
            e = int(stripped.split(":", 1)[1].strip().split()[0])
            break

    if e is None:
        raise RuntimeError("Could not parse public exponent from OpenSSL.")

    if p * q != n:
        raise RuntimeError("Parsed OpenSSL RSA parameters are inconsistent.")

    return n, e, d, p, q


# =====================================================================
# RSA-CRT SIGNING
# =====================================================================

def crt_recombine(s_p: int, s_q: int, p: int, q: int) -> int:
    """
    Recombine:
        S == s_p (mod p)
        S == s_q (mod q)

    using qInv = q^{-1} mod p:

        h = qInv * (s_p - s_q) mod p
        S = s_q + q*h
    """
    q_inv = pow(q, -1, p)
    h = (q_inv * (s_p - s_q)) % p
    return (s_q + q * h) % (p * q)


def crt_sign_representative(
    m: int,
    d: int,
    p: int,
    q: int,
) -> tuple[int, int, int, int, int]:
    """
    Educational raw RSA signature representative.

    No signature padding is used because the goal is to expose the CRT
    arithmetic itself. Real applications should use standardized RSA-PSS.
    """
    n = p * q

    if not 0 < m < n:
        raise ValueError("Message representative must satisfy 0 < m < n.")

    d_p = d % (p - 1)
    d_q = d % (q - 1)

    s_p = pow(m, d_p, p)
    s_q = pow(m, d_q, q)
    signature = crt_recombine(s_p, s_q, p, q)

    return signature, s_p, s_q, d_p, d_q


# =====================================================================
# CONTROLLED FAULT INJECTION
# =====================================================================

def inject_single_branch_fault(
    s_p: int,
    s_q: int,
    p: int,
    q: int,
    *,
    branch: str = "p",
) -> tuple[int, int, int]:
    """
    Deliberately corrupt exactly one CRT residue.

    This models a computation fault for classroom analysis; it does NOT
    attempt to induce a physical fault in any external device.
    """
    if branch == "p":
        faulty_p = (s_p + 1) % p
        faulty_q = s_q
    elif branch == "q":
        faulty_p = s_p
        faulty_q = (s_q + 1) % q
    else:
        raise ValueError("branch must be 'p' or 'q'")

    faulty_signature = crt_recombine(
        faulty_p,
        faulty_q,
        p,
        q,
    )

    return faulty_signature, faulty_p, faulty_q


# =====================================================================
# LAB SETUP
# =====================================================================

def setup() -> tuple[int, int, int, int, int]:
    banner("SETUP — REAL OPENSSL RSA-2048 KEY")

    generate_rsa_keypair(
        PRIVATE_KEY,
        PUBLIC_KEY,
        bits=RSA_BITS,
        verbose=False,
    )

    if not verify_private_key(PRIVATE_KEY, verbose=False):
        raise RuntimeError("OpenSSL rejected the generated private key.")

    n, e, d, p, q = extract_private_parameters(PRIVATE_KEY)

    print(f"Private key : {PRIVATE_KEY}")
    print(f"Public key  : {PUBLIC_KEY}")
    print_bigint("n", n)
    print(f"e                = {e}")
    print_bigint("p", p)
    print_bigint("q", q)

    return n, e, d, p, q


# =====================================================================
# CORRECT AND FAULTY CRT COMPUTATION
# =====================================================================

def demonstrate_fault(
    n: int,
    e: int,
    d: int,
    p: int,
    q: int,
) -> tuple[int, int, int]:
    banner("PART 1 — CORRECT RSA-CRT SIGNATURE")

    # Use a compact integer representative so students can focus on CRT math.
    # It is intentionally raw RSA for this arithmetic demonstration.
    message = b"Week 04 RSA CRT fault demonstration"
    m = int.from_bytes(message, "big")

    if m >= n:
        raise RuntimeError("Message representative unexpectedly exceeds n.")

    signature, s_p, s_q, d_p, d_q = crt_sign_representative(
        m, d, p, q
    )

    print(f"Message          : {message.decode('utf-8')}")
    print_bigint("m", m)
    print_bigint("dP", d_p)
    print_bigint("dQ", d_q)
    print_bigint("sP", s_p)
    print_bigint("sQ", s_q)
    print_bigint("S correct", signature)

    verified = pow(signature, e, n) == m
    print(f"\nPublic verification S^e mod n == m : {verified}")

    if not verified:
        raise RuntimeError("Correct CRT signature failed verification.")

    banner("PART 2 — INJECT ONE LOCAL CRT-BRANCH FAULT")

    faulty_signature, faulty_p, faulty_q = inject_single_branch_fault(
        s_p, s_q, p, q, branch="p"
    )

    print("Injected fault:")
    print("    sP_fault = (sP + 1) mod p")
    print("    sQ_fault = sQ")
    print("\nRecombine the two branches normally.")

    print_bigint("sP faulty", faulty_p)
    print_bigint("sQ unchanged", faulty_q)
    print_bigint("S faulty", faulty_signature)

    faulty_verified = pow(faulty_signature, e, n) == m

    print(f"\nCorrect signature verifies : {verified}")
    print(f"Faulty signature verifies  : {faulty_verified}")

    if faulty_verified:
        raise RuntimeError("Injected fault unexpectedly produced a valid signature.")

    with PUBLIC_REPORT.open("w", encoding="utf-8") as f:
        f.write(f"n={n}\n")
        f.write(f"e={e}\n")
        f.write(f"m={m}\n")
        f.write(f"correct_signature={signature}\n")
        f.write(f"faulty_signature={faulty_signature}\n")

    return m, signature, faulty_signature


# =====================================================================
# ATTACK A — CORRECT + FAULTY SIGNATURE
# =====================================================================

def attack_from_signature_difference(
    n: int,
    correct_signature: int,
    faulty_signature: int,
) -> int:
    banner("PART 3 — FACTOR n FROM CORRECT AND FAULTY SIGNATURES")

    delta = (correct_signature - faulty_signature) % n
    factor = math.gcd(delta, n)

    print("Attacker computes:")
    print("    g = gcd(S - S_fault, n)\n")

    print_bigint("S - S_fault", delta)
    print_bigint("g", factor)

    if factor in (1, n):
        raise RuntimeError("Fault attack did not reveal a non-trivial factor.")

    other = n // factor

    print("\nRecovered factorization:")
    print_bigint("factor 1", factor)
    print_bigint("factor 2", other)
    print(f"factor1 * factor2 == n : {factor * other == n}")

    return factor


# =====================================================================
# ATTACK B — FAULTY SIGNATURE + PUBLIC MESSAGE ONLY
# =====================================================================

def attack_from_public_consistency(
    n: int,
    e: int,
    m: int,
    faulty_signature: int,
) -> int:
    banner("PART 4 — FACTOR n WITHOUT THE CORRECT SIGNATURE")

    print(
        "A stronger Bellcore-style consistency observation uses only:\n"
        "    public n, public e, message representative m, faulty S_fault\n\n"
        "Compute:\n"
        "    v = S_fault^e - m  (mod n)\n"
        "    g = gcd(v, n)"
    )

    v = (pow(faulty_signature, e, n) - m) % n
    factor = math.gcd(v, n)

    print_bigint("v", v)
    print_bigint("g", factor)

    if factor in (1, n):
        raise RuntimeError(
            "Public-consistency form did not reveal a non-trivial factor."
        )

    print_bigint("other factor", n // factor)
    print(f"Recovered n exactly : {factor * (n // factor) == n}")

    return factor


# =====================================================================
# PRIVATE-KEY RECOVERY
# =====================================================================

def reconstruct_private_key(
    n: int,
    e: int,
    factor: int,
) -> int:
    banner("PART 5 — RECONSTRUCT THE COMPLETE PRIVATE KEY")

    p = factor
    q = n // factor

    if p * q != n:
        raise RuntimeError("Recovered factor does not divide n.")

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

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
            n=n,
        ),
    )

    key = numbers.private_key()

    RECOVERED_PRIVATE.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    if not verify_private_key(RECOVERED_PRIVATE, verbose=False):
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

    print_bigint("recovered p", p)
    print_bigint("recovered q", q)
    print_bigint("recovered d", d)

    print("\nOpenSSL private-key validation: PASSED")
    print(f"Recovered private key: {RECOVERED_PRIVATE}")

    with RECOVERY_REPORT.open("w", encoding="utf-8") as f:
        f.write(f"p={p}\n")
        f.write(f"q={q}\n")
        f.write(f"d={d}\n")
        f.write("openssl_validation=PASSED\n")

    return d


# =====================================================================
# COUNTERMEASURE — VERIFY BEFORE RELEASE
# =====================================================================

def verify_before_release(
    signature: int,
    m: int,
    e: int,
    n: int,
) -> bool:
    """
    Simple public-operation consistency check.

    A CRT implementation can verify its computed signature before returning
    it to the caller. A faulted result must not be released.
    """
    return pow(signature, e, n) == m


def countermeasure_demo(
    m: int,
    correct_signature: int,
    faulty_signature: int,
    e: int,
    n: int,
) -> None:
    banner("PART 6 — COUNTERMEASURE: VERIFY BEFORE RELEASE")

    correct_ok = verify_before_release(
        correct_signature, m, e, n
    )
    faulty_ok = verify_before_release(
        faulty_signature, m, e, n
    )

    print("Before returning a CRT signature, compute:")
    print("    S^e mod n ?= m\n")

    print(f"Correct result passes check : {correct_ok}")
    print(f"Faulty result passes check  : {faulty_ok}")

    print("\nRelease policy:")
    print(
        "  Correct result : "
        + ("RELEASE" if correct_ok else "BLOCK")
    )
    print(
        "  Faulty result  : "
        + ("RELEASE" if faulty_ok else "BLOCK")
    )

    if not correct_ok or faulty_ok:
        raise RuntimeError("Countermeasure demonstration produced wrong result.")

    print(
        "\nThe deliberately faulted output is detected internally and never\n"
        "released to the attacker. Production implementations may additionally\n"
        "use hardened CRT computations, fault-detection techniques, blinding,\n"
        "and implementation-specific countermeasures."
    )


# =====================================================================
# SUMMARY
# =====================================================================

def summary(n: int, factor_a: int, factor_b: int) -> None:
    banner("ATTACK → WEAKNESS → CONSEQUENCE → COUNTERMEASURE")

    print(f"RSA modulus size                  : {n.bit_length()} bits")
    print(f"Difference attack recovered factor: {factor_a not in (1, n)}")
    print(f"Public-check attack recovered factor: {factor_b not in (1, n)}")

    print(
        "\nATTACK\n"
        "  Observe a faulty RSA-CRT signature and exploit the branch that still\n"
        "  satisfies the RSA relation modulo one secret prime.\n\n"
        "WEAKNESS\n"
        "  A fault corrupts only one CRT branch and the implementation releases\n"
        "  the resulting faulty signature.\n\n"
        "KEY RELATIONS\n"
        "  With correct S and faulty S~:\n"
        "      gcd(S - S~, n) -> secret factor\n\n"
        "  With public m,e and faulty S~:\n"
        "      gcd(S~^e - m, n) -> secret factor\n\n"
        "CONSEQUENCE\n"
        "  One factor reveals the other factor and permits reconstruction of d;\n"
        "  the complete RSA private key is compromised.\n\n"
        "COUNTERMEASURE\n"
        "  Verify CRT results before release, use hardened implementations and\n"
        "  appropriate fault-resistance measures. For signatures, use standard\n"
        "  schemes such as RSA-PSS rather than exposing raw RSA semantics."
    )

    print(
        "\nCORE LESSON\n"
        "  The RSA key and number theory can be perfectly sound while the system\n"
        "  still fails because implementation state was corrupted. Cryptographic\n"
        "  security therefore includes the computation, not only the equations."
    )


# =====================================================================
# DOCX REPORT
# =====================================================================

def save_transcript_to_docx(transcript: str, output_path: Path) -> None:
    """Save the complete RSA-CRT fault demonstration as a student Word report."""
    document = Document()

    section = document.sections[0]
    section.top_margin = Inches(0.65)
    section.bottom_margin = Inches(0.65)
    section.left_margin = Inches(0.75)
    section.right_margin = Inches(0.75)

    normal = document.styles["Normal"]
    normal.font.name = "Aptos"
    normal.font.size = Pt(10)

    title = document.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run(
        "RSA Cryptanalysis Lab 07\n"
        "RSA-CRT Fault Demonstration"
    )
    run.bold = True
    run.font.size = Pt(16)

    subtitle = document.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle.add_run(
        "Automatically generated student analysis report\n"
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    document.add_paragraph(
        "Purpose: preserve the complete output of the local educational "
        "RSA-CRT fault demonstration so students can analyze how an erroneous "
        "CRT computation can create a mathematically useful relation, compare "
        "correct and faulty results, and study implementation-level "
        "countermeasures such as verification before releasing an output."
    )

    document.add_heading("Complete Demonstration Output", level=1)

    for line in transcript.splitlines():
        p = document.add_paragraph()
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.line_spacing = 1.0
        r = p.add_run(line if line else " ")
        r.font.name = "Consolas"
        r.font.size = Pt(8.5)

    document.add_heading("Student Analysis Questions", level=1)
    questions = [
        "Why is the Chinese Remainder Theorem used to accelerate RSA private-key operations?",
        "Which part of the deliberately simulated CRT computation is corrupted in this demonstration?",
        "Why can a faulty CRT result reveal a non-trivial mathematical relation with the RSA modulus?",
        "How does comparing a correct result with a faulty result help explain the factor-recovery mechanism?",
        "Why is this an implementation/fault weakness rather than a direct failure of the RSA factoring assumption?",
        "What does the demonstration show about the difference between mathematically correct RSA and securely implemented RSA?",
        "How can recomputing or verifying an RSA result before releasing it mitigate CRT fault attacks?",
        "What additional implementation protections are appropriate for devices that perform RSA private-key operations?",
    ]
    for i, question in enumerate(questions, 1):
        document.add_paragraph(f"{i}. {question}")

    document.add_heading("Generated Lab Artifacts", level=1)
    document.add_paragraph(
        f"Lab directory: {LAB_DIR}\n"
        "See the complete transcript above for the generated RSA parameters, "
        "correct/faulty CRT results, recovery/verification results, and "
        "artifact paths produced by this local classroom run."
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    document.save(output_path)


# =====================================================================
# MAIN
# =====================================================================

def main() -> None:
    # Preserve the original local CRT-fault teaching workflow while capturing
    # its detailed output into a persistent DOCX report for student analysis.
    transcript_buffer = io.StringIO()

    with redirect_stdout(transcript_buffer):
        banner("RSA CRYPTANALYSIS LAB 07 — RSA-CRT FAULT DEMONSTRATION")

        print(
            "LOCAL EDUCATIONAL DEMONSTRATION\n"
            "The script generates its own RSA-2048 key and simulates a fault only in\n"
            "its own local CRT computation. No external device or service is targeted."
        )

        # 1. Generate a real RSA-2048 key using the configured OpenSSL.
        n, e, d, p, q = setup()

        # 2. Produce correct and deliberately faulty local CRT signatures.
        m, correct_signature, faulty_signature = demonstrate_fault(
            n, e, d, p, q
        )

        # 3. Classic correct-vs-faulty GCD recovery.
        factor_a = attack_from_signature_difference(
            n,
            correct_signature,
            faulty_signature,
        )

        # 4. Bellcore-style public consistency recovery.
        factor_b = attack_from_public_consistency(
            n,
            e,
            m,
            faulty_signature,
        )

        if factor_a not in (p, q):
            raise RuntimeError("Difference attack recovered the wrong factor.")

        if factor_b not in (p, q):
            raise RuntimeError("Public consistency attack recovered the wrong factor.")

        # Depending on which branch was corrupted, both attacks identify the
        # surviving correct prime. They should therefore agree here.
        if factor_a != factor_b:
            raise RuntimeError("The two fault-analysis methods disagree.")

        # 5. Reconstruct a real PEM private key and validate it with OpenSSL.
        reconstruct_private_key(n, e, factor_a)

        # 6. Show a direct implementation countermeasure.
        countermeasure_demo(
            m,
            correct_signature,
            faulty_signature,
            e,
            n,
        )

        # 7. Teaching synthesis.
        summary(n, factor_a, factor_b)

        print(f"\nLab artifacts saved under:\n  {LAB_DIR}")

    transcript = transcript_buffer.getvalue()
    save_transcript_to_docx(transcript, REPORT_DOCX)

    # Keep terminal output minimal; detailed results are in the Word report.
    print("RSA Cryptanalysis Lab 07 completed successfully.")
    print(f"Student analysis report saved to:\n  {REPORT_DOCX}")


if __name__ == "__main__":
    main()
