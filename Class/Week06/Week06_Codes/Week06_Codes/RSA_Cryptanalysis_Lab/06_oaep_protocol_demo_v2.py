"""
06_oaep_protocol_demo_v2.py
========================

RSA Cryptanalysis Lab 06 — OAEP and Protocol-Level Security Demonstration

LOCAL EDUCATIONAL DEMONSTRATION ONLY.

Goal
----
Move from mathematical RSA attacks to padding/protocol reasoning.

This lab demonstrates four facts with a real OpenSSL RSA-2048 key:

1. Textbook RSA is deterministic:
       c = m^e mod n
   so the same message gives the same ciphertext.

2. Textbook RSA is multiplicatively malleable:
       c' = c * r^e mod n
   decrypts to:
       m' = m*r mod n

3. RSA-OAEP/SHA-256 is randomized:
   encrypting the same plaintext repeatedly gives different ciphertexts.

4. OAEP provides encoded-message integrity checking:
   a modified ciphertext is rejected instead of yielding a useful modified
   plaintext.

The program additionally uses a LOCAL, deliberately simplified "oracle
simulator" to explain why protocol implementations must not reveal distinct
padding/decryption failure information. It does NOT implement an adaptive
padding-oracle exploit and does not contact any network service.

Requires:
    openssl_config.py

Run:
    python 06_oaep_protocol_demo_v2.py
"""

from __future__ import annotations

import math
from pathlib import Path
import io
from contextlib import redirect_stdout
from datetime import datetime

from docx import Document
from docx.shared import Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH

from openssl_config import (
    OUTPUT_DIR,
    run_openssl,
    run_openssl_text,
    generate_rsa_keypair,
    verify_private_key,
)

# =====================================================================
# LAB PATHS / PARAMETERS
# =====================================================================

LAB_DIR = OUTPUT_DIR / "06_oaep_protocol_demo"
LAB_DIR.mkdir(parents=True, exist_ok=True)

REPORT_DOCX = LAB_DIR / "06_oaep_protocol_demo_analysis.docx"

PRIVATE_KEY = LAB_DIR / "private.pem"
PUBLIC_KEY = LAB_DIR / "public.pem"

MESSAGE_FILE = LAB_DIR / "message.bin"

OAEP_C1 = LAB_DIR / "oaep_ciphertext_1.bin"
OAEP_C2 = LAB_DIR / "oaep_ciphertext_2.bin"
OAEP_C3 = LAB_DIR / "oaep_ciphertext_3.bin"
OAEP_RECOVERED = LAB_DIR / "oaep_recovered.bin"
OAEP_TAMPERED = LAB_DIR / "oaep_tampered.bin"
OAEP_TAMPERED_OUT = LAB_DIR / "oaep_tampered_output.bin"

RSA_BITS = 2048
OAEP_HASH = "sha256"
MGF1_HASH = "sha256"


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
        h = h[:preview // 2] + "..." + h[-preview // 2:]
    print(f"{name:<16} bits={value.bit_length():4d}  0x{h}")


# =====================================================================
# RSA PUBLIC NUMBERS FROM OPENSSL
# =====================================================================

def get_public_numbers(public_key: Path) -> tuple[int, int]:
    """
    Obtain n and e from the OpenSSL-generated public key.

    `openssl rsa -pubin -modulus` gives n.
    `openssl pkey -pubin -text` gives e.
    """
    modulus_text = run_openssl_text(
        ["rsa", "-pubin", "-in", public_key, "-modulus", "-noout"],
        verbose=False,
    ).strip()

    if "=" not in modulus_text:
        raise RuntimeError("Could not parse RSA modulus from OpenSSL.")

    n = int(modulus_text.split("=", 1)[1], 16)

    text = run_openssl_text(
        ["pkey", "-pubin", "-in", public_key, "-text", "-noout"],
        verbose=False,
    )

    e = None
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("exponent:"):
            # Example: Exponent: 65537 (0x10001)
            e = int(line.split(":", 1)[1].strip().split()[0])
            break

    if e is None:
        raise RuntimeError("Could not parse RSA public exponent from OpenSSL.")

    return n, e


# =====================================================================
# SETUP
# =====================================================================

def setup() -> tuple[int, int, bytes]:
    banner("SETUP — REAL OPENSSL RSA-2048 KEY")

    generate_rsa_keypair(
        PRIVATE_KEY,
        PUBLIC_KEY,
        bits=RSA_BITS,
        verbose=False,
    )

    if not verify_private_key(PRIVATE_KEY, verbose=False):
        raise RuntimeError("OpenSSL rejected the generated RSA private key.")

    n, e = get_public_numbers(PUBLIC_KEY)

    message = (
        b"Cryptography and Applications: RSA-OAEP protocol demonstration."
    )
    MESSAGE_FILE.write_bytes(message)

    print(f"Private key : {PRIVATE_KEY}")
    print(f"Public key  : {PUBLIC_KEY}")
    print_bigint("n", n)
    print(f"e                = {e}")
    print(f"Message          = {message.decode('utf-8')}")
    print(f"Message length   = {len(message)} bytes")

    return n, e, message


# =====================================================================
# PART 1 — TEXTBOOK RSA DETERMINISM
# =====================================================================

def textbook_rsa_determinism(n: int, e: int, message: bytes) -> int:
    banner("PART 1 — WHY TEXTBOOK RSA IS NOT A SECURE ENCRYPTION PROTOCOL")

    m = int.from_bytes(message, "big")

    if not 0 < m < n:
        raise RuntimeError("Message integer is outside the RSA range.")

    c1 = pow(m, e, n)
    c2 = pow(m, e, n)

    print("Textbook RSA:")
    print("    c = m^e mod n\n")

    print_bigint("m", m)
    print_bigint("c1", c1)
    print_bigint("c2", c2)

    print(f"\nSame message      : True")
    print(f"Same public key   : True")
    print(f"c1 == c2          : {c1 == c2}")

    print(
        "\nObservation:\n"
        "  Raw RSA encryption is deterministic. An observer can recognize\n"
        "  repeated plaintext representatives from repeated ciphertexts."
    )

    return c1


# =====================================================================
# PART 2 — TEXTBOOK RSA MALLEABILITY
# =====================================================================

def textbook_rsa_malleability(
    n: int,
    e: int,
    c: int,
) -> None:
    banner("PART 2 — TEXTBOOK RSA IS MULTIPLICATIVELY MALLEABLE")

    # Small r for transparent classroom mathematics.
    r = 2

    if math.gcd(r, n) != 1:
        raise RuntimeError("Unexpected non-invertible classroom multiplier.")

    re = pow(r, e, n)
    modified_c = (c * re) % n

    print("Original:")
    print("    c = m^e mod n")
    print("\nAttacker chooses r=2 and computes:")
    print("    c' = c * r^e mod n")
    print("\nThen RSA algebra gives:")
    print("    c' = (m*r)^e mod n")

    print_bigint("c", c)
    print_bigint("r^e mod n", re)
    print_bigint("c'", modified_c)

    print(
        "\nThe attacker changed the ciphertext in a mathematically predictable\n"
        "way without knowing the private key. This is why raw RSA does not\n"
        "provide the security properties expected from an encryption protocol."
    )


# =====================================================================
# OAEP COMMAND HELPERS
# =====================================================================

def oaep_encrypt(input_file: Path, output_file: Path):
    return run_openssl(
        [
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey", PUBLIC_KEY,
            "-in", input_file,
            "-out", output_file,
            "-pkeyopt", "rsa_padding_mode:oaep",
            "-pkeyopt", f"rsa_oaep_md:{OAEP_HASH}",
            "-pkeyopt", f"rsa_mgf1_md:{MGF1_HASH}",
        ],
        verbose=False,
    )


def oaep_decrypt(
    input_file: Path,
    output_file: Path,
    *,
    check: bool = True,
):
    return run_openssl(
        [
            "pkeyutl",
            "-decrypt",
            "-inkey", PRIVATE_KEY,
            "-in", input_file,
            "-out", output_file,
            "-pkeyopt", "rsa_padding_mode:oaep",
            "-pkeyopt", f"rsa_oaep_md:{OAEP_HASH}",
            "-pkeyopt", f"rsa_mgf1_md:{MGF1_HASH}",
        ],
        check=check,
        verbose=False,
    )


# =====================================================================
# PART 3 — OAEP RANDOMIZATION
# =====================================================================

def oaep_randomization(message: bytes) -> None:
    banner("PART 3 — RSA-OAEP RANDOMIZATION")

    oaep_encrypt(MESSAGE_FILE, OAEP_C1)
    oaep_encrypt(MESSAGE_FILE, OAEP_C2)
    oaep_encrypt(MESSAGE_FILE, OAEP_C3)

    c1 = OAEP_C1.read_bytes()
    c2 = OAEP_C2.read_bytes()
    c3 = OAEP_C3.read_bytes()

    print(
        f"Encrypting the SAME message three times with the SAME RSA public key\n"
        f"using OAEP/{OAEP_HASH.upper()}."
    )

    print(f"\nCiphertext 1: {len(c1)} bytes")
    print(f"  {c1.hex()[:96]}...")
    print(f"Ciphertext 2: {len(c2)} bytes")
    print(f"  {c2.hex()[:96]}...")
    print(f"Ciphertext 3: {len(c3)} bytes")
    print(f"  {c3.hex()[:96]}...")

    print("\nEquality tests:")
    print(f"C1 == C2 : {c1 == c2}")
    print(f"C1 == C3 : {c1 == c3}")
    print(f"C2 == C3 : {c2 == c3}")

    if len({c1, c2, c3}) != 3:
        raise RuntimeError(
            "Unexpected OAEP ciphertext collision in classroom demonstration."
        )

    # Normal decryption check.
    oaep_decrypt(OAEP_C1, OAEP_RECOVERED)
    recovered = OAEP_RECOVERED.read_bytes()

    print(f"\nNormal OAEP decryption succeeds: {recovered == message}")

    if recovered != message:
        raise RuntimeError("Normal OAEP round trip failed.")


# =====================================================================
# PART 4 — OAEP TAMPER REJECTION
# =====================================================================

def oaep_tamper_rejection() -> None:
    banner("PART 4 — MODIFIED OAEP CIPHERTEXT IS REJECTED")

    original = bytearray(OAEP_C1.read_bytes())

    if not original:
        raise RuntimeError("Missing OAEP ciphertext.")

    # Flip one bit in a locally generated ciphertext.
    original[len(original) // 2] ^= 0x01
    OAEP_TAMPERED.write_bytes(original)

    print(
        "One bit was flipped in the locally generated OAEP ciphertext.\n"
        "OpenSSL now attempts normal OAEP decryption."
    )

    result = oaep_decrypt(
        OAEP_TAMPERED,
        OAEP_TAMPERED_OUT,
        check=False,
    )

    success = result.returncode == 0

    print(f"\nOpenSSL return code : {result.returncode}")
    print(f"Decryption accepted : {success}")

    if result.stderr:
        # Keep the demonstration local and concise. The exact library text may
        # differ across OpenSSL versions.
        err = result.stderr.decode("utf-8", errors="replace").strip()
        if err:
            print("OpenSSL reports a decryption/padding failure.")

    if success:
        print(
            "\nWARNING: this particular altered ciphertext unexpectedly passed.\n"
            "Repeat with another altered ciphertext for the classroom demo."
        )
    else:
        print(
            "\nExpected result:\n"
            "  OAEP validation fails; the implementation does not return a\n"
            "  useful attacker-controlled plaintext."
        )


# =====================================================================
# PART 5 — SAFE LOCAL ORACLE-CONCEPT SIMULATOR
# =====================================================================

def protocol_oracle_concept() -> None:
    banner("PART 5 — WHY ERROR HANDLING IS PART OF CRYPTOGRAPHIC SECURITY")

    print(
        "Consider a server that internally performs RSA decryption and padding\n"
        "validation. Internally, many things may go wrong:\n\n"
        "    A. ciphertext has wrong length\n"
        "    B. RSA/OAEP decoding fails\n"
        "    C. application payload is malformed\n"
        "    D. authentication/authorization later fails\n\n"
        "A dangerous protocol design may expose distinguishable responses such as:\n\n"
        "    'BAD OAEP PADDING'\n"
        "    'VALID PADDING, BAD MESSAGE'\n\n"
        "or measurably different processing behavior.\n"
    )

    internal_events = [
        ("wrong ciphertext length", "DECRYPTION_FAILED"),
        ("OAEP decoding failure", "DECRYPTION_FAILED"),
        ("malformed recovered payload", "DECRYPTION_FAILED"),
    ]

    print("Safer classroom response model:")
    for internal, external in internal_events:
        print(f"  internal: {internal:<30} -> external: {external}")

    print(
        "\nThe cryptographic lesson is not merely 'use padding'. A secure protocol\n"
        "must also avoid turning internal validity checks into useful external\n"
        "signals. Exact production guidance depends on the protocol/library."
    )


# =====================================================================
# PART 6 — OAEP MESSAGE-SIZE BOUND
# =====================================================================

def oaep_size_bound() -> None:
    banner("PART 6 — OAEP IS FOR SMALL PAYLOADS / KEY ENCAPSULATION")

    # OAEP maximum:
    #   mLen <= k - 2*hLen - 2
    # For RSA-2048: k=256 bytes; SHA-256 hLen=32.
    k = RSA_BITS // 8
    h_len = 32
    max_len = k - 2 * h_len - 2

    print(f"RSA modulus             : {RSA_BITS} bits = {k} bytes")
    print(f"OAEP hash               : SHA-256")
    print(f"SHA-256 digest length   : {h_len} bytes")
    print("\nOAEP bound:")
    print("    mLen <= k - 2*hLen - 2")
    print(f"    mLen <= {k} - 2({h_len}) - 2")
    print(f"    mLen <= {max_len} bytes")

    print(
        "\nTherefore RSA-OAEP should not be used to encrypt arbitrary large files.\n"
        "Real systems normally use hybrid encryption:\n\n"
        "    RSA-OAEP -> protects a random symmetric key\n"
        "    AEAD     -> encrypts/authenticates the actual data"
    )


# =====================================================================
# SUMMARY
# =====================================================================

def summary() -> None:
    banner("ATTACK → WEAKNESS → COUNTERMEASURE")

    print(
        "1. TEXTBOOK RSA DETERMINISM\n"
        "   Weakness      : no randomized encoding\n"
        "   Observation   : same m -> same c\n"
        "   Countermeasure: RSA-OAEP / standardized hybrid encryption\n\n"
        "2. TEXTBOOK RSA MALLEABILITY\n"
        "   Weakness      : raw algebraic RSA exposed directly\n"
        "   Observation   : ciphertext can be transformed predictably\n"
        "   Countermeasure: use a secure standardized encryption construction\n\n"
        "3. PADDING / PROTOCOL VALIDITY SIGNALS\n"
        "   Weakness      : distinguishable externally observable failures\n"
        "   Risk          : validation information can become an oracle\n"
        "   Countermeasure: modern padding + careful protocol/error handling\n\n"
        "4. REAL-SYSTEM DESIGN\n"
        "   RSA-OAEP      : small secret/key material\n"
        "   AEAD          : bulk application data\n"
        "   RSA-PSS       : signatures, not encryption"
    )

    print(
        "\nCORE LESSON\n"
        "  RSA security is not only the equation c=m^e mod n. Security depends\n"
        "  on encoding, randomness, validation behavior, API use, and the larger\n"
        "  protocol in which the RSA primitive is embedded."
    )


# =====================================================================
# DOCX REPORT
# =====================================================================

def save_transcript_to_docx(transcript: str, output_path: Path) -> None:
    """Save the complete RSA-OAEP protocol demonstration as a Word report."""
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
        "RSA Cryptanalysis Lab 06\n"
        "RSA-OAEP Protocol Demonstration"
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
        "RSA-OAEP protocol demonstration so students can compare secure "
        "randomized RSA encryption with the structural weaknesses illustrated "
        "in the preceding textbook-RSA attack labs."
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
        "What security problem is RSA-OAEP designed to address compared with deterministic textbook RSA encryption?",
        "Why can encrypting the same plaintext more than once with OAEP produce different ciphertexts?",
        "What roles do the OAEP hash function and MGF1 play in the encoding construction?",
        "Why must encryption and decryption use compatible OAEP parameters?",
        "How does randomized OAEP disrupt the algebraic message relationships exploited by the earlier broadcast/common-modulus demonstrations?",
        "What happens when ciphertext, label, or relevant OAEP parameters are modified or mismatched in the demonstrated protocol?",
        "Why should applications use a standardized cryptographic implementation rather than implement raw RSA padding manually?",
        "Which conclusions from this demonstration concern RSA mathematics, and which concern secure protocol/encoding design?",
    ]
    for i, question in enumerate(questions, 1):
        document.add_paragraph(f"{i}. {question}")

    document.add_heading("Generated Lab Artifacts", level=1)
    document.add_paragraph(
        f"Lab directory: {LAB_DIR}\n"
        "See the complete transcript above for the generated keys, plaintext/"
        "ciphertext operations, OAEP parameter checks, validation results, "
        "and artifact paths produced during this run."
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    document.save(output_path)


# =====================================================================
# MAIN
# =====================================================================

def main() -> None:
    # Preserve the original OAEP protocol workflow while capturing its
    # detailed output into a persistent DOCX report for student analysis.
    transcript_buffer = io.StringIO()

    with redirect_stdout(transcript_buffer):
        banner("RSA CRYPTANALYSIS LAB 06 — OAEP & PROTOCOL SECURITY")

        print(
            "LOCAL EDUCATIONAL DEMONSTRATION\n"
            "This script generates and modifies only its own local RSA data.\n"
            "It does not probe a network service or implement an adaptive oracle attack."
        )

        n, e, message = setup()

        raw_ciphertext = textbook_rsa_determinism(n, e, message)
        textbook_rsa_malleability(n, e, raw_ciphertext)

        oaep_randomization(message)
        oaep_tamper_rejection()

        protocol_oracle_concept()
        oaep_size_bound()
        summary()

        print(f"\nLab artifacts saved under:\n  {LAB_DIR}")

    transcript = transcript_buffer.getvalue()
    save_transcript_to_docx(transcript, REPORT_DOCX)

    # Keep terminal output minimal; detailed results are in the Word report.
    print("RSA Cryptanalysis Lab 06 completed successfully.")
    print(f"Student analysis report saved to:\n  {REPORT_DOCX}")


if __name__ == "__main__":
    main()
