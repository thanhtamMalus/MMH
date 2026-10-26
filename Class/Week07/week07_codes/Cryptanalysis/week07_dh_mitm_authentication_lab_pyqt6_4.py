"""
Week 07 — Diffie-Hellman MITM & Authentication Laboratory
PyQt6 educational demonstration
=========================================================

Five tabs:
1. Lab Settings
2. Honest Diffie-Hellman
3. Man-in-the-Middle Attack
4. Authenticated DH
5. Compare / Security Analysis

Educational goals
-----------------
Show that:
  * DLP hardness alone does NOT authenticate the peer.
  * Unauthenticated DH is vulnerable to an active MITM.
  * Mallory can establish two independent secrets:
        Z_AM with Alice
        Z_MB with Bob
    while Alice and Bob incorrectly believe they share a secret with each other.
  * Authentication must bind identities and DH public shares to the protocol.
  * A signature over the transcript detects public-share substitution.

This is a SMALL-PARAMETER classroom visualization. It is not a production
key-exchange implementation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sys
from dataclasses import dataclass

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QFormLayout, QGroupBox, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPushButton, QSpinBox, QTabWidget, QTextEdit, QVBoxLayout,
    QWidget
)


def i2b(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def short_hex(data: bytes, n: int = 16) -> str:
    h = data.hex()
    return h if len(h) <= 2*n else h[:2*n] + "..."


def kdf(z: int, context: bytes) -> bytes:
    return hashlib.sha256(b"Week07-DH|" + i2b(z) + b"|" + context).digest()


def xor_bytes(data: bytes, key: bytes) -> bytes:
    stream = bytearray()
    counter = 0
    while len(stream) < len(data):
        stream.extend(hashlib.sha256(key + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(a ^ b for a, b in zip(data, stream))


@dataclass
class DHState:
    p: int
    g: int
    a: int
    b: int
    A: int
    B: int
    Z_A: int
    Z_B: int


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Week 07 — DH MITM & Authentication Laboratory")
        self.resize(1240, 880)

        # Small classroom parameters.
        self.p = 65537
        self.g = 3

        self.honest = None
        self.mitm = None

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.tabs.addTab(self.tab1(), "1. Lab Settings")
        self.tabs.addTab(self.tab2(), "2. Honest DH")
        self.tabs.addTab(self.tab3(), "3. MITM Attack")
        self.tabs.addTab(self.tab4(), "4. Authenticated DH")
        self.tabs.addTab(self.tab5(), "5. Security Analysis")

    def mono(self, widget):
        f = QFont("Consolas")
        f.setStyleHint(QFont.StyleHint.Monospace)
        widget.setFont(f)

    def error(self, exc):
        QMessageBox.critical(self, "Error", str(exc))

    def fresh_exp(self):
        return secrets.randbelow(self.p - 3) + 2

    # ------------------------------------------------------------
    # Tab 1 — settings
    # ------------------------------------------------------------
    def tab1(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        intro = QLabel(
            "<b>Purpose:</b> compare honest DH, unauthenticated DH under an "
            "active man-in-the-middle, and authenticated DH. The mathematics "
            "of DLP can remain unbroken while the unauthenticated protocol fails."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        box = QGroupBox("Classroom Finite-Field Parameters")
        form = QFormLayout(box)

        self.p_edit = QLineEdit(str(self.p))
        self.g_edit = QLineEdit(str(self.g))
        form.addRow("Prime p:", self.p_edit)
        form.addRow("Generator/base g:", self.g_edit)

        apply_btn = QPushButton("Apply / Check Parameters")
        apply_btn.clicked.connect(self.apply_params)
        form.addRow(apply_btn)
        layout.addWidget(box)

        self.o1 = QTextEdit()
        self.o1.setReadOnly(True)
        self.mono(self.o1)
        layout.addWidget(self.o1)
        return page

    def apply_params(self):
        try:
            p = int(self.p_edit.text(), 0)
            g = int(self.g_edit.text(), 0)
            if p < 5 or not (1 < g < p):
                raise RuntimeError("Require p >= 5 and 1 < g < p.")
            self.p, self.g = p, g
            self.o1.setPlainText(
                "LAB PARAMETERS\n"
                + "=" * 64
                + f"\np = {p}"
                + f"\n|p| = {p.bit_length()} bits"
                + f"\ng = {g}"
                + "\n\nCore DH equations:"
                + "\n  Alice: A = g^a mod p"
                + "\n  Bob  : B = g^b mod p"
                + "\n  Alice computes Z_A = B^a mod p"
                + "\n  Bob   computes Z_B = A^b mod p"
                + "\n  Z_A = Z_B = g^(ab) mod p"
                + "\n\nSecurity question for this lab:"
                + "\nWho supplied A and B? DLP hardness does not answer that."
            )
        except Exception as exc:
            self.error(exc)

    # ------------------------------------------------------------
    # Tab 2 — honest DH
    # ------------------------------------------------------------
    def tab2(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        intro = QLabel(
            "<b>Honest exchange:</b> Alice and Bob receive each other's genuine "
            "public shares without modification."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        run = QPushButton("Run Honest Diffie-Hellman")
        run.clicked.connect(self.run_honest)
        layout.addWidget(run)

        self.o2 = QTextEdit()
        self.o2.setReadOnly(True)
        self.mono(self.o2)
        layout.addWidget(self.o2)
        return page

    def run_honest(self):
        try:
            self.apply_params()
            a, b = self.fresh_exp(), self.fresh_exp()
            A = pow(self.g, a, self.p)
            B = pow(self.g, b, self.p)
            ZA = pow(B, a, self.p)
            ZB = pow(A, b, self.p)

            self.honest = DHState(
                self.p, self.g, a, b, A, B, ZA, ZB
            )

            KA = kdf(ZA, b"Alice|Bob|honest")
            KB = kdf(ZB, b"Alice|Bob|honest")

            self.o2.setPlainText(
                "HONEST DIFFIE-HELLMAN\n"
                + "=" * 64
                + f"\nAlice secret a = {a}"
                + f"\nAlice share  A = g^a mod p = {A}"
                + f"\n\nBob secret   b = {b}"
                + f"\nBob share    B = g^b mod p = {B}"
                + "\n\nExchange:"
                + f"\n  Alice ---------------- A={A} ----------------> Bob"
                + f"\n  Alice <--------------- B={B} ----------------- Bob"
                + "\n\nShared-secret computation:"
                + f"\n  Alice: Z_A = B^a mod p = {ZA}"
                + f"\n  Bob  : Z_B = A^b mod p = {ZB}"
                + f"\n  Equal? {ZA == ZB}"
                + "\n\nDerived key fingerprints:"
                + f"\n  K_A = {short_hex(KA)}"
                + f"\n  K_B = {short_hex(KB)}"
                + f"\n  Equal? {KA == KB}"
                + "\n\nResult:"
                + "\n  Confidential shared material is established,"
                  " assuming the public shares really came from Alice and Bob."
            )
        except Exception as exc:
            self.error(exc)

    # ------------------------------------------------------------
    # Tab 3 — MITM
    # ------------------------------------------------------------
    def tab3(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        intro = QLabel(
            "<b>Active MITM:</b> Mallory intercepts A and B and substitutes "
            "two of her own DH shares. No discrete logarithm is solved."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        box = QGroupBox("Message Relay Demonstration")
        form = QFormLayout(box)
        self.message = QLineEdit("Meet at 10:00")
        form.addRow("Alice plaintext:", self.message)
        run = QPushButton("Run MITM and Relay Message")
        run.clicked.connect(self.run_mitm)
        form.addRow(run)
        layout.addWidget(box)

        self.o3 = QTextEdit()
        self.o3.setReadOnly(True)
        self.mono(self.o3)
        layout.addWidget(self.o3)
        return page

    def run_mitm(self):
        try:
            self.apply_params()

            a = self.fresh_exp()
            b = self.fresh_exp()
            mA = self.fresh_exp()  # Mallory exponent toward Alice
            mB = self.fresh_exp()  # Mallory exponent toward Bob

            A = pow(self.g, a, self.p)
            B = pow(self.g, b, self.p)
            M_A = pow(self.g, mA, self.p)
            M_B = pow(self.g, mB, self.p)

            # Mallory sends M_A to Alice pretending it is Bob's B.
            # Mallory sends M_B to Bob pretending it is Alice's A.
            Z_A = pow(M_A, a, self.p)
            Z_MA = pow(A, mA, self.p)

            Z_B = pow(M_B, b, self.p)
            Z_MB = pow(B, mB, self.p)

            KA = kdf(Z_A, b"Alice|Mallory-link")
            KMA = kdf(Z_MA, b"Alice|Mallory-link")
            KB = kdf(Z_B, b"Mallory|Bob-link")
            KMB = kdf(Z_MB, b"Mallory|Bob-link")

            msg = self.message.text().encode("utf-8")
            c_from_alice = xor_bytes(msg, KA)
            mallory_plain = xor_bytes(c_from_alice, KMA)

            # Mallory could inspect/modify before re-encrypting.
            relayed_plain = mallory_plain
            c_to_bob = xor_bytes(relayed_plain, KMB)
            bob_plain = xor_bytes(c_to_bob, KB)

            self.mitm = {
                "a": a, "b": b, "mA": mA, "mB": mB,
                "A": A, "B": B, "M_A": M_A, "M_B": M_B,
                "Z_A": Z_A, "Z_MA": Z_MA, "Z_B": Z_B, "Z_MB": Z_MB,
            }

            self.o3.setPlainText(
                "UNAUTHENTICATED DH: MAN-IN-THE-MIDDLE\n"
                + "=" * 64
                + f"\nAlice creates A = {A}"
                + f"\nBob   creates B = {B}"
                + "\n\nMallory intercepts both:"
                + f"\n  Alice ---- A={A} ----X----> Bob"
                + f"\n  Alice <---X---- B={B} ----- Bob"
                + "\n\nMallory substitutes:"
                + f"\n  Mallory -> Alice: M_A = g^mA = {M_A}"
                + f"\n  Mallory -> Bob  : M_B = g^mB = {M_B}"
                + "\n\nAlice believes:"
                + f"\n  Z_A  = M_A^a = {Z_A}"
                + "\nMallory computes with Alice:"
                + f"\n  Z_MA = A^mA   = {Z_MA}"
                + f"\n  MATCH? {Z_A == Z_MA}"
                + "\n\nBob believes:"
                + f"\n  Z_B  = M_B^b = {Z_B}"
                + "\nMallory computes with Bob:"
                + f"\n  Z_MB = B^mB   = {Z_MB}"
                + f"\n  MATCH? {Z_B == Z_MB}"
                + "\n\nCritical observation:"
                + f"\n  Alice secret == Bob secret? {Z_A == Z_B}"
                + "\n  They do NOT share a direct secret."
                + "\n  Mallory shares one secret with each endpoint."
                + "\n\nMESSAGE RELAY"
                + "\n" + "-" * 64
                + f"\nAlice plaintext : {msg.decode(errors='replace')}"
                + f"\nAlice ciphertext: {c_from_alice.hex()}"
                + f"\nMallory recovers: {mallory_plain.decode(errors='replace')}"
                + f"\nRelay ciphertext: {c_to_bob.hex()}"
                + f"\nBob recovers    : {bob_plain.decode(errors='replace')}"
                + "\n\nNo DLP was broken. The failure is missing authentication."
            )
        except Exception as exc:
            self.error(exc)

    # ------------------------------------------------------------
    # Tab 4 — authenticated DH
    # ------------------------------------------------------------
    def tab4(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        intro = QLabel(
            "<b>Authenticated DH:</b> simulate long-term authentication keys "
            "and signatures over identities + DH shares. Then compare an honest "
            "transcript with Mallory's substituted share."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        run = QPushButton("Run Authenticated-DH Verification")
        run.clicked.connect(self.run_authenticated)
        layout.addWidget(run)

        self.o4 = QTextEdit()
        self.o4.setReadOnly(True)
        self.mono(self.o4)
        layout.addWidget(self.o4)
        return page

    def transcript(self, sender: str, receiver: str, share: int) -> bytes:
        return (
            b"Week07-AuthDH|"
            + sender.encode()
            + b"|"
            + receiver.encode()
            + b"|p="
            + str(self.p).encode()
            + b"|g="
            + str(self.g).encode()
            + b"|share="
            + str(share).encode()
        )

    def run_authenticated(self):
        try:
            self.apply_params()

            # HMAC is used here only as a compact classroom stand-in for
            # long-term authentication/signature verification. It lets the
            # students focus on transcript binding. Production authenticated
            # DH normally uses certificates/signatures or an authenticated PSK.
            auth_A = secrets.token_bytes(32)
            auth_B = secrets.token_bytes(32)

            a, b = self.fresh_exp(), self.fresh_exp()
            A = pow(self.g, a, self.p)
            B = pow(self.g, b, self.p)

            sig_A = hmac.new(
                auth_A, self.transcript("Alice", "Bob", A), hashlib.sha256
            ).digest()
            sig_B = hmac.new(
                auth_B, self.transcript("Bob", "Alice", B), hashlib.sha256
            ).digest()

            verify_A = hmac.compare_digest(
                sig_A,
                hmac.new(
                    auth_A, self.transcript("Alice", "Bob", A), hashlib.sha256
                ).digest(),
            )
            verify_B = hmac.compare_digest(
                sig_B,
                hmac.new(
                    auth_B, self.transcript("Bob", "Alice", B), hashlib.sha256
                ).digest(),
            )

            # Mallory substitutes a different share but cannot produce the
            # authentication tag/signature bound to that new transcript.
            m = self.fresh_exp()
            M = pow(self.g, m, self.p)

            forged_verify_as_A = hmac.compare_digest(
                sig_A,
                hmac.new(
                    auth_A, self.transcript("Alice", "Bob", M), hashlib.sha256
                ).digest(),
            )
            forged_verify_as_B = hmac.compare_digest(
                sig_B,
                hmac.new(
                    auth_B, self.transcript("Bob", "Alice", M), hashlib.sha256
                ).digest(),
            )

            ZA = pow(B, a, self.p)
            ZB = pow(A, b, self.p)

            self.o4.setPlainText(
                "AUTHENTICATED DIFFIE-HELLMAN\n"
                + "=" * 64
                + "\nAuthentication concept:"
                + "\n  Auth_A( Alice || Bob || p || g || A )"
                + "\n  Auth_B( Bob || Alice || p || g || B )"
                + "\n\nHonest shares:"
                + f"\n  A = {A}"
                + f"\n  B = {B}"
                + f"\n  Alice authentication verifies: {verify_A}"
                + f"\n  Bob authentication verifies  : {verify_B}"
                + f"\n  Z_A = {ZA}"
                + f"\n  Z_B = {ZB}"
                + f"\n  shared secret equal: {ZA == ZB}"
                + "\n\nMallory substitutes M:"
                + f"\n  M = {M}"
                + "\n  but reuses an authentication value made for A/B."
                + f"\n  M accepted as Alice share? {forged_verify_as_A}"
                + f"\n  M accepted as Bob share?   {forged_verify_as_B}"
                + "\n\nResult:"
                + "\n  Substitution changes the authenticated transcript,"
                  " so verification fails before the substituted DH share is trusted."
                + "\n\nImplementation note:"
                + "\n  This tab uses HMAC as a compact teaching stand-in for"
                  " authentication. Real authenticated DH may use digital"
                  " signatures/certificates or an authenticated PSK, depending"
                  " on the protocol."
            )
        except Exception as exc:
            self.error(exc)

    # ------------------------------------------------------------
    # Tab 5 — synthesis
    # ------------------------------------------------------------
    def tab5(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        intro = QLabel(
            "<b>Synthesis:</b> separate mathematical hardness, confidentiality, "
            "peer authentication, transcript integrity, and key confirmation."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        run = QPushButton("Generate Security Comparison")
        run.clicked.connect(self.security_analysis)
        layout.addWidget(run)

        self.o5 = QTextEdit()
        self.o5.setReadOnly(True)
        self.mono(self.o5)
        layout.addWidget(self.o5)
        return page

    def security_analysis(self):
        self.o5.setPlainText(
            "DH SECURITY SYNTHESIS\n"
            + "=" * 64
            + "\n\n1. HARD PROBLEM"
            + "\n   DLP/CDH-type hardness protects recovery/computation of"
              " secrets from public group values."
            + "\n\n2. WHAT PLAIN DH DOES NOT PROVIDE"
            + "\n   Plain DH does not prove who created a received public share."
            + "\n\n3. ACTIVE MITM"
            + "\n   Mallory substitutes public shares and establishes:"
            + "\n      Alice <-> Mallory : Z_AM"
            + "\n      Mallory <-> Bob   : Z_MB"
            + "\n   No discrete logarithm needs to be solved."
            + "\n\n4. AUTHENTICATION"
            + "\n   Authenticate identities, parameters, public shares, and"
              " relevant transcript/context."
            + "\n\n5. KEY DERIVATION"
            + "\n   Feed the DH shared secret plus transcript/context into an"
              " appropriate KDF rather than using raw Z directly."
            + "\n\n6. KEY CONFIRMATION / FINISHED MESSAGES"
            + "\n   Protocols may explicitly confirm that both endpoints derived"
              " the expected keys and transcript."
            + "\n\nATTACK -> WEAKNESS -> CONTROL"
            + "\n" + "-" * 64
            + "\nPassive eavesdropping -> DLP/CDH target -> strong standardized group"
            + "\nMITM -> no peer authentication -> signatures/certificates or PSK"
            + "\nShare substitution -> transcript not bound -> authenticate transcript"
            + "\nSmall subgroup -> peer value not validated -> group/public-key validation"
            + "\nRaw Z misuse -> no context separation -> KDF with transcript/context"
            + "\nUnknown-key/share confusion -> weak identity binding -> bind both identities"
            + "\n\nCORE WEEK-7 LESSON"
            + "\n" + "-" * 64
            + "\nA cryptographically hard mathematical problem is necessary,"
              " but it is not sufficient for a secure protocol."
        )


def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Arial", 16))
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
