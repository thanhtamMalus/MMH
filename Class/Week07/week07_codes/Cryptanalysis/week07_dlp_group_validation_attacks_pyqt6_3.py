"""
Week 07 — DLP Group Validation & Active-Attack Laboratory
PyQt6 educational demonstration
=========================================================

Companion to:
  week07_elgamal_cryptanalysis_pyqt6_v2.py

Five tabs:
1. Lab / OpenSSL Settings
2. Group & Public-Value Inspection
3. Small-Subgroup / Confinement Demonstration
4. Unvalidated Public-Key Demonstration
5. Defense / Validation Checklist

This is deliberately a SMALL-PARAMETER classroom laboratory.
It demonstrates protocol validation failures; it is not a production attack tool.
"""

from __future__ import annotations

import math
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFormLayout, QGroupBox, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPushButton, QSpinBox, QTabWidget, QTextEdit,
    QVBoxLayout, QWidget
)

APP_DIR = Path.cwd() / "week07_dlp_validation_output"
APP_DIR.mkdir(parents=True, exist_ok=True)


def factor_small(n: int) -> list[tuple[int, int]]:
    out = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            e = 0
            while n % d == 0:
                n //= d
                e += 1
            out.append((d, e))
        d = 3 if d == 2 else d + 2
    if n > 1:
        out.append((n, 1))
    return out


def element_order(a: int, p: int) -> int:
    """Educational order computation for small p."""
    if math.gcd(a, p) != 1:
        return 0
    n = p - 1
    order = n
    for q, _ in factor_small(n):
        while order % q == 0 and pow(a, order // q, p) == 1:
            order //= q
    return order


def find_element_of_order(p: int, r: int) -> int | None:
    """Find an element of exact small order r in Z_p^*."""
    if (p - 1) % r:
        return None
    exponent = (p - 1) // r
    for base in range(2, min(p, 10000)):
        h = pow(base, exponent, p)
        if h != 1 and element_order(h, p) == r:
            return h
    return None


class OpenSSL:
    def __init__(self):
        self.binary = shutil.which("openssl") or "openssl"

    def set_binary(self, value: str):
        self.binary = value.strip() or "openssl"

    def text(self, args: list[str]) -> str:
        cp = subprocess.run(
            [self.binary] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if cp.returncode != 0:
            raise RuntimeError(cp.stderr.decode(errors="replace"))
        return cp.stdout.decode(errors="replace")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Week 07 — DLP Group Validation & Active Attacks")
        self.resize(1220, 860)

        self.openssl = OpenSSL()

        # Small, intentionally weak classroom group.
        # p-1 = 65536 = 2^16, making small subgroups easy to demonstrate.
        self.p = 65537
        self.g = 3
        self.secret = 12345
        self.public = pow(self.g, self.secret, self.p)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.tabs.addTab(self.tab1(), "1. Lab Settings")
        self.tabs.addTab(self.tab2(), "2. Inspect Group")
        self.tabs.addTab(self.tab3(), "3. Small Subgroup")
        self.tabs.addTab(self.tab4(), "4. Unvalidated Public Key")
        self.tabs.addTab(self.tab5(), "5. Defenses")

    def mono(self, w):
        f = QFont("Consolas")
        f.setStyleHint(QFont.StyleHint.Monospace)
        w.setFont(f)

    def error(self, exc):
        QMessageBox.critical(self, "Error", str(exc))

    # ------------------------------------------------------------
    # Tab 1
    # ------------------------------------------------------------
    def tab1(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        intro = QLabel(
            "<b>Purpose:</b> demonstrate why DLP-based protocols must validate "
            "group parameters and peer public values. All active attacks use "
            "small classroom parameters."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        box = QGroupBox("Configuration")
        form = QFormLayout(box)

        self.openssl_path = QLineEdit(self.openssl.binary)
        form.addRow("OpenSSL executable:", self.openssl_path)

        test = QPushButton("Test OpenSSL")
        test.clicked.connect(self.test_openssl)
        form.addRow(test)

        layout.addWidget(box)

        self.o1 = QTextEdit()
        self.o1.setReadOnly(True)
        self.mono(self.o1)
        layout.addWidget(self.o1)
        return page

    def test_openssl(self):
        try:
            self.openssl.set_binary(self.openssl_path.text())
            self.o1.setPlainText(
                self.openssl.text(["version", "-a"])
                + "\nLAB SCOPE\n"
                + "=" * 60
                + "\nThis companion lab focuses on:\n"
                  "  1. subgroup structure\n"
                  "  2. malicious peer public values\n"
                  "  3. confinement/leakage of secret residues\n"
                  "  4. public-key validation\n"
                  "  5. why standardized groups and validation matter\n"
            )
        except Exception as exc:
            self.error(exc)

    # ------------------------------------------------------------
    # Tab 2
    # ------------------------------------------------------------
    def tab2(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        intro = QLabel(
            "<b>Inspect the algebra first.</b> Students should distinguish "
            "modulus size, full group order, element order, private exponent, "
            "and public value."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        box = QGroupBox("Small Demonstration Group")
        form = QFormLayout(box)

        self.p_edit = QLineEdit(str(self.p))
        self.g_edit = QLineEdit(str(self.g))
        self.x_edit = QLineEdit(str(self.secret))
        form.addRow("Prime p:", self.p_edit)
        form.addRow("Generator/base g:", self.g_edit)
        form.addRow("Private exponent x:", self.x_edit)

        inspect = QPushButton("Inspect Group and Public Value")
        inspect.clicked.connect(self.inspect_group)
        form.addRow(inspect)
        layout.addWidget(box)

        self.o2 = QTextEdit()
        self.o2.setReadOnly(True)
        self.mono(self.o2)
        layout.addWidget(self.o2)
        return page

    def read_group(self):
        p = int(self.p_edit.text(), 0)
        g = int(self.g_edit.text(), 0)
        x = int(self.x_edit.text(), 0)
        if p < 5:
            raise RuntimeError("Use p >= 5.")
        if not (1 < g < p):
            raise RuntimeError("Require 1 < g < p.")
        self.p, self.g, self.secret = p, g, x
        self.public = pow(g, x, p)

    def inspect_group(self):
        try:
            self.read_group()
            factors = factor_small(self.p - 1)
            order_g = element_order(self.g, self.p)
            factor_text = " * ".join(
                str(q) if e == 1 else f"{q}^{e}" for q, e in factors
            )

            self.o2.setPlainText(
                "GROUP / KEY INSPECTION\n"
                + "=" * 60
                + f"\np = {self.p}"
                + f"\n|p| = {self.p.bit_length()} bits"
                + f"\n|Z_p^*| = p-1 = {self.p - 1}"
                + f"\nfactorization(p-1) = {factor_text}"
                + f"\n\ng = {self.g}"
                + f"\nord(g) = {order_g}"
                + f"\n\nprivate x = {self.secret}"
                + f"\npublic y = g^x mod p = {self.public}"
                + "\n\nTeaching distinction:"
                + "\n  large p alone is not the whole security story;"
                + "\n  the order of the working subgroup and validation of"
                  " peer elements are also security-critical."
            )
        except Exception as exc:
            self.error(exc)

    # ------------------------------------------------------------
    # Tab 3
    # ------------------------------------------------------------
    def tab3(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        intro = QLabel(
            "<b>Small-subgroup confinement:</b> a malicious peer sends an "
            "element h of small order r. Computing h^x confines the result to "
            "only r possibilities and can reveal x mod r when the result is observable."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        box = QGroupBox("Malicious Small-Order Element")
        form = QFormLayout(box)

        self.r_spin = QSpinBox()
        self.r_spin.setRange(2, 1024)
        self.r_spin.setValue(16)
        form.addRow("Requested small order r:", self.r_spin)

        run = QPushButton("Demonstrate Secret Residue Leakage")
        run.clicked.connect(self.small_subgroup)
        form.addRow(run)
        layout.addWidget(box)

        self.o3 = QTextEdit()
        self.o3.setReadOnly(True)
        self.mono(self.o3)
        layout.addWidget(self.o3)
        return page

    def small_subgroup(self):
        try:
            self.read_group()
            r = self.r_spin.value()

            h = find_element_of_order(self.p, r)
            if h is None:
                raise RuntimeError(
                    f"No element of exact order {r} found. Choose r dividing p-1."
                )

            # Victim performs the dangerous operation without validating h.
            z = pow(h, self.secret, self.p)

            # Observer enumerates only r possibilities.
            recovered_residue = None
            cur = 1
            for j in range(r):
                if cur == z:
                    recovered_residue = j
                    break
                cur = (cur * h) % self.p

            self.o3.setPlainText(
                "SMALL-SUBGROUP / CONFINEMENT DEMONSTRATION\n"
                + "=" * 60
                + f"\np = {self.p}"
                + f"\nmalicious h = {h}"
                + f"\nord(h) = {element_order(h, self.p)}"
                + f"\nvictim private exponent x = {self.secret}"
                + "\n\nVictim computes without peer-value validation:"
                + "\n  Z = h^x mod p"
                + f"\n  Z = {z}"
                + "\n\nBecause h has order r:"
                + "\n  h^x depends only on x mod r."
                + f"\n\nRecovered x mod {r} = {recovered_residue}"
                + f"\nActual    x mod {r} = {self.secret % r}"
                + f"\nMatch = {recovered_residue == self.secret % r}"
                + "\n\nSecurity lesson:"
                + "\nDo not accept arbitrary peer elements merely because"
                  " 1 < h < p-1. Validate subgroup membership/order according"
                  " to the protocol and standardized group."
            )
        except Exception as exc:
            self.error(exc)

    # ------------------------------------------------------------
    # Tab 4
    # ------------------------------------------------------------
    def tab4(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        intro = QLabel(
            "<b>Unvalidated public-key inputs:</b> boundary or low-order values "
            "can force predictable shared results. This tab compares naive "
            "acceptance with simple validation logic."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        box = QGroupBox("Peer Public Value")
        form = QFormLayout(box)

        self.peer_value = QLineEdit("1")
        form.addRow("Received peer value Y:", self.peer_value)

        run = QPushButton("Analyze Peer Value")
        run.clicked.connect(self.invalid_public)
        form.addRow(run)
        layout.addWidget(box)

        self.o4 = QTextEdit()
        self.o4.setReadOnly(True)
        self.mono(self.o4)
        layout.addWidget(self.o4)
        return page

    def invalid_public(self):
        try:
            self.read_group()
            Y = int(self.peer_value.text(), 0)
            in_range = 2 <= Y <= self.p - 2

            order = element_order(Y % self.p, self.p) if math.gcd(Y, self.p) == 1 else 0
            naive_z = pow(Y % self.p, self.secret, self.p)

            # Classroom heuristic: reject boundaries and very small order.
            min_demo_order = 32
            demo_valid = in_range and order >= min_demo_order

            self.o4.setPlainText(
                "PEER PUBLIC-VALUE ANALYSIS\n"
                + "=" * 60
                + f"\np = {self.p}"
                + f"\nreceived Y = {Y}"
                + f"\nrange check 2 <= Y <= p-2 : {in_range}"
                + f"\nord(Y mod p) = {order}"
                + f"\n\nNaive computation:"
                + f"\n  Z = Y^x mod p = {naive_z}"
                + "\n\nClassroom validation result:"
                + f"\n  boundary/range acceptable : {in_range}"
                + f"\n  not tiny-order (>= {min_demo_order}) : {order >= min_demo_order}"
                + f"\n  ACCEPT in this demo       : {demo_valid}"
                + "\n\nExamples to try:"
                + "\n  Y = 1       -> fixed shared value 1"
                + "\n  Y = p-1     -> order 2, result depends only on parity of x"
                + "\n  small-order Y -> secret-dependent result from a tiny set"
                + "\n\nImportant:"
                + "\nReal protocols must follow their exact standardized"
                  " public-key validation rules; this educational threshold is"
                  " only for illustrating the principle."
            )
        except Exception as exc:
            self.error(exc)

    # ------------------------------------------------------------
    # Tab 5
    # ------------------------------------------------------------
    def tab5(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        intro = QLabel(
            "<b>Defense synthesis:</b> connect the mathematical attack surface "
            "to implementation and protocol controls."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        run = QPushButton("Generate Validation / Defense Checklist")
        run.clicked.connect(self.defenses)
        layout.addWidget(run)

        self.o5 = QTextEdit()
        self.o5.setReadOnly(True)
        self.mono(self.o5)
        layout.addWidget(self.o5)
        return page

    def defenses(self):
        self.o5.setPlainText(
            "DLP / FFDHE / ELGAMAL VALIDATION CHECKLIST\n"
            + "=" * 60
            + "\n\n1. DOMAIN PARAMETERS"
            + "\n   • Prefer standardized, well-studied groups."
            + "\n   • Know p, g, and the intended subgroup/order."
            + "\n   • Do not infer security only from the bit length of p."
            + "\n\n2. PEER PUBLIC VALUE"
            + "\n   • Parse the value strictly."
            + "\n   • Reject invalid/boundary encodings and values."
            + "\n   • Apply the subgroup-membership/order checks required by"
              " the protocol/group."
            + "\n\n3. EPHEMERAL SECRETS"
            + "\n   • Generate fresh unpredictable exponents/nonces."
            + "\n   • Never reuse ElGamal k."
            + "\n   • Protect private exponents from side-channel leakage."
            + "\n\n4. PROTOCOL BINDING"
            + "\n   • Authenticate key exchange when active attackers matter."
            + "\n   • Bind identities, transcript, parameters, and context to"
              " the key derivation/authentication step."
            + "\n\n5. ENCRYPTION"
            + "\n   • Textbook ElGamal is multiplicatively malleable."
            + "\n   • Use standardized authenticated encryption / KEM-DEM-style"
              " constructions instead of raw textbook ElGamal in applications."
            + "\n\nATTACK -> WEAKNESS -> CONTROL"
            + "\nSmall subgroup -> unvalidated peer element -> subgroup validation"
            + "\nY=1 / low order -> weak public-value validation -> reject invalid values"
            + "\nRepeated k -> randomness failure -> fresh CSPRNG-generated k"
            + "\nMalleability -> no ciphertext integrity -> authenticated construction"
            + "\nMITM -> unauthenticated DH -> authenticate peers/transcript"
        )


def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Arial", 16))
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
