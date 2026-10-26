"""
Week 07 — ElGamal Cryptanalysis Laboratory
PyQt6 educational demonstration
==========================================

Seven tabs:
1. OpenSSL / Lab Settings
2. Load & Inspect ElGamal Instance
3. Generic DLP: Brute Force / Baby-Step Giant-Step
4. Pollard's rho DLP
5. Pohlig-Hellman / Group-Order Weakness
6. Reused Ephemeral k
7. Malleability & Countermeasures

Purpose
-------
Demonstrate why ElGamal security depends on:
  * hardness of the discrete logarithm problem,
  * sufficiently large groups,
  * fresh unpredictable ephemeral k,
  * authenticated/non-malleable constructions.

Safety / practicality
---------------------
Generic DLP attacks are intentionally limited to small classroom-sized
parameters. They are not intended to attack real FFDHE-2048+ keys.

Input instance format (text)
----------------------------
p=<integer, decimal or 0x...>
g=<integer>
y=<integer>
c1=<integer>
c2=<integer>

Optional for reused-k demonstration:
c1_2=<integer>
c2_2=<integer>
known_m1=<integer>
"""

from __future__ import annotations

import math
import shutil
import subprocess
import sys
import time
from pathlib import Path

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QPushButton, QSpinBox, QTabWidget,
    QTextEdit, QVBoxLayout, QWidget
)

APP_DIR = Path.cwd() / "week07_elgamal_cryptanalysis_output"
APP_DIR.mkdir(parents=True, exist_ok=True)


def parse_int(s: str) -> int:
    return int(s.strip(), 0)


def inv(a: int, p: int) -> int:
    return pow(a, -1, p)


def fmt_int(n: int, width: int = 64) -> str:
    h = format(n, "x")
    if len(h) % 2:
        h = "0" + h
    return "\n".join(h[i:i+width] for i in range(0, len(h), width))


def bsgs(g: int, y: int, p: int, order_bound: int) -> int | None:
    """Find x with g^x=y mod p for 0<=x<order_bound using BSGS."""
    m = math.isqrt(order_bound) + 1

    table = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = (e * g) % p

    factor = pow(pow(g, m, p), -1, p)
    gamma = y
    for i in range(m + 1):
        if gamma in table:
            x = i * m + table[gamma]
            if x < order_bound and pow(g, x, p) == y:
                return x
        gamma = (gamma * factor) % p
    return None


def factor_small(n: int) -> list[tuple[int, int]]:
    """Trial-division factorization for intentionally small classroom orders."""
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


def crt(congruences: list[tuple[int, int]]) -> tuple[int, int]:
    """Chinese Remainder Theorem for pairwise-coprime moduli."""
    x, M = 0, 1
    for a, m in congruences:
        t = ((a - x) * pow(M, -1, m)) % m
        x += M * t
        M *= m
        x %= M
    return x, M


def pollard_rho_dlp(g: int, h: int, p: int, n: int,
                    max_steps: int = 2_000_000) -> tuple[int | None, int]:
    """
    Educational Pollard-rho DLP for a cyclic subgroup of known order n.
    State X = g^a h^b. Uses a 3-way partition and Floyd cycle finding.
    """
    def step(X: int, a: int, b: int):
        r = X % 3
        if r == 0:
            return (X * h) % p, a, (b + 1) % n
        if r == 1:
            return (X * X) % p, (2 * a) % n, (2 * b) % n
        return (X * g) % p, (a + 1) % n, b

    # Deterministic initial state is fine for a classroom demonstration.
    X, a, b = 1, 0, 0
    Y, A, B = X, a, b

    for steps in range(1, max_steps + 1):
        X, a, b = step(X, a, b)
        Y, A, B = step(*step(Y, A, B))

        if X == Y:
            # g^a h^b = g^A h^B  =>  x(B-b) = a-A mod n
            r = (B - b) % n
            s = (a - A) % n
            d = math.gcd(r, n)
            if d == 0 or s % d:
                return None, steps

            r1, s1, n1 = r // d, s // d, n // d
            try:
                x0 = (s1 * pow(r1, -1, n1)) % n1
            except ValueError:
                return None, steps

            # A collision can yield d candidates.
            for j in range(d):
                cand = x0 + j * n1
                if cand < n and pow(g, cand, p) == h:
                    return cand, steps
            return None, steps

    return None, max_steps


def pohlig_hellman(g: int, h: int, p: int, n: int,
                   max_prime_factor: int = 1_000_000) -> tuple[int, list[tuple[int,int]], list[str]]:
    """
    Pohlig-Hellman for a classroom-sized cyclic subgroup of known order n.
    Solves x modulo each prime power using BSGS on the prime-order digit DLPs.
    """
    factors = factor_small(n)
    if not factors:
        raise RuntimeError("Could not factor the supplied group order.")

    logs = []
    congruences = []

    for q, e in factors:
        if q > max_prime_factor:
            raise RuntimeError(
                f"Prime factor {q} is above the classroom limit "
                f"{max_prime_factor}. Pohlig-Hellman is effective when the "
                "group order factors into sufficiently small prime powers."
            )

        qe = q ** e
        x_qe = 0
        gamma = pow(g, n // q, p)  # element of order q

        for j in range(e):
            # h_j = (h * g^{-x_qe})^(n/q^(j+1))
            gx_inv = pow(pow(g, x_qe, p), -1, p)
            hj = pow((h * gx_inv) % p, n // (q ** (j + 1)), p)
            dj = bsgs(gamma, hj, p, q)
            if dj is None:
                raise RuntimeError(f"Could not solve digit {j} modulo q={q}.")
            x_qe += dj * (q ** j)

        x_qe %= qe
        congruences.append((x_qe, qe))
        logs.append(
            f"factor {q}^{e} = {qe}: x ≡ {x_qe} (mod {qe})"
        )

    x, modulus = crt(congruences)
    if modulus != n:
        x %= n
    if pow(g, x, p) != h:
        raise RuntimeError("Pohlig-Hellman reconstruction failed verification.")
    return x, factors, logs


class OpenSSL:
    def __init__(self):
        self.binary = shutil.which("openssl") or "openssl"

    def set_binary(self, value):
        self.binary = value.strip() or "openssl"

    def text(self, args):
        cp = subprocess.run(
            [self.binary] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False
        )
        if cp.returncode != 0:
            raise RuntimeError(cp.stderr.decode(errors="replace"))
        return cp.stdout.decode(errors="replace")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Week 07 — ElGamal Cryptanalysis Laboratory")
        self.resize(1240, 880)

        self.openssl = OpenSSL()

        self.p = None
        self.g = None
        self.y = None
        self.c1 = None
        self.c2 = None
        self.c1_2 = None
        self.c2_2 = None
        self.known_m1 = None

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.tabs.addTab(self.tab1(), "1. Lab Settings")
        self.tabs.addTab(self.tab2(), "2. Inspect Instance")
        self.tabs.addTab(self.tab3(), "3. Generic DLP")
        self.tabs.addTab(self.tab_pollard(), "4. Pollard Rho DLP")
        self.tabs.addTab(self.tab_pohlig(), "5. Pohlig-Hellman")
        self.tabs.addTab(self.tab4(), "6. Reused k")
        self.tabs.addTab(self.tab5(), "7. Malleability")

    def mono(self, w):
        f = QFont("Consolas")
        f.setStyleHint(QFont.StyleHint.Monospace)
        w.setFont(f)

    def err(self, e):
        QMessageBox.critical(self, "Error", str(e))

    # ----------------------------------------------------------------
    # Tab 1
    # ----------------------------------------------------------------
    def tab1(self):
        w = QWidget()
        l = QVBoxLayout(w)

        info = QLabel(
            "<b>Goal:</b> study ElGamal failure modes rather than attack "
            "production-sized FFDHE groups. Generic DLP demonstrations are "
            "restricted to small classroom parameters."
        )
        info.setWordWrap(True)
        l.addWidget(info)

        box = QGroupBox("OpenSSL / Lab Configuration")
        f = QFormLayout(box)

        self.openssl_path = QLineEdit(self.openssl.binary)
        f.addRow("OpenSSL executable:", self.openssl_path)

        self.max_bits = QSpinBox()
        self.max_bits.setRange(8, 40)
        self.max_bits.setValue(28)
        f.addRow("Maximum p bits for generic DLP demo:", self.max_bits)

        b = QPushButton("Test OpenSSL")
        b.clicked.connect(self.test_ssl)
        f.addRow(b)

        l.addWidget(box)

        self.o1 = QTextEdit()
        self.o1.setReadOnly(True)
        self.mono(self.o1)
        l.addWidget(self.o1)
        return w

    def test_ssl(self):
        try:
            self.openssl.set_binary(self.openssl_path.text())
            self.o1.setPlainText(
                self.openssl.text(["version", "-a"]) +
                "\nCryptanalysis scope:\n"
                "• brute-force DLP — conceptual baseline\n"
                "• baby-step giant-step — O(sqrt(n)) generic DLP\n"
                "• Pollard's rho DLP — O(sqrt(n)) expected time, low memory\n"
                "• Pohlig-Hellman — exploits smooth group/subgroup order\n"
                "• reused ephemeral k — protocol/randomness failure\n"
                "• multiplicative malleability — textbook ElGamal property\n"
            )
        except Exception as e:
            self.err(e)

    # ----------------------------------------------------------------
    # Tab 2
    # ----------------------------------------------------------------
    def tab2(self):
        w = QWidget()
        l = QVBoxLayout(w)

        info = QLabel(
            "<b>Load a classroom ElGamal instance.</b> The values may come "
            "from a deliberately small example generated for cryptanalysis."
        )
        info.setWordWrap(True)
        l.addWidget(info)

        box = QGroupBox("Instance")
        f = QFormLayout(box)

        self.instance_path = QLineEdit()
        self.instance_path.setReadOnly(True)
        f.addRow("File:", self.instance_path)

        self.order_input = QLineEdit()
        self.order_input.setPlaceholderText(
            "Optional subgroup order n; blank => use p-1 for classroom demos"
        )
        f.addRow("Known group/subgroup order n:", self.order_input)

        row = QHBoxLayout()
        load = QPushButton("Load Instance")
        load.clicked.connect(self.load_instance)
        demo = QPushButton("Generate Small Demonstration Instance")
        demo.clicked.connect(self.generate_demo)
        row.addWidget(load)
        row.addWidget(demo)
        f.addRow(row)

        l.addWidget(box)

        self.o2 = QTextEdit()
        self.o2.setReadOnly(True)
        self.mono(self.o2)
        l.addWidget(self.o2)
        return w

    def load_instance(self):
        try:
            p, _ = QFileDialog.getOpenFileName(
                self, "Load ElGamal cryptanalysis instance", "",
                "Text (*.txt);;All files (*)"
            )
            if not p:
                return

            vals = {}
            for line in Path(p).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                vals[k.strip()] = parse_int(v)

            for required in ("p", "g", "y", "c1", "c2"):
                if required not in vals:
                    raise RuntimeError(f"Missing required field: {required}")

            self.p = vals["p"]
            self.g = vals["g"]
            self.y = vals["y"]
            self.c1 = vals["c1"]
            self.c2 = vals["c2"]
            self.c1_2 = vals.get("c1_2")
            self.c2_2 = vals.get("c2_2")
            self.known_m1 = vals.get("known_m1")

            self.instance_path.setText(p)
            self.show_instance()

        except Exception as e:
            self.err(e)

    def generate_demo(self):
        # Small prime and generator selected only for classroom analysis.
        # p=65537 is prime; g=3 has large order modulo p.
        p = 65537
        g = 3
        x = 12345
        y = pow(g, x, p)

        m1 = 17031
        m2 = 4242

        # Deliberately reused k.
        k = 2345
        c1 = pow(g, k, p)
        s = pow(y, k, p)
        c2 = (m1 * s) % p
        c1_2 = c1
        c2_2 = (m2 * s) % p

        self.p, self.g, self.y = p, g, y
        self.c1, self.c2 = c1, c2
        self.c1_2, self.c2_2 = c1_2, c2_2
        self.known_m1 = m1

        demo_file = APP_DIR / "small_elgamal_instance.txt"
        demo_file.write_text(
            "# Deliberately weak classroom ElGamal instance\n"
            f"p={p}\n"
            f"g={g}\n"
            f"y={y}\n"
            f"c1={c1}\n"
            f"c2={c2}\n"
            f"c1_2={c1_2}\n"
            f"c2_2={c2_2}\n"
            f"known_m1={m1}\n",
            encoding="utf-8"
        )
        self.instance_path.setText(str(demo_file))
        self.show_instance()

    def show_instance(self):
        self.o2.setPlainText(
            "ELGAMAL PUBLIC INSTANCE\n"
            "============================================================\n"
            f"p = {self.p}\n"
            f"|p| = {self.p.bit_length()} bits\n"
            f"g = {self.g}\n"
            f"y = {self.y}\n\n"
            "Ciphertext 1:\n"
            f"c1 = {self.c1}\n"
            f"c2 = {self.c2}\n\n"
            f"Second ciphertext available: {self.c1_2 is not None}\n"
            f"Known plaintext m1 available: {self.known_m1 is not None}\n\n"
            "Security assumptions:\n"
            "  y = g^x mod p          -> recovering x is a DLP\n"
            "  c1 = g^k mod p         -> recovering k is also a DLP\n"
            "  c2 = m * y^k mod p\n"
        )

    # ----------------------------------------------------------------
    # Tab 3 — DLP attacks
    # ----------------------------------------------------------------
    def tab3(self):
        w = QWidget()
        l = QVBoxLayout(w)

        info = QLabel(
            "<b>Generic DLP cryptanalysis.</b> Recover the private exponent x "
            "from y=g^x mod p, then decrypt. The GUI refuses large p values."
        )
        info.setWordWrap(True)
        l.addWidget(info)

        row = QHBoxLayout()
        brute = QPushButton("Brute-Force x")
        brute.clicked.connect(self.bruteforce)
        bsg = QPushButton("Baby-Step Giant-Step x")
        bsg.clicked.connect(self.run_bsgs)
        row.addWidget(brute)
        row.addWidget(bsg)
        l.addLayout(row)

        self.o3 = QTextEdit()
        self.o3.setReadOnly(True)
        self.mono(self.o3)
        l.addWidget(self.o3)
        return w

    def check_small(self):
        if self.p is None:
            raise RuntimeError("Load/generate an instance in Tab 2 first.")
        if self.p.bit_length() > self.max_bits.value():
            raise RuntimeError(
                f"p is {self.p.bit_length()} bits. Generic DLP demonstration "
                f"is limited to {self.max_bits.value()} bits in this teaching tool."
            )

    def decrypt_with_x(self, x):
        s = pow(self.c1, x, self.p)
        return (self.c2 * inv(s, self.p)) % self.p

    def bruteforce(self):
        try:
            self.check_small()
            t0 = time.perf_counter()

            cur = 1
            found = None
            for x in range(self.p):
                if cur == self.y:
                    found = x
                    break
                cur = (cur * self.g) % self.p

            dt = time.perf_counter() - t0
            if found is None:
                raise RuntimeError("No exponent found in searched range.")

            m = self.decrypt_with_x(found)

            self.o3.setPlainText(
                "BRUTE-FORCE DISCRETE LOGARITHM\n"
                "============================================================\n"
                "Target: y = g^x mod p\n"
                f"Recovered x = {found}\n"
                f"Verification g^x mod p == y: {pow(self.g, found, self.p) == self.y}\n"
                f"Recovered m = {m}\n"
                f"Runtime = {dt:.6f} s\n\n"
                "Complexity: O(n) group operations in the searched exponent range."
            )

        except Exception as e:
            self.err(e)

    def run_bsgs(self):
        try:
            self.check_small()
            t0 = time.perf_counter()

            x = bsgs(self.g, self.y, self.p, self.p)
            dt = time.perf_counter() - t0

            if x is None:
                raise RuntimeError("BSGS did not find x in the configured range.")

            m = self.decrypt_with_x(x)

            self.o3.setPlainText(
                "BABY-STEP GIANT-STEP\n"
                "============================================================\n"
                "Solve y = g^x mod p using time-memory tradeoff.\n\n"
                f"Recovered x = {x}\n"
                f"Verification = {pow(self.g, x, self.p) == self.y}\n"
                f"Recovered m = {m}\n"
                f"Runtime = {dt:.6f} s\n\n"
                f"Approximate table scale: sqrt(p) ≈ {math.isqrt(self.p)} entries\n"
                "Complexity: O(sqrt(n)) time and O(sqrt(n)) memory."
            )

        except Exception as e:
            self.err(e)

    # ----------------------------------------------------------------
    # Tab 4 — Pollard's rho DLP
    # ----------------------------------------------------------------
    def tab_pollard(self):
        w = QWidget()
        l = QVBoxLayout(w)

        info = QLabel(
            "<b>Pollard's rho for DLP.</b> Recover x from y=g^x mod p "
            "using cycle finding. Expected work is O(sqrt(n)) but memory is "
            "approximately O(1), unlike BSGS. Use only the deliberately small "
            "classroom instances."
        )
        info.setWordWrap(True)
        l.addWidget(info)

        b = QPushButton("Run Pollard's rho on x")
        b.clicked.connect(self.run_pollard)
        l.addWidget(b)

        self.o_pollard = QTextEdit()
        self.o_pollard.setReadOnly(True)
        self.mono(self.o_pollard)
        l.addWidget(self.o_pollard)
        return w

    def known_order(self) -> int:
        if self.p is None:
            raise RuntimeError("Load/generate an instance in Tab 2 first.")
        text = self.order_input.text().strip()
        return parse_int(text) if text else self.p - 1

    def run_pollard(self):
        try:
            self.check_small()
            n = self.known_order()
            if n <= 1:
                raise RuntimeError("Group order n must be > 1.")
            if pow(self.g, n, self.p) != 1 or pow(self.y, n, self.p) != 1:
                raise RuntimeError(
                    "The supplied n is not consistent with g/y in the subgroup."
                )

            t0 = time.perf_counter()
            x, steps = pollard_rho_dlp(self.g, self.y, self.p, n)
            dt = time.perf_counter() - t0

            if x is None:
                raise RuntimeError(
                    "This Pollard-rho walk produced a non-invertible/degenerate "
                    "collision. Try a different classroom instance."
                )

            m = self.decrypt_with_x(x)
            self.o_pollard.setPlainText(
                "POLLARD'S RHO DISCRETE LOGARITHM\n"
                "============================================================\n"
                f"Known subgroup/order bound n = {n}\n"
                f"Recovered x = {x}\n"
                f"Verification g^x mod p == y: {pow(self.g, x, self.p) == self.y}\n"
                f"Recovered plaintext integer m = {m}\n"
                f"Cycle-walk steps = {steps}\n"
                f"Runtime = {dt:.6f} s\n\n"
                "Complexity interpretation:\n"
                "  expected time  : O(sqrt(n))\n"
                "  memory         : approximately O(1)\n\n"
                "Compare this with BSGS: similar asymptotic time, but BSGS "
                "stores about sqrt(n) table entries."
            )
        except Exception as e:
            self.err(e)

    # ----------------------------------------------------------------
    # Tab 5 — Pohlig-Hellman
    # ----------------------------------------------------------------
    def tab_pohlig(self):
        w = QWidget()
        l = QVBoxLayout(w)

        info = QLabel(
            "<b>Pohlig–Hellman.</b> Factor the known group/subgroup order n. "
            "The DLP is reduced to DLPs in the prime-power factors of n and "
            "the partial results are recombined with CRT. This demonstrates "
            "why group-order selection matters."
        )
        info.setWordWrap(True)
        l.addWidget(info)

        b = QPushButton("Factor n and Run Pohlig–Hellman")
        b.clicked.connect(self.run_pohlig)
        l.addWidget(b)

        self.o_pohlig = QTextEdit()
        self.o_pohlig.setReadOnly(True)
        self.mono(self.o_pohlig)
        l.addWidget(self.o_pohlig)
        return w

    def run_pohlig(self):
        try:
            self.check_small()
            n = self.known_order()

            if pow(self.g, n, self.p) != 1 or pow(self.y, n, self.p) != 1:
                raise RuntimeError(
                    "The supplied n is not consistent with g/y in the subgroup."
                )

            t0 = time.perf_counter()
            x, factors, logs = pohlig_hellman(self.g, self.y, self.p, n)
            dt = time.perf_counter() - t0
            m = self.decrypt_with_x(x)

            factor_text = " * ".join(
                str(q) if e == 1 else f"{q}^{e}" for q, e in factors
            )

            self.o_pohlig.setPlainText(
                "POHLIG–HELLMAN DISCRETE LOGARITHM\n"
                "============================================================\n"
                f"Group/subgroup order n = {n}\n"
                f"Factorization n = {factor_text}\n\n"
                "Prime-power congruences:\n  "
                + "\n  ".join(logs)
                + "\n\nCRT reconstruction:\n"
                f"  recovered x = {x}\n"
                f"  verification = {pow(self.g, x, self.p) == self.y}\n"
                f"  recovered plaintext integer m = {m}\n"
                f"  runtime = {dt:.6f} s\n\n"
                "Security lesson:\n"
                "Pohlig–Hellman cost is governed mainly by the largest prime "
                "factor of the group order. A smooth order can make the DLP "
                "far easier than its modulus size alone suggests."
            )
        except Exception as e:
            self.err(e)

    # ----------------------------------------------------------------
    # Tab 4 — reused k
    # ----------------------------------------------------------------
    def tab4(self):
        w = QWidget()
        l = QVBoxLayout(w)

        info = QLabel(
            "<b>Ephemeral-k reuse.</b> If two ElGamal ciphertexts use the same "
            "k under the same public key, then they have the same c1 and "
            "c2,1 / c2,2 = m1 / m2 mod p. If one plaintext is known, the other "
            "can be recovered without solving the DLP."
        )
        info.setWordWrap(True)
        l.addWidget(info)

        b = QPushButton("Analyze Reused k")
        b.clicked.connect(self.reused_k)
        l.addWidget(b)

        self.o4 = QTextEdit()
        self.o4.setReadOnly(True)
        self.mono(self.o4)
        l.addWidget(self.o4)
        return w

    def reused_k(self):
        try:
            if None in (self.p, self.c1, self.c2, self.c1_2, self.c2_2, self.known_m1):
                raise RuntimeError(
                    "The instance needs c1_2, c2_2, and known_m1. "
                    "Use the demonstration instance or load such a file."
                )

            same = self.c1 == self.c1_2
            if not same:
                raise RuntimeError(
                    "c1 values differ, so this instance does not demonstrate direct k reuse."
                )

            # c2_1 = m1*s, c2_2 = m2*s
            # m2 = c2_2 * m1 * inverse(c2_1) mod p.
            recovered_m2 = (
                self.c2_2 * self.known_m1 * inv(self.c2, self.p)
            ) % self.p

            self.o4.setPlainText(
                "REUSED EPHEMERAL k ATTACK\n"
                "============================================================\n"
                f"c1_1 = {self.c1}\n"
                f"c1_2 = {self.c1_2}\n"
                f"Same c1: {same}\n\n"
                "Because the same k gives the same mask s = y^k:\n"
                "  c2_1 = m1*s\n"
                "  c2_2 = m2*s\n\n"
                "Given m1:\n"
                "  s  = c2_1 / m1 mod p\n"
                "  m2 = c2_2 / s mod p\n\n"
                f"Known m1     = {self.known_m1}\n"
                f"Recovered m2 = {recovered_m2}\n\n"
                "Lesson: k must be fresh and unpredictable for every encryption."
            )

        except Exception as e:
            self.err(e)

    # ----------------------------------------------------------------
    # Tab 5 — malleability
    # ----------------------------------------------------------------
    def tab5(self):
        w = QWidget()
        l = QVBoxLayout(w)

        info = QLabel(
            "<b>Textbook ElGamal is multiplicatively malleable.</b> An attacker "
            "can transform (c1,c2) into (c1, α·c2 mod p), causing the decrypted "
            "plaintext to become α·m mod p without knowing the private key."
        )
        info.setWordWrap(True)
        l.addWidget(info)

        box = QGroupBox("Ciphertext Transformation")
        f = QFormLayout(box)

        self.alpha = QLineEdit("2")
        f.addRow("Multiplier α:", self.alpha)

        b = QPushButton("Modify Ciphertext and Demonstrate Effect")
        b.clicked.connect(self.malleability)
        f.addRow(b)

        l.addWidget(box)

        self.o5 = QTextEdit()
        self.o5.setReadOnly(True)
        self.mono(self.o5)
        l.addWidget(self.o5)
        return w

    def malleability(self):
        try:
            if self.p is None:
                raise RuntimeError("Load/generate an instance first.")

            alpha = parse_int(self.alpha.text()) % self.p
            if alpha == 0:
                raise RuntimeError("Choose nonzero α modulo p.")

            modified_c2 = (alpha * self.c2) % self.p

            text = (
                "MULTIPLICATIVE MALLEABILITY\n"
                "============================================================\n"
                "Original ciphertext:\n"
                f"  (c1,c2) = ({self.c1}, {self.c2})\n\n"
                f"Choose α = {alpha}\n"
                "Modified ciphertext:\n"
                f"  c1' = c1 = {self.c1}\n"
                f"  c2' = α*c2 mod p = {modified_c2}\n\n"
                "Algebra:\n"
                "  Dec(c1, α*c2)\n"
                "    = α*c2 / c1^x\n"
                "    = α*m mod p\n\n"
            )

            # If the small instance allows recovering x, demonstrate the result.
            if self.p.bit_length() <= self.max_bits.value():
                x = bsgs(self.g, self.y, self.p, self.p)
                if x is not None:
                    original_m = self.decrypt_with_x(x)
                    s = pow(self.c1, x, self.p)
                    modified_m = (modified_c2 * inv(s, self.p)) % self.p
                    text += (
                        "Verification using recovered classroom private exponent:\n"
                        f"  original m       = {original_m}\n"
                        f"  modified m'      = {modified_m}\n"
                        f"  α*m mod p        = {(alpha*original_m)%self.p}\n"
                        f"  relation holds   = {modified_m == (alpha*original_m)%self.p}\n\n"
                    )

            text += (
                "Security consequence:\n"
                "Textbook ElGamal provides confidentiality under appropriate "
                "assumptions but is not non-malleable/CCA-secure.\n\n"
                "Practical lesson:\n"
                "Use authenticated, standardized constructions rather than "
                "raw textbook ElGamal for application encryption."
            )

            self.o5.setPlainText(text)

        except Exception as e:
            self.err(e)


def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Arial", 16))
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
