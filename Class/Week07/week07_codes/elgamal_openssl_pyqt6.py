"""
Week 07 — ElGamal Encryption over Standard FFDHE Groups
OpenSSL + PyQt6
=======================================================

This laboratory keeps the same five-tab teaching style as the FFDHE program:

1. OpenSSL Settings
2. Select Standard FFDHE Group & Check Parameters
3. Generate ElGamal Key Pair
4. ElGamal Encryption
5. ElGamal Decryption

Important implementation note
-----------------------------
OpenSSL 3.x does not expose a generic `openssl elgamal` encryption command.
This program therefore uses OpenSSL for:
  * standardized FFDHE parameter construction and validation,
  * DH/ElGamal-compatible private/public key generation,
  * PEM/DER key encoding, decoding, and inspection.

The ElGamal equations themselves are evaluated with Python arbitrary-precision
integer arithmetic:
    y  = g^x mod p
    c1 = g^k mod p
    c2 = m * y^k mod p
    m  = c2 * (c1^x)^(-1) mod p

The random ephemeral exponent k is generated with Python's `secrets` module.

This is an educational finite-field ElGamal demonstration. It is NOT a
production encryption format and does not add authenticated encryption.
"""

from __future__ import annotations

import secrets
import re
import shutil
import subprocess
import sys
from pathlib import Path

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton,
    QTabWidget, QTextEdit, QVBoxLayout, QWidget
)

APP_DIR = Path.cwd() / "week07_elgamal_output"
APP_DIR.mkdir(parents=True, exist_ok=True)

FFDHE_GROUPS = ["ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192"]


def hex_block(data: bytes, width: int = 64) -> str:
    h = data.hex()
    return "\n".join(h[i:i + width] for i in range(0, len(h), width))


def int_hex(n: int, width: int = 64) -> str:
    h = format(n, "x")
    if len(h) % 2:
        h = "0" + h
    return "\n".join(h[i:i + width] for i in range(0, len(h), width))


def read_hex_file(path: Path) -> bytes:
    s = "".join(path.read_text(encoding="utf-8").split()).replace(":", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    if len(s) % 2:
        s = "0" + s
    return bytes.fromhex(s)


def write_encoded(path: Path, data: bytes, mode: str) -> None:
    if mode == "Binary (.bin)":
        path.write_bytes(data)
    else:
        path.write_text(hex_block(data) + "\n", encoding="utf-8")


class OpenSSL:
    def __init__(self):
        self.binary = shutil.which("openssl") or "openssl"

    def set_binary(self, value: str):
        self.binary = value.strip() or "openssl"

    def run(self, args: list[str]) -> subprocess.CompletedProcess:
        cmd = [self.binary] + [str(x) for x in args]
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if cp.returncode != 0:
            raise RuntimeError(
                "OpenSSL command failed.\n\n"
                f"Command:\n{' '.join(cmd)}\n\n"
                f"STDOUT:\n{cp.stdout.decode(errors='replace')}\n\n"
                f"STDERR:\n{cp.stderr.decode(errors='replace')}"
            )
        return cp

    def text(self, args: list[str]) -> str:
        return self.run(args).stdout.decode(errors="replace")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Week 07 — ElGamal Encryption over FFDHE Groups")
        self.resize(1240, 880)

        self.openssl = OpenSSL()
        self.current_group = "ffdhe2048"

        self.params_file = APP_DIR / "elgamal_params.pem"
        self.private_file = APP_DIR / "elgamal_private.pem"
        self.public_file = APP_DIR / "elgamal_public.pem"

        self.p = self.g = self.x = self.y = None
        self.loaded_public = None
        self.loaded_private = None
        self.c1 = self.c2 = None
        self.recovered = None

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.tabs.addTab(self.make_tab1(), "1. OpenSSL Settings")
        self.tabs.addTab(self.make_tab2(), "2. FFDHE Parameters")
        self.tabs.addTab(self.make_tab3(), "3. ElGamal Key Pair")
        self.tabs.addTab(self.make_tab4(), "4. Encryption")
        self.tabs.addTab(self.make_tab5(), "5. Decryption")

    def monospace(self, w):
        f = QFont("Consolas")
        f.setStyleHint(QFont.StyleHint.Monospace)
        w.setFont(f)

    def error(self, exc):
        QMessageBox.critical(self, "Error", str(exc))

    def refresh_openssl(self):
        self.openssl.set_binary(self.openssl_path.text())

    def browse(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select OpenSSL executable", "", "Executables (*.exe);;All files (*)")
        if p:
            self.openssl_path.setText(p)

    # ---------- common parameter/key extraction ----------
    def create_params(self):
        self.current_group = self.group_combo.currentText()
        self.openssl.run([
            "genpkey", "-genparam", "-algorithm", "DH",
            "-pkeyopt", f"group:{self.current_group}",
            "-out", str(self.params_file)
        ])

    def parse_pg(self):
        self.create_params()
        txt = self.openssl.text(["asn1parse", "-in", str(self.params_file), "-inform", "PEM"])
        vals = []
        for line in txt.splitlines():
            if "prim: INTEGER" in line:
                v = line.rsplit(":", 1)[-1].strip()
                if v:
                    vals.append(v)
        if len(vals) < 2:
            raise RuntimeError("Could not decode explicit p and g from the OpenSSL DH parameter object.")
        self.p = int(vals[0], 16)
        self.g = int(vals[1], 16)
        return self.p, self.g

    def parse_private_public_numbers(self, private_path: Path):
        text = self.openssl.text(["pkey", "-in", str(private_path), "-text", "-noout"])

        # IMPORTANT:
        # OpenSSL commonly starts with a line such as:
        #     DH Private-Key: (2048 bit)
        # followed by the real value heading:
        #     private-key:
        #         01:ab:...
        #
        # A plain substring search for "private-key:" therefore matches the
        # descriptive "DH Private-Key:" line first.  If that heading text is
        # then filtered for hexadecimal characters, letters from the word
        # "private-key" contaminate x and make y != g^x mod p.
        #
        # Parse ONLY exact heading lines and ONLY colon-separated hex lines.
        def exact_hex_section(heading: str) -> int:
            lines = text.splitlines()
            start = None

            for idx, line in enumerate(lines):
                if line.strip().lower() == heading.lower():
                    start = idx + 1
                    break

            if start is None:
                raise RuntimeError(
                    f"Cannot find exact '{heading}' value section in OpenSSL key inspection."
                )

            octets = []
            for line in lines[start:]:
                stripped = line.strip()

                # Stop at the next textual OpenSSL field/heading.
                if not stripped:
                    if octets:
                        break
                    continue

                # Accept only lines made from hexadecimal byte pairs separated
                # by colons, e.g. "01:ab:7f:..." (optional trailing colon).
                if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:)*[0-9A-Fa-f]{2}:?", stripped):
                    octets.extend(re.findall(r"[0-9A-Fa-f]{2}", stripped))
                else:
                    if octets:
                        break

            if not octets:
                raise RuntimeError(
                    f"Cannot parse hexadecimal bytes under exact '{heading}' section."
                )

            return int("".join(octets), 16)

        x = exact_hex_section("private-key:")
        y = exact_hex_section("public-key:")
        return x, y, text

    # ---------- Tab 1 ----------
    def make_tab1(self):
        page = QWidget(); layout = QVBoxLayout(page)
        d = QLabel("<b>Goal:</b> configure OpenSSL. OpenSSL provides standardized FFDHE parameters and key encoding/inspection for this ElGamal laboratory.")
        d.setWordWrap(True); layout.addWidget(d)
        box = QGroupBox("OpenSSL Configuration"); form = QFormLayout(box)
        self.openssl_path = QLineEdit(self.openssl.binary)
        row = QHBoxLayout(); row.addWidget(self.openssl_path)
        b = QPushButton("Browse..."); b.clicked.connect(self.browse); row.addWidget(b)
        form.addRow("OpenSSL executable:", row)
        t = QPushButton("Test OpenSSL"); t.clicked.connect(self.test_openssl); form.addRow(t)
        layout.addWidget(box)
        self.out1 = QTextEdit(); self.out1.setReadOnly(True); self.monospace(self.out1); layout.addWidget(self.out1)
        return page

    def test_openssl(self):
        try:
            self.refresh_openssl()
            self.out1.setPlainText(
                "=== OPENSSL VERSION ===\n" + self.openssl.text(["version", "-a"]) +
                "\n=== PROVIDERS ===\n" + self.openssl.text(["list", "-providers"]) +
                "\nTeaching note:\nOpenSSL has no generic ElGamal cipher CLI. "
                "It is used here for FFDHE groups and key management; ElGamal modular equations are explicit in Python."
            )
        except Exception as e: self.error(e)

    # ---------- Tab 2 ----------
    def make_tab2(self):
        page = QWidget(); layout = QVBoxLayout(page)
        d = QLabel("<b>Goal:</b> choose the public finite-field domain (p,g) from a standardized FFDHE named group.")
        d.setWordWrap(True); layout.addWidget(d)
        box = QGroupBox("Public ElGamal Domain Parameters"); form = QFormLayout(box)
        self.group_combo = QComboBox(); self.group_combo.addItems(FFDHE_GROUPS); form.addRow("Named group:", self.group_combo)
        b = QPushButton("Create, Check, and Show p / g"); b.clicked.connect(self.check_params); form.addRow(b)
        layout.addWidget(box)
        self.out2 = QTextEdit(); self.out2.setReadOnly(True); self.monospace(self.out2); layout.addWidget(self.out2)
        return page

    def check_params(self):
        try:
            self.refresh_openssl()
            p, g = self.parse_pg()
            check = self.openssl.text(["pkeyparam", "-in", str(self.params_file), "-check", "-text"])
            q = (p - 1) // 2
            self.out2.setPlainText(
                f"Named group : {self.current_group}\n"
                f"Parameter file: {self.params_file}\n\n"
                "=== MATHEMATICAL DOMAIN ===\n"
                f"|p| = {p.bit_length()} bits\n"
                f"|q| = {q.bit_length()} bits, q=(p-1)/2\n\n"
                f"p (HEX):\n{int_hex(p)}\n\n"
                f"p (DECIMAL):\n{p}\n\n"
                f"g (HEX)    : {g:x}\n"
                f"g (DECIMAL): {g}\n\n"
                "=== OPENSSL VALIDATION ===\n" + check +
                "\nElGamal setting:\nprivate x; public y = g^x mod p."
            )
        except Exception as e: self.error(e)

    # ---------- Tab 3 ----------
    def make_tab3(self):
        page = QWidget(); layout = QVBoxLayout(page)
        d = QLabel("<b>Goal:</b> generate one ElGamal recipient key pair. OpenSSL generates a DH-compatible key over the selected FFDHE group; mathematically it is x (private) and y=g^x mod p (public).")
        d.setWordWrap(True); layout.addWidget(d)
        b = QPushButton("Generate ElGamal Key Pair"); b.clicked.connect(self.generate_keys); layout.addWidget(b)

        self.show_pg = QCheckBox("Show detailed p and g with key details"); layout.addWidget(self.show_pg)

        pv = QGroupBox("Save Private Key"); fp = QFormLayout(pv)
        self.priv_fmt = QComboBox(); self.priv_fmt.addItems(["PEM (.pem)", "DER binary (.bin)", "DER hex (.hex)"]); fp.addRow("Format:", self.priv_fmt)
        bp = QPushButton("Save Private Key As..."); bp.clicked.connect(self.save_private); fp.addRow(bp); layout.addWidget(pv)

        pu = QGroupBox("Save Public Key"); fu = QFormLayout(pu)
        self.pub_fmt = QComboBox(); self.pub_fmt.addItems(["PEM (.pem)", "DER binary (.bin)", "DER hex (.hex)"]); fu.addRow("Format:", self.pub_fmt)
        bu = QPushButton("Save Public Key As..."); bu.clicked.connect(self.save_public); fu.addRow(bu); layout.addWidget(pu)

        self.out3 = QTextEdit(); self.out3.setReadOnly(True); self.monospace(self.out3); layout.addWidget(self.out3)
        return page

    def generate_keys(self):
        try:
            self.refresh_openssl()
            self.current_group = self.group_combo.currentText()
            self.parse_pg()
            self.openssl.run(["genpkey", "-algorithm", "DH", "-pkeyopt", f"group:{self.current_group}", "-out", str(self.private_file)])
            self.openssl.run(["pkey", "-in", str(self.private_file), "-pubout", "-out", str(self.public_file)])
            self.x, self.y, details = self.parse_private_public_numbers(self.private_file)

            # Cross-check the mathematical ElGamal public key.
            y_math = pow(self.g, self.x, self.p)
            if y_math != self.y:
                raise RuntimeError("Key consistency check failed: OpenSSL public value != g^x mod p.")

            pg = ""
            if self.show_pg.isChecked():
                pg = (
                    "\n=== DOMAIN PARAMETERS ===\n"
                    f"p ({self.p.bit_length()} bits, HEX):\n{int_hex(self.p)}\n\n"
                    f"g = {self.g} (0x{self.g:x})\n"
                )

            self.out3.setPlainText(
                f"Named group: {self.current_group}\n"
                f"{pg}\n"
                "=== ELGAMAL KEY RELATION ===\n"
                "Private key : x\n"
                "Public key  : y = g^x mod p\n\n"
                f"x (HEX):\n{int_hex(self.x)}\n\n"
                f"y (HEX):\n{int_hex(self.y)}\n\n"
                f"Consistency check y == g^x mod p: {self.y == y_math}\n\n"
                "=== OPENSSL KEY INSPECTION ===\n" + details +
                "\nKeep x/private key secret. Distribute only the public key."
            )
        except Exception as e: self.error(e)

    def private_der(self):
        return self.openssl.run(["pkey", "-in", str(self.private_file), "-outform", "DER"]).stdout

    def public_der(self):
        return self.openssl.run(["pkey", "-pubin", "-in", str(self.public_file), "-pubout", "-outform", "DER"]).stdout

    def save_private(self):
        try:
            self.refresh_openssl()
            if not self.private_file.exists(): raise RuntimeError("Generate a key pair first.")
            mode = self.priv_fmt.currentText()
            if mode == "PEM (.pem)":
                p, _ = QFileDialog.getSaveFileName(self, "Save private key", "elgamal_private.pem", "PEM (*.pem)")
                if p: self.openssl.run(["pkey", "-in", str(self.private_file), "-out", p])
            else:
                data = self.private_der(); ext = ".bin" if "binary" in mode else ".hex"
                p, _ = QFileDialog.getSaveFileName(self, "Save private key", "elgamal_private"+ext, "All files (*)")
                if p: write_encoded(Path(p), data, "Binary (.bin)" if ext == ".bin" else "Hex text (.hex)")
        except Exception as e: self.error(e)

    def save_public(self):
        try:
            self.refresh_openssl()
            if not self.public_file.exists(): raise RuntimeError("Generate a key pair first.")
            mode = self.pub_fmt.currentText()
            if mode == "PEM (.pem)":
                p, _ = QFileDialog.getSaveFileName(self, "Save public key", "elgamal_public.pem", "PEM (*.pem)")
                if p: self.openssl.run(["pkey", "-pubin", "-in", str(self.public_file), "-pubout", "-out", p])
            else:
                data = self.public_der(); ext = ".bin" if "binary" in mode else ".hex"
                p, _ = QFileDialog.getSaveFileName(self, "Save public key", "elgamal_public"+ext, "All files (*)")
                if p: write_encoded(Path(p), data, "Binary (.bin)" if ext == ".bin" else "Hex text (.hex)")
        except Exception as e: self.error(e)

    # ---------- key loaders ----------
    def normalize_key(self, source: Path, mode: str, public: bool) -> Path:
        dest = APP_DIR / ("loaded_public.pem" if public else "loaded_private.pem")
        prefix = ["pkey"]
        if public: prefix += ["-pubin"]
        if mode == "PEM (.pem)":
            args = prefix + ["-in", str(source)]
            if public: args += ["-pubout"]
            args += ["-out", str(dest)]
            self.openssl.run(args)
        else:
            data = source.read_bytes() if mode == "DER binary (.bin)" else read_hex_file(source)
            tmp = APP_DIR / "_key.der"; tmp.write_bytes(data)
            try:
                args = prefix + ["-inform", "DER", "-in", str(tmp)]
                if public: args += ["-pubout"]
                args += ["-out", str(dest)]
                self.openssl.run(args)
            finally:
                if tmp.exists(): tmp.unlink()
        return dest

    def public_numbers_from_public_key(self, path: Path):
        text = self.openssl.text(["pkey", "-pubin", "-in", str(path), "-text", "-noout"])
        lines = text.splitlines()
        start = None

        for idx, line in enumerate(lines):
            if line.strip().lower() == "public-key:":
                start = idx + 1
                break

        if start is None:
            raise RuntimeError("Cannot locate exact public-key value section.")

        octets = []
        for line in lines[start:]:
            stripped = line.strip()
            if not stripped:
                if octets:
                    break
                continue
            if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:)*[0-9A-Fa-f]{2}:?", stripped):
                octets.extend(re.findall(r"[0-9A-Fa-f]{2}", stripped))
            else:
                if octets:
                    break

        if not octets:
            raise RuntimeError("Cannot parse public-key hexadecimal bytes.")

        y = int("".join(octets), 16)

        # p,g come from the named group selected in Tab 2.
        self.parse_pg()
        return self.p, self.g, y, text

    # ---------- Tab 4 Encryption ----------
    def make_tab4(self):
        page = QWidget(); layout = QVBoxLayout(page)
        d = QLabel("<b>ElGamal encryption:</b> load the recipient public key, enter plaintext as UTF-8 text or HEX bytes, and compute (c1,c2) using a fresh random k.")
        d.setWordWrap(True); layout.addWidget(d)

        kb = QGroupBox("Recipient Public Key"); f = QFormLayout(kb)
        self.enc_pub_fmt = QComboBox(); self.enc_pub_fmt.addItems(["PEM (.pem)", "DER binary (.bin)", "DER hex (.hex)"]); f.addRow("Format:", self.enc_pub_fmt)
        self.enc_pub_path = QLineEdit(); self.enc_pub_path.setReadOnly(True); f.addRow("File:", self.enc_pub_path)
        b = QPushButton("Load Recipient Public Key"); b.clicked.connect(self.load_enc_public); f.addRow(b); layout.addWidget(kb)

        mb = QGroupBox("Plaintext m"); fm = QFormLayout(mb)
        self.msg_fmt = QComboBox(); self.msg_fmt.addItems(["Text (UTF-8)", "Hex bytes"]); fm.addRow("Input:", self.msg_fmt)
        self.msg = QLineEdit("Hello ElGamal"); fm.addRow("Message:", self.msg)
        e = QPushButton("Encrypt with Fresh Random k"); e.clicked.connect(self.encrypt); fm.addRow(e); layout.addWidget(mb)

        ob = QGroupBox("Save Ciphertext (c1 || c2)"); fo = QFormLayout(ob)
        self.ct_fmt = QComboBox(); self.ct_fmt.addItems(["Hex text (.hex)", "Binary (.bin)"]); fo.addRow("Format:", self.ct_fmt)
        s = QPushButton("Save Ciphertext"); s.clicked.connect(self.save_ciphertext); fo.addRow(s); layout.addWidget(ob)

        self.out4 = QTextEdit(); self.out4.setReadOnly(True); self.monospace(self.out4); layout.addWidget(self.out4)
        return page

    def load_enc_public(self):
        try:
            self.refresh_openssl()
            mode = self.enc_pub_fmt.currentText()
            p, _ = QFileDialog.getOpenFileName(self, "Load recipient public key", "", "All files (*)")
            if not p: return
            self.loaded_public = self.normalize_key(Path(p), mode, True)
            self.p, self.g, self.y, details = self.public_numbers_from_public_key(self.loaded_public)
            self.enc_pub_path.setText(p)
            self.out4.setPlainText(
                f"RECIPIENT PUBLIC KEY LOADED\n{'='*60}\nSource: {p}\n"
                f"Group: {self.current_group}\ny = g^x mod p (HEX):\n{int_hex(self.y)}\n\n{details}"
            )
        except Exception as e: self.error(e)

    def encrypt(self):
        try:
            if self.loaded_public is None: raise RuntimeError("Load recipient public key first.")
            raw = self.msg.text().encode("utf-8") if self.msg_fmt.currentText() == "Text (UTF-8)" else bytes.fromhex("".join(self.msg.text().split()))
            m = int.from_bytes(raw, "big")
            if m <= 0 or m >= self.p:
                raise RuntimeError("Plaintext integer must satisfy 0 < m < p. Use a shorter message.")

            # q=(p-1)/2 for RFC 7919 safe-prime FFDHE groups.
            q = (self.p - 1) // 2
            k = secrets.randbelow(q - 2) + 2
            self.c1 = pow(self.g, k, self.p)
            s = pow(self.y, k, self.p)
            self.c2 = (m * s) % self.p
            self.ct_width = (self.p.bit_length() + 7) // 8

            self.out4.append(
                f"\n\nELGAMAL ENCRYPTION\n{'='*60}\n"
                "Public key: (p,g,y)\nFresh secret: k\n"
                "c1 = g^k mod p\nc2 = m * y^k mod p\n\n"
                f"m (HEX): {raw.hex()}\n"
                f"k (HEX, teaching display):\n{int_hex(k)}\n\n"
                f"c1:\n{int_hex(self.c1)}\n\nc2:\n{int_hex(self.c2)}\n\n"
                "Ciphertext = (c1,c2). A new random k must be used for every encryption."
            )
        except Exception as e: self.error(e)

    def save_ciphertext(self):
        try:
            if self.c1 is None or self.c2 is None: raise RuntimeError("Encrypt first.")
            w = self.ct_width
            data = self.c1.to_bytes(w, "big") + self.c2.to_bytes(w, "big")
            mode = self.ct_fmt.currentText(); ext = ".bin" if "Binary" in mode else ".hex"
            p, _ = QFileDialog.getSaveFileName(self, "Save ElGamal ciphertext", "elgamal_ciphertext"+ext, "All files (*)")
            if p: write_encoded(Path(p), data, mode)
        except Exception as e: self.error(e)

    # ---------- Tab 5 Decryption ----------
    def make_tab5(self):
        page = QWidget(); layout = QVBoxLayout(page)
        d = QLabel("<b>ElGamal decryption:</b> load the recipient private key and ciphertext (c1,c2), then recover m = c2·(c1^x)^(-1) mod p.")
        d.setWordWrap(True); layout.addWidget(d)

        kb = QGroupBox("Recipient Private Key"); f = QFormLayout(kb)
        self.dec_priv_fmt = QComboBox(); self.dec_priv_fmt.addItems(["PEM (.pem)", "DER binary (.bin)", "DER hex (.hex)"]); f.addRow("Format:", self.dec_priv_fmt)
        self.dec_priv_path = QLineEdit(); self.dec_priv_path.setReadOnly(True); f.addRow("File:", self.dec_priv_path)
        b = QPushButton("Load Private Key"); b.clicked.connect(self.load_dec_private); f.addRow(b); layout.addWidget(kb)

        cb = QGroupBox("Ciphertext"); fc = QFormLayout(cb)
        self.dec_ct_fmt = QComboBox(); self.dec_ct_fmt.addItems(["Hex text (.hex)", "Binary (.bin)"]); fc.addRow("Format:", self.dec_ct_fmt)
        self.dec_ct_path = QLineEdit(); self.dec_ct_path.setReadOnly(True); fc.addRow("File:", self.dec_ct_path)
        c = QPushButton("Load Ciphertext"); c.clicked.connect(self.load_ciphertext); fc.addRow(c)
        dec = QPushButton("Decrypt"); dec.clicked.connect(self.decrypt); fc.addRow(dec); layout.addWidget(cb)

        self.out5 = QTextEdit(); self.out5.setReadOnly(True); self.monospace(self.out5); layout.addWidget(self.out5)
        return page

    def load_dec_private(self):
        try:
            self.refresh_openssl()
            mode = self.dec_priv_fmt.currentText()
            p, _ = QFileDialog.getOpenFileName(self, "Load recipient private key", "", "All files (*)")
            if not p: return
            self.loaded_private = self.normalize_key(Path(p), mode, False)
            self.parse_pg()
            self.x, self.y, details = self.parse_private_public_numbers(self.loaded_private)
            self.dec_priv_path.setText(p)
            self.out5.setPlainText(
                f"PRIVATE KEY LOADED\n{'='*60}\nSource: {p}\n"
                f"x (HEX):\n{int_hex(self.x)}\n\n{details}"
            )
        except Exception as e: self.error(e)

    def load_ciphertext(self):
        try:
            mode = self.dec_ct_fmt.currentText()
            p, _ = QFileDialog.getOpenFileName(self, "Load ElGamal ciphertext", "", "All files (*)")
            if not p: return
            data = Path(p).read_bytes() if mode == "Binary (.bin)" else read_hex_file(Path(p))
            if self.p is None: raise RuntimeError("Load the private key first so p is known.")
            w = (self.p.bit_length() + 7) // 8
            if len(data) != 2*w:
                raise RuntimeError(f"Ciphertext must contain exactly 2 × {w} = {2*w} bytes.")
            self.c1 = int.from_bytes(data[:w], "big"); self.c2 = int.from_bytes(data[w:], "big")
            if not (1 <= self.c1 < self.p and 0 <= self.c2 < self.p):
                raise RuntimeError("Ciphertext components are outside the valid field range.")
            self.dec_ct_path.setText(p)
            self.out5.append(f"\nCIPHERTEXT LOADED\n{'='*60}\nc1:\n{int_hex(self.c1)}\n\nc2:\n{int_hex(self.c2)}")
        except Exception as e: self.error(e)

    def decrypt(self):
        try:
            if self.loaded_private is None or self.c1 is None: raise RuntimeError("Load private key and ciphertext first.")
            s = pow(self.c1, self.x, self.p)
            m = (self.c2 * pow(s, -1, self.p)) % self.p
            raw = m.to_bytes(max(1, (m.bit_length()+7)//8), "big")
            try: text = raw.decode("utf-8")
            except UnicodeDecodeError: text = "(not valid UTF-8)"
            self.recovered = raw
            self.out5.append(
                f"\n\nELGAMAL DECRYPTION\n{'='*60}\n"
                "s = c1^x mod p\nm = c2 * s^(-1) mod p\n\n"
                f"Recovered m (HEX):\n{raw.hex()}\n\nRecovered UTF-8:\n{text}\n\n"
                "Correctness: c2/(c1^x) = m·y^k/(g^k)^x = m."
            )
        except Exception as e: self.error(e)


def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Arial", 16))
    w = MainWindow(); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
