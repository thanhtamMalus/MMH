#!/usr/bin/env python3
"""
OpenSSL + PyQt6 Stream Cipher Laboratory v3

Algorithms:
- RC4-128
- RC4-40
- ChaCha20
- ChaCha20-Poly1305 (AEAD)

RC4 and raw ChaCha20 use the local OpenSSL CLI.
ChaCha20-Poly1305 uses Python `cryptography`'s OpenSSL-backed AEAD implementation.

v2 stream-cipher model:
    KS = G(K, state, L)
    |KS| = |input| = L
    C = P XOR KS
    P = C XOR KS

AEAD extension:
    (C, TAG) = AEAD_Encrypt(K, nonce, P, AAD)
    P = AEAD_Decrypt(K, nonce, C, AAD, TAG)

For ChaCha20-Poly1305, the GUI intentionally does NOT expose a raw keystream in
Tab 2. AEAD should be treated as an authenticated-encryption construction, not
as a raw stream-cipher API.
"""

import os, secrets, shutil, subprocess, sys
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QGridLayout, QGroupBox, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton, QPlainTextEdit,
    QTabWidget, QVBoxLayout, QWidget
)
from PyQt6.QtGui import QFont
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.exceptions import InvalidTag
    CRYPTOGRAPHY_OK = True
except Exception:
    ChaCha20Poly1305 = None
    InvalidTag = Exception
    CRYPTOGRAPHY_OK = False

APP = "OpenSSL Stream-Cipher Laboratory v3"

PROFILES = {
    "RC4-128": {
        "openssl": "rc4", "key": 16, "iv": 0, "legacy": True, "aead": False,
        "note": "RC4 with 128-bit key. INSECURE; laboratory/cryptanalysis only."
    },
    "RC4-40": {
        "openssl": "rc4-40", "key": 5, "iv": 0, "legacy": True, "aead": False,
        "note": "40-bit RC4. Extremely weak; availability depends on OpenSSL."
    },
    "ChaCha20": {
        "openssl": "chacha20", "key": 32, "iv": 16, "legacy": False, "aead": False,
        "note": "Raw OpenSSL ChaCha20: 256-bit key + 16-byte IV/counter input."
    },
    "ChaCha20-Poly1305": {
        "openssl": None, "key": 32, "iv": 12, "legacy": False, "aead": True,
        "note": "AEAD: 256-bit key + 96-bit nonce + optional AAD + 128-bit authentication tag."
    },
}


def parse_hex(text, name="hex value"):
    s = "".join(text.split()).replace(":", "").replace("-", "")
    if not s:
        return b""
    if len(s) % 2:
        raise ValueError(f"{name}: hexadecimal input must contain an even number of digits.")
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError(f"{name}: invalid hexadecimal input.") from exc


def pretty_hex(data, bytes_per_line=32):
    h = data.hex()
    width = bytes_per_line * 2
    return "\n".join(h[i:i+width] for i in range(0, len(h), width))


def process(args, data=None):
    kw = {}
    if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW"):
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW
    return subprocess.run(args, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False, **kw)


class Backend:
    def __init__(self):
        self.exe = shutil.which("openssl") or "openssl"

    def version(self):
        p = process([self.exe, "version", "-a"])
        if p.returncode:
            raise RuntimeError(p.stderr.decode(errors="replace"))
        return p.stdout.decode(errors="replace")

    def providers(self):
        p = process([self.exe, "list", "-providers"])
        return (p.stdout if not p.returncode else p.stderr).decode(errors="replace")

    def ciphers(self):
        p = process([self.exe, "list", "-cipher-algorithms"])
        return (p.stdout if not p.returncode else p.stderr).decode(errors="replace")

    def cli_command(self, algorithm, key, iv):
        p = PROFILES[algorithm]
        if p["aead"]:
            raise ValueError("ChaCha20-Poly1305 is handled by the OpenSSL-backed AEAD API.")
        if len(key) != p["key"]:
            raise ValueError(f"{algorithm} requires exactly {p['key']} key bytes.")
        if len(iv) != p["iv"]:
            raise ValueError(f"{algorithm} requires exactly {p['iv']} IV/counter bytes.")
        args = [self.exe, "enc", "-" + p["openssl"]]
        if p["legacy"]:
            args += ["-provider", "default", "-provider", "legacy"]
        args += ["-K", key.hex()]
        if p["iv"]:
            args += ["-iv", iv.hex()]
        return args

    @staticmethod
    def redacted(args):
        shown = list(args)
        if "-K" in shown:
            shown[shown.index("-K") + 1] = "<SECRET-KEY-HEX>"
        return " ".join(shown)

    def transform(self, algorithm, key, iv, data):
        args = self.cli_command(algorithm, key, iv)
        p = process(args, data)
        if p.returncode:
            raise RuntimeError("OpenSSL failed:\n" + p.stderr.decode(errors="replace"))
        return p.stdout, self.redacted(args)

    def keystream(self, algorithm, key, iv, length):
        if PROFILES[algorithm]["aead"]:
            raise ValueError(
                "Raw keystream generation is intentionally unavailable for "
                "ChaCha20-Poly1305. Select ChaCha20 to study KS = G(K,state,L); "
                "use Encryption/Decryption to study the AEAD construction."
            )
        return self.transform(algorithm, key, iv, b"\x00" * length)

    def aead_encrypt(self, key, nonce, plaintext, aad):
        if not CRYPTOGRAPHY_OK:
            raise RuntimeError("Install the 'cryptography' package to use ChaCha20-Poly1305.")
        if len(key) != 32:
            raise ValueError("ChaCha20-Poly1305 requires a 32-byte key.")
        if len(nonce) != 12:
            raise ValueError("ChaCha20-Poly1305 requires a 12-byte (96-bit) nonce.")
        combined = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
        return combined[:-16], combined[-16:]

    def aead_decrypt(self, key, nonce, ciphertext, aad, tag):
        if not CRYPTOGRAPHY_OK:
            raise RuntimeError("Install the 'cryptography' package to use ChaCha20-Poly1305.")
        if len(key) != 32:
            raise ValueError("ChaCha20-Poly1305 requires a 32-byte key.")
        if len(nonce) != 12:
            raise ValueError("ChaCha20-Poly1305 requires a 12-byte (96-bit) nonce.")
        if len(tag) != 16:
            raise ValueError("ChaCha20-Poly1305 requires a 16-byte authentication tag.")
        try:
            return ChaCha20Poly1305(key).decrypt(nonce, ciphertext + tag, aad)
        except InvalidTag as exc:
            raise ValueError(
                "AUTHENTICATION FAILED: wrong key/nonce/AAD/tag, or ciphertext was modified."
            ) from exc


class DataBox(QGroupBox):
    def __init__(self, title, output=False):
        super().__init__(title)
        self.output = output
        self.mode = QComboBox(); self.mode.addItems(["Text (UTF-8)", "Hex", "File"])
        self.editor = QPlainTextEdit()
        self.path = QLineEdit()
        self.browse = QPushButton("Browse…")
        self.count = QLabel("0 bytes")

        row = QHBoxLayout()
        row.addWidget(QLabel("Mode:")); row.addWidget(self.mode)
        row.addWidget(self.path, 1); row.addWidget(self.browse); row.addWidget(self.count)
        lay = QVBoxLayout(self); lay.addLayout(row); lay.addWidget(self.editor)

        self.mode.currentTextChanged.connect(self.mode_changed)
        self.browse.clicked.connect(self.pick)
        self.editor.textChanged.connect(self.update_count)
        self.path.textChanged.connect(self.update_count)
        self.mode_changed(self.mode.currentText())

    def mode_changed(self, mode):
        f = mode == "File"
        self.path.setVisible(f); self.browse.setVisible(f)
        self.update_count()

    def pick(self):
        if self.output:
            p, _ = QFileDialog.getSaveFileName(self, "Select output file")
        else:
            p, _ = QFileDialog.getOpenFileName(self, "Select input file")
        if p:
            self.path.setText(p)
            if not self.output and self.mode.currentText() == "File":
                try:
                    self.editor.setPlainText(f"[Selected file]\n{p}\n{Path(p).stat().st_size} bytes")
                except OSError:
                    pass

    def get_bytes(self):
        m = self.mode.currentText()
        if m == "Text (UTF-8)":
            return self.editor.toPlainText().encode("utf-8")
        if m == "Hex":
            return parse_hex(self.editor.toPlainText(), "input")
        p = self.path.text().strip()
        if not p:
            raise ValueError("Select an input file.")
        return Path(p).read_bytes()

    def set_bytes(self, data):
        m = self.mode.currentText()
        if m == "Text (UTF-8)":
            try:
                self.editor.setPlainText(data.decode("utf-8"))
            except UnicodeDecodeError:
                self.editor.setPlainText("[Binary result: select Hex or File output.]")
        elif m == "Hex":
            self.editor.setPlainText(pretty_hex(data))
        else:
            p = self.path.text().strip()
            if not p:
                p, _ = QFileDialog.getSaveFileName(self, "Select output file")
                if not p:
                    raise ValueError("No output file selected.")
                self.path.setText(p)
            Path(p).write_bytes(data)
            self.editor.setPlainText(f"[Wrote {len(data)} bytes]\n{p}")
        self.count.setText(f"{len(data)} bytes")

    def update_count(self):
        if self.output:
            return
        try:
            self.count.setText(f"{len(self.get_bytes())} bytes")
        except Exception:
            self.count.setText("? bytes")


class CipherInputs(QGroupBox):
    def __init__(self):
        super().__init__("Algorithm and secret inputs")
        self.algorithm = QComboBox(); self.algorithm.addItems(PROFILES.keys())
        self.key = QLineEdit(); self.iv = QLineEdit()
        self.random_key = QPushButton("Random Secret Key")
        self.random_iv = QPushButton("Random IV/Nonce")
        self.note = QLabel(); self.note.setWordWrap(True)

        g = QGridLayout(self)
        g.addWidget(QLabel("Algorithm / variant:"), 0, 0); g.addWidget(self.algorithm, 0, 1, 1, 2)
        g.addWidget(QLabel("Secret key (hex):"), 1, 0); g.addWidget(self.key, 1, 1); g.addWidget(self.random_key, 1, 2)
        g.addWidget(QLabel("IV / nonce / counter (hex):"), 3, 0); g.addWidget(self.iv, 2, 1); g.addWidget(self.random_iv, 3, 3)
        g.addWidget(self.note, 4, 0, 1, 4)

        self.algorithm.currentTextChanged.connect(self.refresh)
        self.random_key.clicked.connect(self.gen_key)
        self.random_iv.clicked.connect(self.gen_iv)
        self.refresh()

    def refresh(self):
        p = PROFILES[self.algorithm.currentText()]
        self.note.setText(
            f"{p['note']}\nRequired key = {p['key']} bytes; "
            f"IV/nonce/counter = {p['iv']} bytes."
        )
        self.iv.setEnabled(p["iv"] > 0)
        self.random_iv.setEnabled(p["iv"] > 0)
        if not p["iv"]:
            self.iv.clear()

    def gen_key(self):
        self.key.setText(secrets.token_bytes(PROFILES[self.algorithm.currentText()]["key"]).hex())

    def gen_iv(self):
        n = PROFILES[self.algorithm.currentText()]["iv"]
        self.iv.setText(secrets.token_bytes(n).hex() if n else "")

    def values(self):
        alg = self.algorithm.currentText()
        p = PROFILES[alg]
        key = parse_hex(self.key.text(), "secret key")
        iv = parse_hex(self.iv.text(), "IV/nonce/counter") if p["iv"] else b""
        if len(key) != p["key"]:
            raise ValueError(f"{alg} requires exactly {p['key']} key bytes.")
        if len(iv) != p["iv"]:
            raise ValueError(f"{alg} requires exactly {p['iv']} IV/nonce/counter bytes.")
        return alg, key, iv


class ConfigTab(QWidget):
    def __init__(self, backend):
        super().__init__(); self.backend = backend
        self.path = QLineEdit(backend.exe)
        self.log = QPlainTextEdit(); self.log.setReadOnly(True)
        browse = QPushButton("Browse…"); test = QPushButton("Test OpenSSL")
        ciphers = QPushButton("List Cipher Algorithms")

        top = QHBoxLayout()
        top.addWidget(QLabel("OpenSSL executable:")); top.addWidget(self.path, 1)
        top.addWidget(browse); top.addWidget(test); top.addWidget(ciphers)

        self.aead_status = QLabel()
        self.aead_status.setWordWrap(True)
        self.update_aead_status()

        lay = QVBoxLayout(self)
        lay.addLayout(top); lay.addWidget(self.aead_status); lay.addWidget(self.log, 1)

        self.path.textChanged.connect(lambda x: setattr(backend, "exe", x.strip() or "openssl"))
        browse.clicked.connect(self.pick); test.clicked.connect(self.test)
        ciphers.clicked.connect(self.list_ciphers)

    def update_aead_status(self):
        self.aead_status.setText(
            "ChaCha20-Poly1305 backend: " +
            ("available through cryptography/OpenSSL."
             if CRYPTOGRAPHY_OK else
             "NOT available — install the cryptography package.")
        )

    def pick(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select OpenSSL executable")
        if p: self.path.setText(p)

    def test(self):
        try:
            self.log.setPlainText(
                self.backend.version() + "\nProviders:\n" + self.backend.providers()
            )
        except Exception as exc:
            self.log.setPlainText(str(exc))

    def list_ciphers(self):
        try: self.log.setPlainText(self.backend.ciphers())
        except Exception as exc: self.log.setPlainText(str(exc))


class KeystreamTab(QWidget):
    def __init__(self, backend):
        super().__init__(); self.backend = backend
        self.cipher = CipherInputs()
        self.input = DataBox("Reference input — determines stream length L")
        self.output = DataBox("Generated stream key / keystream KS", output=True)
        self.output.mode.setCurrentText("Hex")
        self.info = QLabel("KS = G(K,state,L), where L = byte length of input.")
        self.info.setWordWrap(True)
        generate = QPushButton("Generate Keystream")
        self.command = QLineEdit(); self.command.setReadOnly(True)

        lay = QVBoxLayout(self)
        lay.addWidget(self.cipher); lay.addWidget(self.input, 1); lay.addWidget(self.info)
        lay.addWidget(generate); lay.addWidget(self.output, 1)
        lay.addWidget(QLabel("Backend command (secret key redacted):")); lay.addWidget(self.command)
        generate.clicked.connect(self.generate)
        self.cipher.algorithm.currentTextChanged.connect(self.algorithm_changed)
        self.algorithm_changed(self.cipher.algorithm.currentText())

    def algorithm_changed(self, alg):
        if PROFILES[alg]["aead"]:
            self.info.setText(
                "ChaCha20-Poly1305 is AEAD. v3 intentionally does not expose a raw "
                "keystream for this profile. Select ChaCha20 for raw KS experiments; "
                "use Tabs 3–4 for authenticated encryption/decryption."
            )
        else:
            self.info.setText("KS = G(K,state,L), where L = byte length of input.")

    def generate(self):
        try:
            alg, key, iv = self.cipher.values()
            ref = self.input.get_bytes()
            ks, cmd = self.backend.keystream(alg, key, iv, len(ref))
            self.output.set_bytes(ks); self.command.setText(cmd)
            self.info.setText(f"L = {len(ref)} bytes; |KS| = {len(ks)} bytes.")
        except Exception as exc:
            QMessageBox.critical(self, APP, str(exc))


class CryptTab(QWidget):
    def __init__(self, backend, decrypt=False):
        super().__init__(); self.backend = backend; self.decrypt = decrypt
        self.cipher = CipherInputs()
        self.input = DataBox("Ciphertext input" if decrypt else "Plaintext input")
        self.output = DataBox("Recovered plaintext output" if decrypt else "Ciphertext output", True)

        self.aad = QPlainTextEdit(); self.aad.setMaximumHeight(70)
        self.aad_mode = QComboBox(); self.aad_mode.addItems(["Text (UTF-8)", "Hex"])
        self.tag = QLineEdit()
        self.tag.setPlaceholderText("16-byte authentication tag in hex")
        self.aead_box = QGroupBox("AEAD parameters — ChaCha20-Poly1305")
        ag = QGridLayout(self.aead_box)
        ag.addWidget(QLabel("AAD mode:"), 0, 0); ag.addWidget(self.aad_mode, 0, 1)
        ag.addWidget(QLabel("Associated Data (AAD):"), 1, 0); ag.addWidget(self.aad, 1, 1)
        ag.addWidget(QLabel("Authentication tag (hex):"), 2, 0); ag.addWidget(self.tag, 2, 1)

        self.ks = QPlainTextEdit(); self.ks.setReadOnly(True); self.ks.setMaximumHeight(100)
        self.ks_label = QLabel("Generated keystream KS (hex):")
        self.status = QLabel(); self.status.setWordWrap(True)
        self.command = QLineEdit(); self.command.setReadOnly(True)
        go = QPushButton("Decrypt" if decrypt else "Encrypt")

        if decrypt:
            self.input.mode.setCurrentText("Hex")
        else:
            self.output.mode.setCurrentText("Hex")

        lay = QVBoxLayout(self)
        lay.addWidget(self.cipher); lay.addWidget(self.aead_box)
        lay.addWidget(self.input, 1); lay.addWidget(go)
        lay.addWidget(self.ks_label); lay.addWidget(self.ks)
        lay.addWidget(self.status); lay.addWidget(self.output, 1)
        lay.addWidget(QLabel("Backend operation:")); lay.addWidget(self.command)

        go.clicked.connect(self.run)
        self.cipher.algorithm.currentTextChanged.connect(self.algorithm_changed)
        self.algorithm_changed(self.cipher.algorithm.currentText())

    def aad_bytes(self):
        if self.aad_mode.currentText().startswith("Text"):
            return self.aad.toPlainText().encode("utf-8")
        return parse_hex(self.aad.toPlainText(), "AAD")

    def algorithm_changed(self, alg):
        aead = PROFILES[alg]["aead"]
        self.aead_box.setVisible(aead)
        self.ks_label.setVisible(not aead)
        self.ks.setVisible(not aead)
        if aead:
            self.status.setText(
                "AEAD mode: ciphertext and 16-byte authentication tag are separate outputs. "
                "AAD is authenticated but not encrypted."
            )

    def run(self):
        try:
            alg, key, iv = self.cipher.values()
            data = self.input.get_bytes()

            if PROFILES[alg]["aead"]:
                aad = self.aad_bytes()
                if self.decrypt:
                    tag = parse_hex(self.tag.text(), "authentication tag")
                    result = self.backend.aead_decrypt(key, iv, data, aad, tag)
                    self.status.setText(
                        f"AUTHENTICATION SUCCESS. Ciphertext={len(data)} bytes; "
                        f"AAD={len(aad)} bytes; tag=16 bytes."
                    )
                    self.command.setText(
                        "OpenSSL-backed ChaCha20Poly1305.decrypt("
                        "key=<SECRET>, nonce=<12 bytes>, ciphertext||tag, aad)"
                    )
                else:
                    result, tag = self.backend.aead_encrypt(key, iv, data, aad)
                    self.tag.setText(tag.hex())
                    self.status.setText(
                        f"AEAD encryption complete. Plaintext={len(data)} bytes; "
                        f"ciphertext={len(result)} bytes; AAD={len(aad)} bytes; tag=16 bytes."
                    )
                    self.command.setText(
                        "OpenSSL-backed ChaCha20Poly1305.encrypt("
                        "key=<SECRET>, nonce=<12 bytes>, plaintext, aad)"
                    )
                self.output.set_bytes(result)
                return

            ks, cmd = self.backend.keystream(alg, key, iv, len(data))
            result = bytes(a ^ b for a, b in zip(data, ks))
            direct, _ = self.backend.transform(alg, key, iv, data)
            if direct != result:
                raise RuntimeError("Verification failed: input XOR KS != direct OpenSSL result.")
            self.ks.setPlainText(pretty_hex(ks))
            self.output.set_bytes(result)
            self.command.setText(cmd)
            self.status.setText(
                f"L={len(data)} bytes; |KS|={len(ks)} bytes; " +
                ("P = C XOR KS." if self.decrypt else "C = P XOR KS.")
            )
        except Exception as exc:
            self.status.setText("FAILED")
            QMessageBox.critical(self, APP, str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.backend = Backend()
        self.setWindowTitle(APP); self.resize(1120, 930)
        tabs = QTabWidget()
        tabs.addTab(ConfigTab(self.backend), "1. Config Library")
        tabs.addTab(KeystreamTab(self.backend), "2. Generate Stream Key")
        tabs.addTab(CryptTab(self.backend, False), "3. Encryption")
        tabs.addTab(CryptTab(self.backend, True), "4. Decryption")
        self.setCentralWidget(tabs)
        self.statusBar().showMessage(
            "v3: RC4/ChaCha20 stream-cipher labs + ChaCha20-Poly1305 authenticated encryption."
        )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Arial", 16))
    win = MainWindow(); win.show()
    raise SystemExit(app.exec())
