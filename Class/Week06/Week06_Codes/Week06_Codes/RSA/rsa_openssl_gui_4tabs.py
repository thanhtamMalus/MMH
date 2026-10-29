import os
import sys
import subprocess
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFormLayout, QGridLayout,
    QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QPushButton, QTabWidget, QVBoxLayout, QWidget
)


class RSALab(QMainWindow):
    """
    Four-tab RSA teaching GUI.

    Tab 1: OpenSSL configuration
    Tab 2: Generate and verify RSA keys
    Tab 3: RSA-OAEP encryption
    Tab 4: RSA-OAEP decryption

    Cryptographic operations are executed by OpenSSL, not implemented
    manually in Python.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("RSA Laboratory — PyQt6 + OpenSSL")
        self.resize(1080, 760)

        self.private_key_path = ""
        self.public_key_path = ""

        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)

        title = QLabel("RSA Laboratory — Real RSA with OpenSSL")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        outer.addWidget(title)

        note = QLabel(
            "RSA key generation + RSA-OAEP encryption/decryption "
            "(SHA-256, MGF1-SHA-256)"
        )
        note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(note)

        self.tabs = QTabWidget()
        outer.addWidget(self.tabs, 1)

        self.tabs.addTab(self.make_config_tab(), "1. OpenSSL Config")
        self.tabs.addTab(self.make_key_tab(), "2. Generate && Verify Key")
        self.tabs.addTab(self.make_encrypt_tab(), "3. Encryption")
        self.tabs.addTab(self.make_decrypt_tab(), "4. Decryption")

        self.statusBar().showMessage("Start with Tab 1: configure and test OpenSSL.")

    # ================================================================
    # TAB 1 — OPENSSL CONFIG
    # ================================================================
    def make_config_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        intro = QLabel(
            "<b>Step 1.</b> Select the OpenSSL executable and its configuration "
            "file, then test the installation."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        box = QGroupBox("OpenSSL Paths")
        grid = QGridLayout(box)

        if os.name == "nt":
            default_exe = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
            default_conf = r"C:\Program Files\OpenSSL-Win64\bin\openssl.cfg"
        else:
            default_exe = "/usr/bin/openssl"
            default_conf = "/etc/ssl/openssl.cnf"

        self.openssl_edit = QLineEdit(default_exe)
        self.config_edit = QLineEdit(default_conf)

        browse_exe = QPushButton("Browse...")
        browse_exe.clicked.connect(self.browse_openssl)
        browse_conf = QPushButton("Browse...")
        browse_conf.clicked.connect(self.browse_config)

        grid.addWidget(QLabel("OpenSSL executable:"), 0, 0)
        grid.addWidget(self.openssl_edit, 0, 1)
        grid.addWidget(browse_exe, 0, 2)

        grid.addWidget(QLabel("OpenSSL config:"), 1, 0)
        grid.addWidget(self.config_edit, 1, 1)
        grid.addWidget(browse_conf, 1, 2)

        layout.addWidget(box)

        test = QPushButton("Test OpenSSL Configuration")
        test.clicked.connect(self.test_openssl)
        layout.addWidget(test)

        self.config_output = self.make_output()
        layout.addWidget(QLabel("<b>OpenSSL information</b>"))
        layout.addWidget(self.config_output, 1)

        return tab

    # ================================================================
    # TAB 2 — GENERATE AND VERIFY KEY
    # ================================================================
    def make_key_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        intro = QLabel(
            "<b>Step 2.</b> Generate a real RSA private key, derive its public "
            "key, and verify/inspect the key material with OpenSSL."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        genbox = QGroupBox("RSA Key Pair")
        grid = QGridLayout(genbox)

        self.bits = QComboBox()
        self.bits.addItems(["2048", "3072", "4096"])
        self.bits.setCurrentText("2048")

        self.private_edit = QLineEdit()
        self.private_edit.setReadOnly(True)
        self.public_edit = QLineEdit()
        self.public_edit.setReadOnly(True)

        generate = QPushButton("Generate RSA Key Pair...")
        generate.clicked.connect(self.generate_keys)

        load_private = QPushButton("Load Private Key")
        load_private.clicked.connect(self.load_private_key)

        load_public = QPushButton("Load Public Key")
        load_public.clicked.connect(self.load_public_key)

        grid.addWidget(QLabel("RSA key size:"), 0, 0)
        grid.addWidget(self.bits, 0, 1)
        grid.addWidget(generate, 0, 2)

        grid.addWidget(QLabel("Private key:"), 1, 0)
        grid.addWidget(self.private_edit, 1, 1)
        grid.addWidget(load_private, 1, 2)

        grid.addWidget(QLabel("Public key:"), 2, 0)
        grid.addWidget(self.public_edit, 2, 1)
        grid.addWidget(load_public, 2, 2)

        layout.addWidget(genbox)

        buttons = QHBoxLayout()
        verify_private = QPushButton("Verify Private Key")
        verify_private.clicked.connect(self.verify_private_key)
        verify_public = QPushButton("Inspect Public Key")
        verify_public.clicked.connect(self.inspect_public_key)
        inspect_private = QPushButton("Inspect Private Components")
        inspect_private.clicked.connect(self.inspect_private_key)
        buttons.addWidget(verify_private)
        buttons.addWidget(verify_public)
        buttons.addWidget(inspect_private)
        layout.addLayout(buttons)

        self.key_output = self.make_output()
        layout.addWidget(QLabel("<b>Key verification / inspection output</b>"))
        layout.addWidget(self.key_output, 1)

        return tab

    # ================================================================
    # TAB 3 — ENCRYPTION
    # ================================================================
    def make_encrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        intro = QLabel(
            "<b>Step 3.</b> Encrypt a short plaintext using the RSA public key. "
            "The application uses <b>RSA-OAEP with SHA-256 and MGF1-SHA-256</b>."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        keyrow = QHBoxLayout()
        self.enc_public_edit = QLineEdit()
        self.enc_public_edit.setReadOnly(True)
        use_current = QPushButton("Use Current Public Key")
        use_current.clicked.connect(self.use_current_public_for_encrypt)
        choose = QPushButton("Choose Public Key...")
        choose.clicked.connect(self.choose_encrypt_public_key)

        keyrow.addWidget(QLabel("Public key:"))
        keyrow.addWidget(self.enc_public_edit, 1)
        keyrow.addWidget(use_current)
        keyrow.addWidget(choose)
        layout.addLayout(keyrow)

        self.plaintext = QPlainTextEdit()
        self.plaintext.setPlaceholderText(
            "Enter a short UTF-8 message.\n"
            "Example: Cryptography and Applications — RSA Lab"
        )
        layout.addWidget(QLabel("<b>Plaintext</b>"))
        layout.addWidget(self.plaintext)

        encrypt = QPushButton("Encrypt → RSA-OAEP")
        encrypt.clicked.connect(self.encrypt)
        layout.addWidget(encrypt)

        self.ciphertext = QPlainTextEdit()
        self.ciphertext.setReadOnly(True)
        self.ciphertext.setPlaceholderText(
            "Binary RSA ciphertext is displayed here in hexadecimal."
        )
        layout.addWidget(QLabel("<b>Ciphertext (hex)</b>"))
        layout.addWidget(self.ciphertext)

        save = QPushButton("Save Ciphertext (.bin)...")
        save.clicked.connect(self.save_ciphertext)
        layout.addWidget(save)

        self.encrypt_output = self.make_output(max_height=115)
        layout.addWidget(QLabel("<b>OpenSSL command / output</b>"))
        layout.addWidget(self.encrypt_output)

        return tab

    # ================================================================
    # TAB 4 — DECRYPTION
    # ================================================================
    def make_decrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        intro = QLabel(
            "<b>Step 4.</b> Decrypt RSA-OAEP ciphertext using the corresponding "
            "RSA private key."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        keyrow = QHBoxLayout()
        self.dec_private_edit = QLineEdit()
        self.dec_private_edit.setReadOnly(True)
        use_current = QPushButton("Use Current Private Key")
        use_current.clicked.connect(self.use_current_private_for_decrypt)
        choose = QPushButton("Choose Private Key...")
        choose.clicked.connect(self.choose_decrypt_private_key)

        keyrow.addWidget(QLabel("Private key:"))
        keyrow.addWidget(self.dec_private_edit, 1)
        keyrow.addWidget(use_current)
        keyrow.addWidget(choose)
        layout.addLayout(keyrow)

        cipherbuttons = QHBoxLayout()
        copy_current = QPushButton("Use Ciphertext from Encryption Tab")
        copy_current.clicked.connect(self.copy_ciphertext_to_decrypt)
        load_bin = QPushButton("Load Ciphertext (.bin)...")
        load_bin.clicked.connect(self.load_ciphertext)
        cipherbuttons.addWidget(copy_current)
        cipherbuttons.addWidget(load_bin)
        layout.addLayout(cipherbuttons)

        self.decrypt_ciphertext = QPlainTextEdit()
        self.decrypt_ciphertext.setPlaceholderText(
            "Ciphertext is represented as hexadecimal."
        )
        layout.addWidget(QLabel("<b>Ciphertext (hex)</b>"))
        layout.addWidget(self.decrypt_ciphertext)

        decrypt = QPushButton("Decrypt → RSA-OAEP")
        decrypt.clicked.connect(self.decrypt)
        layout.addWidget(decrypt)

        self.recovered = QPlainTextEdit()
        self.recovered.setReadOnly(True)
        layout.addWidget(QLabel("<b>Recovered plaintext</b>"))
        layout.addWidget(self.recovered)

        self.decrypt_output = self.make_output(max_height=115)
        layout.addWidget(QLabel("<b>OpenSSL command / output</b>"))
        layout.addWidget(self.decrypt_output)

        return tab

    # ================================================================
    # HELPERS
    # ================================================================
    @staticmethod
    def make_output(max_height=None):
        edit = QPlainTextEdit()
        edit.setReadOnly(True)
        edit.setFont(QFont("Consolas", 9))
        if max_height:
            edit.setMaximumHeight(max_height)
        return edit

    def browse_openssl(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select OpenSSL executable", "", "All files (*)"
        )
        if path:
            self.openssl_edit.setText(path)

    def browse_config(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select OpenSSL configuration", "",
            "Config (*.cnf *.cfg);;All files (*)"
        )
        if path:
            self.config_edit.setText(path)

    def environment(self):
        env = os.environ.copy()
        conf = self.config_edit.text().strip()
        if conf:
            env["OPENSSL_CONF"] = conf
        return env

    def run_openssl(self, args, output_widget=None, input_bytes=None):
        exe = self.openssl_edit.text().strip()
        conf = self.config_edit.text().strip()

        if not exe or not Path(exe).is_file():
            raise RuntimeError(f"OpenSSL executable not found:\n{exe}")

        if conf and not Path(conf).is_file():
            raise RuntimeError(f"OpenSSL configuration not found:\n{conf}")

        cmd = [exe] + [str(x) for x in args]

        if output_widget is not None:
            output_widget.appendPlainText("> " + subprocess.list2cmdline(cmd))
            if conf:
                output_widget.appendPlainText(f"OPENSSL_CONF={conf}")

        result = subprocess.run(
            cmd,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment(),
            check=False,
        )

        stdout_text = result.stdout.decode("utf-8", errors="replace")
        stderr_text = result.stderr.decode("utf-8", errors="replace")

        if output_widget is not None:
            if stdout_text.strip():
                output_widget.appendPlainText(stdout_text.rstrip())
            if stderr_text.strip():
                output_widget.appendPlainText(stderr_text.rstrip())

        if result.returncode != 0:
            raise RuntimeError(
                f"OpenSSL failed (exit code {result.returncode}).\n"
                f"{stderr_text.strip()}"
            )

        return result.stdout

    def error(self, exc):
        QMessageBox.critical(self, "RSA Laboratory", str(exc))
        self.statusBar().showMessage("Operation failed.")

    # ================================================================
    # TAB 1 ACTIONS
    # ================================================================
    def test_openssl(self):
        self.config_output.clear()
        try:
            out = self.run_openssl(
                ["version", "-a"], self.config_output
            )
            first = out.decode("utf-8", errors="replace").splitlines()[0]
            self.statusBar().showMessage(f"OpenSSL OK: {first}")
        except Exception as exc:
            self.error(exc)

    # ================================================================
    # TAB 2 ACTIONS
    # ================================================================
    def generate_keys(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Choose folder for RSA key pair"
        )
        if not folder:
            return

        private = Path(folder) / "private.pem"
        public = Path(folder) / "public.pem"

        if private.exists() or public.exists():
            answer = QMessageBox.question(
                self, "Overwrite?",
                "private.pem or public.pem already exists. Overwrite?",
                QMessageBox.StandardButton.Yes |
                QMessageBox.StandardButton.No
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        self.key_output.clear()

        try:
            bits = self.bits.currentText()

            self.run_openssl([
                "genpkey",
                "-algorithm", "RSA",
                "-pkeyopt", f"rsa_keygen_bits:{bits}",
                "-out", private
            ], self.key_output)

            self.run_openssl([
                "pkey",
                "-in", private,
                "-pubout",
                "-out", public
            ], self.key_output)

            self.private_key_path = str(private)
            self.public_key_path = str(public)
            self.private_edit.setText(self.private_key_path)
            self.public_edit.setText(self.public_key_path)

            # Propagate generated keys to later tabs.
            self.enc_public_edit.setText(self.public_key_path)
            self.dec_private_edit.setText(self.private_key_path)

            self.key_output.appendPlainText(
                f"\nGenerated {bits}-bit RSA key pair successfully."
            )
            self.statusBar().showMessage(
                f"Generated {bits}-bit RSA key pair."
            )
        except Exception as exc:
            self.error(exc)

    def load_private_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load RSA private key", "",
            "PEM files (*.pem);;All files (*)"
        )
        if path:
            self.private_key_path = path
            self.private_edit.setText(path)
            self.dec_private_edit.setText(path)

    def load_public_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load RSA public key", "",
            "PEM files (*.pem);;All files (*)"
        )
        if path:
            self.public_key_path = path
            self.public_edit.setText(path)
            self.enc_public_edit.setText(path)

    def verify_private_key(self):
        if not self.private_key_path:
            QMessageBox.warning(self, "RSA", "Load or generate a private key first.")
            return
        self.key_output.clear()
        try:
            self.run_openssl([
                "pkey",
                "-in", self.private_key_path,
                "-check",
                "-noout"
            ], self.key_output)
            self.statusBar().showMessage("Private RSA key verified.")
        except Exception as exc:
            self.error(exc)

    def inspect_public_key(self):
        if not self.public_key_path:
            QMessageBox.warning(self, "RSA", "Load or generate a public key first.")
            return
        self.key_output.clear()
        try:
            self.run_openssl([
                "pkey",
                "-pubin",
                "-in", self.public_key_path,
                "-text",
                "-noout"
            ], self.key_output)
            self.statusBar().showMessage("Public RSA key inspected.")
        except Exception as exc:
            self.error(exc)

    def inspect_private_key(self):
        if not self.private_key_path:
            QMessageBox.warning(self, "RSA", "Load or generate a private key first.")
            return
        self.key_output.clear()
        try:
            self.run_openssl([
                "pkey",
                "-in", self.private_key_path,
                "-text",
                "-noout"
            ], self.key_output)
            self.statusBar().showMessage("Private RSA components inspected.")
        except Exception as exc:
            self.error(exc)

    # ================================================================
    # TAB 3 ACTIONS
    # ================================================================
    def use_current_public_for_encrypt(self):
        if self.public_key_path:
            self.enc_public_edit.setText(self.public_key_path)
        else:
            QMessageBox.warning(self, "RSA", "No current public key is available.")

    def choose_encrypt_public_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose RSA public key", "",
            "PEM files (*.pem);;All files (*)"
        )
        if path:
            self.enc_public_edit.setText(path)

    def encrypt(self):
        public = self.enc_public_edit.text().strip()
        message = self.plaintext.toPlainText().encode("utf-8")

        if not public:
            QMessageBox.warning(self, "RSA", "Choose a public key.")
            return
        if not message:
            QMessageBox.warning(self, "RSA", "Enter plaintext.")
            return

        self.encrypt_output.clear()
        try:
            cipher = self.run_openssl([
                "pkeyutl",
                "-encrypt",
                "-pubin",
                "-inkey", public,
                "-pkeyopt", "rsa_padding_mode:oaep",
                "-pkeyopt", "rsa_oaep_md:sha256",
                "-pkeyopt", "rsa_mgf1_md:sha256"
            ], self.encrypt_output, message)

            hex_cipher = cipher.hex()
            self.ciphertext.setPlainText(hex_cipher)
            self.decrypt_ciphertext.setPlainText(hex_cipher)

            self.encrypt_output.appendPlainText(
                f"\nCiphertext size: {len(cipher)} bytes"
            )
            self.statusBar().showMessage("RSA-OAEP encryption successful.")
        except Exception as exc:
            self.error(exc)

    def save_ciphertext(self):
        text = "".join(self.ciphertext.toPlainText().split())
        if not text:
            QMessageBox.warning(self, "RSA", "No ciphertext to save.")
            return
        try:
            data = bytes.fromhex(text)
        except ValueError:
            QMessageBox.warning(self, "RSA", "Ciphertext is not valid hexadecimal.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Save ciphertext", "ciphertext.bin",
            "Binary files (*.bin);;All files (*)"
        )
        if path:
            Path(path).write_bytes(data)
            self.statusBar().showMessage(f"Saved ciphertext: {path}")

    # ================================================================
    # TAB 4 ACTIONS
    # ================================================================
    def use_current_private_for_decrypt(self):
        if self.private_key_path:
            self.dec_private_edit.setText(self.private_key_path)
        else:
            QMessageBox.warning(self, "RSA", "No current private key is available.")

    def choose_decrypt_private_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose RSA private key", "",
            "PEM files (*.pem);;All files (*)"
        )
        if path:
            self.dec_private_edit.setText(path)

    def copy_ciphertext_to_decrypt(self):
        self.decrypt_ciphertext.setPlainText(
            self.ciphertext.toPlainText()
        )

    def load_ciphertext(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load ciphertext", "",
            "Binary files (*.bin);;All files (*)"
        )
        if path:
            self.decrypt_ciphertext.setPlainText(
                Path(path).read_bytes().hex()
            )

    def decrypt(self):
        private = self.dec_private_edit.text().strip()
        text = "".join(self.decrypt_ciphertext.toPlainText().split())

        if not private:
            QMessageBox.warning(self, "RSA", "Choose a private key.")
            return
        if not text:
            QMessageBox.warning(self, "RSA", "Provide ciphertext.")
            return

        try:
            cipher = bytes.fromhex(text)
        except ValueError:
            QMessageBox.warning(self, "RSA", "Ciphertext is not valid hexadecimal.")
            return

        self.decrypt_output.clear()
        try:
            plain = self.run_openssl([
                "pkeyutl",
                "-decrypt",
                "-inkey", private,
                "-pkeyopt", "rsa_padding_mode:oaep",
                "-pkeyopt", "rsa_oaep_md:sha256",
                "-pkeyopt", "rsa_mgf1_md:sha256"
            ], self.decrypt_output, cipher)

            self.recovered.setPlainText(
                plain.decode("utf-8", errors="replace")
            )
            self.decrypt_output.appendPlainText(
                f"\nRecovered plaintext size: {len(plain)} bytes"
            )
            self.statusBar().showMessage("RSA-OAEP decryption successful.")
        except Exception as exc:
            self.error(exc)


def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 18))
    window = RSALab()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
