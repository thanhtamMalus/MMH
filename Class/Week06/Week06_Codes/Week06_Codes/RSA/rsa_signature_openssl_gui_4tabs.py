import os
import sys
import subprocess
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QGridLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QPushButton, QTabWidget, QVBoxLayout, QWidget
)


HASHES = ["SHA-256", "SHA-384", "SHA-512", "SHA-224", "SHA-1"]
OPENSSL_HASH = {
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
    "SHA-224": "sha224",
    "SHA-1": "sha1",
}


class RSASignatureLab(QMainWindow):
    """
    Four-tab teaching GUI for RSA-based digital signatures using OpenSSL.

    Tab 1: OpenSSL configuration
    Tab 2: Generate and verify RSA keys
    Tab 3: Sign with RSA private key
    Tab 4: Verify with RSA public key

    Default signature construction:
        RSA-PSS
        selectable message hash
        MGF1 uses the same selected hash
        PSS salt length = digest length

    PKCS#1 v1.5 signature mode is included for comparison/legacy study.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("RSA Signature Laboratory — PyQt6 + OpenSSL")
        self.resize(1100, 790)

        self.private_key_path = ""
        self.public_key_path = ""

        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)

        title = QLabel("RSA-Based Digital Signature Laboratory")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        outer.addWidget(title)

        subtitle = QLabel(
            "Real RSA signatures using OpenSSL — RSA-PSS by default; "
            "selectable hash functions"
        )
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(subtitle)

        self.tabs = QTabWidget()
        outer.addWidget(self.tabs, 1)

        self.tabs.addTab(self.make_config_tab(), "1. OpenSSL Config")
        self.tabs.addTab(self.make_key_tab(), "2. Generate && Verify Key")
        self.tabs.addTab(self.make_sign_tab(), "3. Signature")
        self.tabs.addTab(self.make_verify_tab(), "4. Verification")

        self.statusBar().showMessage("Start with Tab 1: configure and test OpenSSL.")

    # ================================================================
    # COMMON UI
    # ================================================================
    @staticmethod
    def output_box(max_height=None):
        box = QPlainTextEdit()
        box.setReadOnly(True)
        box.setFont(QFont("Consolas", 9))
        if max_height:
            box.setMaximumHeight(max_height)
        return box

    @staticmethod
    def hash_combo():
        combo = QComboBox()
        combo.addItems(HASHES)
        combo.setCurrentText("SHA-256")
        return combo

    @staticmethod
    def padding_combo():
        combo = QComboBox()
        combo.addItems(["RSA-PSS", "PKCS#1 v1.5"])
        combo.setCurrentText("RSA-PSS")
        return combo

    # ================================================================
    # TAB 1
    # ================================================================
    def make_config_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        intro = QLabel(
            "<b>Step 1.</b> Configure the OpenSSL executable and configuration "
            "file used by all signature operations."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        group = QGroupBox("OpenSSL Configuration")
        grid = QGridLayout(group)

        if os.name == "nt":
            exe = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
            conf = r"C:\Program Files\OpenSSL-Win64\bin\openssl.cfg"
        else:
            exe = "/usr/bin/openssl"
            conf = "/etc/ssl/openssl.cnf"

        self.openssl_edit = QLineEdit(exe)
        self.config_edit = QLineEdit(conf)

        b1 = QPushButton("Browse...")
        b1.clicked.connect(self.browse_openssl)
        b2 = QPushButton("Browse...")
        b2.clicked.connect(self.browse_config)

        grid.addWidget(QLabel("OpenSSL executable:"), 0, 0)
        grid.addWidget(self.openssl_edit, 0, 1)
        grid.addWidget(b1, 0, 2)

        grid.addWidget(QLabel("OpenSSL config:"), 1, 0)
        grid.addWidget(self.config_edit, 1, 1)
        grid.addWidget(b2, 1, 2)

        layout.addWidget(group)

        test = QPushButton("Test OpenSSL Configuration")
        test.clicked.connect(self.test_openssl)
        layout.addWidget(test)

        self.config_output = self.output_box()
        layout.addWidget(QLabel("<b>OpenSSL information</b>"))
        layout.addWidget(self.config_output, 1)
        return tab

    # ================================================================
    # TAB 2
    # ================================================================
    def make_key_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        intro = QLabel(
            "<b>Step 2.</b> Generate a real RSA key pair. "
            "The private key signs; the public key verifies."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        group = QGroupBox("RSA Key Pair")
        grid = QGridLayout(group)

        self.bits = QComboBox()
        self.bits.addItems(["2048", "3072", "4096"])
        self.bits.setCurrentText("2048")

        self.private_edit = QLineEdit()
        self.private_edit.setReadOnly(True)
        self.public_edit = QLineEdit()
        self.public_edit.setReadOnly(True)

        generate = QPushButton("Generate RSA Key Pair...")
        generate.clicked.connect(self.generate_keys)
        load_priv = QPushButton("Load Private Key")
        load_priv.clicked.connect(self.load_private)
        load_pub = QPushButton("Load Public Key")
        load_pub.clicked.connect(self.load_public)

        grid.addWidget(QLabel("RSA key size:"), 0, 0)
        grid.addWidget(self.bits, 0, 1)
        grid.addWidget(generate, 0, 2)
        grid.addWidget(QLabel("Private key:"), 1, 0)
        grid.addWidget(self.private_edit, 1, 1)
        grid.addWidget(load_priv, 1, 2)
        grid.addWidget(QLabel("Public key:"), 2, 0)
        grid.addWidget(self.public_edit, 2, 1)
        grid.addWidget(load_pub, 2, 2)
        layout.addWidget(group)

        buttons = QHBoxLayout()
        check = QPushButton("Verify Private Key")
        check.clicked.connect(self.verify_private_key)
        inspect_pub = QPushButton("Inspect Public Key")
        inspect_pub.clicked.connect(self.inspect_public_key)
        inspect_priv = QPushButton("Inspect Private Components")
        inspect_priv.clicked.connect(self.inspect_private_key)
        buttons.addWidget(check)
        buttons.addWidget(inspect_pub)
        buttons.addWidget(inspect_priv)
        layout.addLayout(buttons)

        self.key_output = self.output_box()
        layout.addWidget(QLabel("<b>Key verification / inspection</b>"))
        layout.addWidget(self.key_output, 1)
        return tab

    # ================================================================
    # TAB 3 — SIGNATURE
    # ================================================================
    def make_sign_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        intro = QLabel(
            "<b>Step 3.</b> Hash the message and create an RSA signature "
            "using the <b>private key</b>. RSA-PSS is the recommended mode."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        keyrow = QHBoxLayout()
        self.sign_private_edit = QLineEdit()
        self.sign_private_edit.setReadOnly(True)
        use = QPushButton("Use Current Private Key")
        use.clicked.connect(self.use_private_for_sign)
        choose = QPushButton("Choose Private Key...")
        choose.clicked.connect(self.choose_sign_private)
        keyrow.addWidget(QLabel("Private key:"))
        keyrow.addWidget(self.sign_private_edit, 1)
        keyrow.addWidget(use)
        keyrow.addWidget(choose)
        layout.addLayout(keyrow)

        options = QGroupBox("Signature Parameters")
        grid = QGridLayout(options)
        self.sign_hash = self.hash_combo()
        self.sign_padding = self.padding_combo()
        self.sign_hash.currentTextChanged.connect(self.sync_verify_hash)
        self.sign_padding.currentTextChanged.connect(self.sync_verify_padding)

        grid.addWidget(QLabel("Hash function:"), 0, 0)
        grid.addWidget(self.sign_hash, 0, 1)
        grid.addWidget(QLabel("RSA signature scheme:"), 0, 2)
        grid.addWidget(self.sign_padding, 0, 3)
        layout.addWidget(options)

        warning = QLabel(
            "<b>Note:</b> SHA-256/SHA-384/SHA-512 are appropriate teaching "
            "defaults. SHA-1 is included only for legacy/cryptanalysis comparison."
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)

        self.message = QPlainTextEdit()
        self.message.setPlaceholderText(
            "Enter the message to sign.\n"
            "Example: Cryptography and Applications — RSA Signature Lab"
        )
        layout.addWidget(QLabel("<b>Message</b>"))
        layout.addWidget(self.message)

        sign = QPushButton("Sign with RSA Private Key")
        sign.clicked.connect(self.sign_message)
        layout.addWidget(sign)

        self.signature_hex = QPlainTextEdit()
        self.signature_hex.setReadOnly(True)
        self.signature_hex.setPlaceholderText(
            "The binary RSA signature will be displayed in hexadecimal."
        )
        layout.addWidget(QLabel("<b>Signature (hex)</b>"))
        layout.addWidget(self.signature_hex)

        save = QPushButton("Save Signature (.bin)...")
        save.clicked.connect(self.save_signature)
        layout.addWidget(save)

        self.sign_output = self.output_box(max_height=110)
        layout.addWidget(QLabel("<b>OpenSSL command / output</b>"))
        layout.addWidget(self.sign_output)
        return tab

    # ================================================================
    # TAB 4 — VERIFICATION
    # ================================================================
    def make_verify_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        intro = QLabel(
            "<b>Step 4.</b> Verify the signature using the <b>public key</b>, "
            "the original message, and exactly the same hash/signature parameters."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        keyrow = QHBoxLayout()
        self.verify_public_edit = QLineEdit()
        self.verify_public_edit.setReadOnly(True)
        use = QPushButton("Use Current Public Key")
        use.clicked.connect(self.use_public_for_verify)
        choose = QPushButton("Choose Public Key...")
        choose.clicked.connect(self.choose_verify_public)
        keyrow.addWidget(QLabel("Public key:"))
        keyrow.addWidget(self.verify_public_edit, 1)
        keyrow.addWidget(use)
        keyrow.addWidget(choose)
        layout.addLayout(keyrow)

        options = QGroupBox("Verification Parameters")
        grid = QGridLayout(options)
        self.verify_hash = self.hash_combo()
        self.verify_padding = self.padding_combo()
        grid.addWidget(QLabel("Hash function:"), 0, 0)
        grid.addWidget(self.verify_hash, 0, 1)
        grid.addWidget(QLabel("RSA signature scheme:"), 0, 2)
        grid.addWidget(self.verify_padding, 0, 3)
        layout.addWidget(options)

        copy_msg = QPushButton("Use Message from Signature Tab")
        copy_msg.clicked.connect(self.copy_message)
        layout.addWidget(copy_msg)

        self.verify_message = QPlainTextEdit()
        self.verify_message.setPlaceholderText("Original message to verify.")
        layout.addWidget(QLabel("<b>Message</b>"))
        layout.addWidget(self.verify_message)

        sigbuttons = QHBoxLayout()
        copy_sig = QPushButton("Use Signature from Signature Tab")
        copy_sig.clicked.connect(self.copy_signature)
        load_sig = QPushButton("Load Signature (.bin)...")
        load_sig.clicked.connect(self.load_signature)
        sigbuttons.addWidget(copy_sig)
        sigbuttons.addWidget(load_sig)
        layout.addLayout(sigbuttons)

        self.verify_signature_hex = QPlainTextEdit()
        self.verify_signature_hex.setPlaceholderText("Signature represented as hexadecimal.")
        layout.addWidget(QLabel("<b>Signature (hex)</b>"))
        layout.addWidget(self.verify_signature_hex)

        verify = QPushButton("Verify RSA Signature")
        verify.clicked.connect(self.verify_signature)
        layout.addWidget(verify)

        self.verify_result = QLabel("Verification result: —")
        self.verify_result.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.verify_result.setFont(QFont("Arial", 13, QFont.Weight.Bold))
        layout.addWidget(self.verify_result)

        self.verify_output = self.output_box(max_height=110)
        layout.addWidget(QLabel("<b>OpenSSL command / output</b>"))
        layout.addWidget(self.verify_output)
        return tab

    # ================================================================
    # OPENSSL
    # ================================================================
    def environment(self):
        env = os.environ.copy()
        conf = self.config_edit.text().strip()
        if conf:
            env["OPENSSL_CONF"] = conf
        return env

    def run_openssl(self, args, widget=None, input_bytes=None, allow_failure=False):
        exe = self.openssl_edit.text().strip()
        conf = self.config_edit.text().strip()

        if not exe or not Path(exe).is_file():
            raise RuntimeError(f"OpenSSL executable not found:\n{exe}")
        if conf and not Path(conf).is_file():
            raise RuntimeError(f"OpenSSL configuration not found:\n{conf}")

        cmd = [exe] + [str(a) for a in args]

        if widget:
            widget.appendPlainText("> " + subprocess.list2cmdline(cmd))
            if conf:
                widget.appendPlainText(f"OPENSSL_CONF={conf}")

        result = subprocess.run(
            cmd,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment(),
            check=False,
        )

        out = result.stdout.decode("utf-8", errors="replace")
        err = result.stderr.decode("utf-8", errors="replace")

        if widget:
            if out.strip():
                widget.appendPlainText(out.rstrip())
            if err.strip():
                widget.appendPlainText(err.rstrip())

        if result.returncode != 0 and not allow_failure:
            raise RuntimeError(
                f"OpenSSL failed (exit code {result.returncode}).\n{err.strip()}"
            )
        return result

    def error(self, exc):
        QMessageBox.critical(self, "RSA Signature Laboratory", str(exc))
        self.statusBar().showMessage("Operation failed.")

    # ================================================================
    # CONFIG ACTIONS
    # ================================================================
    def browse_openssl(self):
        path, _ = QFileDialog.getOpenFileName(self, "OpenSSL executable", "", "All files (*)")
        if path:
            self.openssl_edit.setText(path)

    def browse_config(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "OpenSSL config", "", "Config (*.cnf *.cfg);;All files (*)"
        )
        if path:
            self.config_edit.setText(path)

    def test_openssl(self):
        self.config_output.clear()
        try:
            result = self.run_openssl(["version", "-a"], self.config_output)
            first = result.stdout.decode(errors="replace").splitlines()[0]
            self.statusBar().showMessage(f"OpenSSL OK: {first}")
        except Exception as exc:
            self.error(exc)

    # ================================================================
    # KEY ACTIONS
    # ================================================================
    def generate_keys(self):
        folder = QFileDialog.getExistingDirectory(self, "Choose folder for RSA keys")
        if not folder:
            return

        private = Path(folder) / "private.pem"
        public = Path(folder) / "public.pem"

        if private.exists() or public.exists():
            ans = QMessageBox.question(
                self, "Overwrite?",
                "private.pem or public.pem already exists. Overwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if ans != QMessageBox.StandardButton.Yes:
                return

        self.key_output.clear()
        try:
            bits = self.bits.currentText()
            self.run_openssl([
                "genpkey", "-algorithm", "RSA",
                "-pkeyopt", f"rsa_keygen_bits:{bits}",
                "-out", private
            ], self.key_output)

            self.run_openssl([
                "pkey", "-in", private, "-pubout", "-out", public
            ], self.key_output)

            self.private_key_path = str(private)
            self.public_key_path = str(public)

            self.private_edit.setText(self.private_key_path)
            self.public_edit.setText(self.public_key_path)
            self.sign_private_edit.setText(self.private_key_path)
            self.verify_public_edit.setText(self.public_key_path)

            self.key_output.appendPlainText(f"\nGenerated {bits}-bit RSA key pair.")
            self.statusBar().showMessage(f"Generated {bits}-bit RSA key pair.")
        except Exception as exc:
            self.error(exc)

    def load_private(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load private key", "", "PEM (*.pem);;All files (*)"
        )
        if path:
            self.private_key_path = path
            self.private_edit.setText(path)
            self.sign_private_edit.setText(path)

    def load_public(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load public key", "", "PEM (*.pem);;All files (*)"
        )
        if path:
            self.public_key_path = path
            self.public_edit.setText(path)
            self.verify_public_edit.setText(path)

    def verify_private_key(self):
        if not self.private_key_path:
            QMessageBox.warning(self, "RSA", "Generate or load a private key first.")
            return
        self.key_output.clear()
        try:
            self.run_openssl(
                ["pkey", "-in", self.private_key_path, "-check", "-noout"],
                self.key_output
            )
        except Exception as exc:
            self.error(exc)

    def inspect_public_key(self):
        if not self.public_key_path:
            QMessageBox.warning(self, "RSA", "Generate or load a public key first.")
            return
        self.key_output.clear()
        try:
            self.run_openssl(
                ["pkey", "-pubin", "-in", self.public_key_path, "-text", "-noout"],
                self.key_output
            )
        except Exception as exc:
            self.error(exc)

    def inspect_private_key(self):
        if not self.private_key_path:
            QMessageBox.warning(self, "RSA", "Generate or load a private key first.")
            return
        self.key_output.clear()
        try:
            self.run_openssl(
                ["pkey", "-in", self.private_key_path, "-text", "-noout"],
                self.key_output
            )
        except Exception as exc:
            self.error(exc)

    # ================================================================
    # SIGN ACTIONS
    # ================================================================
    def use_private_for_sign(self):
        if self.private_key_path:
            self.sign_private_edit.setText(self.private_key_path)

    def choose_sign_private(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose RSA private key", "", "PEM (*.pem);;All files (*)"
        )
        if path:
            self.sign_private_edit.setText(path)

    def sync_verify_hash(self, value):
        if hasattr(self, "verify_hash"):
            self.verify_hash.setCurrentText(value)

    def sync_verify_padding(self, value):
        if hasattr(self, "verify_padding"):
            self.verify_padding.setCurrentText(value)

    def signature_options(self, padding, hash_name):
        if padding == "RSA-PSS":
            return [
                "-sigopt", "rsa_padding_mode:pss",
                "-sigopt", f"rsa_mgf1_md:{hash_name}",
                "-sigopt", "rsa_pss_saltlen:digest",
            ]
        return [
            "-sigopt", "rsa_padding_mode:pkcs1"
        ]

    def sign_message(self):
        private = self.sign_private_edit.text().strip()
        message = self.message.toPlainText().encode("utf-8")
        if not private:
            QMessageBox.warning(self, "RSA", "Choose a private key.")
            return
        if not message:
            QMessageBox.warning(self, "RSA", "Enter a message to sign.")
            return

        selected = self.sign_hash.currentText()
        digest = OPENSSL_HASH[selected]
        padding = self.sign_padding.currentText()

        self.sign_output.clear()
        try:
            args = ["dgst", f"-{digest}", "-sign", private]
            args += self.signature_options(padding, digest)

            result = self.run_openssl(args, self.sign_output, message)
            signature = result.stdout

            self.signature_hex.setPlainText(signature.hex())
            self.verify_signature_hex.setPlainText(signature.hex())
            self.verify_message.setPlainText(self.message.toPlainText())
            self.verify_hash.setCurrentText(selected)
            self.verify_padding.setCurrentText(padding)

            self.sign_output.appendPlainText(
                f"\nHash: {selected}\nScheme: {padding}\n"
                f"Signature size: {len(signature)} bytes"
            )
            self.statusBar().showMessage(
                f"Signature created using {padding} + {selected}."
            )
        except Exception as exc:
            self.error(exc)

    def save_signature(self):
        text = "".join(self.signature_hex.toPlainText().split())
        if not text:
            QMessageBox.warning(self, "RSA", "No signature to save.")
            return
        try:
            data = bytes.fromhex(text)
        except ValueError:
            QMessageBox.warning(self, "RSA", "Signature is not valid hexadecimal.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Save signature", "signature.bin",
            "Binary (*.bin);;All files (*)"
        )
        if path:
            Path(path).write_bytes(data)

    # ================================================================
    # VERIFY ACTIONS
    # ================================================================
    def use_public_for_verify(self):
        if self.public_key_path:
            self.verify_public_edit.setText(self.public_key_path)

    def choose_verify_public(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose RSA public key", "", "PEM (*.pem);;All files (*)"
        )
        if path:
            self.verify_public_edit.setText(path)

    def copy_message(self):
        self.verify_message.setPlainText(self.message.toPlainText())

    def copy_signature(self):
        self.verify_signature_hex.setPlainText(self.signature_hex.toPlainText())

    def load_signature(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load signature", "", "Binary (*.bin);;All files (*)"
        )
        if path:
            self.verify_signature_hex.setPlainText(Path(path).read_bytes().hex())

    def verify_signature(self):
        public = self.verify_public_edit.text().strip()
        message = self.verify_message.toPlainText().encode("utf-8")
        hex_sig = "".join(self.verify_signature_hex.toPlainText().split())

        if not public:
            QMessageBox.warning(self, "RSA", "Choose a public key.")
            return
        if not message:
            QMessageBox.warning(self, "RSA", "Enter the original message.")
            return
        if not hex_sig:
            QMessageBox.warning(self, "RSA", "Provide a signature.")
            return

        try:
            signature = bytes.fromhex(hex_sig)
        except ValueError:
            QMessageBox.warning(self, "RSA", "Signature is not valid hexadecimal.")
            return

        selected = self.verify_hash.currentText()
        digest = OPENSSL_HASH[selected]
        padding = self.verify_padding.currentText()

        # OpenSSL dgst expects the signature in a file for -signature.
        import tempfile
        tmp_name = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as f:
                f.write(signature)
                tmp_name = f.name

            self.verify_output.clear()
            args = [
                "dgst", f"-{digest}",
                "-verify", public,
                "-signature", tmp_name
            ]
            args += self.signature_options(padding, digest)

            result = self.run_openssl(
                args, self.verify_output, message, allow_failure=True
            )

            combined = (
                result.stdout.decode("utf-8", errors="replace") +
                result.stderr.decode("utf-8", errors="replace")
            )

            if result.returncode == 0:
                self.verify_result.setText("Verification result: VALID SIGNATURE")
                self.statusBar().showMessage("RSA signature verification succeeded.")
            else:
                self.verify_result.setText("Verification result: INVALID SIGNATURE")
                self.verify_output.appendPlainText(
                    "\nVerification failed. Check the message, public key, "
                    "hash function, signature scheme, and signature."
                )
                self.statusBar().showMessage("RSA signature verification failed.")
        except Exception as exc:
            self.error(exc)
        finally:
            if tmp_name:
                try:
                    os.remove(tmp_name)
                except OSError:
                    pass


def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 17))
    window = RSASignatureLab()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
