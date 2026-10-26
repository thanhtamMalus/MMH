"""
Week 07 — FFDHE Key Establishment using OpenSSL + PyQt6
========================================================

Tabs
----
1. OpenSSL Settings
2. Select Standard FFDHE Group & Check Parameters
3. Generate ONE endpoint key pair; custom-save private/public as PEM/BIN/HEX
4. Load LOCAL private key + PEER public share; compute/save Z as HEX/BIN
5. Load Z; derive and save Shared Key K

Requirements
------------
    pip install PyQt6

OpenSSL 3.x is recommended.

Teaching flow
-------------
Standard FFDHE group
    -> one endpoint's ephemeral private exponent and public share
    -> exchange public share with the other endpoint
    -> load peer public share
    -> OpenSSL DH derivation Z
    -> OpenSSL HKDF
    -> K_A == K_B

All cryptographic DH and HKDF operations are performed by OpenSSL.
Python/PyQt6 provides only the GUI, file handling, and orchestration.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PyQt6.QtGui import QFont
APP_DIR = Path.cwd() / "week07_ffdhe_output"
APP_DIR.mkdir(parents=True, exist_ok=True)

FFDHE_GROUPS = [
    "ffdhe2048",
    "ffdhe3072",
    "ffdhe4096",
    "ffdhe6144",
    "ffdhe8192",
]

HKDF_DIGESTS = ["SHA256", "SHA384", "SHA512"]


def hex_block(data: bytes, width: int = 64) -> str:
    h = data.hex()
    return "\n".join(h[i:i + width] for i in range(0, len(h), width))


def clean_hex(text: str) -> str:
    value = "".join(text.split()).lower()
    if value.startswith("0x"):
        value = value[2:]
    if value and any(c not in "0123456789abcdef" for c in value):
        raise ValueError("Salt must contain hexadecimal characters only.")
    if len(value) % 2:
        raise ValueError("Hexadecimal salt must contain an even number of digits.")
    return value


def read_hex_or_bin(path: Path, mode: str) -> bytes:
    """Read raw binary or whitespace/formatted hexadecimal."""
    if mode == "Binary (.bin)":
        return path.read_bytes()

    text = path.read_text(encoding="utf-8")
    value = "".join(text.split())
    value = value.replace(":", "")
    if value.lower().startswith("0x"):
        value = value[2:]
    if len(value) % 2:
        raise ValueError(f"Odd number of hex digits in {path}.")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"Invalid hexadecimal data in {path}.") from exc


def write_hex_or_bin(path: Path, data: bytes, mode: str) -> None:
    """Write bytes either as raw binary or readable hexadecimal."""
    if mode == "Binary (.bin)":
        path.write_bytes(data)
    else:
        path.write_text(hex_block(data) + "\n", encoding="utf-8")


class OpenSSL:
    def __init__(self) -> None:
        self.binary = shutil.which("openssl") or "openssl"

    def set_binary(self, value: str) -> None:
        self.binary = value.strip() or "openssl"

    def run(
        self,
        args: list[str],
        *,
        input_data: bytes | None = None,
    ) -> subprocess.CompletedProcess:
        cmd = [self.binary] + [str(x) for x in args]

        cp = subprocess.run(
            cmd,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        if cp.returncode != 0:
            stdout = cp.stdout.decode(errors="replace")
            stderr = cp.stderr.decode(errors="replace")
            raise RuntimeError(
                "OpenSSL command failed.\n\n"
                f"Command:\n{' '.join(cmd)}\n\n"
                f"STDOUT:\n{stdout}\n\n"
                f"STDERR:\n{stderr}"
            )

        return cp

    def text(self, args: list[str]) -> str:
        cp = self.run(args)
        return cp.stdout.decode(errors="replace")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()

        self.setWindowTitle(
            "Week 07 — FFDHE: Ephemeral DH, Shared Secret Z, and Shared Key K"
        )
        self.resize(1220, 850)

        self.openssl = OpenSSL()
        self.current_group = "ffdhe2048"

        # Generated artifacts.
        self.params_file = APP_DIR / "ffdhe_params.pem"

        self.alice_private = APP_DIR / "alice_ephemeral_private.pem"
        self.alice_public = APP_DIR / "alice_ephemeral_public.pem"

        self.bob_private = APP_DIR / "bob_ephemeral_private.pem"
        self.bob_public = APP_DIR / "bob_ephemeral_public.pem"

        self.alice_z = APP_DIR / "alice_shared_secret_Z.bin"
        self.bob_z = APP_DIR / "bob_shared_secret_Z.bin"

        self.alice_k = APP_DIR / "alice_shared_key_K.bin"
        self.bob_k = APP_DIR / "bob_shared_key_K.bin"

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.tabs.addTab(self.make_tab1(), "1. OpenSSL Settings")
        self.tabs.addTab(self.make_tab2(), "2. Standard FFDHE")
        self.tabs.addTab(self.make_tab3(), "3. Ephemeral Key Shares")
        self.tabs.addTab(self.make_tab4(), "4. Shared Secret Z")
        self.tabs.addTab(self.make_tab5(), "5. Shared Key K")

    # ================================================================
    # General helpers
    # ================================================================

    def show_error(self, exc: Exception) -> None:
        QMessageBox.critical(self, "Error", str(exc))

    def monospace(self, edit: QTextEdit) -> None:
        font = QFont("Consolas")
        font.setStyleHint(QFont.StyleHint.Monospace)
        edit.setFont(font)

    def refresh_openssl_path(self) -> None:
        self.openssl.set_binary(self.openssl_path.text())

    def require_files(self, *paths: Path) -> None:
        missing = [str(p) for p in paths if not p.exists()]
        if missing:
            raise RuntimeError(
                "Required files do not exist yet.\n"
                "Complete the preceding tab first.\n\n"
                + "\n".join(missing)
            )

    # ================================================================
    # TAB 1 — OpenSSL
    # ================================================================

    def make_tab1(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        description = QLabel(
            "<b>Goal:</b> configure and verify the OpenSSL executable used "
            "for every cryptographic operation in this Week 07 demonstration."
        )
        description.setWordWrap(True)
        layout.addWidget(description)

        group = QGroupBox("OpenSSL Configuration")
        form = QFormLayout(group)

        self.openssl_path = QLineEdit(self.openssl.binary)

        browse = QPushButton("Browse...")
        browse.clicked.connect(self.browse_openssl)

        row = QHBoxLayout()
        row.addWidget(self.openssl_path)
        row.addWidget(browse)

        form.addRow("OpenSSL executable:", row)

        test = QPushButton("Test OpenSSL")
        test.clicked.connect(self.test_openssl)
        form.addRow(test)

        layout.addWidget(group)

        self.openssl_output = QTextEdit()
        self.openssl_output.setReadOnly(True)
        self.monospace(self.openssl_output)
        layout.addWidget(self.openssl_output)

        return page

    def browse_openssl(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select OpenSSL executable",
            "",
            "Executables (*.exe);;All files (*)",
        )
        if path:
            self.openssl_path.setText(path)

    def test_openssl(self) -> None:
        try:
            self.refresh_openssl_path()

            version = self.openssl.text(["version", "-a"])
            providers = self.openssl.text(["list", "-providers"])

            self.openssl_output.setPlainText(
                "=== OPENSSL VERSION ===\n"
                + version
                + "\n=== AVAILABLE PROVIDERS ===\n"
                + providers
                + "\nOutput directory:\n"
                + str(APP_DIR)
            )

        except Exception as exc:
            self.show_error(exc)

    # ================================================================
    # TAB 2 — Standard FFDHE group
    # ================================================================

    def make_tab2(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        description = QLabel(
            "<b>Goal:</b> select a standardized finite-field DH group and "
            "ask OpenSSL to construct, inspect, and validate its parameters."
        )
        description.setWordWrap(True)
        layout.addWidget(description)

        box = QGroupBox("Standard FFDHE Group")
        form = QFormLayout(box)

        self.group_combo = QComboBox()
        self.group_combo.addItems(FFDHE_GROUPS)
        form.addRow("Named group:", self.group_combo)

        check = QPushButton("Create and Check Standard Parameters")
        check.clicked.connect(self.check_parameters)
        form.addRow(check)

        layout.addWidget(box)

        self.parameter_output = QTextEdit()
        self.parameter_output.setReadOnly(True)
        self.monospace(self.parameter_output)
        layout.addWidget(self.parameter_output)

        return page

    def check_parameters(self) -> None:
        try:
            self.refresh_openssl_path()
            self.current_group = self.group_combo.currentText()

            # Generate parameters by standardized named group.
            self.openssl.run(
                [
                    "genpkey",
                    "-genparam",
                    "-algorithm",
                    "DH",
                    "-pkeyopt",
                    f"group:{self.current_group}",
                    "-out",
                    str(self.params_file),
                ]
            )

            inspect = self.openssl.text(
                ["pkeyparam", "-in", str(self.params_file), "-text"]
            )

            check = self.openssl.text(
                ["pkeyparam", "-in", str(self.params_file), "-check", "-text"]
            )

            self.parameter_output.setPlainText(
                f"Selected named group: {self.current_group}\n"
                f"Parameter file      : {self.params_file}\n\n"
                "=== PARAMETER INSPECTION ===\n"
                f"{inspect}\n"
                "=== PARAMETER VALIDATION ===\n"
                f"{check}\n"
                "Teaching interpretation:\n"
                "The group parameters are public. Security depends on choosing "
                "an appropriate standardized group and fresh secret exponents."
            )

        except Exception as exc:
            self.show_error(exc)

    # ================================================================
    # TAB 3 — ONE SIDE: generate + custom-save private/public material
    # ================================================================

    def make_tab3(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        description = QLabel(
            "<b>One endpoint only.</b> Generate a fresh ephemeral FFDHE key pair. "
            "Then save the <b>local private key</b> and the <b>public share</b> "
            "independently as PEM, DER-binary (.bin), or DER-hex (.hex). "
            "Only the public share should be sent to the peer."
        )
        description.setWordWrap(True)
        layout.addWidget(description)

        generate = QPushButton("Generate This Side's Ephemeral Key Pair")
        generate.clicked.connect(self.generate_local_keypair)
        layout.addWidget(generate)

        # Optional teaching output only; all original v5 behavior is unchanged.
        self.show_pg_details = QCheckBox(
            "Show detailed domain parameters p and g in output"
        )
        self.show_pg_details.setChecked(False)
        layout.addWidget(self.show_pg_details)

        private_box = QGroupBox("Save Local Private Key")
        private_form = QFormLayout(private_box)
        self.private_output_format = QComboBox()
        self.private_output_format.addItems([
            "PEM (.pem)",
            "DER binary (.bin)",
            "DER hex (.hex)",
        ])
        private_form.addRow("Format:", self.private_output_format)
        save_private = QPushButton("Save Private Key As...")
        save_private.clicked.connect(self.save_local_private_key)
        private_form.addRow(save_private)
        layout.addWidget(private_box)

        public_box = QGroupBox("Save Public Share for Peer")
        public_form = QFormLayout(public_box)
        self.public_output_format = QComboBox()
        self.public_output_format.addItems([
            "PEM (.pem)",
            "DER binary (.bin)",
            "DER hex (.hex)",
        ])
        public_form.addRow("Format:", self.public_output_format)
        save_public = QPushButton("Save Public Share As...")
        save_public.clicked.connect(self.save_local_public_share)
        public_form.addRow(save_public)
        layout.addWidget(public_box)

        self.key_output = QTextEdit()
        self.key_output.setReadOnly(True)
        self.monospace(self.key_output)
        layout.addWidget(self.key_output)
        return page

    def get_pg_details(self) -> str:
        """
        Decode p and g from the selected FFDHE parameter file.
        This is display/teaching logic only; it does not change key generation.
        """
        # Ensure the parameter file corresponds to the group selected in Tab 3.
        self.openssl.run([
            "genpkey", "-genparam", "-algorithm", "DH",
            "-pkeyopt", f"group:{self.current_group}",
            "-out", str(self.params_file),
        ])

        parsed = self.openssl.text([
            "asn1parse", "-in", str(self.params_file), "-inform", "PEM"
        ])

        integers = []
        for line in parsed.splitlines():
            if "prim: INTEGER" in line:
                value = line.rsplit(":", 1)[-1].strip()
                if value:
                    integers.append(value)

        if len(integers) < 2:
            return (
                "=== DETAILED DOMAIN PARAMETERS p AND g ===\n"
                "OpenSSL did not expose p and g as explicit ASN.1 INTEGER values "
                "for this named-group encoding.\n"
            )

        p_hex = integers[0].upper()
        g_hex = integers[1].upper()
        p = int(p_hex, 16)
        g = int(g_hex, 16)

        # Format long p for classroom readability.
        p_hex_lines = "\n".join(
            p_hex[i:i + 64] for i in range(0, len(p_hex), 64)
        )

        return (
            "=== DETAILED DOMAIN PARAMETERS p AND g ===\n"
            f"Named group : {self.current_group}\n"
            f"p bit length: {p.bit_length()} bits\n\n"
            "Prime modulus p (HEX):\n"
            f"{p_hex_lines}\n\n"
            "Prime modulus p (DECIMAL):\n"
            f"{p}\n\n"
            "Generator g:\n"
            f"  HEX     : {g_hex}\n"
            f"  DECIMAL : {g}\n\n"
            "Mathematical setting:\n"
            "  A = g^a mod p\n"
            "  B = g^b mod p\n"
            "  Z = B^a mod p = A^b mod p = g^(ab) mod p\n"
        )

    def generate_local_keypair(self) -> None:
        try:
            self.refresh_openssl_path()
            self.current_group = self.group_combo.currentText()

            self.openssl.run([
                "genpkey", "-algorithm", "DH",
                "-pkeyopt", f"group:{self.current_group}",
                "-out", str(self.alice_private),
            ])
            self.openssl.run([
                "pkey", "-in", str(self.alice_private),
                "-pubout", "-out", str(self.alice_public),
            ])

            private_details = self.openssl.text([
                "pkey", "-in", str(self.alice_private), "-text", "-noout"
            ])
            public_details = self.openssl.text([
                "pkey", "-pubin", "-in", str(self.alice_public), "-text", "-noout"
            ])

            pg_details = ""
            if self.show_pg_details.isChecked():
                pg_details = self.get_pg_details() + "\n"

            self.key_output.setPlainText(
                f"Selected FFDHE group: {self.current_group}\n\n"
                f"{pg_details}"
                "LOCAL EPHEMERAL KEY PAIR\n"
                "============================================================\n"
                f"Working private key: {self.alice_private}\n"
                f"Working public key : {self.alice_public}\n\n"
                "PRIVATE / SECRET COMPONENT\n"
                "------------------------------------------------------------\n"
                f"{private_details}\n\n"
                "PUBLIC SHARE TO SEND TO PEER\n"
                "------------------------------------------------------------\n"
                f"{public_details}\n\n"
                "Use the two Save controls above to choose PEM, DER binary, "
                "or DER hex independently for the private key and public share.\n\n"
                "Protocol rule: keep the private key local; exchange only the public share."
            )
        except Exception as exc:
            self.show_error(exc)

    def _private_der(self) -> bytes:
        self.require_files(self.alice_private)
        return self.openssl.run([
            "pkey", "-in", str(self.alice_private),
            "-outform", "DER",
        ]).stdout

    def _public_der(self) -> bytes:
        self.require_files(self.alice_public)
        return self.openssl.run([
            "pkey", "-pubin", "-in", str(self.alice_public),
            "-pubout", "-outform", "DER",
        ]).stdout

    def save_local_private_key(self) -> None:
        try:
            self.refresh_openssl_path()
            self.require_files(self.alice_private)
            mode = self.private_output_format.currentText()

            if mode == "PEM (.pem)":
                default = "my_ffdhe_private.pem"
                path, _ = QFileDialog.getSaveFileName(
                    self, "Save local private key", default,
                    "PEM (*.pem);;All files (*)"
                )
                if not path:
                    return
                # Re-encode through OpenSSL instead of blindly copying.
                self.openssl.run([
                    "pkey", "-in", str(self.alice_private),
                    "-out", str(Path(path)),
                ])
                size = Path(path).stat().st_size
            else:
                der = self._private_der()
                is_bin = mode == "DER binary (.bin)"
                ext = ".bin" if is_bin else ".hex"
                path, _ = QFileDialog.getSaveFileName(
                    self, "Save local private key",
                    f"my_ffdhe_private{ext}",
                    "Binary (*.bin);;Hex text (*.hex);;All files (*)"
                )
                if not path:
                    return
                if is_bin:
                    Path(path).write_bytes(der)
                else:
                    Path(path).write_text(hex_block(der) + "\n", encoding="utf-8")
                size = len(der)

            self.key_output.append(
                f"\nPRIVATE KEY SAVED\n"
                f"File: {path}\nFormat: {mode}\nEncoded size: {size} bytes\n"
                "Do NOT send this file to the peer."
            )
        except Exception as exc:
            self.show_error(exc)

    def save_local_public_share(self) -> None:
        try:
            self.refresh_openssl_path()
            self.require_files(self.alice_public)
            mode = self.public_output_format.currentText()

            if mode == "PEM (.pem)":
                default = "my_ffdhe_public_share.pem"
                path, _ = QFileDialog.getSaveFileName(
                    self, "Save public share for peer", default,
                    "PEM (*.pem);;All files (*)"
                )
                if not path:
                    return
                self.openssl.run([
                    "pkey", "-pubin", "-in", str(self.alice_public),
                    "-pubout", "-out", str(Path(path)),
                ])
                size = Path(path).stat().st_size
            else:
                der = self._public_der()
                is_bin = mode == "DER binary (.bin)"
                ext = ".bin" if is_bin else ".hex"
                path, _ = QFileDialog.getSaveFileName(
                    self, "Save public share for peer",
                    f"my_ffdhe_public_share{ext}",
                    "Binary (*.bin);;Hex text (*.hex);;All files (*)"
                )
                if not path:
                    return
                if is_bin:
                    Path(path).write_bytes(der)
                else:
                    Path(path).write_text(hex_block(der) + "\n", encoding="utf-8")
                size = len(der)

            self.key_output.append(
                f"\nPUBLIC SHARE SAVED\n"
                f"File: {path}\nFormat: {mode}\nEncoded size: {size} bytes\n"
                "This is the value/file that may be sent to the peer."
            )
        except Exception as exc:
            self.show_error(exc)

    # ================================================================
    # TAB 4 — Load matching Tab-3 formats: LOCAL private + PEER public -> Z
    # ================================================================

    def make_tab4(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        description = QLabel(
            "<b>Independent endpoint derivation.</b> Load your local private key "
            "and the peer's public share in any format exported by Tab 3: "
            "PEM, DER binary, or DER hex. OpenSSL validates/normalizes both before "
            "computing Z = DH(local private, peer public)."
        )
        description.setWordWrap(True)
        layout.addWidget(description)

        private_box = QGroupBox("Input 1 — Local Private Key")
        private_form = QFormLayout(private_box)
        self.private_input_format = QComboBox()
        self.private_input_format.addItems([
            "PEM (.pem)",
            "DER binary (.bin)",
            "DER hex (.hex)",
        ])
        private_form.addRow("Format:", self.private_input_format)

        self.local_private_path = QLineEdit()
        self.local_private_path.setReadOnly(True)
        private_form.addRow("Loaded file:", self.local_private_path)

        load_private = QPushButton("Load Local Private Key")
        load_private.clicked.connect(self.load_local_private_key)
        private_form.addRow(load_private)
        layout.addWidget(private_box)

        peer_box = QGroupBox("Input 2 — Peer Public Share")
        peer_form = QFormLayout(peer_box)
        self.peer_input_format = QComboBox()
        self.peer_input_format.addItems([
            "PEM (.pem)",
            "DER binary (.bin)",
            "DER hex (.hex)",
        ])
        peer_form.addRow("Format:", self.peer_input_format)

        self.peer_share_path = QLineEdit()
        self.peer_share_path.setReadOnly(True)
        peer_form.addRow("Loaded file:", self.peer_share_path)

        load_peer = QPushButton("Load Peer Public Share")
        load_peer.clicked.connect(self.load_peer_public_share)
        peer_form.addRow(load_peer)
        layout.addWidget(peer_box)

        derive = QPushButton("Compute Shared Secret Z")
        derive.clicked.connect(self.compute_local_z)
        layout.addWidget(derive)

        output_box = QGroupBox("Save Shared Secret Z")
        output_form = QFormLayout(output_box)
        self.z_format = QComboBox()
        self.z_format.addItems(["Hex text (.hex)", "Binary (.bin)"])
        output_form.addRow("Output format:", self.z_format)
        save_z = QPushButton("Save Z As...")
        save_z.clicked.connect(self.save_local_z)
        output_form.addRow(save_z)
        layout.addWidget(output_box)

        self.z_output = QTextEdit()
        self.z_output.setReadOnly(True)
        self.monospace(self.z_output)
        layout.addWidget(self.z_output)

        # Normalized PEM files used internally by OpenSSL pkeyutl.
        self.loaded_private_key = APP_DIR / "tab4_local_private_normalized.pem"
        self.loaded_peer_public = APP_DIR / "tab4_peer_public_normalized.pem"
        return page

    @staticmethod
    def _read_der_hex(path: Path) -> bytes:
        text = path.read_text(encoding="utf-8")
        value = "".join(text.split()).replace(":", "")
        if value.lower().startswith("0x"):
            value = value[2:]
        if len(value) % 2:
            raise ValueError(f"Odd number of hexadecimal digits in {path}.")
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError(f"Invalid hexadecimal encoding in {path}.") from exc

    def load_local_private_key(self) -> None:
        try:
            self.refresh_openssl_path()
            mode = self.private_input_format.currentText()
            path, _ = QFileDialog.getOpenFileName(
                self, "Load local private key", "",
                "PEM (*.pem);;Binary (*.bin);;Hex text (*.hex);;All files (*)"
            )
            if not path:
                return
            source = Path(path)

            if mode == "PEM (.pem)":
                self.openssl.run([
                    "pkey", "-in", str(source),
                    "-out", str(self.loaded_private_key),
                ])
            else:
                der = source.read_bytes() if mode == "DER binary (.bin)" else self._read_der_hex(source)
                tmp = APP_DIR / "_tab4_private.der"
                tmp.write_bytes(der)
                try:
                    self.openssl.run([
                        "pkey", "-inform", "DER", "-in", str(tmp),
                        "-out", str(self.loaded_private_key),
                    ])
                finally:
                    if tmp.exists():
                        tmp.unlink()

            details = self.openssl.text([
                "pkey", "-in", str(self.loaded_private_key), "-text", "-noout"
            ])
            self.local_private_path.setText(str(source))
            self.z_output.setPlainText(
                "LOCAL PRIVATE KEY LOADED AND VALIDATED\n"
                "============================================================\n"
                f"Source: {source}\nFormat: {mode}\n\n{details}"
            )
        except Exception as exc:
            if self.loaded_private_key.exists():
                self.loaded_private_key.unlink()
            self.local_private_path.clear()
            self.show_error(exc)

    def load_peer_public_share(self) -> None:
        try:
            self.refresh_openssl_path()
            mode = self.peer_input_format.currentText()
            path, _ = QFileDialog.getOpenFileName(
                self, "Load peer public share", "",
                "PEM (*.pem);;Binary (*.bin);;Hex text (*.hex);;All files (*)"
            )
            if not path:
                return
            source = Path(path)

            if mode == "PEM (.pem)":
                self.openssl.run([
                    "pkey", "-pubin", "-in", str(source),
                    "-pubout", "-out", str(self.loaded_peer_public),
                ])
            else:
                der = source.read_bytes() if mode == "DER binary (.bin)" else self._read_der_hex(source)
                tmp = APP_DIR / "_tab4_peer.der"
                tmp.write_bytes(der)
                try:
                    self.openssl.run([
                        "pkey", "-pubin", "-inform", "DER", "-in", str(tmp),
                        "-pubout", "-out", str(self.loaded_peer_public),
                    ])
                finally:
                    if tmp.exists():
                        tmp.unlink()

            details = self.openssl.text([
                "pkey", "-pubin", "-in", str(self.loaded_peer_public),
                "-text", "-noout",
            ])
            self.peer_share_path.setText(str(source))
            self.z_output.append(
                "\n\nPEER PUBLIC SHARE LOADED AND VALIDATED\n"
                "============================================================\n"
                f"Source: {source}\nFormat: {mode}\n\n{details}"
            )
        except Exception as exc:
            if self.loaded_peer_public.exists():
                self.loaded_peer_public.unlink()
            self.peer_share_path.clear()
            self.show_error(exc)

    def compute_local_z(self) -> None:
        try:
            self.refresh_openssl_path()
            self.require_files(self.loaded_private_key, self.loaded_peer_public)

            self.openssl.run([
                "pkeyutl", "-derive",
                "-inkey", str(self.loaded_private_key),
                "-peerkey", str(self.loaded_peer_public),
                "-out", str(self.alice_z),
            ])

            z = self.alice_z.read_bytes()
            self.z_output.append(
                "\n\nSHARED SECRET Z\n"
                "============================================================\n"
                f"Local private input : {self.local_private_path.text()}\n"
                f"Peer public input   : {self.peer_share_path.text()}\n\n"
                "Mathematics:\n"
                "  local private = a\n"
                "  peer public   = B = g^b\n"
                "  Z = B^a = (g^b)^a = g^(ab)\n\n"
                f"Z length: {len(z)} bytes\n"
                f"Z (hex):\n{hex_block(z)}\n\n"
                "The peer obtains the same Z by loading private b and public A."
            )
        except Exception as exc:
            self.show_error(exc)

    def save_local_z(self) -> None:
        try:
            self.require_files(self.alice_z)
            data = self.alice_z.read_bytes()
            mode = self.z_format.currentText()
            ext = ".bin" if mode == "Binary (.bin)" else ".hex"
            path, _ = QFileDialog.getSaveFileName(
                self, "Save shared secret Z", f"shared_secret_Z{ext}",
                "Binary (*.bin);;Hex text (*.hex);;All files (*)"
            )
            if not path:
                return
            write_hex_or_bin(Path(path), data, mode)
            self.z_output.append(
                f"\nZ saved to: {path}\nFormat: {mode}\nLength: {len(data)} bytes"
            )
        except Exception as exc:
            self.show_error(exc)

    # ================================================================
    # TAB 5 — Load Z -> OpenSSL HKDF -> save K
    # ================================================================

    def make_tab5(self) -> QWidget:
        page=QWidget(); layout=QVBoxLayout(page)
        d=QLabel("<b>Independent KDF step:</b> load shared secret Z from HEX/BIN, select HKDF parameters, derive K with OpenSSL, then save K as HEX/BIN."); d.setWordWrap(True); layout.addWidget(d)
        zi=QGroupBox("Input — Shared Secret Z"); fz=QFormLayout(zi)
        self.kdf_z_format=QComboBox(); self.kdf_z_format.addItems(["Hex text (.hex)","Binary (.bin)"]); fz.addRow("Z format:",self.kdf_z_format)
        self.kdf_z_path=QLineEdit(); self.kdf_z_path.setReadOnly(True); fz.addRow("Z file:",self.kdf_z_path)
        bz=QPushButton("Load Shared Secret Z"); bz.clicked.connect(self.load_z_for_kdf); fz.addRow(bz); layout.addWidget(zi)
        box=QGroupBox("OpenSSL HKDF Settings"); form=QFormLayout(box)
        self.hkdf_digest=QComboBox(); self.hkdf_digest.addItems(HKDF_DIGESTS); self.key_length=QSpinBox(); self.key_length.setRange(16,64); self.key_length.setValue(32)
        self.hkdf_salt=QLineEdit(); self.hkdf_salt.setPlaceholderText("Optional hex salt"); self.hkdf_info=QLineEdit("Week07-FFDHE-session-key")
        form.addRow("Digest:",self.hkdf_digest); form.addRow("Key length (bytes):",self.key_length); form.addRow("Salt (hex):",self.hkdf_salt); form.addRow("Context / info:",self.hkdf_info)
        bd=QPushButton("Derive Shared Key K with OpenSSL HKDF"); bd.clicked.connect(self.derive_application_key); form.addRow(bd); layout.addWidget(box)
        ko=QGroupBox("Output — Shared Key K"); fk=QFormLayout(ko); self.k_format=QComboBox(); self.k_format.addItems(["Hex text (.hex)","Binary (.bin)"]); fk.addRow("K format:",self.k_format)
        bk=QPushButton("Save Shared Key K"); bk.clicked.connect(self.save_application_key); fk.addRow(bk); layout.addWidget(ko)
        self.kdf_output=QTextEdit(); self.kdf_output.setReadOnly(True); self.monospace(self.kdf_output); layout.addWidget(self.kdf_output); self.loaded_z=None; self.derived_k=None; return page

    def load_z_for_kdf(self) -> None:
        try:
            mode=self.kdf_z_format.currentText(); path,_=QFileDialog.getOpenFileName(self,"Load shared secret Z","","Binary (*.bin);;Hex text (*.hex);;All files (*)")
            if not path: return
            self.loaded_z=read_hex_or_bin(Path(path),mode); self.kdf_z_path.setText(path); self.kdf_output.setPlainText(f"Z LOADED\n{'='*60}\nSource: {path}\nLength: {len(self.loaded_z)} bytes\n{hex_block(self.loaded_z)}")
        except Exception as exc: self.show_error(exc)

    def openssl_hkdf(self,z:bytes,digest:str,salt_hex:str,info_text:str,out_len:int)->bytes:
        args=["kdf","-keylen",str(out_len),"-kdfopt",f"digest:{digest}","-kdfopt",f"hexkey:{z.hex()}"]
        if salt_hex: args += ["-kdfopt",f"hexsalt:{salt_hex}"]
        if info_text: args += ["-kdfopt",f"info:{info_text}"]
        args += ["HKDF"]; result=self.openssl.text(args).strip(); normalized=result.replace(":","").replace(" ","").replace("\n","")
        try: return bytes.fromhex(normalized)
        except ValueError as exc: raise RuntimeError(f"Cannot parse OpenSSL HKDF output:\n{result}") from exc

    def derive_application_key(self) -> None:
        try:
            self.refresh_openssl_path()
            if self.loaded_z is None: raise RuntimeError("Load shared secret Z first.")
            digest=self.hkdf_digest.currentText(); length=self.key_length.value(); salt=clean_hex(self.hkdf_salt.text()); info=self.hkdf_info.text()
            self.derived_k=self.openssl_hkdf(self.loaded_z,digest,salt,info,length)
            self.kdf_output.append(f"\nDERIVED SHARED KEY K\n{'='*60}\nHKDF-{digest}; length={length} bytes\nSalt={salt or '(none)'}\nInfo={info}\nK:\n{hex_block(self.derived_k)}")
        except Exception as exc: self.show_error(exc)

    def save_application_key(self) -> None:
        try:
            if self.derived_k is None: raise RuntimeError("Derive shared key K first.")
            mode=self.k_format.currentText(); ext=".bin" if mode=="Binary (.bin)" else ".hex"; path,_=QFileDialog.getSaveFileName(self,"Save shared key K",f"shared_key_K{ext}","Binary (*.bin);;Hex text (*.hex);;All files (*)")
            if not path: return
            write_hex_or_bin(Path(path),self.derived_k,mode); self.kdf_output.append(f"\nSaved K: {path} ({mode})")
        except Exception as exc: self.show_error(exc)


def main() -> None:
    app = QApplication(sys.argv)
    app.setFont(QFont("Arial", 16))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
