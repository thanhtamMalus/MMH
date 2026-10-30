#!/usr/bin/env python3
"""
RC4 CLI + PyQt6 GUI Demo — Week 3

One self-contained file provides:
  * CLI encryption/decryption/keystream/self-test
  * PyQt6 GUI for classroom demonstrations

RC4 is obsolete and unauthenticated. This program is for teaching only.
"""

from __future__ import annotations

import argparse
import base64
import secrets
import sys


RFC6229_KEY = bytes.fromhex("0102030405")
RFC6229_FIRST16 = bytes.fromhex("b2396305f03dc027ccc3524a0a1118a8")


# ---------------------------------------------------------------------------
# RC4 core
# ---------------------------------------------------------------------------

def validate_key(key: bytes) -> None:
    if not key:
        raise ValueError("Key must not be empty.")
    if len(key) > 256:
        raise ValueError("Use a key of 1..256 bytes for this teaching demo.")


def rc4_ksa(key: bytes) -> list[int]:
    validate_key(key)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


def rc4_keystream(key: bytes, n: int, drop_n: int = 0) -> bytes:
    validate_key(key)
    if n < 0 or drop_n < 0:
        raise ValueError("n and drop_n must be non-negative.")

    s = rc4_ksa(key)
    i = j = 0
    out = bytearray()
    for position in range(drop_n + n):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        t = (s[i] + s[j]) & 0xFF
        z = s[t]
        if position >= drop_n:
            out.append(z)
    return bytes(out)


def rc4_crypt(key: bytes, data: bytes, drop_n: int = 0) -> bytes:
    z = rc4_keystream(key, len(data), drop_n)
    return bytes(x ^ y for x, y in zip(data, z))


def selftest() -> bool:
    return rc4_keystream(RFC6229_KEY, 16) == RFC6229_FIRST16


# ---------------------------------------------------------------------------
# Encoding helpers shared by CLI and GUI
# ---------------------------------------------------------------------------

def clean_hex(text: str) -> str:
    cleaned = "".join(text.split()).replace(":", "").replace("-", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    return cleaned


def decode_value(text: str, fmt: str) -> bytes:
    fmt = fmt.lower()
    if fmt == "text":
        return text.encode("utf-8")
    if fmt == "hex":
        cleaned = clean_hex(text)
        if len(cleaned) % 2:
            raise ValueError("Hex input must have an even number of digits.")
        return bytes.fromhex(cleaned)
    if fmt == "base64":
        try:
            return base64.b64decode(text.strip(), validate=True)
        except Exception as exc:
            raise ValueError("Invalid Base64 input.") from exc
    raise ValueError(f"Unsupported input format: {fmt}")


def encode_value(data: bytes, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "hex":
        return data.hex()
    if fmt == "base64":
        return base64.b64encode(data).decode("ascii")
    if fmt == "text":
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return "<output is not valid UTF-8; choose Hex or Base64>"
    raise ValueError(f"Unsupported output format: {fmt}")


def parse_key(value: str, fmt: str) -> bytes:
    if fmt not in {"text", "hex"}:
        raise ValueError("Key format must be text or hex.")
    key = decode_value(value, fmt)
    validate_key(key)
    return key


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def add_key_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--key", required=True, help="key value")
    p.add_argument("--key-format", choices=["text", "hex"], default="text")
    p.add_argument("--drop-n", type=int, default=0,
                   help="historical experiment: discard first N keystream bytes")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RC4 CLI/PyQt6 demonstration program — educational use only."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("gui", help="launch the PyQt6 GUI")
    sub.add_parser("selftest", help="validate against RFC 6229")

    p_enc = sub.add_parser("encrypt", help="encrypt input")
    add_key_options(p_enc)
    p_enc.add_argument("--input", required=True)
    p_enc.add_argument("--input-format", choices=["text", "hex", "base64"], default="text")
    p_enc.add_argument("--output-format", choices=["hex", "base64"], default="hex")

    p_dec = sub.add_parser("decrypt", help="decrypt input")
    add_key_options(p_dec)
    p_dec.add_argument("--input", required=True)
    p_dec.add_argument("--input-format", choices=["hex", "base64"], default="hex")
    p_dec.add_argument("--output-format", choices=["text", "hex", "base64"], default="text")

    p_ks = sub.add_parser("keystream", help="generate keystream")
    add_key_options(p_ks)
    p_ks.add_argument("--n", type=int, required=True)
    p_ks.add_argument("--output-format", choices=["hex", "base64"], default="hex")

    return parser


def run_cli(args: argparse.Namespace) -> int:
    if args.command == "selftest":
        actual = rc4_keystream(RFC6229_KEY, 16)
        print("RFC 6229 self-test")
        print(f"Expected: {RFC6229_FIRST16.hex()}")
        print(f"Actual  : {actual.hex()}")
        print("PASS" if actual == RFC6229_FIRST16 else "FAIL")
        return 0 if actual == RFC6229_FIRST16 else 1

    key = parse_key(args.key, args.key_format)

    if args.command == "keystream":
        out = rc4_keystream(key, args.n, args.drop_n)
        print(encode_value(out, args.output_format))
        return 0

    data = decode_value(args.input, args.input_format)
    out = rc4_crypt(key, data, args.drop_n)
    print(encode_value(out, args.output_format))
    return 0


# ---------------------------------------------------------------------------
# PyQt6 GUI — imported lazily so CLI mode does not require PyQt6 to start.
# ---------------------------------------------------------------------------

def launch_gui() -> int:
    try:
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import (
            QApplication,
            QComboBox,
            QFormLayout,
            QGridLayout,
            QGroupBox,
            QHBoxLayout,
            QLabel,
            QMainWindow,
            QMessageBox,
            QPlainTextEdit,
            QPushButton,
            QSpinBox,
            QVBoxLayout,
            QWidget,
            QLineEdit,
        )
    except ImportError:
        print("PyQt6 is not installed. Install it with: pip install PyQt6", file=sys.stderr)
        return 2

    class RC4Window(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("RC4 Demo — Week 3 (Educational Use Only)")
            self.resize(900, 700)

            root = QWidget()
            self.setCentralWidget(root)
            layout = QVBoxLayout(root)

            warning = QLabel(
                "RC4 is obsolete and unauthenticated. Use this tool only for classroom demonstration."
            )
            warning.setWordWrap(True)
            warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(warning)

            settings = QGroupBox("Operation and key")
            form = QFormLayout(settings)

            self.operation = QComboBox()
            self.operation.addItems(["Encrypt", "Decrypt", "Keystream"])
            self.operation.currentTextChanged.connect(self.sync_formats)
            form.addRow("Operation:", self.operation)

            key_line = QHBoxLayout()
            self.key_edit = QLineEdit("secret")
            self.key_format = QComboBox()
            self.key_format.addItems(["Text", "Hex"])
            key_line.addWidget(self.key_edit, 1)
            key_line.addWidget(self.key_format)
            form.addRow("Key:", key_line)

            random_line = QHBoxLayout()
            self.random_len = QSpinBox()
            self.random_len.setRange(1, 256)
            self.random_len.setValue(16)
            self.random_button = QPushButton("Generate random key")
            self.random_button.clicked.connect(self.generate_random_key)
            random_line.addWidget(self.random_len)
            random_line.addWidget(self.random_button)
            random_line.addStretch(1)
            form.addRow("Random key bytes:", random_line)

            self.drop_n = QSpinBox()
            self.drop_n.setRange(0, 1_000_000)
            self.drop_n.setValue(0)
            form.addRow("Drop-N (experiment):", self.drop_n)

            self.stream_len = QSpinBox()
            self.stream_len.setRange(1, 1_000_000)
            self.stream_len.setValue(32)
            form.addRow("Keystream bytes:", self.stream_len)

            layout.addWidget(settings)

            io_box = QGroupBox("Input / output")
            io_layout = QGridLayout(io_box)

            self.input_format = QComboBox()
            self.output_format = QComboBox()
            io_layout.addWidget(QLabel("Input format:"), 0, 0)
            io_layout.addWidget(self.input_format, 0, 1)
            io_layout.addWidget(QLabel("Output format:"), 0, 2)
            io_layout.addWidget(self.output_format, 0, 3)

            self.input_edit = QPlainTextEdit()
            self.input_edit.setPlaceholderText("Enter plaintext or ciphertext here...")
            self.output_edit = QPlainTextEdit()
            self.output_edit.setReadOnly(True)

            io_layout.addWidget(QLabel("Input"), 1, 0, 1, 2)
            io_layout.addWidget(QLabel("Output"), 1, 2, 1, 2)
            io_layout.addWidget(self.input_edit, 2, 0, 1, 2)
            io_layout.addWidget(self.output_edit, 2, 2, 1, 2)
            layout.addWidget(io_box, 1)

            buttons = QHBoxLayout()
            self.run_button = QPushButton("Run")
            self.run_button.clicked.connect(self.run_operation)
            self.selftest_button = QPushButton("RFC 6229 Self-test")
            self.selftest_button.clicked.connect(self.run_selftest)
            self.use_output_button = QPushButton("Use output as input")
            self.use_output_button.clicked.connect(self.use_output_as_input)
            self.clear_button = QPushButton("Clear")
            self.clear_button.clicked.connect(self.clear_io)
            buttons.addWidget(self.run_button)
            buttons.addWidget(self.selftest_button)
            buttons.addWidget(self.use_output_button)
            buttons.addWidget(self.clear_button)
            layout.addLayout(buttons)

            self.status = QLabel("Ready")
            layout.addWidget(self.status)
            self.sync_formats()

        def generate_random_key(self) -> None:
            key = secrets.token_bytes(self.random_len.value())
            self.key_edit.setText(key.hex())
            self.key_format.setCurrentText("Hex")
            self.status.setText(f"Generated {len(key)} random key bytes.")

        def sync_formats(self) -> None:
            op = self.operation.currentText()
            self.input_format.clear()
            self.output_format.clear()
            if op == "Encrypt":
                self.input_format.addItems(["Text", "Hex", "Base64"])
                self.output_format.addItems(["Hex", "Base64"])
                self.stream_len.setEnabled(False)
                self.input_edit.setEnabled(True)
            elif op == "Decrypt":
                self.input_format.addItems(["Hex", "Base64"])
                self.output_format.addItems(["Text", "Hex", "Base64"])
                self.stream_len.setEnabled(False)
                self.input_edit.setEnabled(True)
            else:
                self.input_format.addItems(["Text"])
                self.output_format.addItems(["Hex", "Base64"])
                self.stream_len.setEnabled(True)
                self.input_edit.setEnabled(False)
                self.input_edit.clear()

        def current_key(self) -> bytes:
            return parse_key(self.key_edit.text(), self.key_format.currentText().lower())

        def run_operation(self) -> None:
            try:
                key = self.current_key()
                op = self.operation.currentText()
                drop_n = self.drop_n.value()

                if op == "Keystream":
                    out = rc4_keystream(key, self.stream_len.value(), drop_n)
                else:
                    data = decode_value(
                        self.input_edit.toPlainText(),
                        self.input_format.currentText().lower(),
                    )
                    out = rc4_crypt(key, data, drop_n)

                self.output_edit.setPlainText(
                    encode_value(out, self.output_format.currentText().lower())
                )
                self.status.setText(f"Completed: {len(out)} output byte(s).")
            except Exception as exc:
                QMessageBox.critical(self, "Input / RC4 error", str(exc))
                self.status.setText("Error")

        def run_selftest(self) -> None:
            actual = rc4_keystream(RFC6229_KEY, 16)
            ok = actual == RFC6229_FIRST16
            text = (
                f"Key:      {RFC6229_KEY.hex(' ')}\n"
                f"Expected: {RFC6229_FIRST16.hex(' ')}\n"
                f"Actual:   {actual.hex(' ')}\n\n"
                f"Result: {'PASS' if ok else 'FAIL'}"
            )
            if ok:
                QMessageBox.information(self, "RFC 6229 Self-test", text)
            else:
                QMessageBox.critical(self, "RFC 6229 Self-test", text)

        def use_output_as_input(self) -> None:
            if self.operation.currentText() == "Keystream":
                return
            output = self.output_edit.toPlainText()
            if not output:
                return

            if self.operation.currentText() == "Encrypt":
                # Encryption output is Hex or Base64; switch to Decrypt.
                fmt = self.output_format.currentText()
                self.operation.setCurrentText("Decrypt")
                self.input_format.setCurrentText(fmt)
                self.input_edit.setPlainText(output)
            else:
                # For decryption, simply move the result to input for inspection.
                self.input_edit.setPlainText(output)

        def clear_io(self) -> None:
            self.input_edit.clear()
            self.output_edit.clear()
            self.status.setText("Ready")

    app = QApplication(sys.argv)
    window = RC4Window()
    window.show()
    return app.exec()


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "gui":
        raise SystemExit(launch_gui())

    try:
        raise SystemExit(run_cli(args))
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
