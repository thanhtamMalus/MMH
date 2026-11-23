#!/usr/bin/env python3
"""
ChaCha20 CLI + PyQt6 GUI Demo — Week 3

One self-contained source file provides:
  * CLI: encrypt / decrypt / keystream / block / self-test
  * PyQt6 GUI for classroom demonstrations

IETF ChaCha20 (RFC 8439): 32-byte key, 12-byte nonce, 32-bit counter.
ChaCha20 ONLY — no Poly1305, hence no authentication/integrity protection.
"""

from __future__ import annotations

import argparse
import base64
import secrets
import struct
import sys

MASK32 = 0xFFFFFFFF
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)

RFC_KEY = bytes(range(32))
RFC_BLOCK_NONCE = bytes.fromhex("000000090000004a00000000")
RFC_BLOCK_EXPECTED = bytes.fromhex(
    "10f1e7e4d13b5915500fdd1fa32071c4"
    "c7d1f4c733c068030422aa9ac3d46c4e"
    "d2826446079faa0914c2d705d98b02a2"
    "b5129cd1de164eb9cbd083e8a2503c4e"
)
RFC_ENC_NONCE = bytes.fromhex("000000000000004a00000000")
RFC_PLAINTEXT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
    b"for the future, sunscreen would be it."
)
RFC_CIPHERTEXT = bytes.fromhex(
    "6e2e359a2568f98041ba0728dd0d6981"
    "e97e7aec1d4360c20a27afccfd9fae0b"
    "f91b65c5524733ab8f593dabcd62b357"
    "1639d624e65152ab8f530c359f0861d8"
    "07ca0dbf500d6a6156a38e088a22b65e"
    "52bc514d16ccf806818ce91ab7793736"
    "5af90bbf74a35be6b40b8eedf2785e42"
    "874d"
)


def rotl32(x: int, n: int) -> int:
    x &= MASK32
    return ((x << n) & MASK32) | (x >> (32 - n))


def quarter_round(x: list[int], a: int, b: int, c: int, d: int) -> None:
    x[a] = (x[a] + x[b]) & MASK32
    x[d] = rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & MASK32
    x[b] = rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & MASK32
    x[d] = rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & MASK32
    x[b] = rotl32(x[b] ^ x[c], 7)


def inner_block(x: list[int]) -> None:
    quarter_round(x, 0, 4, 8, 12)
    quarter_round(x, 1, 5, 9, 13)
    quarter_round(x, 2, 6, 10, 14)
    quarter_round(x, 3, 7, 11, 15)
    quarter_round(x, 0, 5, 10, 15)
    quarter_round(x, 1, 6, 11, 12)
    quarter_round(x, 2, 7, 8, 13)
    quarter_round(x, 3, 4, 9, 14)


def validate_inputs(key: bytes, nonce: bytes, counter: int) -> None:
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes (256 bits).")
    if len(nonce) != 12:
        raise ValueError("Nonce must be exactly 12 bytes (96 bits).")
    if not 0 <= counter <= MASK32:
        raise ValueError("Counter must be in 0..2^32-1.")


def initial_state(key: bytes, counter: int, nonce: bytes) -> list[int]:
    validate_inputs(key, nonce, counter)
    return [*CONSTANTS, *struct.unpack("<8I", key), counter, *struct.unpack("<3I", nonce)]


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = initial_state(key, counter, nonce)
    x = state.copy()
    for _ in range(10):
        inner_block(x)
    x = [(x[i] + state[i]) & MASK32 for i in range(16)]
    return struct.pack("<16I", *x)


def chacha20_keystream(key: bytes, nonce: bytes, counter: int, n: int) -> bytes:
    validate_inputs(key, nonce, counter)
    if n < 0:
        raise ValueError("Length must be non-negative.")
    blocks = (n + 63) // 64
    if blocks and counter + blocks - 1 > MASK32:
        raise ValueError("Message would make the 32-bit counter wrap.")
    out = bytearray()
    for j in range(blocks):
        out.extend(chacha20_block(key, counter + j, nonce))
    return bytes(out[:n])


def chacha20_crypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    z = chacha20_keystream(key, nonce, counter, len(data))
    return bytes(a ^ b for a, b in zip(data, z))


def selftest() -> bool:
    block_ok = chacha20_block(RFC_KEY, 1, RFC_BLOCK_NONCE) == RFC_BLOCK_EXPECTED
    enc_ok = chacha20_crypt(RFC_KEY, RFC_ENC_NONCE, 1, RFC_PLAINTEXT) == RFC_CIPHERTEXT
    dec_ok = chacha20_crypt(RFC_KEY, RFC_ENC_NONCE, 1, RFC_CIPHERTEXT) == RFC_PLAINTEXT
    return block_ok and enc_ok and dec_ok


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
            raise ValueError("Hex input must contain an even number of digits.")
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
    key = decode_value(value, fmt)
    if len(key) != 32:
        raise ValueError(f"Key must be exactly 32 bytes; got {len(key)}.")
    return key


def parse_nonce(value: str, fmt: str) -> bytes:
    nonce = decode_value(value, fmt)
    if len(nonce) != 12:
        raise ValueError(f"Nonce must be exactly 12 bytes; got {len(nonce)}.")
    return nonce


def add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--key", required=True, help="key value")
    p.add_argument("--key-format", choices=["text", "hex"], default="hex")
    p.add_argument("--nonce", required=True, help="nonce value")
    p.add_argument("--nonce-format", choices=["text", "hex"], default="hex")
    p.add_argument("--counter", type=lambda s: int(s, 0), default=1,
                   help="initial 32-bit block counter [default: 1]")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ChaCha20 CLI/PyQt6 classroom demo — no Poly1305."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("gui", help="launch PyQt6 GUI")
    sub.add_parser("selftest", help="run RFC 8439 validation")

    p_block = sub.add_parser("block", help="generate one 64-byte block")
    add_common(p_block)
    p_block.add_argument("--output-format", choices=["hex", "base64"], default="hex")

    p_ks = sub.add_parser("keystream", help="generate keystream")
    add_common(p_ks)
    p_ks.add_argument("--n", type=int, required=True)
    p_ks.add_argument("--output-format", choices=["hex", "base64"], default="hex")

    p_enc = sub.add_parser("encrypt", help="encrypt input")
    add_common(p_enc)
    p_enc.add_argument("--input", required=True)
    p_enc.add_argument("--input-format", choices=["text", "hex", "base64"], default="text")
    p_enc.add_argument("--output-format", choices=["hex", "base64"], default="hex")

    p_dec = sub.add_parser("decrypt", help="decrypt input")
    add_common(p_dec)
    p_dec.add_argument("--input", required=True)
    p_dec.add_argument("--input-format", choices=["hex", "base64"], default="hex")
    p_dec.add_argument("--output-format", choices=["text", "hex", "base64"], default="text")
    return parser


def run_cli(args: argparse.Namespace) -> int:
    if args.command == "selftest":
        block = chacha20_block(RFC_KEY, 1, RFC_BLOCK_NONCE)
        enc = chacha20_crypt(RFC_KEY, RFC_ENC_NONCE, 1, RFC_PLAINTEXT)
        print("RFC 8439 ChaCha20 self-test")
        print(f"Block vector : {'PASS' if block == RFC_BLOCK_EXPECTED else 'FAIL'}")
        print(f"Encryption   : {'PASS' if enc == RFC_CIPHERTEXT else 'FAIL'}")
        print(f"Round trip   : {'PASS' if chacha20_crypt(RFC_KEY, RFC_ENC_NONCE, 1, enc) == RFC_PLAINTEXT else 'FAIL'}")
        return 0 if selftest() else 1

    key = parse_key(args.key, args.key_format)
    nonce = parse_nonce(args.nonce, args.nonce_format)
    validate_inputs(key, nonce, args.counter)

    if args.command == "block":
        print(encode_value(chacha20_block(key, args.counter, nonce), args.output_format))
        return 0
    if args.command == "keystream":
        print(encode_value(chacha20_keystream(key, nonce, args.counter, args.n), args.output_format))
        return 0

    data = decode_value(args.input, args.input_format)
    out = chacha20_crypt(key, nonce, args.counter, data)
    print(encode_value(out, args.output_format))
    return 0


def launch_gui() -> int:
    try:
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import (
            QApplication, QComboBox, QFormLayout, QGroupBox, QHBoxLayout,
            QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
            QPushButton, QSpinBox, QVBoxLayout, QWidget,
        )
    except ImportError:
        print("PyQt6 is not installed. Install it with: pip install PyQt6", file=sys.stderr)
        return 2

    class ChaCha20Window(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("ChaCha20 Demo — Week 3 (No Poly1305)")
            self.resize(980, 760)

            root = QWidget()
            self.setCentralWidget(root)
            layout = QVBoxLayout(root)

            warning = QLabel(
                "ChaCha20 stream cipher only: confidentiality without authentication. "
                "Never reuse a nonce with the same key."
            )
            warning.setWordWrap(True)
            warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(warning)

            settings = QGroupBox("Operation, key, nonce, counter")
            form = QFormLayout(settings)

            self.operation = QComboBox()
            self.operation.addItems(["Encrypt", "Decrypt", "Keystream", "Block"])
            self.operation.currentTextChanged.connect(self.sync_ui)
            form.addRow("Operation:", self.operation)

            key_line = QHBoxLayout()
            self.key_edit = QLineEdit("00" * 32)
            self.key_format = QComboBox()
            self.key_format.addItems(["Hex", "Text"])
            self.key_random = QPushButton("Random 32-byte key")
            self.key_random.clicked.connect(self.generate_key)
            key_line.addWidget(self.key_edit, 1)
            key_line.addWidget(self.key_format)
            key_line.addWidget(self.key_random)
            form.addRow("Key:", key_line)

            nonce_line = QHBoxLayout()
            self.nonce_edit = QLineEdit("00" * 12)
            self.nonce_format = QComboBox()
            self.nonce_format.addItems(["Hex", "Text"])
            self.nonce_random = QPushButton("Random 12-byte nonce")
            self.nonce_random.clicked.connect(self.generate_nonce)
            nonce_line.addWidget(self.nonce_edit, 1)
            nonce_line.addWidget(self.nonce_format)
            nonce_line.addWidget(self.nonce_random)
            form.addRow("Nonce:", nonce_line)

            self.counter = QSpinBox()
            self.counter.setRange(0, MASK32)
            self.counter.setValue(1)
            form.addRow("Initial block counter:", self.counter)

            self.nbytes = QSpinBox()
            self.nbytes.setRange(0, 10_000_000)
            self.nbytes.setValue(64)
            form.addRow("Keystream bytes:", self.nbytes)
            layout.addWidget(settings)

            data_box = QGroupBox("Input / output")
            data_layout = QVBoxLayout(data_box)
            fmt_line = QHBoxLayout()
            self.input_format = QComboBox()
            self.input_format.addItems(["Text", "Hex", "Base64"])
            self.output_format = QComboBox()
            self.output_format.addItems(["Hex", "Base64", "Text"])
            fmt_line.addWidget(QLabel("Input format:"))
            fmt_line.addWidget(self.input_format)
            fmt_line.addSpacing(30)
            fmt_line.addWidget(QLabel("Output format:"))
            fmt_line.addWidget(self.output_format)
            fmt_line.addStretch(1)
            data_layout.addLayout(fmt_line)

            self.input_edit = QPlainTextEdit()
            self.input_edit.setPlaceholderText("Enter plaintext/ciphertext here")
            data_layout.addWidget(QLabel("Input:"))
            data_layout.addWidget(self.input_edit, 1)

            self.output_edit = QPlainTextEdit()
            self.output_edit.setReadOnly(True)
            data_layout.addWidget(QLabel("Output:"))
            data_layout.addWidget(self.output_edit, 1)
            layout.addWidget(data_box, 1)

            buttons = QHBoxLayout()
            self.run_button = QPushButton("Run")
            self.run_button.clicked.connect(self.run_operation)
            self.selftest_button = QPushButton("RFC 8439 Self-test")
            self.selftest_button.clicked.connect(self.run_selftest)
            self.clear_button = QPushButton("Clear")
            self.clear_button.clicked.connect(lambda: (self.input_edit.clear(), self.output_edit.clear()))
            buttons.addWidget(self.run_button)
            buttons.addWidget(self.selftest_button)
            buttons.addWidget(self.clear_button)
            buttons.addStretch(1)
            layout.addLayout(buttons)
            self.sync_ui()

        def generate_key(self) -> None:
            self.key_edit.setText(secrets.token_bytes(32).hex())
            self.key_format.setCurrentText("Hex")

        def generate_nonce(self) -> None:
            self.nonce_edit.setText(secrets.token_bytes(12).hex())
            self.nonce_format.setCurrentText("Hex")

        def sync_ui(self) -> None:
            op = self.operation.currentText()
            is_stream = op == "Keystream"
            is_block = op == "Block"
            self.input_edit.setEnabled(not (is_stream or is_block))
            self.input_format.setEnabled(not (is_stream or is_block))
            self.nbytes.setEnabled(is_stream)
            if op == "Encrypt":
                self.input_format.setCurrentText("Text")
                self.output_format.setCurrentText("Hex")
            elif op == "Decrypt":
                self.input_format.setCurrentText("Hex")
                self.output_format.setCurrentText("Text")
            else:
                self.output_format.setCurrentText("Hex")

        def get_material(self) -> tuple[bytes, bytes, int]:
            key = parse_key(self.key_edit.text(), self.key_format.currentText().lower())
            nonce = parse_nonce(self.nonce_edit.text(), self.nonce_format.currentText().lower())
            counter = self.counter.value()
            validate_inputs(key, nonce, counter)
            return key, nonce, counter

        def run_operation(self) -> None:
            try:
                key, nonce, counter = self.get_material()
                op = self.operation.currentText()
                out_fmt = self.output_format.currentText().lower()
                if op == "Block":
                    out = chacha20_block(key, counter, nonce)
                elif op == "Keystream":
                    out = chacha20_keystream(key, nonce, counter, self.nbytes.value())
                else:
                    data = decode_value(self.input_edit.toPlainText(), self.input_format.currentText().lower())
                    out = chacha20_crypt(key, nonce, counter, data)
                self.output_edit.setPlainText(encode_value(out, out_fmt))
            except Exception as exc:
                QMessageBox.critical(self, "Input/error", str(exc))

        def run_selftest(self) -> None:
            ok = selftest()
            QMessageBox.information(
                self, "RFC 8439 Self-test",
                "PASS — block, encryption, and decryption vectors match RFC 8439." if ok
                else "FAIL — implementation does not match the expected RFC 8439 vectors."
            )

    app = QApplication(sys.argv)
    window = ChaCha20Window()
    window.show()
    return app.exec()


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "gui":
        return launch_gui()
    return run_cli(args)


if __name__ == "__main__":
    raise SystemExit(main())
