#!/usr/bin/env python3
"""
ChaCha20-Poly1305 CLI + PyQt6 GUI Demo — Week 3

One file provides:
  * CLI encrypt/decrypt/self-test
  * PyQt6 GUI for classroom demonstration

Implements RFC 8439 IETF ChaCha20-Poly1305 directly for educational use.
For real applications, use a vetted cryptographic library.
"""

from __future__ import annotations

import argparse
import base64
import hmac
import secrets
import struct
import sys

MASK32 = 0xFFFFFFFF
P1305 = (1 << 130) - 5
R_MASK = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)

RFC_KEY = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f"
)
RFC_NONCE = bytes.fromhex("070000004041424344454647")
RFC_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
RFC_PLAINTEXT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
    b"for the future, sunscreen would be it."
)
RFC_CIPHERTEXT = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "6116"
)
RFC_TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")


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


def validate_key_nonce(key: bytes, nonce: bytes) -> None:
    if len(key) != 32:
        raise ValueError(f"key must be exactly 32 bytes; got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"nonce must be exactly 12 bytes; got {len(nonce)}")


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    validate_key_nonce(key, nonce)
    if not 0 <= counter <= MASK32:
        raise ValueError("counter must be in 0..2^32-1")
    state = [*CONSTANTS, *struct.unpack("<8I", key), counter, *struct.unpack("<3I", nonce)]
    x = state.copy()
    for _ in range(10):
        inner_block(x)
    x = [(x[i] + state[i]) & MASK32 for i in range(16)]
    return struct.pack("<16I", *x)


def chacha20_xor(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    validate_key_nonce(key, nonce)
    blocks = (len(data) + 63) // 64
    if blocks and counter + blocks - 1 > MASK32:
        raise ValueError("message too long: ChaCha20 counter would wrap")
    out = bytearray()
    for j in range(blocks):
        z = chacha20_block(key, counter + j, nonce)
        chunk = data[64*j : 64*(j+1)]
        out.extend(a ^ b for a, b in zip(chunk, z))
    return bytes(out)


def pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return b"" if rem == 0 else b"\x00" * (16 - rem)


def poly1305_mac(message: bytes, one_time_key: bytes) -> bytes:
    if len(one_time_key) != 32:
        raise ValueError("Poly1305 one-time key must be exactly 32 bytes")
    r = int.from_bytes(one_time_key[:16], "little") & R_MASK
    s = int.from_bytes(one_time_key[16:], "little")
    h = 0
    for off in range(0, len(message), 16):
        block = message[off : off + 16]
        n = int.from_bytes(block + b"\x01", "little")
        h = ((h + n) * r) % P1305
    return ((h + s) % (1 << 128)).to_bytes(16, "little")


def poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    return chacha20_block(key, 0, nonce)[:32]


def mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return (
        aad + pad16(aad)
        + ciphertext + pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    validate_key_nonce(key, nonce)
    otk = poly1305_key_gen(key, nonce)
    ciphertext = chacha20_xor(key, nonce, 1, plaintext)
    tag = poly1305_mac(mac_data(aad, ciphertext), otk)
    return ciphertext, tag


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    validate_key_nonce(key, nonce)
    if len(tag) != 16:
        raise ValueError("tag must be exactly 16 bytes")
    otk = poly1305_key_gen(key, nonce)
    expected = poly1305_mac(mac_data(aad, ciphertext), otk)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("authentication failed")
    return chacha20_xor(key, nonce, 1, ciphertext)


def clean_hex(text: str) -> bytes:
    t = "".join(text.split()).replace(":", "").replace("-", "")
    if t.lower().startswith("0x"):
        t = t[2:]
    if len(t) % 2:
        raise ValueError("hex input must contain an even number of digits")
    return bytes.fromhex(t)


def decode_value(text: str, fmt: str) -> bytes:
    if fmt == "text":
        return text.encode("utf-8")
    if fmt == "hex":
        return clean_hex(text)
    if fmt == "base64":
        return base64.b64decode(text, validate=True)
    raise ValueError("unsupported format")


def encode_value(data: bytes, fmt: str) -> str:
    if fmt == "hex":
        return data.hex()
    if fmt == "base64":
        return base64.b64encode(data).decode("ascii")
    if fmt == "text":
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return "<not valid UTF-8>"
    raise ValueError("unsupported format")


def selftest(verbose: bool = True) -> bool:
    ct, tag = aead_encrypt(RFC_KEY, RFC_NONCE, RFC_PLAINTEXT, RFC_AAD)
    ok_ct = ct == RFC_CIPHERTEXT
    ok_tag = tag == RFC_TAG
    ok_dec = aead_decrypt(RFC_KEY, RFC_NONCE, RFC_CIPHERTEXT, RFC_TAG, RFC_AAD) == RFC_PLAINTEXT

    bad = bytearray(RFC_CIPHERTEXT)
    bad[-1] ^= 1
    rejected = False
    try:
        aead_decrypt(RFC_KEY, RFC_NONCE, bytes(bad), RFC_TAG, RFC_AAD)
    except ValueError:
        rejected = True

    tests = [
        ("RFC 8439 ciphertext", ok_ct),
        ("RFC 8439 tag", ok_tag),
        ("RFC 8439 decryption", ok_dec),
        ("Tampering rejected", rejected),
    ]
    if verbose:
        print("ChaCha20-Poly1305 self-test")
        print("=" * 42)
        for name, ok in tests:
            print(f"{name:28s}: {'PASS' if ok else 'FAIL'}")
    return all(ok for _, ok in tests)


def cli_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="ChaCha20-Poly1305 CLI/PyQt6 classroom demo")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("selftest", help="run RFC 8439 tests")
    sub.add_parser("gui", help="launch PyQt6 GUI")

    for name in ("encrypt", "decrypt"):
        s = sub.add_parser(name)
        s.add_argument("--key", required=True, help="32-byte key hex")
        s.add_argument("--nonce", required=True, help="12-byte nonce hex")
        s.add_argument("--aad", default="")
        s.add_argument("--aad-format", choices=["text", "hex", "base64"], default="text")
        s.add_argument("--input", required=True)
        s.add_argument("--input-format", choices=["text", "hex", "base64"],
                       default="text" if name == "encrypt" else "hex")
        s.add_argument("--output-format", choices=["text", "hex", "base64"],
                       default="hex" if name == "encrypt" else "text")
        if name == "decrypt":
            s.add_argument("--tag", required=True, help="16-byte tag hex")

    return p


def run_cli(args: argparse.Namespace) -> int:
    if args.command == "selftest":
        return 0 if selftest() else 1
    if args.command == "gui":
        return run_gui()

    key = clean_hex(args.key)
    nonce = clean_hex(args.nonce)
    aad = decode_value(args.aad, args.aad_format)
    data = decode_value(args.input, args.input_format)

    try:
        if args.command == "encrypt":
            ct, tag = aead_encrypt(key, nonce, data, aad)
            print("Ciphertext:", encode_value(ct, args.output_format))
            print("Tag (hex) :", tag.hex())
            print("Combined  :", (ct + tag).hex())
        else:
            tag = clean_hex(args.tag)
            pt = aead_decrypt(key, nonce, data, tag, aad)
            print("Authentication: PASS")
            print("Plaintext:", encode_value(pt, args.output_format))
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def run_gui() -> int:
    try:
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QFont
        from PyQt6.QtWidgets import (
            QApplication, QComboBox, QFormLayout, QGridLayout, QGroupBox,
            QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox,
            QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
        )
    except ImportError:
        print("PyQt6 is not installed. Install it with: pip install PyQt6", file=sys.stderr)
        return 3

    class MainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("Week 3 — ChaCha20-Poly1305 AEAD Demo")
            self.resize(1000, 780)

            central = QWidget()
            self.setCentralWidget(central)
            layout = QVBoxLayout(central)

            title = QLabel("ChaCha20-Poly1305 — Encryption + Authentication")
            f = QFont()
            f.setPointSize(16)
            f.setBold(True)
            title.setFont(f)
            title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(title)

            note = QLabel(
                "RFC 8439 IETF construction: counter 0 derives the Poly1305 key; "
                "payload encryption starts at counter 1. Never reuse a nonce with the same key."
            )
            note.setWordWrap(True)
            layout.addWidget(note)

            params = QGroupBox("Parameters")
            form = QFormLayout(params)
            self.key_edit = QLineEdit()
            self.nonce_edit = QLineEdit()
            form.addRow("256-bit key (hex):", self.key_edit)
            form.addRow("96-bit nonce (hex):", self.nonce_edit)

            buttons = QHBoxLayout()
            b_key = QPushButton("Random Key")
            b_nonce = QPushButton("Random Nonce")
            b_rfc = QPushButton("Load RFC 8439 Vector")
            b_test = QPushButton("Self-test")
            buttons.addWidget(b_key)
            buttons.addWidget(b_nonce)
            buttons.addWidget(b_rfc)
            buttons.addWidget(b_test)
            form.addRow(buttons)
            layout.addWidget(params)

            aad_box = QGroupBox("Additional Authenticated Data (AAD)")
            aad_l = QGridLayout(aad_box)
            self.aad_format = QComboBox(); self.aad_format.addItems(["text", "hex", "base64"])
            self.aad_edit = QPlainTextEdit()
            self.aad_edit.setMaximumHeight(90)
            aad_l.addWidget(QLabel("Format:"), 0, 0)
            aad_l.addWidget(self.aad_format, 0, 1)
            aad_l.addWidget(self.aad_edit, 1, 0, 1, 2)
            layout.addWidget(aad_box)

            io_box = QGroupBox("Input / Output")
            grid = QGridLayout(io_box)
            self.operation = QComboBox(); self.operation.addItems(["Encrypt", "Decrypt"])
            self.input_format = QComboBox(); self.input_format.addItems(["text", "hex", "base64"])
            self.output_format = QComboBox(); self.output_format.addItems(["hex", "base64", "text"])
            self.tag_edit = QLineEdit()
            self.input_edit = QPlainTextEdit()
            self.output_edit = QPlainTextEdit(); self.output_edit.setReadOnly(True)

            grid.addWidget(QLabel("Operation:"), 0, 0); grid.addWidget(self.operation, 0, 1)
            grid.addWidget(QLabel("Input format:"), 0, 2); grid.addWidget(self.input_format, 0, 3)
            grid.addWidget(QLabel("Output format:"), 0, 4); grid.addWidget(self.output_format, 0, 5)
            grid.addWidget(QLabel("Tag (hex, required for decrypt):"), 1, 0)
            grid.addWidget(self.tag_edit, 1, 1, 1, 5)
            grid.addWidget(QLabel("Input:"), 2, 0, 1, 6)
            grid.addWidget(self.input_edit, 3, 0, 1, 6)
            grid.addWidget(QLabel("Output:"), 4, 0, 1, 6)
            grid.addWidget(self.output_edit, 5, 0, 1, 6)
            layout.addWidget(io_box)

            action_row = QHBoxLayout()
            self.run_button = QPushButton("Encrypt")
            self.clear_button = QPushButton("Clear")
            action_row.addWidget(self.run_button)
            action_row.addWidget(self.clear_button)
            layout.addLayout(action_row)

            self.status = QLabel("Ready")
            layout.addWidget(self.status)

            b_key.clicked.connect(lambda: self.key_edit.setText(secrets.token_bytes(32).hex()))
            b_nonce.clicked.connect(lambda: self.nonce_edit.setText(secrets.token_bytes(12).hex()))
            b_rfc.clicked.connect(self.load_rfc)
            b_test.clicked.connect(self.do_selftest)
            self.run_button.clicked.connect(self.process)
            self.clear_button.clicked.connect(self.clear_io)
            self.operation.currentTextChanged.connect(self.mode_changed)
            self.mode_changed(self.operation.currentText())

        def mode_changed(self, mode: str) -> None:
            decrypt = mode == "Decrypt"
            self.tag_edit.setEnabled(decrypt)
            self.run_button.setText(mode)
            if decrypt:
                self.input_format.setCurrentText("hex")
                self.output_format.setCurrentText("text")
            else:
                self.input_format.setCurrentText("text")
                self.output_format.setCurrentText("hex")

        def load_rfc(self) -> None:
            self.key_edit.setText(RFC_KEY.hex())
            self.nonce_edit.setText(RFC_NONCE.hex())
            self.aad_format.setCurrentText("hex")
            self.aad_edit.setPlainText(RFC_AAD.hex())
            self.operation.setCurrentText("Encrypt")
            self.input_format.setCurrentText("text")
            self.input_edit.setPlainText(RFC_PLAINTEXT.decode("ascii"))
            self.output_format.setCurrentText("hex")
            self.status.setText("Loaded RFC 8439 AEAD test vector")

        def do_selftest(self) -> None:
            ok = selftest(False)
            QMessageBox.information(self, "Self-test", "PASS" if ok else "FAIL")
            self.status.setText("Self-test: PASS" if ok else "Self-test: FAIL")

        def clear_io(self) -> None:
            self.input_edit.clear(); self.output_edit.clear(); self.tag_edit.clear()
            self.status.setText("Ready")

        def process(self) -> None:
            try:
                key = clean_hex(self.key_edit.text())
                nonce = clean_hex(self.nonce_edit.text())
                aad = decode_value(self.aad_edit.toPlainText(), self.aad_format.currentText())
                data = decode_value(self.input_edit.toPlainText(), self.input_format.currentText())

                if self.operation.currentText() == "Encrypt":
                    ct, tag = aead_encrypt(key, nonce, data, aad)
                    rendered = encode_value(ct, self.output_format.currentText())
                    self.output_edit.setPlainText(
                        rendered + "\n\nTag (hex): " + tag.hex() + "\nCombined (hex): " + (ct + tag).hex()
                    )
                    self.tag_edit.setText(tag.hex())
                    self.status.setText("Encryption complete; tag generated")
                else:
                    tag = clean_hex(self.tag_edit.text())
                    pt = aead_decrypt(key, nonce, data, tag, aad)
                    self.output_edit.setPlainText(encode_value(pt, self.output_format.currentText()))
                    self.status.setText("Authentication PASS; plaintext released")
            except Exception as exc:
                self.output_edit.clear()
                self.status.setText("ERROR")
                QMessageBox.critical(self, "ChaCha20-Poly1305", str(exc))

    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    return app.exec()


def main() -> int:
    return run_cli(cli_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
