#!/usr/bin/env python3
"""
Mã hóa lai (Hybrid Encryption): AES-256-CBC + RSA-OAEP cho file lớn.

Cấu trúc file đầu ra (.enc):
    [2 bytes]  độ dài Encrypted AES Key (big-endian)
    [N bytes]  Encrypted AES Key (RSA-OAEP)
    [16 bytes] IV
    [2 bytes]  độ dài tên file gốc (big-endian)
    [M bytes]  tên file gốc (UTF-8)
    [...]      dữ liệu file đã mã hóa AES-256-CBC (PKCS7 padding)

Yêu cầu:  pip install pycryptodome   (GUI: pip install PyQt6)
RSA-OAEP dùng SHA-256 + MGF1-SHA-256.
Cách dùng:
    python hybrid_encrypt.py --gui   # giao diện kéo-thả file (cần: pip install PyQt6)
    python hybrid_encrypt.py genkey  [--out-dir keys]
    python hybrid_encrypt.py encrypt <file> <public.pem> [-o out.enc]
    python hybrid_encrypt.py decrypt <file.enc> <private.pem> [-d out_dir]
    python hybrid_encrypt.py demo    # tự tạo khóa + file mẫu 5MB, mã hóa, giải mã, kiểm tra
"""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Callable

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

CHUNK_SIZE: int = 64 * 1024        # 64 KB, là bội số của 16 (AES block size)
AES_KEY_SIZE: int = 32             # AES-256
IV_SIZE: int = 16
MAX_U16: int = 0xFFFF

ProgressCb = Callable[[int, int], None]  # (bytes_đã_xử_lý, tổng_bytes)


# --------------------------------------------------------------------------
# Quản lý khóa RSA
# --------------------------------------------------------------------------
def generate_rsa_keypair(
    out_dir: str | Path, bits: int = 2048
) -> tuple[Path, Path]:
    """Sinh cặp khóa RSA và lưu ra file PEM. Trả về (private_path, public_path)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    key = RSA.generate(bits)
    private_path = out / "private.pem"
    public_path = out / "public.pem"

    private_path.write_bytes(key.export_key("PEM"))
    public_path.write_bytes(key.publickey().export_key("PEM"))
    try:
        os.chmod(private_path, 0o600)  # chỉ chủ sở hữu được đọc/ghi
    except OSError:
        pass
    return private_path, public_path


def load_rsa_key(pem_path: str | Path) -> RSA.RsaKey:
    """Đọc khóa RSA (public hoặc private) từ file PEM."""
    return RSA.import_key(Path(pem_path).read_bytes())


def key_fingerprint(pem_path: str | Path) -> str:
    """SHA-256 của public key (DER) — dùng để đối chiếu khóa."""
    der = load_rsa_key(pem_path).publickey().export_key("DER")
    return hashlib.sha256(der).hexdigest()


# --------------------------------------------------------------------------
# Ghi thông tin AES ra file text
# --------------------------------------------------------------------------
def write_aes_info(
    info_path: Path, *, input_path: Path, output_path: Path, aes_key: bytes,
    iv: bytes, encrypted_key: bytes, in_sha256: str, ct_sha256: str, ct_len: int,
) -> None:
    """Ghi input / output / key / IV của phiên mã hóa AES-CBC ra file text."""
    lines = [
        "=== AES-256-CBC ENCRYPTION INFO ===",
        f"Time              : {datetime.now().isoformat(timespec='seconds')}",
        f"Algorithm         : AES-256-CBC, PKCS7 padding, chunk {CHUNK_SIZE} bytes",
        "",
        "[INPUT]",
        f"File              : {input_path.resolve()}",
        f"Size              : {input_path.stat().st_size} bytes",
        f"SHA-256           : {in_sha256}",
        "",
        "[OUTPUT]",
        f"File              : {output_path.resolve()}",
        f"Total size        : {output_path.stat().st_size} bytes (header + ciphertext)",
        f"Ciphertext size   : {ct_len} bytes",
        f"Ciphertext SHA-256: {ct_sha256}",
        "",
        "[KEY / IV]",
        f"AES key (32 bytes): {aes_key.hex()}",
        f"IV (16 bytes)     : {iv.hex()}",
        f"RSA-OAEP encrypted AES key ({len(encrypted_key)} bytes, stored in header):",
        f"  {encrypted_key.hex()}",
        "",
        "WARNING: this file contains the AES session key in plain text.",
        "Anyone who has it can decrypt the .enc file without the RSA private key.",
        "Keep it private or delete it after the lab.",
        "",
    ]
    info_path.write_text("\n".join(lines), encoding="utf-8")


# --------------------------------------------------------------------------
# Mã hóa
# --------------------------------------------------------------------------
def encrypt_file(
    input_path: str | Path,
    public_key_path: str | Path,
    output_path: str | Path | None = None,
    progress: ProgressCb | None = None,
    save_info: bool = False,
) -> Path:
    """
    Mã hóa file bằng AES-256-CBC (streaming theo chunk 64KB),
    khóa AES được mã hóa bằng RSA-OAEP. Trả về đường dẫn file .enc.

    save_info=True: ghi thêm file text "<output>.txt" chứa input, output,
    AES key, IV (hex). CẢNH BÁO: file này chứa session key dạng rõ.
    """
    input_path = Path(input_path)
    output_path = Path(output_path) if output_path else input_path.with_name(
        input_path.name + ".enc"
    )

    # 1. Khóa RSA public & cipher RSA-OAEP
    rsa_key = load_rsa_key(public_key_path)
    rsa_cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)  # MGF1 mặc định dùng cùng SHA-256

    # 2. Sinh Session Key (AES-256) và IV ngẫu nhiên
    aes_key: bytes = get_random_bytes(AES_KEY_SIZE)
    iv: bytes = get_random_bytes(IV_SIZE)

    # 3. Mã hóa AES key bằng RSA
    encrypted_key: bytes = rsa_cipher.encrypt(aes_key)
    if len(encrypted_key) > MAX_U16:
        raise ValueError("Encrypted AES key quá dài cho trường 2 bytes.")

    # 4. Tên file gốc
    name_bytes: bytes = input_path.name.encode("utf-8")
    if len(name_bytes) > MAX_U16:
        raise ValueError("Tên file quá dài (> 65535 bytes).")

    aes = AES.new(aes_key, AES.MODE_CBC, iv)

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        # ---- Header ----
        fout.write(struct.pack(">H", len(encrypted_key)))
        fout.write(encrypted_key)
        fout.write(iv)
        fout.write(struct.pack(">H", len(name_bytes)))
        fout.write(name_bytes)

        # ---- Body: đọc từng chunk ----
        # Luôn giữ lại một chunk "đang chờ" để biết chunk nào là cuối cùng.
        total = max(input_path.stat().st_size, 1)
        done = 0
        h_in, h_ct, ct_len = hashlib.sha256(), hashlib.sha256(), 0
        pending: bytes = fin.read(CHUNK_SIZE)
        while True:
            nxt: bytes = fin.read(CHUNK_SIZE)
            if nxt:
                # pending chắc chắn không phải chunk cuối, và dài đúng 64KB
                ct = aes.encrypt(pending)
                fout.write(ct)
                h_in.update(pending)
                h_ct.update(ct)
                ct_len += len(ct)
                done += len(pending)
                if progress:
                    progress(done, total)
                pending = nxt
            else:
                # pending là chunk cuối (có thể rỗng nếu file rỗng) -> PKCS7
                ct = aes.encrypt(pad(pending, AES.block_size))
                fout.write(ct)
                h_in.update(pending)
                h_ct.update(ct)
                ct_len += len(ct)
                if progress:
                    progress(total, total)
                break

    if save_info:
        write_aes_info(
            output_path.with_name(output_path.name + ".txt"),
            input_path=input_path, output_path=output_path,
            aes_key=aes_key, iv=iv, encrypted_key=encrypted_key,
            in_sha256=h_in.hexdigest(), ct_sha256=h_ct.hexdigest(), ct_len=ct_len,
        )
    return output_path


# --------------------------------------------------------------------------
# Giải mã
# --------------------------------------------------------------------------
def _read_exact(f, n: int) -> bytes:
    data = f.read(n)
    if len(data) != n:
        raise ValueError("File mã hóa bị cắt cụt hoặc sai định dạng.")
    return data


def decrypt_file(
    encrypted_path: str | Path,
    private_key_path: str | Path,
    output_dir: str | Path | None = None,
    progress: ProgressCb | None = None,
) -> Path:
    """
    Giải mã file .enc, khôi phục file gốc với tên gốc trong header.
    Trả về đường dẫn file đã giải mã.
    """
    encrypted_path = Path(encrypted_path)
    out_dir = Path(output_dir) if output_dir else encrypted_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    rsa_key = load_rsa_key(private_key_path)
    if not rsa_key.has_private():
        raise ValueError("Cần Private Key để giải mã.")
    rsa_cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    enc_size = max(encrypted_path.stat().st_size, 1)

    with open(encrypted_path, "rb") as fin:
        # ---- Đọc header ----
        (key_len,) = struct.unpack(">H", _read_exact(fin, 2))
        encrypted_key = _read_exact(fin, key_len)
        iv = _read_exact(fin, IV_SIZE)
        (name_len,) = struct.unpack(">H", _read_exact(fin, 2))
        original_name = _read_exact(fin, name_len).decode("utf-8")

        # Chống path traversal: chỉ lấy phần tên file, bỏ mọi đường dẫn
        safe_name = os.path.basename(original_name.replace("\\", "/")) or "decrypted.bin"
        output_path = out_dir / safe_name

        aes_key = rsa_cipher.decrypt(encrypted_key)  # ValueError nếu sai khóa
        if len(aes_key) != AES_KEY_SIZE:
            raise ValueError("AES key sau khi giải mã có độ dài không hợp lệ.")

        aes = AES.new(aes_key, AES.MODE_CBC, iv)

        # ---- Body ----
        # Ghi ra file tạm, chỉ đổi tên khi unpadding hợp lệ (tránh để lại file rác)
        tmp_path = output_path.with_name(output_path.name + ".part")
        try:
            with open(tmp_path, "wb") as fout:
                pending: bytes = fin.read(CHUNK_SIZE)
                if not pending or len(pending) % AES.block_size != 0:
                    raise ValueError("Dữ liệu mã hóa rỗng hoặc không đúng bội số 16 bytes.")
                while True:
                    nxt = fin.read(CHUNK_SIZE)
                    if nxt:
                        fout.write(aes.decrypt(pending))
                        if progress:
                            progress(fin.tell(), enc_size)
                        pending = nxt
                    else:
                        if len(pending) % AES.block_size != 0:
                            raise ValueError("Khối cuối không đúng độ dài.")
                        fout.write(unpad(aes.decrypt(pending), AES.block_size))
                        if progress:
                            progress(enc_size, enc_size)
                        break
            os.replace(tmp_path, output_path)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise

    return output_path


# --------------------------------------------------------------------------
# Tiện ích kiểm tra
# --------------------------------------------------------------------------
def sha256_of_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def demo() -> None:
    """Tạo khóa RSA, file mẫu 5MB, mã hóa -> giải mã -> so sánh SHA-256."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)

        print("[1] Sinh cặp khóa RSA-2048...")
        priv, pub = generate_rsa_keypair(tmp_dir / "keys")

        sample = tmp_dir / "sample_video.bin"
        sample.write_bytes(os.urandom(5 * 1024 * 1024 + 123))  # không chia hết cho 16
        print(f"[2] File mẫu: {sample.name} ({sample.stat().st_size:,} bytes)")

        enc = encrypt_file(sample, pub, save_info=True)
        print(f"[3] Đã mã hóa  -> {enc.name} ({enc.stat().st_size:,} bytes)")
        print(f"    Thông tin AES -> {enc.name}.txt")

        out_dir = tmp_dir / "decrypted"
        dec = decrypt_file(enc, priv, out_dir)
        print(f"[4] Đã giải mã -> {dec.name} ({dec.stat().st_size:,} bytes)")

        h1, h2 = sha256_of_file(sample), sha256_of_file(dec)
        print(f"    SHA-256 gốc     : {h1}")
        print(f"    SHA-256 giải mã : {h2}")
        print("KẾT QUẢ:", "ĐÚNG - file khôi phục giống hệt bản gốc" if h1 == h2 else "SAI!")
        if h1 != h2:
            sys.exit(1)

        # Trường hợp biên: file rỗng và file đúng bội số 64KB
        for label, size in (("file rỗng", 0), ("file đúng 64KB", CHUNK_SIZE),
                            ("file 128KB", 2 * CHUNK_SIZE)):
            f = tmp_dir / f"edge_{size}.bin"
            f.write_bytes(os.urandom(size))
            e = encrypt_file(f, pub)
            d = decrypt_file(e, priv, tmp_dir / f"out_{size}")
            ok = sha256_of_file(f) == sha256_of_file(d)
            print(f"[edge] {label}: {'OK' if ok else 'LỖI'}")
            if not ok:
                sys.exit(1)


# --------------------------------------------------------------------------
# Giao diện đồ họa (PyQt6): kéo-thả file để mã hóa / giải mã
# --------------------------------------------------------------------------
def run_gui() -> None:
    """Mở GUI. Thả file bất kỳ -> mã hóa; thả file .enc -> giải mã."""
    try:
        from PyQt6.QtCore import Qt, QThread, QUrl, pyqtSignal
        from PyQt6.QtGui import QDesktopServices
        from PyQt6.QtWidgets import (
            QApplication, QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
            QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QTabWidget,
            QVBoxLayout, QWidget,
        )
    except ImportError:
        sys.exit("Chưa cài PyQt6. Hãy chạy:  pip install PyQt6")

    class Worker(QThread):
        """Chạy tác vụ nặng ở thread riêng để giao diện không bị đơ."""
        progress = pyqtSignal(int)
        succeeded = pyqtSignal(object)
        failed = pyqtSignal(str)

        def __init__(self, job: Callable[[ProgressCb], object]) -> None:
            super().__init__()
            self._job = job

        def run(self) -> None:
            last = -1

            def cb(done: int, total: int) -> None:
                nonlocal last
                pct = int(done * 100 / total) if total else 100
                if pct != last:
                    last = pct
                    self.progress.emit(pct)

            try:
                self.succeeded.emit(self._job(cb))
            except Exception as exc:  # hiển thị lỗi lên GUI
                self.failed.emit(f"{type(exc).__name__}: {exc}")

    class DropZone(QLabel):
        fileDropped = pyqtSignal(str)
        clicked = pyqtSignal()
        IDLE = ("QLabel { border: 2px dashed #8a8a8a; border-radius: 10px; "
                "background: #fafafa; color: #555; font-size: 17px; }")
        HOVER = ("QLabel { border: 2px dashed #2d7ff9; border-radius: 10px; "
                 "background: #eaf2ff; color: #1b5fd1; font-size: 17px; }")

        def __init__(self, text: str) -> None:
            super().__init__(text)
            self.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.setAcceptDrops(True)
            self.setMinimumHeight(150)
            self.setStyleSheet(self.IDLE)
            self.setCursor(Qt.CursorShape.PointingHandCursor)

        def dragEnterEvent(self, e) -> None:
            if e.mimeData().hasUrls():
                e.acceptProposedAction()
                self.setStyleSheet(self.HOVER)

        def dragLeaveEvent(self, e) -> None:
            self.setStyleSheet(self.IDLE)

        def dropEvent(self, e) -> None:
            self.setStyleSheet(self.IDLE)
            urls = e.mimeData().urls()
            if urls:
                self.fileDropped.emit(urls[0].toLocalFile())

        def mousePressEvent(self, e) -> None:
            self.clicked.emit()

    def heading(text: str) -> QLabel:
        lb = QLabel(text)
        lb.setStyleSheet("font-weight: bold; font-size: 16px;")
        return lb

    def log_box(placeholder: str, height: int = 150) -> QPlainTextEdit:
        box = QPlainTextEdit()
        box.setReadOnly(True)
        box.setPlaceholderText(placeholder)
        box.setMinimumHeight(height)
        return box

    def row(label: str, edit: QLineEdit, *buttons: QPushButton) -> QHBoxLayout:
        lay = QHBoxLayout()
        if label:
            lay.addWidget(QLabel(label))
        lay.addWidget(edit, 1)
        for b in buttons:
            lay.addWidget(b)
        return lay

    class MainWindow(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("Hybrid Encryption Lab — AES-256-CBC + RSA-OAEP")
            self.resize(900, 780)
            self.setAcceptDrops(True)
            self.setStyleSheet("QWidget { font-size: 14px; } QPushButton { padding: 6px 10px; }")

            self.default_keys_dir = Path(__file__).resolve().parent / "keys"
            self.cur_pub = ""
            self.cur_priv = ""
            self.enc_out_dir: Path | None = None
            self.dec_out_dir: Path | None = None
            self.worker: Worker | None = None

            title = QLabel("Hybrid Encryption Lab — AES-256 + RSA")
            title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            title.setStyleSheet("font-size: 22px; font-weight: bold;")
            subtitle = QLabel("Large-file encryption: AES-256-CBC (64 KB chunks) + "
                              "RSA-OAEP session key (SHA-256, MGF1-SHA-256)")
            subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
            subtitle.setStyleSheet("font-size: 15px;")

            self.tabs = QTabWidget()
            self.tabs.addTab(self._build_keys_tab(), "1. Keys")
            self.tabs.addTab(self._build_encrypt_tab(), "2. Encryption")
            self.tabs.addTab(self._build_decrypt_tab(), "3. Decryption")
            self.tabs.setCurrentIndex(1)

            self.status = QLabel("Drop any file to encrypt it — drop a .enc file to decrypt it.")

            lay = QVBoxLayout(self)
            lay.addWidget(title)
            lay.addWidget(subtitle)
            lay.addWidget(self.tabs, 1)
            lay.addWidget(self.status)

            self._load_existing_keys()

        # ---------------- Tab 1: Keys ----------------
        def _build_keys_tab(self) -> QWidget:
            w = QWidget()
            lay = QVBoxLayout(w)
            step = QLabel("<b>Step 1.</b> Create an RSA key pair (or skip: one is created "
                          "automatically on first encryption). The <b>public key</b> encrypts, "
                          "the <b>private key</b> decrypts — keep it secret and back it up.")
            step.setWordWrap(True)
            lay.addWidget(step)

            self.keys_dir_edit = QLineEdit(str(self.default_keys_dir))
            b_dir = QPushButton("Choose Folder…")
            b_dir.clicked.connect(self._choose_keys_dir)
            lay.addWidget(heading("Key folder"))
            lay.addLayout(row("", self.keys_dir_edit, b_dir))

            self.size_combo = QComboBox()
            self.size_combo.addItems(["2048", "3072", "4096"])
            size_row = QHBoxLayout()
            size_row.addWidget(QLabel("RSA key size (bits):"))
            size_row.addWidget(self.size_combo)
            size_row.addStretch(1)
            lay.addLayout(size_row)

            self.gen_btn = QPushButton("Generate RSA Key Pair")
            self.gen_btn.clicked.connect(self._generate_keys)
            lay.addWidget(self.gen_btn)
            self.keys_bar = QProgressBar()
            lay.addWidget(self.keys_bar)

            lay.addWidget(heading("Key info"))
            self.keys_log = log_box("Public key fingerprint and file paths appear here.", 200)
            lay.addWidget(self.keys_log, 1)
            return w

        # ---------------- Tab 2: Encryption ----------------
        def _build_encrypt_tab(self) -> QWidget:
            w = QWidget()
            lay = QVBoxLayout(w)
            step = QLabel("<b>Step 2.</b> Drop a file (PDF, PNG, video, ZIP…) below. It is "
                          "encrypted with a fresh <b>AES-256</b> key, which is then wrapped by "
                          "your <b>RSA public key</b>. Output: <i>filename.ext.enc</i>.")
            step.setWordWrap(True)
            lay.addWidget(step)

            self.pub_edit = QLineEdit()
            self.pub_edit.setPlaceholderText("Leave empty to use / auto-create keys/public.pem")
            b_cur = QPushButton("Use Current Public Key")
            b_cur.clicked.connect(lambda: self.pub_edit.setText(self.cur_pub))
            b_pick = QPushButton("Choose Public Key…")
            b_pick.clicked.connect(lambda: self._pick_into(self.pub_edit, "Choose public key"))
            lay.addLayout(row("Public key:", self.pub_edit, b_cur, b_pick))

            self.save_info_chk = QCheckBox(
                "Save AES details (input, output, key, IV) to a .txt file next to the output")
            self.save_info_chk.setChecked(True)
            lay.addWidget(self.save_info_chk)

            self.enc_zone = DropZone("⬇  Drop a file here to encrypt\n(or click to choose a file)")
            self.enc_zone.fileDropped.connect(self._route)
            self.enc_zone.clicked.connect(lambda: self._pick_and_route("Choose file to encrypt"))
            lay.addWidget(self.enc_zone)

            self.enc_bar = QProgressBar()
            lay.addWidget(self.enc_bar)
            lay.addWidget(heading("Log / output"))
            self.enc_log = log_box("Encryption results appear here.")
            lay.addWidget(self.enc_log, 1)
            self.enc_open = QPushButton("Open Output Folder")
            self.enc_open.setEnabled(False)
            self.enc_open.clicked.connect(lambda: self._open_dir(self.enc_out_dir))
            lay.addWidget(self.enc_open)
            return w

        # ---------------- Tab 3: Decryption ----------------
        def _build_decrypt_tab(self) -> QWidget:
            w = QWidget()
            lay = QVBoxLayout(w)
            step = QLabel("<b>Step 3.</b> Drop a <b>.enc</b> file below. The AES key is "
                          "unwrapped with your <b>RSA private key</b> and the original file is "
                          "restored (original name) into a <i>decrypted</i> sub-folder.")
            step.setWordWrap(True)
            lay.addWidget(step)

            self.priv_edit = QLineEdit()
            self.priv_edit.setPlaceholderText("Leave empty to use keys/private.pem")
            b_cur = QPushButton("Use Current Private Key")
            b_cur.clicked.connect(lambda: self.priv_edit.setText(self.cur_priv))
            b_pick = QPushButton("Choose Private Key…")
            b_pick.clicked.connect(lambda: self._pick_into(self.priv_edit, "Choose private key"))
            lay.addLayout(row("Private key:", self.priv_edit, b_cur, b_pick))

            self.dec_zone = DropZone("⬇  Drop a .enc file here to decrypt\n(or click to choose a file)")
            self.dec_zone.fileDropped.connect(self._route)
            self.dec_zone.clicked.connect(lambda: self._pick_and_route("Choose .enc file"))
            lay.addWidget(self.dec_zone)

            self.dec_bar = QProgressBar()
            lay.addWidget(self.dec_bar)
            lay.addWidget(heading("Log / output"))
            self.dec_log = log_box("Decryption results appear here.")
            lay.addWidget(self.dec_log, 1)
            self.dec_open = QPushButton("Open Output Folder")
            self.dec_open.setEnabled(False)
            self.dec_open.clicked.connect(lambda: self._open_dir(self.dec_out_dir))
            lay.addWidget(self.dec_open)
            return w

        # ---------------- Helpers ----------------
        def _keys_dir(self) -> Path:
            return Path(self.keys_dir_edit.text().strip() or str(self.default_keys_dir))

        def _choose_keys_dir(self) -> None:
            d = QFileDialog.getExistingDirectory(self, "Choose key folder", str(self._keys_dir()))
            if d:
                self.keys_dir_edit.setText(d)
                self._load_existing_keys()

        def _pick_into(self, edit: QLineEdit, caption: str) -> None:
            path, _ = QFileDialog.getOpenFileName(self, caption, str(self._keys_dir()),
                                                  "PEM key (*.pem);;All files (*)")
            if path:
                edit.setText(path)

        def _pick_and_route(self, caption: str) -> None:
            path, _ = QFileDialog.getOpenFileName(self, caption)
            if path:
                self._route(path)

        def _open_dir(self, d: Path | None) -> None:
            if d:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(d)))

        def _warn(self, msg: str) -> None:
            QMessageBox.warning(self, "Hybrid Encryption Lab", msg)

        def set_keys(self, pub: str, priv: str) -> None:
            self.cur_pub, self.cur_priv = pub, priv
            self.pub_edit.setText(pub)
            self.priv_edit.setText(priv)
            try:
                self.keys_log.appendPlainText(
                    f"Public key : {pub}\nPrivate key: {priv}\n"
                    f"Fingerprint (SHA-256 of public key):\n  {key_fingerprint(pub)}\n")
            except Exception as exc:
                self.keys_log.appendPlainText(f"✖ Cannot read key: {exc}")

        def _load_existing_keys(self) -> None:
            d = self._keys_dir()
            pub, priv = d / "public.pem", d / "private.pem"
            if pub.is_file() and priv.is_file():
                self.keys_log.appendPlainText("Loaded existing key pair.")
                self.set_keys(str(pub), str(priv))

        def _busy(self) -> bool:
            if self.worker is not None and self.worker.isRunning():
                self.status.setText("Busy — please wait for the current job to finish.")
                return True
            return False

        def _run(self, job: Callable[[ProgressCb], object], bar: QProgressBar,
                 log: QPlainTextEdit, lock: QWidget, on_ok: Callable[[object], None],
                 indeterminate: bool = False) -> None:
            bar.setRange(0, 0 if indeterminate else 100)
            bar.setValue(0)
            lock.setEnabled(False)
            worker = Worker(job)
            self.worker = worker

            def finish(ok: bool) -> None:
                lock.setEnabled(True)
                bar.setRange(0, 100)
                bar.setValue(100 if ok else 0)

            def succeeded(res: object) -> None:
                finish(True)
                on_ok(res)

            def failed(msg: str) -> None:
                finish(False)
                log.appendPlainText(f"✖ {msg}")
                self.status.setText("Failed — see log.")

            if not indeterminate:
                worker.progress.connect(bar.setValue)
            worker.succeeded.connect(succeeded)
            worker.failed.connect(failed)
            worker.start()

        # ---------------- Actions ----------------
        def _generate_keys(self) -> None:
            if self._busy():
                return
            d, bits = self._keys_dir(), int(self.size_combo.currentText())
            if (d / "private.pem").exists() or (d / "public.pem").exists():
                ans = QMessageBox.question(
                    self, "Overwrite keys?",
                    "Key files already exist in this folder.\nOverwriting them means files "
                    "encrypted with the OLD key can no longer be decrypted.\n\nOverwrite?")
                if ans != QMessageBox.StandardButton.Yes:
                    return
            self.keys_log.appendPlainText(f"Generating RSA-{bits} key pair…")

            def job(cb: ProgressCb) -> tuple[str, str]:
                priv, pub = generate_rsa_keypair(d, bits)
                return str(pub), str(priv)

            def ok(res: object) -> None:
                pub, priv = res  # type: ignore[misc]
                self.set_keys(pub, priv)
                self.status.setText("RSA key pair created.")

            self._run(job, self.keys_bar, self.keys_log, self.gen_btn, ok, indeterminate=True)

        def _route(self, path: str) -> None:
            """.enc -> giải mã, còn lại -> mã hóa (tự chuyển tab)."""
            if not path or self._busy():
                return
            if Path(path).suffix.lower() == ".enc":
                self.tabs.setCurrentIndex(2)
                self._start_decrypt(path)
            else:
                self.tabs.setCurrentIndex(1)
                self._start_encrypt(path)

        def _start_encrypt(self, path: str) -> None:
            src = Path(path)
            if not src.is_file():
                self._warn("Please drop a single file (not a folder).")
                return
            pub_text = self.pub_edit.text().strip()
            keys_dir, bits = self._keys_dir(), int(self.size_combo.currentText())
            save_info = self.save_info_chk.isChecked()
            self.enc_log.appendPlainText(f"Encrypting: {src}  ({src.stat().st_size:,} bytes)")
            self.status.setText(f"Encrypting {src.name}…")

            def job(cb: ProgressCb) -> dict:
                generated = None
                pub = pub_text
                if not pub:
                    existing = keys_dir / "public.pem"
                    if existing.is_file():
                        pub = str(existing)
                    else:  # chưa có khóa -> tự tạo
                        priv_p, pub_p = generate_rsa_keypair(keys_dir, bits)
                        pub = str(pub_p)
                        generated = (str(pub_p), str(priv_p))
                elif not Path(pub).is_file():
                    raise FileNotFoundError(f"Public key not found: {pub}")
                out = encrypt_file(src, pub, None, cb, save_info)
                return {"out": out, "pub": pub, "generated": generated}

            def ok(res: object) -> None:
                r: dict = res  # type: ignore[assignment]
                out: Path = r["out"]
                if r["generated"]:
                    self.set_keys(*r["generated"])
                    self.enc_log.appendPlainText(
                        f"ℹ New RSA key pair created in {keys_dir}\n"
                        "  Back up private.pem — without it the file cannot be decrypted.")
                else:
                    self.pub_edit.setText(r["pub"])
                self.enc_out_dir = out.parent
                self.enc_open.setEnabled(True)
                self.enc_log.appendPlainText(
                    f"✔ Encrypted → {out}\n  {out.stat().st_size:,} bytes "
                    "(AES-256-CBC + RSA-OAEP SHA-256)")
                if save_info:
                    self.enc_log.appendPlainText(
                        f"✔ AES info (input, output, key, IV) → {out}.txt\n"
                        "  ⚠ Contains the AES key in plain text — keep it private.")
                self.enc_log.appendPlainText("")
                self.status.setText(f"Encrypted: {out.name}")

            self._run(job, self.enc_bar, self.enc_log, self.enc_zone, ok)

        def _start_decrypt(self, path: str) -> None:
            src = Path(path)
            if not src.is_file():
                self._warn("Please drop a single .enc file (not a folder).")
                return
            priv = self.priv_edit.text().strip() or str(self._keys_dir() / "private.pem")
            if not Path(priv).is_file():
                self.dec_log.appendPlainText(f"✖ Private key not found: {priv}\n"
                                             "  Choose it with “Choose Private Key…”.")
                self.status.setText("Private key missing.")
                return
            out_dir = src.parent / "decrypted"  # tránh ghi đè file gốc nếu nằm cùng thư mục
            self.dec_log.appendPlainText(f"Decrypting: {src}")
            self.status.setText(f"Decrypting {src.name}…")

            def job(cb: ProgressCb) -> Path:
                return decrypt_file(src, priv, out_dir, cb)

            def ok(res: object) -> None:
                out: Path = res  # type: ignore[assignment]
                self.dec_out_dir = out.parent
                self.dec_open.setEnabled(True)
                self.dec_log.appendPlainText(f"✔ Decrypted → {out}\n  {out.stat().st_size:,} bytes\n")
                self.status.setText(f"Decrypted: {out.name}")

            self._run(job, self.dec_bar, self.dec_log, self.dec_zone, ok)

        # ---------------- Drop ở bất kỳ đâu trên cửa sổ ----------------
        def dragEnterEvent(self, e) -> None:
            if e.mimeData().hasUrls():
                e.acceptProposedAction()

        def dropEvent(self, e) -> None:
            urls = e.mimeData().urls()
            if urls:
                self._route(urls[0].toLocalFile())

        def closeEvent(self, e) -> None:
            if self.worker is not None and self.worker.isRunning():
                self.worker.wait()
            super().closeEvent(e)

    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid encryption AES-256-CBC + RSA-OAEP")
    parser.add_argument("--gui", action="store_true", help="Mở giao diện kéo-thả")
    sub = parser.add_subparsers(dest="cmd")

    p_gen = sub.add_parser("genkey", help="Sinh cặp khóa RSA")
    p_gen.add_argument("--out-dir", default="keys")
    p_gen.add_argument("--bits", type=int, default=2048)

    p_enc = sub.add_parser("encrypt", help="Mã hóa file")
    p_enc.add_argument("input")
    p_enc.add_argument("public_key")
    p_enc.add_argument("-o", "--output")
    p_enc.add_argument("--save-info", action="store_true",
                       help="Ghi input/output/AES key/IV ra file <output>.txt")

    p_dec = sub.add_parser("decrypt", help="Giải mã file")
    p_dec.add_argument("input")
    p_dec.add_argument("private_key")
    p_dec.add_argument("-d", "--out-dir")

    sub.add_parser("demo", help="Chạy ví dụ end-to-end")

    args = parser.parse_args()

    if args.gui:
        run_gui()
    elif args.cmd is None:
        parser.print_help()
    elif args.cmd == "genkey":
        priv, pub = generate_rsa_keypair(args.out_dir, args.bits)
        print(f"Private key: {priv}\nPublic key : {pub}")
    elif args.cmd == "encrypt":
        print("Đã mã hóa:", encrypt_file(args.input, args.public_key, args.output,
                                               save_info=args.save_info))
    elif args.cmd == "decrypt":
        print("Đã giải mã:", decrypt_file(args.input, args.private_key, args.out_dir))
    elif args.cmd == "demo":
        demo()


if __name__ == "__main__":
    main()