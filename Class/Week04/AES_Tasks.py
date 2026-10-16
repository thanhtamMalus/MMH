# -*- coding: utf-8 -*-
"""
AES_tasks_compare.py

python AES_tasks_compare.py  # hien menu, hoi duong dan anh
python AES_tasks_compare.py --task 1
python AES_tasks_compare.py --task 2 --image ~/Pictures/images.jpeg
python AES_tasks_compare.py --task all --backend reference --key-bits 256
"""

from __future__ import annotations

import argparse
import csv
import importlib
import math
import os
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

sys.path.insert(0, os.getcwd())
sys.path.insert(0, str(Path(__file__).resolve().parent))

# ----------------------------------------------------------------------------
# Hang so
# ----------------------------------------------------------------------------
CLASSIC = ("ECB", "CBC", "CFB", "OFB", "CTR")
AEAD = ("GCM", "CCM", "GCM-SIV")
MODES_TASK1 = ["ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "GMAC", "CCM", "GCM-SIV", "XTS", "KW", "KWP"]
MODES_IMAGE = ["ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "CCM", "GCM-SIV", "XTS"]
FAMILY = {
    "ECB": "Confidentiality", "CBC": "Confidentiality", "CFB": "Confidentiality",
    "OFB": "Confidentiality", "CTR": "Confidentiality", "XTS": "Storage",
    "GCM": "AEAD", "CCM": "AEAD", "GCM-SIV": "AEAD",
    "GMAC": "Auth-only", "KW": "Key wrap", "KWP": "Key wrap",
}
NONCE_LEN = 12          # GCM / GMAC / GCM-SIV bat buoc 12; CCM dung 12 de ho tro anh > 64KB
TAG_LEN = 16
AAD_DEFAULT = b"AES-demo-header"
DEFAULT_BLOCK = b"AES_BLOCK_16BYTE"   # dung 16 byte


@dataclass
class Params:
    key: bytes
    xts_key: bytes
    iv: bytes
    nonce: bytes
    tweak: bytes
    aad: bytes


def make_params(key_bits: int) -> Params:
    klen = key_bits // 8
    return Params(
        key=secrets.token_bytes(klen),
        xts_key=secrets.token_bytes(32 if key_bits == 128 else 64),
        iv=secrets.token_bytes(16),
        nonce=secrets.token_bytes(NONCE_LEN),
        tweak=secrets.token_bytes(16),
        aad=AAD_DEFAULT,
    )


def layout(mode: str) -> Tuple[int, int]:
    """(so byte prefix, so byte suffix) cua token ma backend project tra ve."""
    if mode in ("CBC", "CFB", "OFB", "CTR"):
        return 16, 0
    if mode in AEAD:
        return NONCE_LEN, TAG_LEN
    return 0, 0


# ----------------------------------------------------------------------------
# Backend 1: dung file du an cua ban
# ----------------------------------------------------------------------------
class ProjectCipher:
    def __init__(self, proj, mode: str, p: Params):
        self.proj, self.mode, self.p = proj, mode, p
        ctor_key = proj.build_constructor_key(mode, p.key, p.xts_key)
        self.aes = proj.new_aes_modes(ctor_key, verbose=False)
        self._gmac_data = b""

    def encrypt(self, data: bytes) -> bytes:
        m, a, p, pr = self.mode, self.aes, self.p, self.proj
        if m in CLASSIC:
            return pr.encrypt_classic(a, m, data, iv=p.iv, segment_size=128)
        if m in AEAD:
            return pr.encrypt_aead(a, m, data, nonce=p.nonce, aad=p.aad, tag_length=TAG_LEN)
        if m == "XTS":
            return a.xts_encrypt(data, xts_key=p.xts_key, tweak=p.tweak)
        if m == "GMAC":
            self._gmac_data = data
            return a.gmac(data, nonce=p.nonce, prepend_nonce=True)
        if m in ("KW", "KWP"):
            return a.key_wrap(data, pad=(m == "KWP"))
        raise ValueError(f"Mode khong ho tro: {m}")

    def decrypt(self, token: bytes) -> bytes:
        m, a, p, pr = self.mode, self.aes, self.p, self.proj
        if m in CLASSIC:
            return pr.decrypt_classic(a, m, token, has_prefix=True, iv=None, segment_size=128)
        if m in AEAD:
            return pr.decrypt_aead(a, m, token, has_prefix=True, nonce=None, aad=p.aad,
                                   nonce_length=NONCE_LEN, tag_length=TAG_LEN)
        if m == "XTS":
            return a.xts_decrypt(token, xts_key=p.xts_key, tweak=p.tweak, output_encoding=None)
        if m == "GMAC":
            if not a.gmac_verify(self._gmac_data, token, nonce=None, has_nonce=True):
                raise ValueError("GMAC verify FAILED")
            return self._gmac_data
        if m in ("KW", "KWP"):
            return a.key_unwrap(token, pad=(m == "KWP"))
        raise ValueError(f"Mode khong ho tro: {m}")


class ProjectBackend:
    name = "project"

    def __init__(self, module_name: str):
        self.proj = importlib.import_module(module_name)
        self.proj.load_modes_module()          # bao loi som neu thieu AES_modes_revised / mypackages

    def make(self, mode: str, p: Params) -> ProjectCipher:
        return ProjectCipher(self.proj, mode, p)


# ----------------------------------------------------------------------------
# Backend 2: thu vien `cryptography` (doi chieu, chay nhanh)
# ----------------------------------------------------------------------------
class ReferenceCipher:
    def __init__(self, mode: str, p: Params):
        self.mode, self.p = mode, p
        self._gmac_data = b""

    def _c(self, key, m):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        return Cipher(algorithms.AES(key), m)

    def encrypt(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import modes as M
        from cryptography.hazmat.primitives.ciphers import aead
        m, p = self.mode, self.p
        if m in ("ECB", "CBC"):
            padder = padding.PKCS7(128).padder()
            padded = padder.update(data) + padder.finalize()
            mm = M.ECB() if m == "ECB" else M.CBC(p.iv)
            e = self._c(p.key, mm).encryptor()
            ct = e.update(padded) + e.finalize()
            return ct if m == "ECB" else p.iv + ct
        if m in ("CFB", "OFB", "CTR"):
            mm = {"CFB": M.CFB, "OFB": M.OFB, "CTR": M.CTR}[m](p.iv)
            e = self._c(p.key, mm).encryptor()
            return p.iv + e.update(data) + e.finalize()
        if m == "GCM":
            return p.nonce + aead.AESGCM(p.key).encrypt(p.nonce, data, p.aad)
        if m == "CCM":
            return p.nonce + aead.AESCCM(p.key, tag_length=TAG_LEN).encrypt(p.nonce, data, p.aad)
        if m == "GCM-SIV":
            return p.nonce + aead.AESGCMSIV(p.key).encrypt(p.nonce, data, p.aad)
        if m == "GMAC":
            self._gmac_data = data
            return p.nonce + aead.AESGCM(p.key).encrypt(p.nonce, b"", data)
        if m == "XTS":
            e = self._c(p.xts_key, M.XTS(p.tweak)).encryptor()
            return e.update(data) + e.finalize()
        if m in ("KW", "KWP"):
            from cryptography.hazmat.primitives import keywrap
            fn = keywrap.aes_key_wrap if m == "KW" else keywrap.aes_key_wrap_with_padding
            return fn(p.key, data)
        raise ValueError(f"Mode khong ho tro: {m}")

    def decrypt(self, token: bytes) -> bytes:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import modes as M
        from cryptography.hazmat.primitives.ciphers import aead
        m, p = self.mode, self.p
        if m == "ECB":
            d = self._c(p.key, M.ECB()).decryptor()
            pad = d.update(token) + d.finalize()
            u = padding.PKCS7(128).unpadder()
            return u.update(pad) + u.finalize()
        if m == "CBC":
            d = self._c(p.key, M.CBC(token[:16])).decryptor()
            pad = d.update(token[16:]) + d.finalize()
            u = padding.PKCS7(128).unpadder()
            return u.update(pad) + u.finalize()
        if m in ("CFB", "OFB", "CTR"):
            mm = {"CFB": M.CFB, "OFB": M.OFB, "CTR": M.CTR}[m](token[:16])
            d = self._c(p.key, mm).decryptor()
            return d.update(token[16:]) + d.finalize()
        if m == "GCM":
            return aead.AESGCM(p.key).decrypt(token[:NONCE_LEN], token[NONCE_LEN:], p.aad)
        if m == "CCM":
            return aead.AESCCM(p.key, tag_length=TAG_LEN).decrypt(token[:NONCE_LEN], token[NONCE_LEN:], p.aad)
        if m == "GCM-SIV":
            return aead.AESGCMSIV(p.key).decrypt(token[:NONCE_LEN], token[NONCE_LEN:], p.aad)
        if m == "GMAC":
            aead.AESGCM(p.key).decrypt(token[:NONCE_LEN], token[NONCE_LEN:], self._gmac_data)
            return self._gmac_data
        if m == "XTS":
            d = self._c(p.xts_key, M.XTS(p.tweak)).decryptor()
            return d.update(token) + d.finalize()
        if m in ("KW", "KWP"):
            from cryptography.hazmat.primitives import keywrap
            fn = keywrap.aes_key_unwrap if m == "KW" else keywrap.aes_key_unwrap_with_padding
            return fn(p.key, token)
        raise ValueError(f"Mode khong ho tro: {m}")


class ReferenceBackend:
    name = "reference (cryptography)"

    def make(self, mode: str, p: Params) -> ReferenceCipher:
        return ReferenceCipher(mode, p)


def get_backend(args):
    if args.backend == "reference":
        return ReferenceBackend()
    try:
        return ProjectBackend(args.project_module)
    except Exception as exc:
        print(f"[!] Khong load duoc backend du an '{args.project_module}': {exc}")
        print("    -> chuyen sang backend 'reference' (cryptography).\n"
              "    (Dat file nay cung thu muc voi AES_project_all_modes_PyQt6.py va modes backend)\n")
        return ReferenceBackend()


# ----------------------------------------------------------------------------
# Tien ich: do thoi gian, in bang, luu CSV
# ----------------------------------------------------------------------------
def timed(fn: Callable, arg, repeat: int):
    out = None
    t0 = time.perf_counter()
    for _ in range(repeat):
        out = fn(arg)
    return out, (time.perf_counter() - t0) / repeat * 1e6      # micro-giay / lan


def print_table(title: str, headers: List[str], rows: List[List[str]]) -> None:
    rows = [[str(c) for c in r] for r in rows]
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    print("\n" + title)
    print(sep)
    print("| " + " | ".join(h.ljust(w) for h, w in zip(headers, widths)) + " |")
    print(sep)
    for r in rows:
        print("| " + " | ".join(c.ljust(w) for c, w in zip(r, widths)) + " |")
    print(sep)


def save_csv(path: Path, headers: List[str], rows: List[List[str]]) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)
    print(f"  -> da luu {path}")


def parse_block(text: Optional[str]) -> bytes:
    if not text:
        return DEFAULT_BLOCK
    t = text.strip()
    data = bytes.fromhex(t[4:]) if t.lower().startswith("hex:") else t.encode("utf-8")
    if len(data) != 16:
        raise SystemExit(f"--block phai dung 16 byte (hien tai {len(data)}). Dung hex:... neu can.")
    return data


def table_figure(title: str, headers, rows, path: Path, color_rule=None, figsize=(16, 6), fontsize=8):
    import matplotlib.pyplot as plt
    rows = [[str(v) for v in r] for r in rows]
    fig, ax = plt.subplots(figsize=figsize)
    ax.axis("off")
    ax.set_title(title, fontsize=14, fontweight="bold", pad=12)
    tbl = ax.table(cellText=rows, colLabels=headers, loc="center", cellLoc="center")
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(fontsize)
    tbl.auto_set_column_width(list(range(len(headers))))
    tbl.scale(1, 1.7)
    for c in range(len(headers)):
        cell = tbl[0, c]
        cell.set_facecolor("#2c3e50")
        cell.set_text_props(color="white", fontweight="bold")
    if color_rule:
        for r, row in enumerate(rows, start=1):
            for c, val in enumerate(row):
                col = color_rule(headers[c], val)
                if col:
                    tbl[r, c].set_facecolor(col)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    print(f"  -> da luu {path}")
    return fig


def rule_common(header: str, val: str) -> Optional[str]:
    if header in ("Decrypt OK", "Round-trip"):
        return "#c8f7c5" if val == "YES" else "#f7c5c5"
    if header == "C1 == C2":
        if val.startswith("YES"):
            return "#f7c5c5"      # lo pattern -> do
        if val == "no":
            return "#c8f7c5"
    if val.startswith("ERROR"):
        return "#f7dfa5"
    return None


# ----------------------------------------------------------------------------
# TASK 01 : 2 block giong nhau
# ----------------------------------------------------------------------------
def run_task1(backend, args, outdir: Path):
    print("\n" + "=" * 90)
    print("TASK 01 - 2 block giong nhau (block 1 = block 2), encrypt / decrypt tat ca mode")
    print("=" * 90)
    block = parse_block(args.block)
    pt = block + block
    p = make_params(args.key_bits)
    print(f"Backend      : {backend.name}")
    print(f"Block 1 = 2  : {block.hex()}  ({block!r})")
    print(f"Plaintext    : {pt.hex()}  (32 byte)")
    print(f"AES key      : {p.key.hex()}  (AES-{args.key_bits})")
    print(f"IV / counter : {p.iv.hex()}")
    print(f"Nonce (12B)  : {p.nonce.hex()}")
    print(f"XTS key/tweak: {p.xts_key.hex()} / {p.tweak.hex()}")
    print(f"AAD          : {p.aad!r}")
    print(f"Lap lai moi phep do: {args.repeat1} lan (lay trung binh)")

    headers = ["Mode", "Loai", "Out (B)", "Ciphertext block 1", "Ciphertext block 2",
               "C1 == C2", "Decrypt OK", "Enc (us)", "Dec (us)"]
    rows = []
    for mode in MODES_TASK1:
        try:
            c = backend.make(mode, p)
            token, enc_us = timed(c.encrypt, pt, args.repeat1)
            rec, dec_us = timed(c.decrypt, token, args.repeat1)
            ok = "YES" if rec == pt else "NO"
            pre, suf = layout(mode)
            if mode in ("GMAC", "KW", "KWP"):
                c1, c2, eq = token.hex(), "-", "N/A"
            else:
                body = token[pre:len(token) - suf if suf else None]
                c1, c2 = body[:16].hex(), body[16:32].hex()
                eq = "YES (lo pattern)" if c1 == c2 else "no"
            rows.append([mode, FAMILY[mode], len(token), c1, c2, eq, ok,
                         f"{enc_us:.1f}", f"{dec_us:.1f}"])
        except Exception as exc:
            rows.append([mode, FAMILY[mode], "-", "-", "-", f"ERROR: {type(exc).__name__}", "-", "-", "-"])
            print(f"  [!] {mode}: {type(exc).__name__}: {exc}")

    # bang console (rut gon hex) + bang day du
    short = [r[:3] + [r[3][:16] + ("..." if len(r[3]) > 16 else ""),
                      r[4][:16] + ("..." if len(r[4]) > 16 else "")] + r[5:] for r in rows]
    print_table("BANG SO SANH TASK 01 (hex rut gon - xem day du trong CSV / anh)", headers, short)
    print("\nGhi chu: ECB cho C1 == C2 vi cung key + cung block -> cung ciphertext (lo pattern). "
          "CBC/CFB/OFB/CTR/GCM/CCM/GCM-SIV/XTS cho C1 != C2.\n"
          "GMAC chi tao tag (khong ma hoa); KW/KWP boc khoa nen khong so sanh 2 block.")

    save_csv(outdir / "task1_results.csv", headers, rows)
    return table_figure("Task 01 - AES modes voi 2 block giong nhau (block1 = block2)",
                        headers, rows, outdir / "task1_table.png", rule_common, figsize=(20, 6.5))


# ----------------------------------------------------------------------------
# TASK 02 : anh
# ----------------------------------------------------------------------------
def ask_image_path() -> Path:
    while True:
        raw = input("\nNhap duong dan anh (dan path hoac keo-tha file vao terminal): ").strip()
        raw = raw.strip("'\"")
        if os.name == "posix":
            raw = raw.replace("\\ ", " ")
        p = Path(os.path.expanduser(raw))
        if p.is_file():
            return p
        print(f"  [!] Khong tim thay file: {p}")


def load_image(path: Path, max_side: int, visual=None):
    import numpy as np
    from PIL import Image
    img = None
    if visual is not None:
        try:
            img = visual.load_rgb_image(str(path))[0]      # ham cua AESVisual_all_modes_rgb
        except Exception as exc:
            print(f"[!] visual.load_rgb_image loi ({type(exc).__name__}: {exc}) -> doc anh bang Pillow")
    if img is None:
        img = Image.open(path).convert("RGB")
    if max_side and max(img.size) > max_side:
        old = img.size
        img.thumbnail((max_side, max_side))
        print(f"  (anh {old[0]}x{old[1]} duoc thu nho thanh {img.size[0]}x{img.size[1]} "
              f"de chay nhanh; dung --max-side 0 de giu nguyen)")
    return np.asarray(img, dtype=np.uint8)


def load_visual_module(args):
    """Import AESVisual_all_modes_rgb.py. Tra ve None neu khong dung duoc."""
    if args.backend == "reference":
        return None
    try:
        mod = importlib.import_module(args.visual_module)
        need = ("load_rgb_image", "encrypt_image_bytes", "decrypt_image_bytes",
                "select_cipher_visual_bytes", "bytes_to_rgb_visual", "save_container")
        missing = [n for n in need if not hasattr(mod, n)]
        if missing:
            raise ImportError(f"module thieu ham: {', '.join(missing)}")
        return mod
    except Exception as exc:
        print(f"[!] Khong import duoc '{args.visual_module}': {exc}")
        print("    -> Task 02 dung cai dat noi bo (backend reference). "
              "Dat AESVisual_all_modes_rgb.py cung thu muc de dung file cua ban.")
        return None


def shannon_entropy(data: bytes) -> float:
    import numpy as np
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(float)
    pr = counts[counts > 0] / counts.sum()
    return float(-(pr * np.log2(pr)).sum())


def adjacent_corr(arr) -> float:
    import numpy as np
    g = arr.astype(float).mean(axis=2)
    a, b = g[:, :-1].ravel(), g[:, 1:].ravel()
    if a.std() == 0 or b.std() == 0:
        return float("nan")
    return float(np.corrcoef(a, b)[0, 1])


def token_to_image(token: bytes, pre: int, suf: int, shape):
    import numpy as np
    h, w, ch = shape
    n = h * w * ch
    body = token[pre:len(token) - suf if suf else None][:n]
    body = body + bytes(n - len(body))
    return np.frombuffer(body, dtype=np.uint8).reshape(h, w, ch)


def run_task2(backend, args, outdir: Path):
    import numpy as np
    from PIL import Image
    import matplotlib.pyplot as plt

    print("\n" + "=" * 90)
    print("TASK 02 - Anh dau vao, encrypt / decrypt cac mode")
    print("=" * 90)
    path = Path(os.path.expanduser(args.image.strip("'\""))) if args.image else ask_image_path()
    if not path.is_file():
        raise SystemExit(f"Khong tim thay file anh: {path}")
    visual = load_visual_module(args)
    arr = load_image(path, args.max_side, visual)
    h, w, ch = arr.shape
    data = arr.tobytes()
    p = make_params(args.key_bits)
    print(f"Module   : {visual.__name__ + '.py (AESVisual)' if visual else 'noi bo (reference)'}")
    print(f"Anh      : {path.name}  ({w}x{h}, {ch} kenh, {len(data)} byte pixel)")
    print(f"AES key  : {p.key.hex()}  (AES-{args.key_bits})")
    print(f"Lap lai  : {args.repeat2} lan / phep do\n")

    enc_dir = outdir / "images_encrypted"
    dec_dir = outdir / "images_decrypted"
    cont_dir = outdir / "containers_aesimg"
    for d in (enc_dir, dec_dir, cont_dir):
        d.mkdir(parents=True, exist_ok=True)
    Image.fromarray(arr).save(outdir / "image_original.png")

    def run_mode_visual(mode):
        """Encrypt/decrypt bang cac ham cua AESVisual_all_modes_rgb.py."""
        common = dict(key=None if mode == "XTS" else p.key,
                      xts_key=p.xts_key if mode == "XTS" else None,
                      tweak=p.tweak if mode == "XTS" else None,
                      aad=p.aad if mode in AEAD else b"")
        iv = p.iv if mode in CLASSIC else None
        nonce = p.nonce if mode in AEAD else None
        out, enc_us = timed(lambda _: visual.encrypt_image_bytes(
            mode, data, iv=iv, nonce=nonce, cfb_segment_size=128,
            ccm_tag_length=TAG_LEN, verbose=False, **common), None, args.repeat2)
        full, nonce_len, tag_len = out
        rec, dec_us = timed(lambda _: visual.decrypt_image_bytes(
            mode, full, cfb_segment_size=128, ccm_nonce_length=nonce_len,
            ccm_tag_length=tag_len, verbose=False, **common), None, args.repeat2)
        vis_bytes = visual.select_cipher_visual_bytes(
            mode, full, raw_len=len(data), nonce_length=nonce_len, tag_length=tag_len)
        cimg = np.asarray(visual.bytes_to_rgb_visual(vis_bytes, w, h), dtype=np.uint8)
        header = {"version": 2, "mode": mode, "operation": "image-encryption",
                  "width": w, "height": h, "channels": 3, "raw_len": len(data),
                  "payload_len": len(full), "nonce_length": nonce_len, "tag_length": tag_len,
                  "segment_size": 128, "aad_hex": common["aad"].hex(),
                  "layout": "mode-dependent; revised modes output with IV/nonce prefix when applicable"}
        visual.save_container(str(cont_dir / f"cipher_rgb_{mode.lower().replace('-', '_')}.aesimg"), header, full)
        return len(full), cimg, rec, enc_us, dec_us

    def run_mode_builtin(mode):
        c = backend.make(mode, p)
        token, enc_us = timed(c.encrypt, data, args.repeat2)
        rec, dec_us = timed(c.decrypt, token, args.repeat2)
        pre, suf = layout(mode)
        return len(token), token_to_image(token, pre, suf, arr.shape), rec, enc_us, dec_us

    run_mode = run_mode_visual if visual else run_mode_builtin

    headers = ["Mode", "Out (B)", "Enc (ms)", "Dec (ms)", "Enc (MB/s)", "Dec (MB/s)",
               "Entropy", "Correlation", "Round-trip"]
    rows, cipher_imgs = [], {}
    print(f"Entropy anh goc = {shannon_entropy(data):.4f} | correlation anh goc = {adjacent_corr(arr):.4f}")
    import traceback
    errors = []
    if len(data) > 2_000_000:
        print(f"[i] Anh {len(data)/1e6:.1f} MB (khong thu nho). Neu backend AES la Python thuan, "
              f"moi mode co the mat vai phut - chuong trinh van dang chay, vui long cho.\n")
    for mode in MODES_IMAGE:
        print(f"  dang chay {mode} ...", end=" ", flush=True)
        label = mode
        t_start = time.perf_counter()
        try:
            try:
                res = run_mode(mode)
            except Exception as exc:
                if run_mode is run_mode_visual:
                    errors.append(f"[{mode}] AESVisual loi:\n{traceback.format_exc()}")
                    print(f"\n     [!] AESVisual loi o {mode}: {type(exc).__name__}: {exc}"
                          f"\n         -> thu lai bang backend du an ...", end=" ", flush=True)
                    res = run_mode_builtin(mode)
                    label = mode + "*"
                else:
                    raise
            out_len, cimg, rec, enc_us, dec_us = res
            rec = bytes(rec)
            cipher_imgs[mode] = cimg
            ok = rec[:len(data)] == data
            dec_img = np.frombuffer(rec[:len(data)].ljust(len(data), b"\0"), dtype=np.uint8).reshape(arr.shape)
            Image.fromarray(cimg).save(enc_dir / f"{mode}.png")
            Image.fromarray(dec_img).save(dec_dir / f"{mode}.png")
            mb = len(data) / 1e6
            rows.append([label, out_len, f"{enc_us/1e3:.2f}", f"{dec_us/1e3:.2f}",
                         f"{mb/(enc_us/1e6):.2f}", f"{mb/(dec_us/1e6):.2f}",
                         f"{shannon_entropy(cimg.tobytes()):.4f}", f"{adjacent_corr(cimg):+.4f}",
                         "YES" if ok else "NO"])
            print(f"xong ({time.perf_counter() - t_start:.1f}s)")
        except Exception as exc:
            errors.append(f"[{mode}] LOI:\n{traceback.format_exc()}")
            rows.append([mode, "-", "-", "-", "-", "-", "-", "-", f"ERROR: {type(exc).__name__}"])
            print(f"LOI: {type(exc).__name__}: {exc}")
    if errors:
        log = outdir / "task2_errors.log"
        log.write_text("\n".join(errors), encoding="utf-8")
        print(f"\n[!] Co loi - chi tiet day du (traceback) trong: {log}")
        print("    '*' trong bang = mode do AESVisual bi loi, da chay lai bang backend du an.")
    if not cipher_imgs:
        print("\n[!] Tat ca mode deu loi, xem task2_errors.log. Tom tat loi dau tien:")
        print(errors[0][-1200:] if errors else "(khong co thong tin)")

    print_table("BANG SO SANH TASK 02", headers, rows)
    print("\nGhi chu: Entropy cang gan 8.0 va correlation cang gan 0 -> ciphertext cang 'ngau nhien'.")
    print("Anh ma hoa:", enc_dir, "| anh giai ma:", dec_dir)
    if visual:
        print("Container .aesimg (giai ma lai bang AESVisual_all_modes_rgb.py):", cont_dir)
    save_csv(outdir / "task2_results.csv", headers, rows)

    # --- Hinh 1: luoi anh goc + cac mode (giong hinh tham khao) ---
    tiles = [("Original", arr)] + [(m, cipher_imgs[m]) for m in MODES_IMAGE if m in cipher_imgs]
    ncols = 4
    nrows = math.ceil(len(tiles) / ncols)
    fig1, axes = plt.subplots(nrows, ncols, figsize=(4 * ncols, 4.2 * nrows))
    axes = np.atleast_1d(axes).ravel()
    for ax in axes:
        ax.axis("off")
    for ax, (name, img) in zip(axes, tiles):
        ax.imshow(img)
        ax.set_title(name, fontsize=12)
    fig1.suptitle(f"AES Mode Visual Comparison: {path.name} ({w}x{h})", fontsize=15, fontweight="bold")
    fig1.tight_layout()
    fig1.savefig(outdir / "task2_visual_comparison.png", dpi=150)
    print(f"  -> da luu {outdir / 'task2_visual_comparison.png'}")

    # --- Hinh 2: bang + bieu do thoi gian Enc/Dec ---
    good = [r for r in rows if not str(r[-1]).startswith("ERROR")]
    fig2, (axt, axb) = plt.subplots(1, 2, figsize=(18, 6), gridspec_kw={"width_ratios": [1.5, 1]})
    axt.axis("off")
    rows = [[str(v) for v in r] for r in rows]
    tbl = axt.table(cellText=rows, colLabels=headers, loc="center", cellLoc="center")
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(9)
    tbl.auto_set_column_width(list(range(len(headers))))
    tbl.scale(1, 1.8)
    for ci in range(len(headers)):
        tbl[0, ci].set_facecolor("#2c3e50")
        tbl[0, ci].set_text_props(color="white", fontweight="bold")
    for ri, row in enumerate(rows, start=1):
        for ci, val in enumerate(row):
            col = rule_common(headers[ci], val)
            if col:
                tbl[ri, ci].set_facecolor(col)
    axt.set_title("Bang so sanh cac mode AES (anh)", fontsize=13, fontweight="bold")
    if good:
        x = np.arange(len(good))
        axb.bar(x - 0.2, [float(r[2]) for r in good], 0.4, label="Encrypt", color="#1f77b4")
        axb.bar(x + 0.2, [float(r[3]) for r in good], 0.4, label="Decrypt", color="#ff7f0e")
        axb.set_xticks(x)
        axb.set_xticklabels([r[0] for r in good], rotation=45)
        axb.set_ylabel("Time (ms)")
        axb.set_title(f"Encrypt / Decrypt time - {len(data)/1e3:.0f} KB image")
        axb.grid(axis="y", alpha=0.3)
        axb.legend()
    fig2.tight_layout()
    fig2.savefig(outdir / "task2_table_and_time.png", dpi=150)
    print(f"  -> da luu {outdir / 'task2_table_and_time.png'}")
    return fig1, fig2



# ----------------------------------------------------------------------------
# TASK 03 : benchmark theo kich thuoc du lieu (4 subplot)
# ----------------------------------------------------------------------------
MODES_BENCH = ["ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "EAX", "CCM", "SIV", "OCB"]
PROJECT_BENCH_MODES = {"ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "CCM"}   # file du an khong co EAX/SIV/OCB


class CryptodomeBench:
    """Cipher PyCryptodome; moi lan encrypt/decrypt tao doi tuong moi (do ca chi phi khoi tao)."""

    def __init__(self, mode: str, key_bits: int):
        from Crypto.Cipher import AES
        self.AES, self.mode = AES, mode
        klen = key_bits // 8
        self.key = secrets.token_bytes(2 * klen if mode == "SIV" else klen)   # SIV can khoa gap doi
        self.iv = secrets.token_bytes(16)
        self.nonce = {"CTR": 8, "GCM": 12, "CCM": 12, "OCB": 12, "EAX": 16}.get(mode, 0)
        self.nonce = secrets.token_bytes(self.nonce) if self.nonce else b""

    def _new(self):
        A, m = self.AES, self.mode
        if m == "ECB":
            return A.new(self.key, A.MODE_ECB)
        if m == "CBC":
            return A.new(self.key, A.MODE_CBC, iv=self.iv)
        if m == "CFB":
            return A.new(self.key, A.MODE_CFB, iv=self.iv, segment_size=128)
        if m == "OFB":
            return A.new(self.key, A.MODE_OFB, iv=self.iv)
        if m == "CTR":
            return A.new(self.key, A.MODE_CTR, nonce=self.nonce)
        if m == "SIV":
            return A.new(self.key, A.MODE_SIV)
        mode_const = {"GCM": A.MODE_GCM, "EAX": A.MODE_EAX, "CCM": A.MODE_CCM, "OCB": A.MODE_OCB}[m]
        return A.new(self.key, mode_const, nonce=self.nonce)

    def encrypt(self, data: bytes):
        from Crypto.Util.Padding import pad
        c = self._new()
        if self.mode in ("ECB", "CBC"):
            return c.encrypt(pad(data, 16))
        if self.mode in ("CFB", "OFB", "CTR"):
            return c.encrypt(data)
        return c.encrypt_and_digest(data)            # AEAD: (ciphertext, tag)

    def decrypt(self, token):
        from Crypto.Util.Padding import unpad
        c = self._new()
        if self.mode in ("ECB", "CBC"):
            return unpad(c.decrypt(token), 16)
        if self.mode in ("CFB", "OFB", "CTR"):
            return c.decrypt(token)
        return c.decrypt_and_verify(*token)


class ProjectBench:
    """Dung chinh backend du an (chi cac mode co trong file du an)."""

    def __init__(self, backend, mode: str, key_bits: int):
        self.c = backend.make(mode, make_params(key_bits))

    def encrypt(self, data):
        return self.c.encrypt(data)

    def decrypt(self, token):
        return self.c.decrypt(token)


def bench_op(fn, arg, max_rep: int, budget: float = 0.25) -> Tuple[object, float]:
    """Chay fn(arg) nhieu lan (toi da max_rep, trong ~budget giay). Tra ve (ket qua, us/lan)."""
    t0 = time.perf_counter()
    out = fn(arg)
    first = time.perf_counter() - t0
    n = int(min(max_rep, max(1, budget / first))) if first > 0 else max_rep
    total = first
    for _ in range(n - 1):
        t0 = time.perf_counter()
        fn(arg)
        total += time.perf_counter() - t0
    return out, total / n * 1e6


def run_task3(backend, args, outdir: Path):
    import numpy as np
    import matplotlib.pyplot as plt

    print("\n" + "=" * 90)
    print("TASK 03 - Benchmark AES theo kich thuoc du lieu (4 subplot)")
    print("=" * 90)
    sizes = [int(float(x)) for x in args.sizes.split(",")]
    use_project = args.bench_backend == "project"
    if use_project:
        modes = [m for m in MODES_BENCH if m in PROJECT_BENCH_MODES]
        skipped = [m for m in MODES_BENCH if m not in PROJECT_BENCH_MODES]
        print(f"Backend: file du an (bo qua {', '.join(skipped)} vi file du an khong co)")
        make = lambda m: ProjectBench(backend, m, args.key_bits)
    else:
        try:
            import Crypto  # noqa: F401
        except ImportError:
            raise SystemExit("Task 03 can PyCryptodome:  pip install pycryptodome")
        modes = list(MODES_BENCH)
        print("Backend: PyCryptodome (day du ECB, CBC, CFB, OFB, CTR, GCM, EAX, CCM, SIV, OCB)")
        make = lambda m: CryptodomeBench(m, args.key_bits)
    print(f"AES-{args.key_bits} | sizes (byte): {sizes} | toi da {args.bench_repeat} lan lap/phep do\n")

    res = {m: {"enc": [], "dec": [], "thr": []} for m in modes}
    csv_rows = []
    for m in modes:
        print(f"  {m:4s}:", end=" ", flush=True)
        try:
            c = make(m)
            for n in sizes:
                data = os.urandom(n)
                token, enc_us = bench_op(c.encrypt, data, args.bench_repeat)
                rec, dec_us = bench_op(c.decrypt, token, args.bench_repeat)
                if bytes(rec) != data:
                    raise ValueError("giai ma khong khop du lieu goc")
                thr = (n / 1e6) / (enc_us / 1e6)          # MB/s (ma hoa)
                res[m]["enc"].append(enc_us); res[m]["dec"].append(dec_us); res[m]["thr"].append(thr)
                csv_rows.append([m, n, f"{enc_us:.3f}", f"{dec_us:.3f}", f"{thr:.3f}",
                                 f"{(n / 1e6) / (dec_us / 1e6):.3f}"])
                print(f"{n:g}B ok", end="  ", flush=True)
            print()
        except Exception as exc:
            print(f"LOI: {type(exc).__name__}: {exc}")
            del res[m]
    if not res:
        raise SystemExit("Khong mode nao chay duoc.")

    # --- bang console ---
    lat_headers = ["Mode"] + [f"{n} B" for n in sizes]
    print_table("ENCRYPT LATENCY (us)", lat_headers,
                [[m] + [f"{v:.1f}" for v in res[m]["enc"]] for m in res])
    print_table("DECRYPT LATENCY (us)", lat_headers,
                [[m] + [f"{v:.1f}" for v in res[m]["dec"]] for m in res])
    print_table("ENCRYPT THROUGHPUT (MB/s)", lat_headers,
                [[m] + [f"{v:.1f}" for v in res[m]["thr"]] for m in res])
    save_csv(outdir / "task3_results.csv",
             ["Mode", "Size (B)", "Encrypt (us)", "Decrypt (us)", "Enc throughput (MB/s)", "Dec throughput (MB/s)"],
             csv_rows)

    # --- hinh 4 subplot ---
    cmap = plt.get_cmap("tab10")
    color = {m: cmap(i % 10) for i, m in enumerate(MODES_BENCH)}
    fig, axs = plt.subplots(2, 2, figsize=(16, 11))
    panels = [(axs[0, 0], "thr", "Throughput (MB/s)", "AES Throughput vs Data Size", "lower left"),
              (axs[0, 1], "enc", "Encrypt Time (\u00b5s)", "Encrypt Latency", "upper left"),
              (axs[1, 0], "dec", "Decrypt Time (\u00b5s)", "Decrypt Latency", "upper left")]
    for ax, key, ylab, title, loc in panels:
        for m in res:
            ax.plot(sizes, res[m][key], marker="o", markersize=4, linewidth=1.5, label=m, color=color[m])
        ax.set_xscale("log"); ax.set_yscale("log")
        ax.set_xlabel("Data Size (bytes)"); ax.set_ylabel(ylab); ax.set_title(title, fontsize=13)
        ax.grid(True, which="both", alpha=0.3)
        ax.legend(ncol=2, fontsize=8, loc=loc)

    axb = axs[1, 1]
    big = max(sizes) if 1_000_000 not in sizes else 1_000_000
    idx = sizes.index(big)
    names = list(res.keys())
    x = np.arange(len(names))
    axb.bar(x - 0.2, [res[m]["enc"][idx] for m in names], 0.4, label="Encrypt", color="#1f77b4", alpha=0.9)
    axb.bar(x + 0.2, [res[m]["dec"][idx] for m in names], 0.4, label="Decrypt", color="#ff7f0e", alpha=0.9)
    axb.set_xticks(x); axb.set_xticklabels(names, rotation=45)
    axb.set_ylabel("Time (\u00b5s)")
    axb.set_title(f"{big / 1e6:g} MB Encrypt/Decrypt Latency" if big >= 1e6 else f"{big} B Encrypt/Decrypt Latency",
                  fontsize=13)
    axb.grid(axis="y", alpha=0.3); axb.legend()
    fig.suptitle(f"AES-{args.key_bits} benchmark - {'project backend' if use_project else 'PyCryptodome'}",
                 fontsize=15, fontweight="bold")
    fig.tight_layout()
    out = outdir / "task3_benchmark.png"
    fig.savefig(out, dpi=150)
    print(f"  -> da luu {out}")
    return fig


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def build_parser():
    ap = argparse.ArgumentParser(description="So sanh cac che do AES: Task 01 (2 block) va Task 02 (anh).")
    ap.add_argument("--task", choices=["1", "2", "3", "all"], help="1 = 2 block, 2 = anh, 3 = benchmark 4 subplot, all = ca ba. Bo trong de hien menu.")
    ap.add_argument("--image", help="Duong dan anh (Task 02). Bo trong de duoc hoi khi chay.")
    ap.add_argument("--backend", choices=["project", "reference"], default="project",
                    help="reference = dung thu vien cryptography cho ca 2 task (khong dung file cua ban).")
    ap.add_argument("--project-module", default="AES_project_all_modes_PyQt6",
                    help="Ten module (khong .py) cua file du an AES cua ban.")
    ap.add_argument("--visual-module", default="AESVisual_all_modes_rgb",
                    help="Ten module (khong .py) cua file AESVisual_all_modes_rgb.py - dung cho Task 02.")
    ap.add_argument("--sizes", default="1e3,1e4,1e5,1e6", help="Task 03: kich thuoc du lieu (byte), cach nhau dau phay.")
    ap.add_argument("--bench-backend", choices=["pycryptodome", "project"], default="pycryptodome",
                    help="Task 03: pycryptodome (du 10 mode) hoac project (chi cac mode co trong file du an, rat cham voi 1 MB).")
    ap.add_argument("--bench-repeat", type=int, default=1000, help="Task 03: so lan lap toi da moi phep do.")
    ap.add_argument("--key-bits", type=int, choices=[128, 192, 256], default=128)
    ap.add_argument("--block", help="Block 16 byte cho Task 01 (text hoac hex:...). Mac dinh: AES_BLOCK_16BYTE")
    ap.add_argument("--repeat1", type=int, default=100, help="So lan lap moi phep do Task 01 (mac dinh 100).")
    ap.add_argument("--repeat2", type=int, default=1, help="So lan lap moi phep do Task 02 (mac dinh 1).")
    ap.add_argument("--max-side", type=int, default=0,
                    help="(tuy chon) thu nho anh neu canh dai hon gia tri nay. Mac dinh 0 = GIU NGUYEN anh goc.")
    ap.add_argument("--out-dir", default="aes_output", help="Thu muc luu ket qua.")
    ap.add_argument("--no-show", action="store_true", help="Khong mo cua so do thi, chi luu file.")
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    import matplotlib
    if args.no_show:
        matplotlib.use("Agg")

    task = args.task
    if task is None:
        print("Chon task:\n  1. Task 01 - 2 block (block1 = block2)\n  2. Task 02 - Anh\n"
              "  3. Task 03 - Benchmark 4 subplot (throughput / latency)\n  4. Ca ba")
        task = {"1": "1", "2": "2", "3": "3", "4": "all"}.get(input("Nhap lua chon [4]: ").strip() or "4", "all")

    outdir = Path(args.out_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    backend = get_backend(args)

    if task in ("1", "all"):
        run_task1(backend, args, outdir)
    if task in ("2", "all"):
        run_task2(backend, args, outdir)
    if task in ("3", "all"):
        run_task3(backend, args, outdir)

    print(f"\nHoan tat. Tat ca ket qua nam trong thu muc: {outdir.resolve()}")
    if not args.no_show:
        import matplotlib.pyplot as plt
        plt.show()


if __name__ == "__main__":
    main()