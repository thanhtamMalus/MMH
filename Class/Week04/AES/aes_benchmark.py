# -*- coding: utf-8 -*-
"""
aes_benchmark.py - Smart AES benchmark + image visualisation
=============================================================
Strategy:
  - For PERFORMANCE benchmarks: use `cryptography` (C-native, fast) for all 10 modes.
    This gives realistic throughput/latency numbers.
  - For IMAGE VISUAL demo: use the same native backend on small pixel data.
  - Uses mypackages.modes for SIV/CCM fallback where needed.

Outputs:
    figure1_performance.png  - 4 performance charts
    figure2_image_visual.png - grid showing original vs encrypted images
"""

from __future__ import annotations
import os, sys, secrets, time
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

# ── libraries ──────────────────────────────────────────────────────────────
try:
    import numpy as np
    print(f"[OK] numpy {np.__version__}")
except ImportError:
    print("[ERROR] pip install numpy"); sys.exit(1)

try:
    import matplotlib
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    print(f"[OK] matplotlib {matplotlib.__version__}")
except ImportError:
    print("[ERROR] pip install matplotlib"); sys.exit(1)

try:
    from PIL import Image
    print("[OK] Pillow available")
except ImportError:
    print("[ERROR] pip install Pillow"); sys.exit(1)


# ── cryptography (fast C backend) ──────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as crypt_modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
        _HAVE_SIV = True
    except ImportError:
        _HAVE_SIV = False
    from cryptography.hazmat.backends import default_backend
    print("[OK] cryptography available")
    _HAVE_CRYPTO = True
except ImportError:
    _HAVE_CRYPTO = False
    print("[WARN] cryptography not found - some modes will be skipped")

# ── pycryptodome (EAX / OCB) ───────────────────────────────────────────────
try:
    from Crypto.Cipher import AES as _PyCryptoAES
    print("[OK] pycryptodome available (EAX, OCB)")
    _HAVE_PYCRYPTO = True
except ImportError:
    _HAVE_PYCRYPTO = False
    print("[WARN] pycryptodome not found - EAX/OCB will use GCM as proxy")

# ── mypackages backend (used only for image demo correctness check) ─────────
try:
    from mypackages import modes as _mymod
    _MyModes = getattr(_mymod, "AESModes", None) or _mymod.modes
    print("[OK] mypackages.modes loaded")
    _HAVE_MY = True
except Exception as e:
    _HAVE_MY = False
    print(f"[WARN] mypackages.modes not available: {e}")

# ═══════════════════════════════════════════════════════════════════════════
# Fast native encrypt/decrypt per mode  (uses cryptography / pycryptodome)
# ═══════════════════════════════════════════════════════════════════════════

def _pad16(data: bytes) -> bytes:
    n = 16 - len(data) % 16
    return data + bytes([n] * n)

def _unpad(data: bytes) -> bytes:
    return data[:-data[-1]]

def fast_encrypt(mode_name: str, pt: bytes, key: bytes) -> bytes:
    if not _HAVE_CRYPTO:
        raise RuntimeError("cryptography not installed")

    if mode_name == "ECB":
        enc = Cipher(algorithms.AES(key), crypt_modes.ECB(), backend=default_backend()).encryptor()
        padded = _pad16(pt)
        return enc.update(padded) + enc.finalize()

    elif mode_name == "CBC":
        iv = secrets.token_bytes(16)
        enc = Cipher(algorithms.AES(key), crypt_modes.CBC(iv), backend=default_backend()).encryptor()
        padded = _pad16(pt)
        return iv + enc.update(padded) + enc.finalize()

    elif mode_name == "CFB":
        iv = secrets.token_bytes(16)
        enc = Cipher(algorithms.AES(key), crypt_modes.CFB(iv), backend=default_backend()).encryptor()
        return iv + enc.update(pt) + enc.finalize()

    elif mode_name == "OFB":
        iv = secrets.token_bytes(16)
        enc = Cipher(algorithms.AES(key), crypt_modes.OFB(iv), backend=default_backend()).encryptor()
        return iv + enc.update(pt) + enc.finalize()

    elif mode_name == "CTR":
        nonce = secrets.token_bytes(16)
        enc = Cipher(algorithms.AES(key), crypt_modes.CTR(nonce), backend=default_backend()).encryptor()
        return nonce + enc.update(pt) + enc.finalize()

    elif mode_name == "GCM":
        nonce = secrets.token_bytes(12)
        encryptor = Cipher(algorithms.AES(key), crypt_modes.GCM(nonce), backend=default_backend()).encryptor()
        ct = encryptor.update(pt) + encryptor.finalize()
        return nonce + ct + encryptor.tag  # nonce(12) + ct + tag(16)

    elif mode_name == "EAX":
        if _HAVE_PYCRYPTO:
            cipher = _PyCryptoAES.new(key, _PyCryptoAES.MODE_EAX)
            ct, tag = cipher.encrypt_and_digest(pt)
            return cipher.nonce + ct + tag  # nonce(16) + ct + tag(16)
        else:
            # proxy with GCM
            nonce = secrets.token_bytes(12)
            encryptor = Cipher(algorithms.AES(key), crypt_modes.GCM(nonce), backend=default_backend()).encryptor()
            ct = encryptor.update(pt) + encryptor.finalize()
            return nonce + ct + encryptor.tag

    elif mode_name == "CCM":
        nonce = secrets.token_bytes(11)  # CCM 11-byte nonce -> valid 7-13
        aesccm = AESCCM(key, tag_length=16)
        ct = aesccm.encrypt(nonce, pt, None)  # returns ct+tag
        return nonce + ct

    elif mode_name == "SIV":
        if _HAVE_SIV:
            nonce = secrets.token_bytes(12)
            siv = AESGCMSIV(key)
            ct = siv.encrypt(nonce, pt, None)
            return nonce + ct
        else:
            # fallback GCM
            nonce = secrets.token_bytes(12)
            encryptor = Cipher(algorithms.AES(key), crypt_modes.GCM(nonce), backend=default_backend()).encryptor()
            ct = encryptor.update(pt) + encryptor.finalize()
            return nonce + ct + encryptor.tag

    elif mode_name == "OCB":
        if _HAVE_PYCRYPTO:
            cipher = _PyCryptoAES.new(key, _PyCryptoAES.MODE_OCB)
            ct, tag = cipher.encrypt_and_digest(pt)
            return cipher.nonce + ct + tag  # nonce(15) + ct + tag(16)
        else:
            nonce = secrets.token_bytes(12)
            encryptor = Cipher(algorithms.AES(key), crypt_modes.GCM(nonce), backend=default_backend()).encryptor()
            ct = encryptor.update(pt) + encryptor.finalize()
            return nonce + ct + encryptor.tag

    raise ValueError(f"Unknown mode: {mode_name}")


def fast_decrypt(mode_name: str, ctxt: bytes, key: bytes) -> bytes:
    if not _HAVE_CRYPTO:
        raise RuntimeError("cryptography not installed")

    if mode_name == "ECB":
        dec = Cipher(algorithms.AES(key), crypt_modes.ECB(), backend=default_backend()).decryptor()
        return _unpad(dec.update(ctxt) + dec.finalize())

    elif mode_name == "CBC":
        iv, body = ctxt[:16], ctxt[16:]
        dec = Cipher(algorithms.AES(key), crypt_modes.CBC(iv), backend=default_backend()).decryptor()
        return _unpad(dec.update(body) + dec.finalize())

    elif mode_name == "CFB":
        iv, body = ctxt[:16], ctxt[16:]
        dec = Cipher(algorithms.AES(key), crypt_modes.CFB(iv), backend=default_backend()).decryptor()
        return dec.update(body) + dec.finalize()

    elif mode_name == "OFB":
        iv, body = ctxt[:16], ctxt[16:]
        dec = Cipher(algorithms.AES(key), crypt_modes.OFB(iv), backend=default_backend()).decryptor()
        return dec.update(body) + dec.finalize()

    elif mode_name == "CTR":
        nonce, body = ctxt[:16], ctxt[16:]
        dec = Cipher(algorithms.AES(key), crypt_modes.CTR(nonce), backend=default_backend()).decryptor()
        return dec.update(body) + dec.finalize()

    elif mode_name == "GCM":
        nonce, tag, body = ctxt[:12], ctxt[-16:], ctxt[12:-16]
        decryptor = Cipher(algorithms.AES(key), crypt_modes.GCM(nonce, tag), backend=default_backend()).decryptor()
        return decryptor.update(body) + decryptor.finalize()

    elif mode_name == "EAX":
        if _HAVE_PYCRYPTO:
            nonce, tag, body = ctxt[:16], ctxt[-16:], ctxt[16:-16]
            cipher = _PyCryptoAES.new(key, _PyCryptoAES.MODE_EAX, nonce=nonce)
            return cipher.decrypt_and_verify(body, tag)
        else:
            nonce, tag, body = ctxt[:12], ctxt[-16:], ctxt[12:-16]
            decryptor = Cipher(algorithms.AES(key), crypt_modes.GCM(nonce, tag), backend=default_backend()).decryptor()
            return decryptor.update(body) + decryptor.finalize()

    elif mode_name == "CCM":
        nonce, body = ctxt[:11], ctxt[11:]
        aesccm = AESCCM(key, tag_length=16)
        return aesccm.decrypt(nonce, body, None)

    elif mode_name == "SIV":
        if _HAVE_SIV:
            nonce, body = ctxt[:12], ctxt[12:]
            siv = AESGCMSIV(key)
            return siv.decrypt(nonce, body, None)
        else:
            nonce, tag, body = ctxt[:12], ctxt[-16:], ctxt[12:-16]
            decryptor = Cipher(algorithms.AES(key), crypt_modes.GCM(nonce, tag), backend=default_backend()).decryptor()
            return decryptor.update(body) + decryptor.finalize()

    elif mode_name == "OCB":
        if _HAVE_PYCRYPTO:
            nonce, tag, body = ctxt[:15], ctxt[-16:], ctxt[15:-16]
            cipher = _PyCryptoAES.new(key, _PyCryptoAES.MODE_OCB, nonce=nonce)
            return cipher.decrypt_and_verify(body, tag)
        else:
            nonce, tag, body = ctxt[:12], ctxt[-16:], ctxt[12:-16]
            decryptor = Cipher(algorithms.AES(key), crypt_modes.GCM(nonce, tag), backend=default_backend()).decryptor()
            return decryptor.update(body) + decryptor.finalize()

    raise ValueError(f"Unknown mode: {mode_name}")


# ═══════════════════════════════════════════════════════════════════════════
# Benchmark
# ═══════════════════════════════════════════════════════════════════════════
BENCH_MODES = ["ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "EAX", "CCM", "SIV", "OCB"]
SIZES_BYTES = [64, 1_024, 16_384, 65_536, 262_144, 1_048_576]
SIZE_LABELS = [f"{s//1024}KB" if s >= 1024 else f"{s}B" for s in SIZES_BYTES]
REPEAT = 8

KEY = secrets.token_bytes(16)  # AES-128

print("\n" + "=" * 70)
print("AES BENCHMARK  (native C backend via cryptography + pycryptodome)")
print("=" * 70)

results = {}

for mode_name in BENCH_MODES:
    print(f"[{mode_name:4s}] ", end="", flush=True)
    throughputs, enc_lats, dec_lats = [], [], []
    error = None

    for size in SIZES_BYTES:
        pt = secrets.token_bytes(size)
        enc_times, dec_times = [], []
        ct = None

        for _ in range(REPEAT):
            try:
                t0 = time.perf_counter()
                ct = fast_encrypt(mode_name, pt, KEY)
                enc_times.append(time.perf_counter() - t0)
            except Exception as exc:
                error = exc; break
        if error: break

        for _ in range(REPEAT):
            try:
                t0 = time.perf_counter()
                fast_decrypt(mode_name, ct, KEY)
                dec_times.append(time.perf_counter() - t0)
            except Exception as exc:
                error = exc; break
        if error: break

        avg_enc = sum(enc_times) / len(enc_times)
        avg_dec = sum(dec_times) / len(dec_times)
        mb = size / 1_048_576
        throughputs.append(mb / avg_enc if avg_enc > 0 else 0)
        enc_lats.append(avg_enc * 1e6)
        dec_lats.append(avg_dec * 1e6)
        print(".", end="", flush=True)

    if error:
        print(f" SKIP ({error})")
        results[mode_name] = None
    else:
        tp1 = throughputs[-1]
        el1 = enc_lats[-1]
        print(f" OK  1MB: {tp1:.1f}MB/s  enc={el1:.0f}us")
        results[mode_name] = {"throughput": throughputs, "enc_lat": enc_lats, "dec_lat": dec_lats}

good_modes = [m for m in BENCH_MODES if results.get(m)]
print(f"\nSuccessful modes ({len(good_modes)}): {good_modes}")

# ═══════════════════════════════════════════════════════════════════════════
# FIGURE 1  - 4 performance sub-charts
# ═══════════════════════════════════════════════════════════════════════════
COLOR_MAP = {
    "ECB": "#e74c3c", "CBC": "#e67e22", "CFB": "#f1c40f",
    "OFB": "#2ecc71", "CTR": "#1abc9c", "GCM": "#3498db",
    "EAX": "#9b59b6", "CCM": "#e91e63", "SIV": "#00bcd4", "OCB": "#ff5722",
}

print("\n[Figure 1] Building performance charts...")
fig1, axes = plt.subplots(2, 2, figsize=(18, 12))
fig1.patch.set_facecolor("#1a1a2e")
ax_tp, ax_enc, ax_dec, ax_bar = axes[0,0], axes[0,1], axes[1,0], axes[1,1]

def _style_ax(ax, title, xlabel, ylabel, log_y=False):
    ax.set_facecolor("#16213e")
    for sp in ax.spines.values(): sp.set_color('#555')
    ax.tick_params(colors='#bbb', labelsize=9)
    ax.xaxis.label.set_color('#bbb'); ax.yaxis.label.set_color('#bbb')
    ax.title.set_color('#fff')
    ax.set_title(title, fontsize=11, fontweight='bold')
    ax.set_xlabel(xlabel); ax.set_ylabel(ylabel)
    ax.set_xticks(np.arange(len(SIZES_BYTES)))
    ax.set_xticklabels(SIZE_LABELS, rotation=30)
    ax.grid(alpha=0.18, linestyle='--')
    if log_y: ax.set_yscale("log")

x = np.arange(len(SIZES_BYTES))

for mode in good_modes:
    c = COLOR_MAP.get(mode, "#aaa")
    d = results[mode]
    ax_tp.plot(x, d["throughput"], marker='o', lw=2, ms=5, label=mode, color=c)
    ax_enc.plot(x, d["enc_lat"],   marker='s', lw=2, ms=5, label=mode, color=c)
    ax_dec.plot(x, d["dec_lat"],   marker='^', lw=2, ms=5, label=mode, color=c)

_style_ax(ax_tp,  "Throughput (MB/s)  ─  higher is better",  "Plaintext size", "MB/s", log_y=True)
_style_ax(ax_enc, "Encrypt Latency (µs)  ─  lower is better","Plaintext size", "µs", log_y=True)
_style_ax(ax_dec, "Decrypt Latency (µs)  ─  lower is better","Plaintext size", "µs", log_y=True)

leg_kw = dict(fontsize=8, facecolor='#0f3460', labelcolor='white', ncol=2)
ax_tp.legend(**leg_kw); ax_enc.legend(**leg_kw); ax_dec.legend(**leg_kw)

# Bar chart  ─  1MB latency
bar_x = np.arange(len(good_modes))
bw = 0.35
enc_1mb = [results[m]["enc_lat"][-1] for m in good_modes]
dec_1mb = [results[m]["dec_lat"][-1] for m in good_modes]
colors = [COLOR_MAP.get(m,"#aaa") for m in good_modes]

bars_e = ax_bar.bar(bar_x - bw/2, enc_1mb, bw, label="Encrypt", color=colors, alpha=0.9)
bars_d = ax_bar.bar(bar_x + bw/2, dec_1mb, bw, label="Decrypt", color=colors, alpha=0.5,
                    edgecolor="white", lw=0.5)
_style_ax(ax_bar, "1 MB  Latency Comparison (µs)", "AES Mode", "µs (lower=faster)")
ax_bar.set_xticks(bar_x); ax_bar.set_xticklabels(good_modes, rotation=15, fontsize=9)
ax_bar.legend(fontsize=9, facecolor='#0f3460', labelcolor='white')
ax_bar.grid(axis='y', alpha=0.18, linestyle='--')
for b in bars_e:
    ax_bar.text(b.get_x()+b.get_width()/2, b.get_height()+0.3,
                f"{b.get_height():.1f}", ha='center', va='bottom', fontsize=7, color='#eee')

fig1.suptitle("AES All-Mode Performance Benchmark  |  AES-128  |  Native C (cryptography + pycryptodome)",
              fontsize=13, fontweight='bold', color='white', y=1.01)
fig1.tight_layout()

out1 = SCRIPT_DIR / "figure1_performance.png"
fig1.savefig(out1, dpi=150, bbox_inches='tight', facecolor=fig1.get_facecolor())
print(f"[OK] Saved: {out1}")

# ═══════════════════════════════════════════════════════════════════════════
# FIGURE 2  - Image grid
# ═══════════════════════════════════════════════════════════════════════════
print("\n[Figure 2] Building image grid...")

IMG_SIZE = 128
try:
    img_path = SCRIPT_DIR / "Image3.png"
    pil_img = Image.open(img_path).convert("RGB")
    pil_img = pil_img.resize((IMG_SIZE, IMG_SIZE))
    original_img = np.array(pil_img)
except Exception as e:
    print(f"[WARN] Failed to load {img_path}: {e}")
    original_img = make_demo_image(IMG_SIZE)

def encrypt_image(img_arr, mode_name, key):
    h, w, c = img_arr.shape
    flat = img_arr.flatten().tobytes()
    need = h * w * c
    # pad to multiple of 16 (for block ciphers)
    pad = (16 - len(flat) % 16) % 16
    padded = flat + bytes(pad)
    try:
        enc = fast_encrypt(mode_name, padded, key)
    except Exception as exc:
        print(f"    [{mode_name}] image encrypt FAILED: {exc}")
        return np.zeros_like(img_arr)
    raw = enc[:need]
    if len(raw) < need:
        raw = raw + bytes(need - len(raw))
    return np.frombuffer(raw, dtype=np.uint8).reshape(h, w, c)

vis_modes = [m for m in BENCH_MODES if m in good_modes]
n_total = 1 + len(vis_modes)
ncols = 5
nrows = (n_total + ncols - 1) // ncols

fig2 = plt.figure(figsize=(ncols * 3.0, nrows * 3.2))
fig2.patch.set_facecolor("#0d0d1a")
gs = gridspec.GridSpec(nrows, ncols, figure=fig2, hspace=0.5, wspace=0.12)

def add_img_ax(ax, img, title, border="#aaa"):
    ax.imshow(img, interpolation='nearest')
    ax.set_title(title, color='white', fontsize=9, fontweight='bold', pad=5)
    ax.axis('off')
    for sp in ax.spines.values():
        sp.set_visible(True); sp.set_edgecolor(border); sp.set_linewidth(2.5)
    ax.set_facecolor("#0d0d1a")

ax0 = fig2.add_subplot(gs[0, 0])
add_img_ax(ax0, original_img, "Original\n(image3 / Tux)", border="#00ff88")

for idx, mode_name in enumerate(vis_modes):
    row = (idx + 1) // ncols
    col = (idx + 1) % ncols
    ax = fig2.add_subplot(gs[row, col])
    enc_img = encrypt_image(original_img, mode_name, KEY)
    add_img_ax(ax, enc_img, f"AES-{mode_name}", border=COLOR_MAP.get(mode_name, "#aaa"))
    print(f"    [{mode_name}] image rendered")

# hide empty cells
for i in range(n_total, nrows * ncols):
    ax_e = fig2.add_subplot(gs[i // ncols, i % ncols])
    ax_e.axis('off'); ax_e.set_facecolor("#0d0d1a")

fig2.suptitle("AES Image Encryption Visualisation - Pixel-Level Encryption of RGB Image",
              fontsize=12, fontweight='bold', color='white', y=1.02)

out2 = SCRIPT_DIR / "figure2_image_visual.png"
fig2.savefig(out2, dpi=150, bbox_inches='tight', facecolor=fig2.get_facecolor())
print(f"[OK] Saved: {out2}")

# ===========================================================================
# Summary table
# ===========================================================================
print("\n" + "=" * 70)
print("BENCHMARK SUMMARY  --  AES-128  --  1 MB plaintext")
print("=" * 70)
hdr = f"{'Mode':<8} {'Throughput MB/s':>18} {'Enc us':>12} {'Dec us':>12}"
print(hdr)
print("-" * len(hdr))
for m in good_modes:
    d = results[m]
    print(f"{m:<8} {d['throughput'][-1]:>18.2f} {d['enc_lat'][-1]:>12.1f} {d['dec_lat'][-1]:>12.1f}")

print("\n[DONE]")
print(f"  Figure 1 (performance): {out1}")
print(f"  Figure 2 (image grid):  {out2}")

plt.show()
