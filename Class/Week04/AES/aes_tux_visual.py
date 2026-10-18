# -*- coding: utf-8 -*-
"""
aes_tux_visual.py
=================
Minh hoa ma hoa AES pixel-level tren hinh Tux (Linux penguin) THAT.

- Load hinh tux_original.png (500x593 RGBA)
- Ma hoa toan bo pixel data bang 10 AES mode
- Ve luoi so sanh: original + 10 anh ma hoa
- Luu figure2_tux_visual.png

Backend: cryptography + pycryptodome (native C, fast)
"""

from __future__ import annotations
import sys, os, secrets, warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=DeprecationWarning)

SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

# ── libs ────────────────────────────────────────────────────────────────────
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.patches import FancyBboxPatch
from PIL import Image

print("[OK] numpy, matplotlib, Pillow loaded")

# ── cryptography / pycryptodome ─────────────────────────────────────────────
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as crypt_modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM
from cryptography.hazmat.backends import default_backend
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
    _HAVE_SIV = True
except ImportError:
    _HAVE_SIV = False

try:
    from Crypto.Cipher import AES as _PyAES
    _HAVE_PYCRYPTO = True
except ImportError:
    _HAVE_PYCRYPTO = False

print(f"[OK] cryptography | pycryptodome={'yes' if _HAVE_PYCRYPTO else 'no'} | SIV={'yes' if _HAVE_SIV else 'no'}")

# ── Load REAL Tux image ──────────────────────────────────────────────────────
TUX_PATH = SCRIPT_DIR / "tux_original.png"
if not TUX_PATH.exists():
    print(f"[ERROR] {TUX_PATH} not found. Please run the download step first.")
    sys.exit(1)

# Load with RGBA, then composite onto WHITE background for clean visualization
tux_rgba = Image.open(TUX_PATH).convert("RGBA")
# Resize to manageable size while keeping aspect ratio
MAX_W = 320
w, h = tux_rgba.size
scale = MAX_W / w
new_w, new_h = MAX_W, int(h * scale)
tux_rgba = tux_rgba.resize((new_w, new_h), Image.LANCZOS)

# White background composite (for display)
bg_white = Image.new("RGBA", tux_rgba.size, (255, 255, 255, 255))
tux_rgb_white = Image.alpha_composite(bg_white, tux_rgba).convert("RGB")

# Also keep the raw RGBA array for encryption
tux_arr_rgb = np.array(tux_rgb_white)   # shape: (H, W, 3), dtype uint8

print(f"[OK] Tux image loaded: {tux_arr_rgb.shape} (H x W x 3 RGB)")

# ── AES key (fixed for reproducibility) ────────────────────────────────────
KEY = secrets.token_bytes(16)  # AES-128, random per run (realistic demo)
print(f"[KEY] AES-128 key: {KEY.hex()[:16]}... (random)")

# ── Encrypt/Decrypt helpers ─────────────────────────────────────────────────
def _pad16(data: bytes) -> bytes:
    n = 16 - len(data) % 16
    return data + bytes([n] * n)

def encrypt_pixels(mode_name: str, pixel_bytes: bytes, key: bytes) -> bytes:
    """Encrypt raw pixel bytes with given AES mode. Returns encrypted bytes."""
    
    if mode_name == "ECB":
        padded = _pad16(pixel_bytes)
        enc = Cipher(algorithms.AES(key), crypt_modes.ECB(), backend=default_backend()).encryptor()
        return enc.update(padded) + enc.finalize()

    elif mode_name == "CBC":
        iv = secrets.token_bytes(16)
        padded = _pad16(pixel_bytes)
        enc = Cipher(algorithms.AES(key), crypt_modes.CBC(iv), backend=default_backend()).encryptor()
        ct = enc.update(padded) + enc.finalize()
        return ct  # IV không prepend để giữ kích thước

    elif mode_name == "CFB":
        iv = secrets.token_bytes(16)
        try:
            from cryptography.hazmat.decrepit.ciphers.modes import CFB
        except ImportError:
            CFB = crypt_modes.CFB
        enc = Cipher(algorithms.AES(key), CFB(iv), backend=default_backend()).encryptor()
        return enc.update(pixel_bytes) + enc.finalize()

    elif mode_name == "OFB":
        iv = secrets.token_bytes(16)
        try:
            from cryptography.hazmat.decrepit.ciphers.modes import OFB
        except ImportError:
            OFB = crypt_modes.OFB
        enc = Cipher(algorithms.AES(key), OFB(iv), backend=default_backend()).encryptor()
        return enc.update(pixel_bytes) + enc.finalize()

    elif mode_name == "CTR":
        nonce = secrets.token_bytes(16)
        enc = Cipher(algorithms.AES(key), crypt_modes.CTR(nonce), backend=default_backend()).encryptor()
        return enc.update(pixel_bytes) + enc.finalize()

    elif mode_name == "GCM":
        nonce = secrets.token_bytes(12)
        encryptor = Cipher(algorithms.AES(key), crypt_modes.GCM(nonce), backend=default_backend()).encryptor()
        ct = encryptor.update(pixel_bytes) + encryptor.finalize()
        return ct  # skip tag for pixel display

    elif mode_name == "EAX":
        if _HAVE_PYCRYPTO:
            cipher = _PyAES.new(key, _PyAES.MODE_EAX)
            ct, _ = cipher.encrypt_and_digest(pixel_bytes)
            return ct
        else:
            nonce = secrets.token_bytes(12)
            encryptor = Cipher(algorithms.AES(key), crypt_modes.GCM(nonce), backend=default_backend()).encryptor()
            ct = encryptor.update(pixel_bytes) + encryptor.finalize()
            return ct

    elif mode_name == "CCM":
        # CCM needs small data or chunked -- use pycryptodome for simplicity
        if _HAVE_PYCRYPTO:
            nonce = secrets.token_bytes(11)
            cipher = _PyAES.new(key, _PyAES.MODE_CCM, nonce=nonce, mac_len=4)
            ct, _ = cipher.encrypt_and_digest(pixel_bytes)
            return ct
        else:
            nonce = secrets.token_bytes(11)
            aesccm = AESCCM(key, tag_length=4)
            # AESCCM has data size limits; chunk if needed
            try:
                ct = aesccm.encrypt(nonce, pixel_bytes, None)
                return ct[:len(pixel_bytes)]
            except Exception:
                nonce2 = secrets.token_bytes(12)
                encryptor = Cipher(algorithms.AES(key), crypt_modes.GCM(nonce2), backend=default_backend()).encryptor()
                return encryptor.update(pixel_bytes) + encryptor.finalize()

    elif mode_name == "SIV":
        if _HAVE_SIV:
            nonce = secrets.token_bytes(12)
            siv = AESGCMSIV(key)
            ct = siv.encrypt(nonce, pixel_bytes, None)
            return ct[:len(pixel_bytes)]
        else:
            # fallback: GCM
            nonce = secrets.token_bytes(12)
            encryptor = Cipher(algorithms.AES(key), crypt_modes.GCM(nonce), backend=default_backend()).encryptor()
            ct = encryptor.update(pixel_bytes) + encryptor.finalize()
            return ct

    elif mode_name == "OCB":
        if _HAVE_PYCRYPTO:
            cipher = _PyAES.new(key, _PyAES.MODE_OCB)
            ct, _ = cipher.encrypt_and_digest(pixel_bytes)
            return ct
        else:
            nonce = secrets.token_bytes(12)
            encryptor = Cipher(algorithms.AES(key), crypt_modes.GCM(nonce), backend=default_backend()).encryptor()
            ct = encryptor.update(pixel_bytes) + encryptor.finalize()
            return ct

    raise ValueError(f"Unknown mode: {mode_name}")


def make_encrypted_image(img_arr: np.ndarray, mode_name: str, key: bytes) -> np.ndarray:
    """
    Encrypt the RGB pixel bytes of img_arr using the given AES mode.
    Returns a numpy array of same shape (H, W, 3) with encrypted pixel values.
    """
    H, W, C = img_arr.shape
    total_pixels = H * W * C  # = H*W*3 bytes

    flat_bytes = img_arr.flatten().tobytes()  # raw RGB bytes

    try:
        enc_bytes = encrypt_pixels(mode_name, flat_bytes, key)
    except Exception as exc:
        print(f"    [{mode_name}] FAILED: {exc}")
        return np.zeros_like(img_arr)

    # Take exactly H*W*C bytes for reconstruction
    enc_bytes = enc_bytes[:total_pixels]
    if len(enc_bytes) < total_pixels:
        enc_bytes = enc_bytes + bytes(total_pixels - len(enc_bytes))

    return np.frombuffer(enc_bytes, dtype=np.uint8).reshape(H, W, C)


# ── Modes to visualize ───────────────────────────────────────────────────────
MODES = ["ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "EAX", "CCM", "SIV", "OCB"]

# Mode descriptions for annotation
MODE_DESC = {
    "ECB": "Electronic Codebook\n[INSECURE - pattern leak!]",
    "CBC": "Cipher Block Chaining\n[Confidential only]",
    "CFB": "Cipher Feedback\n[Confidential only]",
    "OFB": "Output Feedback\n[Confidential only]",
    "CTR": "Counter Mode\n[Confidential only]",
    "GCM": "Galois/Counter Mode\n[AEAD - Authenticated]",
    "EAX": "EAX Mode\n[AEAD - Authenticated]",
    "CCM": "CCM Mode\n[AEAD - Authenticated]",
    "SIV": "GCM-SIV\n[AEAD - Misuse-resistant]",
    "OCB": "OCB Mode\n[AEAD - Authenticated]",
}

MODE_SECURITY = {
    "ECB": "INSECURE",
    "CBC": "Confidential",
    "CFB": "Confidential",
    "OFB": "Confidential",
    "CTR": "Confidential",
    "GCM": "AEAD",
    "EAX": "AEAD",
    "CCM": "AEAD",
    "SIV": "AEAD",
    "OCB": "AEAD",
}

BORDER_COLOR = {
    "ECB": "#ff2222",       # RED = danger/insecure
    "CBC": "#f39c12",
    "CFB": "#e67e22",
    "OFB": "#f1c40f",
    "CTR": "#2ecc71",
    "GCM": "#3498db",
    "EAX": "#9b59b6",
    "CCM": "#1abc9c",
    "SIV": "#e91e63",
    "OCB": "#ff5722",
}

LABEL_BG = {
    "ECB": "#5a0000",
    "CBC": "#4a3000",
    "CFB": "#4a2800",
    "OFB": "#4a4000",
    "CTR": "#003a1a",
    "GCM": "#00264a",
    "EAX": "#2a1a4a",
    "CCM": "#004a3a",
    "SIV": "#4a0030",
    "OCB": "#4a1a00",
}

print("\n[Encrypting Tux with all 10 AES modes...]")
encrypted_images = {}
for mode in MODES:
    enc = make_encrypted_image(tux_arr_rgb, mode, KEY)
    encrypted_images[mode] = enc
    # Check if ECB leaks structure (it should)
    correlation = np.corrcoef(tux_arr_rgb.flatten()[:1000], enc.flatten()[:1000])[0,1]
    print(f"  [{mode:4s}] done | pixel correlation with original: {correlation:+.4f}")


# ── FIGURE: Original + 10 encrypted ─────────────────────────────────────────
print("\n[Building visualization figure...]")

# Layout: 1 row for original (full height), 2 rows x 5 cols for encrypted
# Better: 3 rows x 4 cols = 12 cells (1 original + 10 encrypted + 1 legend)
NCOLS = 4
NROWS = 3  # 3*4=12, we need 11

fig = plt.figure(figsize=(NCOLS * 4.5, NROWS * 6.0))
fig.patch.set_facecolor("#0a0a14")

# Title
fig.text(0.5, 0.98,
         "AES Pixel Encryption Visualisation on Linux Tux Penguin",
         ha='center', va='top', fontsize=17, fontweight='bold', color='white',
         fontfamily='DejaVu Sans')
fig.text(0.5, 0.955,
         "AES-128  |  RGB pixel data encrypted block by block  |  Each mode produces different visual output",
         ha='center', va='top', fontsize=10, color='#aaaaaa')

# Add colored security level legend at bottom
fig.text(0.15, 0.012, "Border Color Key:", ha='left', fontsize=9, color='#aaa')
fig.text(0.30, 0.012, "RED = INSECURE (ECB)",    ha='left', fontsize=9, color='#ff4444', fontweight='bold')
fig.text(0.50, 0.012, "ORANGE/YELLOW = Confidential only",  ha='left', fontsize=9, color='#f39c12')
fig.text(0.73, 0.012, "BLUE/TEAL/PURPLE = AEAD (Authenticated)", ha='left', fontsize=9, color='#3498db')

# Grid: row0=original(span) + first 3 modes, row1=4 modes, row2=3 modes + caption
gs = gridspec.GridSpec(NROWS, NCOLS,
                        figure=fig,
                        top=0.94, bottom=0.04,
                        left=0.02, right=0.98,
                        hspace=0.30, wspace=0.08)

def draw_image_cell(ax, img_arr, title, subtitle, border_color, bg_color, is_original=False):
    """Draw an image in an axes with styled border and title."""
    ax.set_facecolor(bg_color)
    ax.imshow(img_arr, interpolation='lanczos' if is_original else 'nearest', aspect='auto')

    # Styled title bar
    title_color = '#00ff88' if is_original else 'white'
    title_size = 11 if is_original else 10

    ax.set_title(title, color=title_color, fontsize=title_size, fontweight='bold',
                 pad=6, loc='center')

    # Subtitle annotation inside plot
    ax.text(0.5, 0.02, subtitle,
            transform=ax.transAxes,
            ha='center', va='bottom',
            fontsize=7.5, color='#dddddd',
            bbox=dict(facecolor=bg_color, alpha=0.85, pad=2, edgecolor='none'),
            linespacing=1.4)

    ax.axis('off')

    # Draw colored border
    for spine in ax.spines.values():
        spine.set_visible(True)
        spine.set_edgecolor(border_color)
        spine.set_linewidth(3.5 if is_original else 2.5)

# ── Row 0, Col 0: ORIGINAL (tall, spanning) ─────────────────────────────────
# Use the first column of rows 0+1 for the original (larger display)
ax_orig = fig.add_subplot(gs[0:2, 0])
draw_image_cell(ax_orig,
    tux_arr_rgb,
    "ORIGINAL  (Tux Penguin)",
    f"Linux mascot | {tux_arr_rgb.shape[1]}x{tux_arr_rgb.shape[0]} px | RGB\nUnencrypted - all detail visible",
    "#00ff88", "#04150b",
    is_original=True)

# ── Encrypted modes ──────────────────────────────────────────────────────────
# Layout of 10 modes in remaining cells:
# Row 0: cols 1,2,3  -> modes ECB, CBC, CFB
# Row 1: cols 1,2,3  -> modes OFB, CTR, GCM
# Row 2: cols 0,1,2,3 -> modes EAX, CCM, SIV, OCB

positions = [
    (0, 1), (0, 2), (0, 3),   # ECB CBC CFB
    (1, 1), (1, 2), (1, 3),   # OFB CTR GCM
    (2, 0), (2, 1), (2, 2), (2, 3),  # EAX CCM SIV OCB
]

for idx, mode in enumerate(MODES):
    row, col = positions[idx]
    ax = fig.add_subplot(gs[row, col])

    enc_img = encrypted_images[mode]
    security = MODE_SECURITY[mode]
    desc = MODE_DESC[mode]
    border = BORDER_COLOR[mode]
    bg = LABEL_BG[mode]

    # Build subtitle
    if mode == "ECB":
        subtitle = f"{desc}\n⚠ PATTERN VISIBLE - NOT SECURE"
    else:
        subtitle = f"{desc}\nPixel data: fully randomized"

    title_prefix = "⚠ " if mode == "ECB" else ("✓ " if security == "AEAD" else "○ ")
    draw_image_cell(ax, enc_img,
                    f"{title_prefix}AES-{mode}",
                    subtitle,
                    border, bg)

# ── Save figure ──────────────────────────────────────────────────────────────
out_path = SCRIPT_DIR / "figure2_tux_visual.png"
fig.savefig(out_path, dpi=150, bbox_inches='tight',
            facecolor=fig.get_facecolor(), edgecolor='none')

print(f"\n[OK] Saved: {out_path}")
print("     Open the file to see:")
print("     - ECB: still shows penguin outline (INSECURE!)")
print("     - All other modes: pure noise (secure)")
