# -*- coding: utf-8 -*-
"""
AESVisual_all_modes_rgb.py

RGB image visualizer and file container for AES modes.

Revision from AESVisual.py:
    - Converts images to RGB instead of grayscale.
    - Supports the revised AES mode set:
        ECB, CBC, CFB, OFB, CTR, GCM, GMAC, CCM, GCM-SIV, XTS, KW, KWP.
    - Supports separate operations:
        * encrypt-image / decrypt-image for image-encryption modes
        * gmac-generate / gmac-verify for GMAC over RGB image bytes
        * wrap / unwrap for KW/KWP key material
    - Can display the original RGB image beside the encrypted RGB visualization.
    - Can save the full encrypted image container and decrypt it later.

Expected AES backend:
    from mypackages import modes
or local fallback:
    import AES_modes_revised as modes

Notes:
    - ECB is intentionally kept for teaching because it reveals visual patterns.
    - CBC/CFB/OFB/CTR/XTS do not authenticate ciphertexts.
    - Prefer GCM/CCM/GCM-SIV for authenticated image/file encryption.
    - GMAC authenticates image bytes but does not encrypt them, so no cipher image is produced.
    - KW/KWP are key-wrapping modes and are not image-encryption modes.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import struct
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import matplotlib.pyplot as plt
import numpy as np
from PIL import Image

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.append(os.getcwd())

NORMAL_AES_KEY_LENGTHS = (16, 24, 32)
XTS_AES_KEY_LENGTHS = (32, 64)
CLASSIC_IV_MODES = {"CBC", "CFB", "OFB", "CTR"}
AEAD_MODES = {"GCM", "CCM", "GCM-SIV"}
AEAD_NONCE_12_MODES = {"GCM", "GMAC", "GCM-SIV"}
IMAGE_ENCRYPTION_MODES = {"ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "CCM", "GCM-SIV", "XTS"}
ALL_MODES = IMAGE_ENCRYPTION_MODES | {"GMAC", "KW", "KWP"}

OP_ENCRYPT_IMAGE = "ENCRYPT-IMAGE"
OP_DECRYPT_IMAGE = "DECRYPT-IMAGE"
OP_GMAC_GENERATE = "GMAC-GENERATE"
OP_GMAC_VERIFY = "GMAC-VERIFY"
OP_WRAP = "WRAP"
OP_UNWRAP = "UNWRAP"

MAGIC = b"AESIMG2\x00"
HEADER_LEN_STRUCT = struct.Struct(">I")
DEFAULT_TAG_LENGTH = 16


# -----------------------------------------------------------------------------
# AES backend loading
# -----------------------------------------------------------------------------
def load_modes_module():
    """Load AES modes backend while preserving the classroom project layout."""
    try:
        from mypackages import modes as modes_module  # type: ignore
        return modes_module
    except Exception:
        try:
            import AES_modes_revised as modes_module  # type: ignore
            return modes_module
        except Exception:
            try:
                import modes as modes_module  # type: ignore
                return modes_module
            except Exception as exc:
                raise ImportError(
                    "Cannot import AES modes backend. Put revised modes.py in mypackages/, "
                    "or place AES_modes_revised.py plus AES.py beside this script."
                ) from exc


def new_aes_modes(key: bytes, *, verbose: bool = False):
    modes_module = load_modes_module()
    if hasattr(modes_module, "AESModes"):
        return modes_module.AESModes(key, verbose=verbose)
    try:
        return modes_module.modes(key, verbose=verbose)
    except TypeError:
        return modes_module.modes(key)


# -----------------------------------------------------------------------------
# Normalization, parsing, validation
# -----------------------------------------------------------------------------
def normalize_mode(mode: str) -> str:
    value = mode.strip().upper().replace("AES-", "").replace("_", "-").replace(" ", "")
    aliases = {
        "GCMSIV": "GCM-SIV",
        "GCM-SIV": "GCM-SIV",
        "GMAC": "GMAC",
        "KEYWRAP": "KW",
        "KEY-WRAP": "KW",
        "AESKW": "KW",
        "KW": "KW",
        "KEYWRAPPAD": "KWP",
        "KEY-WRAP-PAD": "KWP",
        "AESKWP": "KWP",
        "KWP": "KWP",
    }
    return aliases.get(value, value)


def normalize_operation(operation: str, mode: str) -> str:
    raw = operation.strip().upper().replace("_", "-").replace(" ", "-")
    aliases = {
        "E": OP_ENCRYPT_IMAGE,
        "ENC": OP_ENCRYPT_IMAGE,
        "ENCRYPT": OP_ENCRYPT_IMAGE,
        "ENCRYPTION": OP_ENCRYPT_IMAGE,
        "ENCRYPT-IMAGE": OP_ENCRYPT_IMAGE,
        "IMAGE-ENCRYPT": OP_ENCRYPT_IMAGE,
        "D": OP_DECRYPT_IMAGE,
        "DEC": OP_DECRYPT_IMAGE,
        "DECRYPT": OP_DECRYPT_IMAGE,
        "DECRYPTION": OP_DECRYPT_IMAGE,
        "DECRYPT-IMAGE": OP_DECRYPT_IMAGE,
        "IMAGE-DECRYPT": OP_DECRYPT_IMAGE,
        "TAG": OP_GMAC_GENERATE,
        "GENERATE": OP_GMAC_GENERATE,
        "GMAC": OP_GMAC_GENERATE,
        "GMAC-GENERATE": OP_GMAC_GENERATE,
        "VERIFY": OP_GMAC_VERIFY,
        "GMAC-VERIFY": OP_GMAC_VERIFY,
        "WRAP": OP_WRAP,
        "UNWRAP": OP_UNWRAP,
    }
    op = aliases.get(raw, raw)

    # Natural mapping for special modes.
    if mode == "GMAC" and op == OP_ENCRYPT_IMAGE:
        return OP_GMAC_GENERATE
    if mode == "GMAC" and op == OP_DECRYPT_IMAGE:
        return OP_GMAC_VERIFY
    if mode in {"KW", "KWP"} and op == OP_ENCRYPT_IMAGE:
        return OP_WRAP
    if mode in {"KW", "KWP"} and op == OP_DECRYPT_IMAGE:
        return OP_UNWRAP
    return op


def require_lengths(data: bytes, lengths: Tuple[int, ...], name: str) -> bytes:
    if len(data) not in lengths:
        options = ", ".join(str(n) for n in lengths)
        raise ValueError(f"{name} must be exactly one of these byte lengths: {options}. Got {len(data)}.")
    return data


def require_min_len(data: bytes, min_len: int, name: str) -> bytes:
    if len(data) < min_len:
        raise ValueError(f"{name} must be at least {min_len} byte(s). Got {len(data)}.")
    return data


def require_range(data: bytes, min_len: int, max_len: int, name: str) -> bytes:
    if not (min_len <= len(data) <= max_len):
        raise ValueError(f"{name} must be {min_len}..{max_len} bytes. Got {len(data)}.")
    return data


def parse_text_or_hex(value: str, *, name: str, default_format: str = "text") -> bytes:
    """
    Friendly byte parser:
        hex:001122... -> raw bytes
        text:hello    -> UTF-8 bytes for hello
        R/random      -> handled by caller
        otherwise     -> default_format decides text or hex
    """
    raw = value
    stripped = raw.strip()
    lower = stripped.lower()
    if lower.startswith("hex:"):
        compact = "".join(stripped[4:].split())
        try:
            return bytes.fromhex(compact)
        except ValueError as exc:
            raise ValueError(f"{name} is not valid hex.") from exc
    if lower.startswith("text:"):
        return raw[5:].encode("utf-8")
    if default_format == "hex":
        compact = "".join(stripped.split())
        try:
            return bytes.fromhex(compact)
        except ValueError as exc:
            raise ValueError(f"{name} is not valid hex. Use hex:001122... or plain hex.") from exc
    if default_format == "text":
        return raw.encode("utf-8")
    raise ValueError("default_format must be text or hex.")


def decode_bytes_for_display(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return f"<non-UTF8 bytes: {data.hex()}>"


def print_bytes(label: str, data: bytes, *, max_hex: int = 128) -> None:
    hex_value = data.hex()
    if len(hex_value) > max_hex:
        hex_value = hex_value[:max_hex] + f"... <{len(data)} byte(s) total>"
    print(f"{label} length: {len(data)} byte(s)")
    print(f"{label} hex   : {hex_value}\n")


# -----------------------------------------------------------------------------
# Interactive helpers
# -----------------------------------------------------------------------------
def ask_raw(prompt: str, *, allow_empty: bool = False) -> str:
    while True:
        value = input(prompt)
        if value or allow_empty:
            return value
        print("Input cannot be empty.")


def ask_yes_no(prompt: str, *, default: Optional[bool] = None) -> bool:
    while True:
        suffix = " [y/n]"
        if default is True:
            suffix = " [Y/n]"
        elif default is False:
            suffix = " [y/N]"
        raw = ask_raw(f"{prompt}{suffix}: ", allow_empty=default is not None).strip().lower()
        if raw == "" and default is not None:
            return default
        if raw in {"y", "yes", "1", "true", "t", "co", "có"}:
            return True
        if raw in {"n", "no", "0", "false", "f", "khong", "không"}:
            return False
        print("Please enter y or n.")


def ask_int(label: str, *, default: Optional[int] = None, allowed: Optional[Tuple[int, ...]] = None) -> int:
    while True:
        suffix = f" [{default}]" if default is not None else ""
        raw = ask_raw(f"{label}{suffix}: ", allow_empty=default is not None).strip()
        if raw == "" and default is not None:
            value = default
        else:
            try:
                value = int(raw)
            except ValueError:
                print("Please enter an integer.")
                continue
        if allowed is not None and value not in allowed:
            print("Allowed values:", ", ".join(str(x) for x in allowed))
            continue
        return value


def ask_data(
    label: str,
    *,
    default_format: str = "text",
    allowed_lengths: Optional[Tuple[int, ...]] = None,
    min_len: Optional[int] = None,
    max_len: Optional[int] = None,
    allow_empty: bool = False,
    allow_random: bool = False,
    random_length: Optional[int] = None,
) -> bytes:
    while True:
        notes = []
        if default_format == "text":
            notes.append("type text directly")
            notes.append("use hex:001122... for raw bytes")
        else:
            notes.append("hex bytes")
            notes.append("or use text:hello for UTF-8")
        if allow_random:
            notes.append("R=random")
        raw = ask_raw(f"{label} [{'; '.join(notes)}]: ", allow_empty=allow_empty)
        if allow_random and raw.strip().lower() in {"r", "random"}:
            if random_length is None:
                raise ValueError("random_length must be provided when random generation is allowed.")
            value = secrets.token_bytes(random_length)
            print_bytes(f"Generated {label}", value)
            return value
        try:
            value = parse_text_or_hex(raw, name=label, default_format=default_format)
            if allowed_lengths is not None:
                require_lengths(value, allowed_lengths, label)
            if min_len is not None:
                require_min_len(value, min_len, label)
            if max_len is not None and len(value) > max_len:
                raise ValueError(f"{label} must be at most {max_len} bytes. Got {len(value)}.")
            return value
        except ValueError as exc:
            print(f"Invalid input: {exc}")


def value_from_cli_or_prompt(
    *,
    cli_value: Optional[str],
    label: str,
    default_format: str = "text",
    allowed_lengths: Optional[Tuple[int, ...]] = None,
    min_len: Optional[int] = None,
    max_len: Optional[int] = None,
    allow_empty: bool = False,
    allow_random: bool = False,
    random_length: Optional[int] = None,
) -> bytes:
    if cli_value is None:
        return ask_data(
            label,
            default_format=default_format,
            allowed_lengths=allowed_lengths,
            min_len=min_len,
            max_len=max_len,
            allow_empty=allow_empty,
            allow_random=allow_random,
            random_length=random_length,
        )
    if allow_random and cli_value.strip().lower() in {"r", "random"}:
        if random_length is None:
            raise ValueError("random_length must be provided when random generation is allowed.")
        value = secrets.token_bytes(random_length)
        print_bytes(f"Generated {label}", value)
    else:
        value = parse_text_or_hex(cli_value, name=label, default_format=default_format)
    if allowed_lengths is not None:
        require_lengths(value, allowed_lengths, label)
    if min_len is not None:
        require_min_len(value, min_len, label)
    if max_len is not None and len(value) > max_len:
        raise ValueError(f"{label} must be at most {max_len} bytes. Got {len(value)}.")
    return value


# -----------------------------------------------------------------------------
# Image and container helpers
# -----------------------------------------------------------------------------
def load_rgb_image(path: str) -> Tuple[Image.Image, bytes, int, int]:
    image = Image.open(path).convert("RGB")
    width, height = image.size
    raw = image.tobytes()
    return image, raw, width, height


def raw_rgb_to_image(raw: bytes, width: int, height: int) -> Image.Image:
    expected = width * height * 3
    if len(raw) != expected:
        raise ValueError(f"RGB raw data must be {expected} bytes for {width}x{height}; got {len(raw)}.")
    return Image.frombytes("RGB", (width, height), raw)


def bytes_to_rgb_visual(data: bytes, width: int, height: int) -> Image.Image:
    needed = width * height * 3
    visual = data
    if len(visual) < needed:
        visual = visual + (b"\x00" * (needed - len(visual)))
    elif len(visual) > needed:
        visual = visual[:needed]
    return Image.frombytes("RGB", (width, height), visual)


def show_side_by_side(original: Image.Image, cipher_visual: Image.Image, title: str) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(12, 6))
    axes[0].imshow(original)
    axes[0].set_title("Original RGB")
    axes[0].axis("off")
    axes[1].imshow(cipher_visual)
    axes[1].set_title(title)
    axes[1].axis("off")
    plt.tight_layout()
    plt.show()


def show_single_image(image: Image.Image, title: str) -> None:
    plt.figure(figsize=(7, 7))
    plt.imshow(image)
    plt.title(title)
    plt.axis("off")
    plt.tight_layout()
    plt.show()


def save_container(path: str, header: Dict[str, Any], payload: bytes) -> None:
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with open(path, "wb") as f:
        f.write(MAGIC)
        f.write(HEADER_LEN_STRUCT.pack(len(header_bytes)))
        f.write(header_bytes)
        f.write(payload)


def load_container(path: str) -> Tuple[Dict[str, Any], bytes]:
    with open(path, "rb") as f:
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Not an AES RGB image container produced by this script.")
        header_len_data = f.read(HEADER_LEN_STRUCT.size)
        if len(header_len_data) != HEADER_LEN_STRUCT.size:
            raise ValueError("Corrupt container: missing header length.")
        header_len = HEADER_LEN_STRUCT.unpack(header_len_data)[0]
        header_bytes = f.read(header_len)
        if len(header_bytes) != header_len:
            raise ValueError("Corrupt container: incomplete header.")
        header = json.loads(header_bytes.decode("utf-8"))
        payload = f.read()
    return header, payload


def select_cipher_visual_bytes(mode: str, full_output: bytes, *, raw_len: int, nonce_length: int, tag_length: int) -> bytes:
    """Select the ciphertext bytes that should be rendered as an RGB visual."""
    if mode in {"CBC", "CFB", "OFB", "CTR"}:
        # Output layout from revised modes layer: IV/counter || ciphertext body.
        return full_output[16:]
    if mode in {"GCM", "GCM-SIV"}:
        # Output layout: 12-byte nonce || ciphertext || 16-byte tag.
        return full_output[12:-16]
    if mode == "CCM":
        # Output layout: nonce || ciphertext || tag.
        return full_output[nonce_length:-tag_length]
    return full_output[:raw_len]


# -----------------------------------------------------------------------------
# AES mode operations
# -----------------------------------------------------------------------------
def build_constructor_key(mode: str, key: Optional[bytes], xts_key: Optional[bytes]) -> bytes:
    if mode == "XTS":
        if xts_key is None:
            raise ValueError("XTS requires a double-length XTS key.")
        require_lengths(xts_key, XTS_AES_KEY_LENGTHS, "XTS key")
        return xts_key[: len(xts_key) // 2]
    if key is None:
        raise ValueError("AES key is required.")
    require_lengths(key, NORMAL_AES_KEY_LENGTHS, "AES key")
    return key


def encrypt_image_bytes(
    mode: str,
    raw: bytes,
    *,
    key: Optional[bytes],
    xts_key: Optional[bytes],
    iv: Optional[bytes],
    nonce: Optional[bytes],
    tweak: Optional[bytes],
    aad: bytes,
    cfb_segment_size: int,
    ccm_tag_length: int,
    verbose: bool,
) -> Tuple[bytes, int, int]:
    constructor_key = build_constructor_key(mode, key, xts_key)
    aes_mode = new_aes_modes(constructor_key, verbose=verbose)

    if mode == "ECB":
        return aes_mode.ecb_encrypt(raw), 0, 16
    if mode == "CBC":
        require_lengths(iv or b"", (16,), "CBC IV")
        return aes_mode.cbc_encrypt(raw, iv=iv, prepend_iv=True), 0, 16
    if mode == "CFB":
        require_lengths(iv or b"", (16,), "CFB IV")
        return aes_mode.cfb_encrypt(raw, iv=iv, segment_size=cfb_segment_size, prepend_iv=True), 0, 16
    if mode == "OFB":
        require_lengths(iv or b"", (16,), "OFB IV")
        return aes_mode.ofb_encrypt(raw, iv=iv, prepend_iv=True), 0, 16
    if mode == "CTR":
        require_lengths(iv or b"", (16,), "CTR counter block")
        return aes_mode.ctr_encrypt(raw, iv=iv, prepend_iv=True), 0, 16
    if mode == "GCM":
        require_lengths(nonce or b"", (12,), "GCM nonce")
        return aes_mode.gcm_encrypt(raw, associated_data=aad or None, nonce=nonce, prepend_nonce=True), 12, 16
    if mode == "CCM":
        require_range(nonce or b"", 7, 13, "CCM nonce")
        return aes_mode.ccm_encrypt(
            raw,
            associated_data=aad or None,
            nonce=nonce,
            tag_length=ccm_tag_length,
            prepend_nonce=True,
        ), len(nonce or b""), ccm_tag_length
    if mode == "GCM-SIV":
        require_lengths(nonce or b"", (12,), "GCM-SIV nonce")
        return aes_mode.gcm_siv_encrypt(raw, associated_data=aad or None, nonce=nonce, prepend_nonce=True), 12, 16
    if mode == "XTS":
        require_lengths(xts_key or b"", XTS_AES_KEY_LENGTHS, "XTS key")
        require_lengths(tweak or b"", (16,), "XTS tweak")
        require_min_len(raw, 16, "RGB image raw data")
        return aes_mode.xts_encrypt(raw, xts_key=xts_key, tweak=tweak), 0, 16
    raise ValueError(f"{mode} is not an image-encryption mode.")


def decrypt_image_bytes(
    mode: str,
    payload: bytes,
    *,
    key: Optional[bytes],
    xts_key: Optional[bytes],
    tweak: Optional[bytes],
    aad: bytes,
    cfb_segment_size: int,
    ccm_nonce_length: int,
    ccm_tag_length: int,
    verbose: bool,
) -> bytes:
    constructor_key = build_constructor_key(mode, key, xts_key)
    aes_mode = new_aes_modes(constructor_key, verbose=verbose)

    if mode == "ECB":
        return aes_mode.ecb_decrypt(payload, output_encoding=None)
    if mode == "CBC":
        return aes_mode.cbc_decrypt(payload, has_iv=True, output_encoding=None)
    if mode == "CFB":
        return aes_mode.cfb_decrypt(payload, has_iv=True, segment_size=cfb_segment_size, output_encoding=None)
    if mode == "OFB":
        return aes_mode.ofb_decrypt(payload, has_iv=True, output_encoding=None)
    if mode == "CTR":
        return aes_mode.ctr_decrypt(payload, has_iv=True, output_encoding=None)
    if mode == "GCM":
        return aes_mode.gcm_decrypt(payload, associated_data=aad or None, has_nonce=True, output_encoding=None)
    if mode == "CCM":
        return aes_mode.ccm_decrypt(
            payload,
            associated_data=aad or None,
            has_nonce=True,
            nonce_length=ccm_nonce_length,
            tag_length=ccm_tag_length,
            output_encoding=None,
        )
    if mode == "GCM-SIV":
        return aes_mode.gcm_siv_decrypt(payload, associated_data=aad or None, has_nonce=True, output_encoding=None)
    if mode == "XTS":
        require_lengths(xts_key or b"", XTS_AES_KEY_LENGTHS, "XTS key")
        require_lengths(tweak or b"", (16,), "XTS tweak")
        return aes_mode.xts_decrypt(payload, xts_key=xts_key, tweak=tweak, output_encoding=None)
    raise ValueError(f"{mode} is not an image-decryption mode.")


# -----------------------------------------------------------------------------
# High-level operations
# -----------------------------------------------------------------------------
def run_encrypt_image(args: argparse.Namespace, mode: str) -> None:
    if mode not in IMAGE_ENCRYPTION_MODES:
        raise ValueError(f"{mode} does not encrypt RGB images. Use GMAC generate/verify or KW/KWP wrap/unwrap.")

    image_path = args.image or ask_raw("Input RGB image path: ").strip()
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Image file does not exist: {image_path}")

    image, raw, width, height = load_rgb_image(image_path)
    print(f"Loaded RGB image: {image_path}")
    print(f"Size: {width}x{height}; raw RGB bytes: {len(raw)}\n")

    key: Optional[bytes] = None
    xts_key: Optional[bytes] = None
    iv: Optional[bytes] = None
    nonce: Optional[bytes] = None
    tweak: Optional[bytes] = None
    aad = b""

    if mode == "XTS":
        xts_key = value_from_cli_or_prompt(
            cli_value=args.xts_key,
            label="Input XTS double-length key",
            allowed_lengths=XTS_AES_KEY_LENGTHS,
            allow_random=True,
            random_length=32,
        )
        tweak = value_from_cli_or_prompt(
            cli_value=args.tweak,
            label="Input XTS 16-byte tweak",
            default_format="hex",
            allowed_lengths=(16,),
            allow_random=True,
            random_length=16,
        )
    else:
        key = value_from_cli_or_prompt(
            cli_value=args.key,
            label="Input AES key",
            allowed_lengths=NORMAL_AES_KEY_LENGTHS,
            allow_random=True,
            random_length=16,
        )

    if mode in CLASSIC_IV_MODES:
        iv = value_from_cli_or_prompt(
            cli_value=args.iv,
            label=f"Input {mode} IV/counter block",
            default_format="hex",
            allowed_lengths=(16,),
            allow_random=True,
            random_length=16,
        )
    if mode in {"GCM", "GCM-SIV"}:
        nonce = value_from_cli_or_prompt(
            cli_value=args.nonce,
            label=f"Input {mode} 12-byte nonce",
            default_format="hex",
            allowed_lengths=(12,),
            allow_random=True,
            random_length=12,
        )
    if mode == "CCM":
        nonce = value_from_cli_or_prompt(
            cli_value=args.nonce,
            label="Input CCM nonce",
            default_format="hex",
            min_len=7,
            max_len=13,
            allow_random=True,
            random_length=13,
        )
    if mode in AEAD_MODES:
        aad = value_from_cli_or_prompt(
            cli_value=args.aad,
            label="Input AAD/authenticated data",
            min_len=0,
            allow_empty=True,
        )

    full_output, nonce_length, tag_length = encrypt_image_bytes(
        mode,
        raw,
        key=key,
        xts_key=xts_key,
        iv=iv,
        nonce=nonce,
        tweak=tweak,
        aad=aad,
        cfb_segment_size=args.segment_size,
        ccm_tag_length=args.tag_length,
        verbose=args.verbose,
    )

    visual_bytes = select_cipher_visual_bytes(
        mode,
        full_output,
        raw_len=len(raw),
        nonce_length=nonce_length,
        tag_length=tag_length,
    )
    cipher_visual = bytes_to_rgb_visual(visual_bytes, width, height)

    header = {
        "version": 2,
        "mode": mode,
        "operation": "image-encryption",
        "width": width,
        "height": height,
        "channels": 3,
        "raw_len": len(raw),
        "payload_len": len(full_output),
        "nonce_length": nonce_length,
        "tag_length": tag_length,
        "segment_size": args.segment_size,
        "aad_hex": aad.hex(),
        "layout": "mode-dependent; revised modes output with IV/nonce prefix when applicable",
    }

    out_bin = args.output_bin or f"cipher_rgb_{mode.lower().replace('-', '_')}.aesimg"
    save_container(out_bin, header, full_output)
    print(f"Saved encrypted RGB container: {out_bin}")
    print_bytes("Full encrypted payload", full_output)

    if args.output_visual_image:
        cipher_visual.save(args.output_visual_image)
        print(f"Saved encrypted RGB visual image: {args.output_visual_image}")

    if not args.no_show:
        show_side_by_side(image, cipher_visual, f"{mode} cipher visual, RGB")



def run_decrypt_image(args: argparse.Namespace, mode_arg: str) -> None:
    container_path = args.input_bin or args.output_bin or ask_raw("Input encrypted RGB container path (.aesimg): ").strip()
    header, payload = load_container(container_path)
    mode = normalize_mode(str(header.get("mode", mode_arg)))
    if mode not in IMAGE_ENCRYPTION_MODES:
        raise ValueError(f"Container mode {mode} is not an image-encryption mode.")

    width = int(header["width"])
    height = int(header["height"])
    raw_len = int(header["raw_len"])
    ccm_nonce_length = int(header.get("nonce_length", 13))
    ccm_tag_length = int(header.get("tag_length", DEFAULT_TAG_LENGTH))
    segment_size = int(header.get("segment_size", args.segment_size))

    key: Optional[bytes] = None
    xts_key: Optional[bytes] = None
    tweak: Optional[bytes] = None
    stored_aad = bytes.fromhex(str(header.get("aad_hex", "")))
    aad = stored_aad

    print(f"Loaded encrypted container: {container_path}")
    print(f"Mode: {mode}; RGB size: {width}x{height}; payload bytes: {len(payload)}\n")

    if mode == "XTS":
        xts_key = value_from_cli_or_prompt(
            cli_value=args.xts_key,
            label="Input XTS double-length key",
            allowed_lengths=XTS_AES_KEY_LENGTHS,
        )
        tweak = value_from_cli_or_prompt(
            cli_value=args.tweak,
            label="Input XTS 16-byte tweak",
            default_format="hex",
            allowed_lengths=(16,),
        )
    else:
        key = value_from_cli_or_prompt(
            cli_value=args.key,
            label="Input AES key",
            allowed_lengths=NORMAL_AES_KEY_LENGTHS,
        )

    if mode in AEAD_MODES:
        if args.aad is not None:
            aad = parse_text_or_hex(args.aad, name="AAD", default_format="text")
        elif stored_aad:
            print("Using AAD stored in the container header.")
        elif ask_yes_no("AEAD mode: enter AAD manually?", default=False):
            aad = ask_data("Input AAD/authenticated data", allow_empty=True, min_len=0)

    recovered = decrypt_image_bytes(
        mode,
        payload,
        key=key,
        xts_key=xts_key,
        tweak=tweak,
        aad=aad,
        cfb_segment_size=segment_size,
        ccm_nonce_length=ccm_nonce_length,
        ccm_tag_length=ccm_tag_length,
        verbose=args.verbose,
    )
    if len(recovered) != raw_len:
        # ECB/CBC unpadding should already give exact raw_len; this crop is defensive.
        recovered = recovered[:raw_len]
    recovered_img = raw_rgb_to_image(recovered, width, height)

    if args.output_recovered_image:
        recovered_img.save(args.output_recovered_image)
        print(f"Saved recovered RGB image: {args.output_recovered_image}")

    print_bytes("Recovered RGB raw data", recovered)
    if not args.no_show:
        show_single_image(recovered_img, f"Recovered RGB image ({mode})")



def run_gmac_generate(args: argparse.Namespace) -> None:
    image_path = args.image or ask_raw("Input RGB image path to authenticate with GMAC: ").strip()
    _, raw, width, height = load_rgb_image(image_path)
    key = value_from_cli_or_prompt(
        cli_value=args.key,
        label="Input AES key for GMAC",
        allowed_lengths=NORMAL_AES_KEY_LENGTHS,
        allow_random=True,
        random_length=16,
    )
    nonce = value_from_cli_or_prompt(
        cli_value=args.nonce,
        label="Input GMAC 12-byte nonce",
        default_format="hex",
        allowed_lengths=(12,),
        allow_random=True,
        random_length=12,
    )
    aes_mode = new_aes_modes(key, verbose=args.verbose)
    token = aes_mode.gmac(raw, nonce=nonce, prepend_nonce=True)
    header = {
        "version": 2,
        "mode": "GMAC",
        "operation": "image-authentication",
        "width": width,
        "height": height,
        "channels": 3,
        "raw_len": len(raw),
        "tag_layout": "nonce || tag",
    }
    out_bin = args.output_bin or "gmac_rgb_image.aesimg"
    save_container(out_bin, header, token)
    print(f"Saved GMAC token container: {out_bin}")
    print_bytes("GMAC token", token)



def run_gmac_verify(args: argparse.Namespace) -> None:
    image_path = args.image or ask_raw("Input RGB image path to verify with GMAC: ").strip()
    _, raw, _, _ = load_rgb_image(image_path)
    token_path = args.input_bin or ask_raw("Input GMAC token container path: ").strip()
    header, token = load_container(token_path)
    if normalize_mode(str(header.get("mode", ""))) != "GMAC":
        raise ValueError("The input container is not a GMAC token container.")
    key = value_from_cli_or_prompt(
        cli_value=args.key,
        label="Input AES key for GMAC verification",
        allowed_lengths=NORMAL_AES_KEY_LENGTHS,
    )
    aes_mode = new_aes_modes(key, verbose=args.verbose)
    ok = aes_mode.gmac_verify(raw, token, has_nonce=True)
    print("GMAC verification:", "OK" if ok else "FAILED")



def run_key_wrap(args: argparse.Namespace, mode: str) -> None:
    key = value_from_cli_or_prompt(
        cli_value=args.key,
        label="Input AES KEK",
        allowed_lengths=NORMAL_AES_KEY_LENGTHS,
        allow_random=True,
        random_length=16,
    )
    material = value_from_cli_or_prompt(
        cli_value=args.key_material,
        label="Input key material to wrap",
        min_len=16 if mode == "KW" else 1,
    )
    aes_mode = new_aes_modes(key, verbose=args.verbose)
    wrapped = aes_mode.key_wrap(material, pad=(mode == "KWP"))
    out_bin = args.output_bin or f"wrapped_{mode.lower()}.bin"
    with open(out_bin, "wb") as f:
        f.write(wrapped)
    print(f"Saved wrapped key: {out_bin}")
    print_bytes("Wrapped key", wrapped)



def run_key_unwrap(args: argparse.Namespace, mode: str) -> None:
    key = value_from_cli_or_prompt(
        cli_value=args.key,
        label="Input AES KEK",
        allowed_lengths=NORMAL_AES_KEY_LENGTHS,
    )
    if args.input_bin:
        wrapped = Path(args.input_bin).read_bytes()
    else:
        wrapped = ask_data("Input wrapped key", default_format="hex", min_len=16)
    aes_mode = new_aes_modes(key, verbose=args.verbose)
    material = aes_mode.key_unwrap(wrapped, pad=(mode == "KWP"))
    if args.output_bin:
        Path(args.output_bin).write_bytes(material)
        print(f"Saved unwrapped key material: {args.output_bin}")
    print_bytes("Unwrapped key material", material)
    print("Unwrapped key text:", decode_bytes_for_display(material))


# -----------------------------------------------------------------------------
# Interactive menus and CLI
# -----------------------------------------------------------------------------
def print_mode_menu() -> None:
    print("Select AES mode:")
    print(" 1. ECB       Electronic Codebook                  [image demo / teaching only]")
    print(" 2. CBC       Cipher Block Chaining")
    print(" 3. CFB       Cipher Feedback")
    print(" 4. OFB       Output Feedback")
    print(" 5. CTR       Counter")
    print(" 6. GCM       AEAD")
    print(" 7. GMAC      Authentication-only over RGB bytes")
    print(" 8. CCM       AEAD")
    print(" 9. GCM-SIV   Misuse-resistant AEAD, backend-dependent")
    print("10. XTS       Storage/data-unit mode")
    print("11. KW        AES key wrap, no padding")
    print("12. KWP       AES key wrap with padding")


def ask_mode_interactive() -> str:
    mode_map = {
        "1": "ECB", "2": "CBC", "3": "CFB", "4": "OFB", "5": "CTR", "6": "GCM",
        "7": "GMAC", "8": "CCM", "9": "GCM-SIV", "10": "XTS", "11": "KW", "12": "KWP",
    }
    print_mode_menu()
    raw = ask_raw("Enter mode choice: ").strip()
    mode = mode_map.get(raw, normalize_mode(raw))
    if mode not in ALL_MODES:
        raise ValueError(f"Unsupported mode: {mode}")
    return mode


def ask_operation_interactive(mode: str) -> str:
    if mode == "GMAC":
        print("Select operation:")
        print(" 1. Generate GMAC tag for RGB image")
        print(" 2. Verify GMAC tag for RGB image")
    elif mode in {"KW", "KWP"}:
        print("Select operation:")
        print(" 1. Wrap key material")
        print(" 2. Unwrap key material")
    else:
        print("Select operation:")
        print(" 1. Encrypt RGB image and view encrypted RGB visual")
        print(" 2. Decrypt saved RGB image container")
    raw = ask_raw("Enter operation: ").strip()
    if raw == "1":
        if mode == "GMAC":
            return OP_GMAC_GENERATE
        if mode in {"KW", "KWP"}:
            return OP_WRAP
        return OP_ENCRYPT_IMAGE
    if raw == "2":
        if mode == "GMAC":
            return OP_GMAC_VERIFY
        if mode in {"KW", "KWP"}:
            return OP_UNWRAP
        return OP_DECRYPT_IMAGE
    return normalize_operation(raw, mode)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AES RGB image visualizer supporting ECB/CBC/CFB/OFB/CTR/GCM/GMAC/CCM/GCM-SIV/XTS/KW/KWP.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--mode", help="ECB, CBC, CFB, OFB, CTR, GCM, GMAC, CCM, GCM-SIV, XTS, KW, or KWP. Omit for menu.")
    parser.add_argument(
        "--operation", "--op",
        help="encrypt/decrypt for image modes; generate/verify for GMAC; wrap/unwrap for KW/KWP.",
    )
    parser.add_argument("--image", help="Input image path for image encryption or GMAC verification/generation.")
    parser.add_argument("--input-bin", help="Input .aesimg container, GMAC token container, or wrapped-key binary file.")
    parser.add_argument("--output-bin", help="Output encrypted .aesimg container, GMAC token container, or wrapped-key file.")
    parser.add_argument("--output-visual-image", help="Save the encrypted RGB visual as PNG/JPG/BMP.")
    parser.add_argument("--output-recovered-image", help="Save recovered RGB image after decryption.")

    parser.add_argument("--key", help="AES key / KEK. Type text directly, use hex:001122..., or R for random on encryption.")
    parser.add_argument("--xts-key", help="XTS double-length key. Type text directly, use hex:001122..., or R for random on encryption.")
    parser.add_argument("--key-material", help="KW/KWP key material to wrap. Type text directly or use hex:001122...")
    parser.add_argument("--iv", help="CBC/CFB/OFB/CTR IV/counter block. Use hex:001122..., text:..., or R for random.")
    parser.add_argument("--nonce", help="GCM/GMAC/CCM/GCM-SIV nonce. Use hex:001122..., text:..., or R for random.")
    parser.add_argument("--tweak", help="XTS 16-byte tweak. Use hex:001122..., text:..., or R for random.")
    parser.add_argument("--aad", help="AAD/authenticated data. Type text directly or use hex:001122...")

    parser.add_argument("--segment-size", type=int, default=128, help="CFB segment size in bits.")
    parser.add_argument("--tag-length", type=int, default=16, help="CCM tag length in bytes.")
    parser.add_argument("--no-show", action="store_true", help="Do not open matplotlib windows.")
    parser.add_argument("--verbose", action="store_true", help="Enable backend verbose output where supported.")
    return parser


def main(argv: Optional[list[str]] = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.segment_size not in (8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128):
        raise ValueError("CFB segment size must be byte-aligned between 8 and 128 bits.")
    if args.tag_length not in (4, 6, 8, 10, 12, 14, 16):
        raise ValueError("CCM tag length must be one of 4, 6, 8, 10, 12, 14, 16.")

    mode = normalize_mode(args.mode) if args.mode else ask_mode_interactive()
    if mode not in ALL_MODES:
        raise ValueError(f"Unsupported AES mode: {mode}")

    operation = normalize_operation(args.operation, mode) if args.operation else ask_operation_interactive(mode)

    if operation == OP_ENCRYPT_IMAGE:
        run_encrypt_image(args, mode)
    elif operation == OP_DECRYPT_IMAGE:
        run_decrypt_image(args, mode)
    elif operation == OP_GMAC_GENERATE:
        if mode != "GMAC":
            raise ValueError("GMAC generate operation requires --mode GMAC.")
        run_gmac_generate(args)
    elif operation == OP_GMAC_VERIFY:
        if mode != "GMAC":
            raise ValueError("GMAC verify operation requires --mode GMAC.")
        run_gmac_verify(args)
    elif operation == OP_WRAP:
        if mode not in {"KW", "KWP"}:
            raise ValueError("Wrap operation requires --mode KW or --mode KWP.")
        run_key_wrap(args, mode)
    elif operation == OP_UNWRAP:
        if mode not in {"KW", "KWP"}:
            raise ValueError("Unwrap operation requires --mode KW or --mode KWP.")
        run_key_unwrap(args, mode)
    else:
        raise ValueError(f"Unsupported operation: {operation}")


if __name__ == "__main__":
    main()
