# -*- coding: utf-8 -*-
"""
AES_project_all_modes_PyQt6.py

Operation-first AES project driver.

Main revision from AES_project_screen_input.py:
    - User selects the AES mode first.
    - User then selects operation separately:
          Encrypt / Decrypt
      For special modes:
          GMAC: Encrypt  -> generate authentication tag
                Decrypt  -> verify authentication tag
          KW/KWP: Encrypt -> wrap key material
                  Decrypt -> unwrap key material
    - No hard-coded key, IV, nonce, tweak, plaintext, AAD, ciphertext, or wrapped key.
    - Plaintext/AAD/key material can be typed directly; use hex:... for raw bytes.
    - Ciphertext/token/wrapped-key input for decryption is requested as hexadecimal.
    - Supports --input-file / --output-file for raw binary or hex-text files.
    - Also supports key/IV/nonce/tweak/AAD file inputs for repeatable lab demos.
    - Optional PyQt6 GUI via --gui; CLI/menu behavior remains available.

Expected modes backend:
    from mypackages import modes
or local fallback:
    import AES_modes_revised as modes

Supported modes:
    ECB, CBC, CFB, OFB, CTR, GCM, GMAC, CCM, GCM-SIV, XTS, KW, KWP
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

sys.path.append(os.getcwd())

NORMAL_AES_KEY_LENGTHS = (16, 24, 32)
XTS_AES_KEY_LENGTHS = (32, 64)
CLASSIC_IV_MODES = {"CBC", "CFB", "OFB", "CTR"}
AEAD_NONCE_12_MODES = {"GCM", "GMAC", "GCM-SIV"}
AEAD_MODES = {"GCM", "CCM", "GCM-SIV"}
ALL_MODES = {
    "ECB", "CBC", "CFB", "OFB", "CTR",
    "GCM", "GMAC", "CCM", "GCM-SIV",
    "XTS", "KW", "KWP",
}
OP_ENCRYPT = "ENCRYPT"
OP_DECRYPT = "DECRYPT"
ALL_OPERATIONS = {OP_ENCRYPT, OP_DECRYPT}


# -----------------------------------------------------------------------------
# Lazy imports
# -----------------------------------------------------------------------------
def load_modes_module():
    """Load the AES modes backend while preserving the original project layout."""
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


def load_key_expansion_module():
    try:
        from mypackages import key_expansion as key_expansion_module  # type: ignore
        return key_expansion_module
    except Exception:
        return None


def new_aes_modes(key: bytes, *, verbose: bool = False):
    """Instantiate the revised modes class with compatibility for class names."""
    modes_module = load_modes_module()
    if hasattr(modes_module, "AESModes"):
        return modes_module.AESModes(key, verbose=verbose)
    try:
        return modes_module.modes(key, verbose=verbose)
    except TypeError:
        return modes_module.modes(key)


# -----------------------------------------------------------------------------
# Normalization and validation
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


def normalize_operation(operation: str) -> str:
    value = operation.strip().upper().replace(" ", "").replace("-", "_")
    aliases = {
        "E": OP_ENCRYPT,
        "ENC": OP_ENCRYPT,
        "ENCRYPT": OP_ENCRYPT,
        "ENCRYPTION": OP_ENCRYPT,
        "TAG": OP_ENCRYPT,
        "GENERATE": OP_ENCRYPT,
        "GEN": OP_ENCRYPT,
        "WRAP": OP_ENCRYPT,
        "D": OP_DECRYPT,
        "DEC": OP_DECRYPT,
        "DECRYPT": OP_DECRYPT,
        "DECRYPTION": OP_DECRYPT,
        "VERIFY": OP_DECRYPT,
        "VER": OP_DECRYPT,
        "UNWRAP": OP_DECRYPT,
    }
    return aliases.get(value, value)


def require_lengths(data: bytes, lengths: Tuple[int, ...], name: str) -> bytes:
    if len(data) not in lengths:
        joined = ", ".join(str(n) for n in lengths)
        raise ValueError(f"{name} must be exactly one of these byte lengths: {joined}. Got {len(data)}.")
    return data


def require_min_len(data: bytes, min_len: int, name: str) -> bytes:
    if len(data) < min_len:
        raise ValueError(f"{name} must be at least {min_len} byte(s). Got {len(data)}.")
    return data


def require_max_len(data: bytes, max_len: int, name: str) -> bytes:
    if len(data) > max_len:
        raise ValueError(f"{name} must be at most {max_len} byte(s). Got {len(data)}.")
    return data


def require_range(data: bytes, min_len: int, max_len: int, name: str) -> bytes:
    require_min_len(data, min_len, name)
    require_max_len(data, max_len, name)
    return data


def require_hex_bytes(value: str, *, name: str) -> bytes:
    compact = "".join(value.strip().split())
    if compact.lower().startswith("hex:"):
        compact = compact[4:]
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal bytes, for example: 001122aabb or hex:001122aabb.") from exc


def parse_text_or_hex(value: str, *, name: str, default_format: str = "text") -> bytes:
    """
    Friendly input parser.

    Rules:
        hex:001122...  -> raw bytes from hexadecimal
        text:hello     -> UTF-8 bytes for 'hello'
        otherwise:
            default_format='text' -> UTF-8 bytes
            default_format='hex'  -> hexadecimal bytes
    """
    raw = value
    stripped = raw.strip()
    lower = stripped.lower()
    if lower.startswith("hex:"):
        return require_hex_bytes(stripped[4:], name=name)
    if lower.startswith("text:"):
        return raw[5:].encode("utf-8")
    if default_format == "hex":
        return require_hex_bytes(stripped, name=name)
    if default_format == "text":
        return raw.encode("utf-8")
    raise ValueError("default_format must be text or hex.")


def decode_bytes_for_display(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return f"<non-UTF8 bytes: {data.hex()}>"


def print_bytes(label: str, data: bytes) -> None:
    #print(f"{label} bytes : {data!r}")
    print(f"{label} hex   : {data.hex()}")
    print(f"{label} length: {len(data)} byte(s)\n")


# -----------------------------------------------------------------------------
# File I/O helpers
# -----------------------------------------------------------------------------
def parse_file_format(value: str) -> str:
    fmt = value.strip().lower()
    if fmt not in {"raw", "hex", "text"}:
        raise ValueError("File format must be raw, hex, or text.")
    return fmt


def read_file_bytes(path: str, *, file_format: str = "raw", name: str = "input file") -> bytes:
    """
    Read bytes from a file.

    file_format='raw':
        Use the file bytes exactly as stored. This is the safest default for
        arbitrary plaintext/ciphertext/binary outputs.

    file_format='hex':
        Interpret the file as UTF-8 text containing hexadecimal bytes. Spaces,
        tabs, and newlines are ignored. An optional leading hex: is accepted.

    file_format='text':
        Read the file as UTF-8 text and return its UTF-8 encoded bytes. This is
        convenient for teaching plaintext files.
    """
    fmt = parse_file_format(file_format)
    file_path = Path(path)
    try:
        raw = file_path.read_bytes()
    except OSError as exc:
        raise OSError(f"Cannot read {name} at {file_path!s}: {exc}") from exc

    if fmt == "raw":
        return raw

    try:
        text_data = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{name} must be valid UTF-8 text when file_format={fmt}.") from exc

    if fmt == "text":
        return text_data.encode("utf-8")

    # fmt == "hex"
    compact = "".join(text_data.split())
    if compact.lower().startswith("hex:"):
        compact = compact[4:]
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError(f"{name} does not contain valid hexadecimal bytes.") from exc


def write_file_bytes(path: str, data: bytes, *, file_format: str = "raw", label: str = "output") -> None:
    """
    Save bytes to a file.

    file_format='raw':
        Write exact bytes. Recommended for ciphertext and binary plaintext.

    file_format='hex':
        Write lowercase hexadecimal text plus a newline.

    file_format='text':
        Decode bytes as UTF-8 and write text. Use only when you know the
        recovered plaintext is textual.
    """
    fmt = parse_file_format(file_format)
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True) if file_path.parent != Path(".") else None

    if fmt == "raw":
        payload = data
        mode = "wb"
    elif fmt == "hex":
        payload = (data.hex() + "\n").encode("ascii")
        mode = "wb"
    else:
        try:
            payload_text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"{label} cannot be saved as text because it is not valid UTF-8.") from exc
        payload = payload_text
        mode = "w"

    try:
        if mode == "wb":
            file_path.write_bytes(payload)  # type: ignore[arg-type]
        else:
            file_path.write_text(payload, encoding="utf-8")  # type: ignore[arg-type]
    except OSError as exc:
        raise OSError(f"Cannot write {label} to {file_path!s}: {exc}") from exc

    print(f"Saved {label} to: {file_path!s} ({fmt})\n")


def validate_data_constraints(
    value: bytes,
    *,
    label: str,
    allowed_lengths: Optional[Tuple[int, ...]] = None,
    min_len: Optional[int] = None,
    max_len: Optional[int] = None,
) -> bytes:
    if allowed_lengths is not None:
        require_lengths(value, allowed_lengths, label)
    if min_len is not None:
        require_min_len(value, min_len, label)
    if max_len is not None:
        require_max_len(value, max_len, label)
    return value


def read_file_with_validation(
    path: str,
    *,
    file_format: str,
    label: str,
    allowed_lengths: Optional[Tuple[int, ...]] = None,
    min_len: Optional[int] = None,
    max_len: Optional[int] = None,
) -> bytes:
    value = read_file_bytes(path, file_format=file_format, name=label)
    return validate_data_constraints(
        value,
        label=label,
        allowed_lengths=allowed_lengths,
        min_len=min_len,
        max_len=max_len,
    )


def maybe_save_output(output_file: Optional[str], data: bytes, *, output_format: str, label: str) -> None:
    if output_file:
        write_file_bytes(output_file, data, file_format=output_format, label=label)


def print_mode_note(mode: str) -> None:
    if mode == "ECB":
        print("Warning: ECB is teaching-only and leaks plaintext patterns.\n")
    elif mode in {"CBC", "CFB", "OFB", "CTR", "XTS"}:
        print(f"Note: {mode} provides confidentiality only; it does not authenticate ciphertext.\n")
    elif mode in AEAD_MODES:
        print(f"Note: {mode} authenticates ciphertext and AAD. Decryption fails if ciphertext/tag/AAD/nonce is wrong.\n")
    elif mode == "GMAC":
        print("Note: GMAC authenticates data only; it does not encrypt plaintext.\n")
    elif mode in {"KW", "KWP"}:
        print(f"Note: {mode} wraps cryptographic key material, not ordinary messages.\n")


# -----------------------------------------------------------------------------
# Interactive input helpers
# -----------------------------------------------------------------------------
def ask_raw(prompt: str, *, allow_empty: bool = False) -> str:
    while True:
        value = input(prompt)
        if value or allow_empty:
            return value
        print("Input cannot be empty.")


def ask_yes_no(prompt: str, *, default: Optional[bool] = None) -> bool:
    while True:
        suffix = ""
        if default is True:
            suffix = " [Y/n]"
        elif default is False:
            suffix = " [y/N]"
        else:
            suffix = " [y/n]"
        raw = ask_raw(f"{prompt}{suffix}: ", allow_empty=default is not None).strip().lower()
        if raw == "" and default is not None:
            return default
        if raw in {"y", "yes", "1", "true"}:
            return True
        if raw in {"n", "no", "0", "false"}:
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
    """
    Ask for bytes using one direct prompt.

    Examples:
        Hello world       -> UTF-8 bytes when default_format='text'
        hex:001122aabb    -> raw hex bytes
        R                 -> random bytes, only when allow_random=True
    """
    while True:
        notes = []
        if default_format == "text":
            notes.append("type text directly")
            notes.append("use hex:001122... for raw bytes")
        else:
            notes.append("hex bytes")
            notes.append("or use text:hello for UTF-8 text")
        if allow_random:
            notes.append("R=random")
        note = "; ".join(notes)
        raw = ask_raw(f"{label} [{note}]: ", allow_empty=allow_empty)
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
            if max_len is not None:
                require_max_len(value, max_len, label)
            return value
        except ValueError as exc:
            print(f"Invalid input: {exc}")


def ask_ciphertext(label: str, *, min_len: int = 0) -> bytes:
    return ask_data(label, default_format="hex", min_len=min_len)


def ask_data_or_file(
    label: str,
    *,
    default_format: str = "text",
    file_format_default: str = "raw",
    allowed_lengths: Optional[Tuple[int, ...]] = None,
    min_len: Optional[int] = None,
    max_len: Optional[int] = None,
    allow_empty: bool = False,
    allow_random: bool = False,
    random_length: Optional[int] = None,
) -> bytes:
    """
    Interactive helper for the same value from screen or from file.
    For file input, raw binary is the default because plaintext/ciphertext may
    be arbitrary bytes. Select hex when the file contains hexadecimal text.
    """
    if ask_yes_no(f"Read {label} from file?", default=False):
        file_path = ask_raw(f"{label} file path: ")
        fmt_prompt = f"{label} file format [raw/hex/text] [{file_format_default}]: "
        file_format = ask_raw(fmt_prompt, allow_empty=True).strip().lower() or file_format_default
        return read_file_with_validation(
            file_path,
            file_format=file_format,
            label=label,
            allowed_lengths=allowed_lengths,
            min_len=min_len,
            max_len=max_len,
        )

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


# -----------------------------------------------------------------------------
# CLI value resolution helpers
# -----------------------------------------------------------------------------
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
    cli_file: Optional[str] = None,
    cli_file_format: str = "raw",
) -> bytes:
    if cli_value is not None and cli_file is not None:
        raise ValueError(f"Provide either {label} value or {label} file, not both.")

    if cli_file is not None:
        value = read_file_with_validation(
            cli_file,
            file_format=cli_file_format,
            label=label,
            allowed_lengths=allowed_lengths,
            min_len=min_len,
            max_len=max_len,
        )
        print_bytes(f"{label} read from file", value)
        return value

    if cli_value is not None:
        if allow_random and cli_value.strip().lower() in {"r", "random"}:
            if random_length is None:
                raise ValueError("random_length must be provided when random generation is allowed.")
            value = secrets.token_bytes(random_length)
            print_bytes(f"Generated {label}", value)
        else:
            value = parse_text_or_hex(cli_value, name=label, default_format=default_format)
        return validate_data_constraints(
            value,
            label=label,
            allowed_lengths=allowed_lengths,
            min_len=min_len,
            max_len=max_len,
        )

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


def bool_from_cli_or_prompt(*, cli_value: Optional[str], label: str, default: Optional[bool] = None) -> bool:
    if cli_value is not None:
        value = cli_value.strip().lower()
        if value in {"y", "yes", "true", "1", "include", "included"}:
            return True
        if value in {"n", "no", "false", "0", "separate", "not-included"}:
            return False
        raise ValueError(f"{label} must be yes/no.")
    return ask_yes_no(label, default=default)


# -----------------------------------------------------------------------------
# Backend execution helpers: encryption side
# -----------------------------------------------------------------------------
def encrypt_classic(aes_mode, mode: str, plaintext: bytes, *, iv: Optional[bytes], segment_size: int) -> bytes:
    if mode == "ECB":
        return aes_mode.ecb_encrypt(plaintext)
    if mode == "CBC":
        return aes_mode.cbc_encrypt(plaintext, iv=iv, prepend_iv=True)
    if mode == "CFB":
        return aes_mode.cfb_encrypt(plaintext, iv=iv, segment_size=segment_size, prepend_iv=True)
    if mode == "OFB":
        return aes_mode.ofb_encrypt(plaintext, iv=iv, prepend_iv=True)
    if mode == "CTR":
        return aes_mode.ctr_encrypt(plaintext, iv=iv, prepend_iv=True)
    raise ValueError(f"Unsupported classic encryption mode: {mode}")


def decrypt_classic(
    aes_mode,
    mode: str,
    ciphertext: bytes,
    *,
    has_prefix: bool,
    iv: Optional[bytes],
    segment_size: int,
) -> bytes:
    if mode == "ECB":
        return aes_mode.ecb_decrypt(ciphertext, output_encoding=None)
    if mode == "CBC":
        return aes_mode.cbc_decrypt(ciphertext, iv=iv, has_iv=has_prefix, output_encoding=None)
    if mode == "CFB":
        return aes_mode.cfb_decrypt(ciphertext, iv=iv, has_iv=has_prefix, segment_size=segment_size, output_encoding=None)
    if mode == "OFB":
        return aes_mode.ofb_decrypt(ciphertext, iv=iv, has_iv=has_prefix, output_encoding=None)
    if mode == "CTR":
        return aes_mode.ctr_decrypt(ciphertext, iv=iv, has_iv=has_prefix, output_encoding=None)
    raise ValueError(f"Unsupported classic decryption mode: {mode}")


def encrypt_aead(aes_mode, mode: str, plaintext: bytes, *, nonce: bytes, aad: bytes, tag_length: int) -> bytes:
    associated_data = aad if aad else None
    if mode == "GCM":
        return aes_mode.gcm_encrypt(plaintext, associated_data=associated_data, nonce=nonce, prepend_nonce=True)
    if mode == "CCM":
        return aes_mode.ccm_encrypt(
            plaintext,
            associated_data=associated_data,
            nonce=nonce,
            tag_length=tag_length,
            prepend_nonce=True,
        )
    if mode == "GCM-SIV":
        return aes_mode.gcm_siv_encrypt(plaintext, associated_data=associated_data, nonce=nonce, prepend_nonce=True)
    raise ValueError(f"Unsupported AEAD encryption mode: {mode}")


def decrypt_aead(
    aes_mode,
    mode: str,
    token: bytes,
    *,
    has_prefix: bool,
    nonce: Optional[bytes],
    aad: bytes,
    nonce_length: int,
    tag_length: int,
) -> bytes:
    associated_data = aad if aad else None
    if mode == "GCM":
        return aes_mode.gcm_decrypt(token, associated_data=associated_data, nonce=nonce, has_nonce=has_prefix, output_encoding=None)
    if mode == "CCM":
        return aes_mode.ccm_decrypt(
            token,
            associated_data=associated_data,
            nonce=nonce,
            has_nonce=has_prefix,
            nonce_length=nonce_length,
            tag_length=tag_length,
            output_encoding=None,
        )
    if mode == "GCM-SIV":
        return aes_mode.gcm_siv_decrypt(token, associated_data=associated_data, nonce=nonce, has_nonce=has_prefix, output_encoding=None)
    raise ValueError(f"Unsupported AEAD decryption mode: {mode}")


# -----------------------------------------------------------------------------
# Operation-level execution and reports
# -----------------------------------------------------------------------------
def build_constructor_key(mode: str, key: Optional[bytes], xts_key: Optional[bytes]) -> bytes:
    if mode == "XTS":
        if xts_key is None:
            raise ValueError("XTS key is required.")
        require_lengths(xts_key, XTS_AES_KEY_LENGTHS, "XTS key")
        return xts_key[: len(xts_key) // 2]
    if key is None:
        raise ValueError("AES key is required.")
    require_lengths(key, NORMAL_AES_KEY_LENGTHS, "AES key")
    return key


def run_encrypt(
    mode: str,
    *,
    key: Optional[bytes],
    xts_key: Optional[bytes],
    plaintext: bytes,
    iv: Optional[bytes],
    nonce: Optional[bytes],
    tweak: Optional[bytes],
    aad: bytes,
    segment_size: int,
    tag_length: int,
    verbose: bool,
    output_file: Optional[str] = None,
    output_format: str = "raw",
) -> Optional[bytes]:
    constructor_key = build_constructor_key(mode, key, xts_key)
    aes_mode = new_aes_modes(constructor_key, verbose=verbose)

    print("\n" + "=" * 78)
    print(f"AES mode: {mode} | Operation: ENCRYPT / GENERATE / WRAP")
    print("=" * 78)
    print_mode_note(mode)

    if mode == "XTS":
        if xts_key is None or tweak is None:
            raise ValueError("XTS encryption requires XTS key and tweak.")
        require_lengths(tweak, (16,), "XTS tweak")
        require_min_len(plaintext, 16, "XTS plaintext data unit")
        print_bytes("XTS double-length key", xts_key)
        print_bytes("XTS tweak", tweak)
        print_bytes("Plaintext data unit", plaintext)
        ciphertext = aes_mode.xts_encrypt(plaintext, xts_key=xts_key, tweak=tweak)
        #print_bytes("Ciphertext data unit", ciphertext)
        maybe_save_output(output_file, ciphertext, output_format=output_format, label="XTS ciphertext data unit")
        print("For XTS decryption, provide the ciphertext hex plus the same XTS key and tweak.\n")
        return ciphertext

    if key is not None:
        print_bytes("AES key / KEK", key)

    if mode in {"ECB", "CBC", "CFB", "OFB", "CTR"}:
        print_bytes("Plaintext", plaintext)
        if mode in CLASSIC_IV_MODES:
            if iv is None:
                raise ValueError(f"{mode} encryption requires a 16-byte IV/counter block.")
            print_bytes("IV/counter block", iv)
        if mode == "CFB":
            print(f"CFB segment size: {segment_size} bit(s)\n")
        ciphertext = encrypt_classic(aes_mode, mode, plaintext, iv=iv, segment_size=segment_size)
        print_bytes("Ciphertext output", ciphertext)
        maybe_save_output(output_file, ciphertext, output_format=output_format, label="ciphertext output")
        if mode in CLASSIC_IV_MODES:
            print("Output format: IV/counter block || ciphertext body. Use this full hex as decryption input.\n")
        return ciphertext

    if mode in AEAD_MODES:
        if nonce is None:
            raise ValueError(f"{mode} encryption requires a nonce.")
        if mode in {"GCM", "GCM-SIV"}:
            require_lengths(nonce, (12,), f"{mode} nonce")
        elif mode == "CCM":
            require_range(nonce, 7, 13, "CCM nonce")
        print_bytes("Plaintext", plaintext)
        print_bytes("Nonce", nonce)
        print_bytes("AAD", aad)
        if mode == "CCM":
            print(f"CCM tag length: {tag_length} byte(s)\n")
        token = encrypt_aead(aes_mode, mode, plaintext, nonce=nonce, aad=aad, tag_length=tag_length)
        print_bytes("Ciphertext/token output", token)
        maybe_save_output(output_file, token, output_format=output_format, label="ciphertext/token output")
        print("Output format: nonce || ciphertext || authentication tag. Use this full hex as decryption input.\n")
        return token

    if mode == "GMAC":
        if nonce is None:
            raise ValueError("GMAC generation requires a nonce.")
        require_lengths(nonce, (12,), "GMAC nonce")
        authenticated_data = aad if aad else plaintext
        require_min_len(authenticated_data, 1, "GMAC authenticated data")
        print_bytes("Nonce", nonce)
        print_bytes("Authenticated data", authenticated_data)
        token = aes_mode.gmac(authenticated_data, nonce=nonce, prepend_nonce=True)
        print_bytes("GMAC token", token)
        maybe_save_output(output_file, token, output_format=output_format, label="GMAC token")
        print("Output format: nonce || GMAC tag. Use this full hex as verification input.\n")
        return token

    if mode in {"KW", "KWP"}:
        key_to_wrap = plaintext
        if mode == "KW":
            require_min_len(key_to_wrap, 16, "Key material for AES-KW")
            if len(key_to_wrap) % 8 != 0:
                raise ValueError("AES-KW without padding requires key material length to be a multiple of 8 bytes.")
            wrapped = aes_mode.key_wrap(key_to_wrap, pad=False)
        else:
            require_min_len(key_to_wrap, 1, "Key material for AES-KWP")
            wrapped = aes_mode.key_wrap(key_to_wrap, pad=True)
        print_bytes("Key material to wrap", key_to_wrap)
        print_bytes("Wrapped key", wrapped)
        maybe_save_output(output_file, wrapped, output_format=output_format, label="wrapped key")
        print("Use the wrapped-key hex as decryption/unwrap input.\n")
        return wrapped

    raise ValueError(f"Unsupported encryption mode: {mode}")


def run_decrypt(
    mode: str,
    *,
    key: Optional[bytes],
    xts_key: Optional[bytes],
    ciphertext: bytes,
    iv: Optional[bytes],
    nonce: Optional[bytes],
    tweak: Optional[bytes],
    aad: bytes,
    has_prefix: bool,
    nonce_length: int,
    segment_size: int,
    tag_length: int,
    verbose: bool,
    output_file: Optional[str] = None,
    output_format: str = "raw",
) -> Optional[bytes]:
    constructor_key = build_constructor_key(mode, key, xts_key)
    aes_mode = new_aes_modes(constructor_key, verbose=verbose)

    print("\n" + "=" * 78)
    print(f"AES mode: {mode} | Operation: DECRYPT / VERIFY / UNWRAP")
    print("=" * 78)
    print_mode_note(mode)

    if mode == "XTS":
        if xts_key is None or tweak is None:
            raise ValueError("XTS decryption requires XTS key and tweak.")
        require_lengths(tweak, (16,), "XTS tweak")
        require_min_len(ciphertext, 16, "XTS ciphertext data unit")
        print_bytes("XTS double-length key", xts_key)
        print_bytes("XTS tweak", tweak)
        #print_bytes("Ciphertext data unit", ciphertext)
        recovered = aes_mode.xts_decrypt(ciphertext, xts_key=xts_key, tweak=tweak, output_encoding=None)
        print_bytes("Recovered data unit", recovered)
        print("Recovered text:", decode_bytes_for_display(recovered))
        maybe_save_output(output_file, recovered, output_format=output_format, label="recovered data unit")
        return recovered

    if key is not None:
        print_bytes("AES key / KEK", key)

    if mode in {"ECB", "CBC", "CFB", "OFB", "CTR"}:
        print_bytes("Ciphertext input", ciphertext)
        if mode in CLASSIC_IV_MODES and not has_prefix:
            if iv is None:
                raise ValueError(f"{mode} decryption requires IV/counter block when ciphertext does not include it.")
            print_bytes("Separate IV/counter block", iv)
        if mode == "CFB":
            print(f"CFB segment size: {segment_size} bit(s)\n")
        recovered = decrypt_classic(aes_mode, mode, ciphertext, has_prefix=has_prefix, iv=iv, segment_size=segment_size)
        print_bytes("Recovered plaintext", recovered)
        print("Recovered text:", decode_bytes_for_display(recovered))
        maybe_save_output(output_file, recovered, output_format=output_format, label="recovered plaintext")
        return recovered

    if mode in AEAD_MODES:
        print_bytes("Ciphertext/token input", ciphertext)
        print_bytes("AAD", aad)
        if not has_prefix:
            if nonce is None:
                raise ValueError(f"{mode} decryption requires nonce when token does not include it.")
            print_bytes("Separate nonce", nonce)
        if mode == "CCM":
            print(f"CCM nonce length used for parsing: {nonce_length} byte(s)")
            print(f"CCM tag length: {tag_length} byte(s)\n")
        recovered = decrypt_aead(
            aes_mode,
            mode,
            ciphertext,
            has_prefix=has_prefix,
            nonce=nonce,
            aad=aad,
            nonce_length=nonce_length,
            tag_length=tag_length,
        )
        print_bytes("Recovered plaintext", recovered)
        print("Recovered text:", decode_bytes_for_display(recovered))
        maybe_save_output(output_file, recovered, output_format=output_format, label="recovered plaintext")
        return recovered

    if mode == "GMAC":
        authenticated_data = aad
        require_min_len(authenticated_data, 1, "GMAC authenticated data")
        print_bytes("GMAC token input", ciphertext)
        print_bytes("Authenticated data", authenticated_data)
        if not has_prefix:
            if nonce is None:
                raise ValueError("GMAC verification requires nonce when token does not include it.")
            print_bytes("Separate nonce", nonce)
        ok = aes_mode.gmac_verify(authenticated_data, ciphertext, nonce=nonce, has_nonce=has_prefix)
        result = b"OK\n" if ok else b"FAILED\n"
        print("GMAC verification:", "OK" if ok else "FAILED")
        maybe_save_output(output_file, result, output_format="text" if output_format == "raw" else output_format, label="GMAC verification result")
        return result

    if mode in {"KW", "KWP"}:
        print_bytes("Wrapped key input", ciphertext)
        unwrapped = aes_mode.key_unwrap(ciphertext, pad=(mode == "KWP"))
        print_bytes("Unwrapped key material", unwrapped)
        print("Unwrapped key text:", decode_bytes_for_display(unwrapped))
        maybe_save_output(output_file, unwrapped, output_format=output_format, label="unwrapped key material")
        return unwrapped

    raise ValueError(f"Unsupported decryption mode: {mode}")


# -----------------------------------------------------------------------------
# Interactive workflow
# -----------------------------------------------------------------------------
def print_menu() -> None:
    print("Select AES mode:")
    print(" 1. ECB       Electronic Codebook                  [teaching only]")
    print(" 2. CBC       Cipher Block Chaining")
    print(" 3. CFB       Cipher Feedback")
    print(" 4. OFB       Output Feedback")
    print(" 5. CTR       Counter")
    print(" 6. GCM       Galois/Counter Mode AEAD")
    print(" 7. GMAC      GCM authentication-only tag")
    print(" 8. CCM       Counter with CBC-MAC AEAD")
    print(" 9. GCM-SIV   Misuse-resistant AEAD, backend-dependent")
    print("10. XTS       Storage/data-unit encryption")
    print("11. KW        AES Key Wrap, no padding")
    print("12. KWP       AES Key Wrap with Padding")
    print("13. Show AES key expansion demo")


def ask_mode_interactive() -> Optional[str]:
    mode_map: Dict[str, str] = {
        "1": "ECB",
        "2": "CBC",
        "3": "CFB",
        "4": "OFB",
        "5": "CTR",
        "6": "GCM",
        "7": "GMAC",
        "8": "CCM",
        "9": "GCM-SIV",
        "10": "XTS",
        "11": "KW",
        "12": "KWP",
    }
    print_menu()
    choice = ask_raw("Enter choice: ").strip()
    if choice == "13":
        show_key_expansion_demo_interactive()
        return None
    mode = mode_map.get(choice, normalize_mode(choice))
    if mode not in ALL_MODES:
        print("Invalid mode choice.")
        return None
    return mode


def ask_operation_interactive(mode: str) -> str:
    if mode == "GMAC":
        print("Select operation:")
        print(" 1. Generate GMAC tag")
        print(" 2. Verify GMAC tag")
    elif mode in {"KW", "KWP"}:
        print("Select operation:")
        print(" 1. Wrap key material")
        print(" 2. Unwrap key material")
    else:
        print("Select operation:")
        print(" 1. Encryption")
        print(" 2. Decryption")
    raw = ask_raw("Enter operation: ").strip()
    if raw == "1":
        return OP_ENCRYPT
    if raw == "2":
        return OP_DECRYPT
    op = normalize_operation(raw)
    if op not in ALL_OPERATIONS:
        raise ValueError("Invalid operation. Use 1/2, encrypt/decrypt, generate/verify, or wrap/unwrap.")
    return op


def collect_interactive_inputs(mode: str, operation: str) -> dict:
    key: Optional[bytes] = None
    xts_key: Optional[bytes] = None
    iv: Optional[bytes] = None
    nonce: Optional[bytes] = None
    tweak: Optional[bytes] = None
    aad = b""
    plaintext = b""
    ciphertext = b""
    has_prefix = True
    nonce_length = 13
    tag_length = 16
    segment_size = 128
    output_file: Optional[str] = None
    output_format = "raw"

    if mode == "XTS":
        xts_key = ask_data("Input XTS double-length key", allowed_lengths=XTS_AES_KEY_LENGTHS, allow_random=True, random_length=32)
        tweak = ask_data("Input XTS 16-byte tweak", allowed_lengths=(16,), allow_random=True, random_length=16)
        if operation == OP_ENCRYPT:
            plaintext = ask_data_or_file("Input storage data-unit plaintext", min_len=16)
        else:
            ciphertext = ask_data_or_file("Input XTS ciphertext data unit", default_format="hex", file_format_default="raw", min_len=16)
        if ask_yes_no("Save primary output to file?", default=False):
            output_file = ask_raw("Output file path: ")
            output_format = ask_raw("Output file format [raw/hex/text] [raw]: ", allow_empty=True).strip().lower() or "raw"
            parse_file_format(output_format)
        return locals()

    key = ask_data("Input AES key / KEK", allowed_lengths=NORMAL_AES_KEY_LENGTHS, allow_random=True, random_length=16)

    if mode == "CFB":
        segment_size = ask_int(
            "Input CFB segment size in bits",
            default=128,
            allowed=(8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128),
        )

    if operation == OP_ENCRYPT:
        if mode in {"KW", "KWP"}:
            label = "Input key material to wrap"
            plaintext = ask_data_or_file(label, min_len=16 if mode == "KW" else 1)
        elif mode == "GMAC":
            aad = ask_data_or_file("Input data to authenticate", min_len=1)
        else:
            plaintext = ask_data_or_file("Input plaintext", min_len=0, allow_empty=True)

        if mode in CLASSIC_IV_MODES:
            iv = ask_data(f"Input {mode} IV/counter block", allowed_lengths=(16,), allow_random=True, random_length=16)
        if mode in {"GCM", "GMAC", "GCM-SIV"}:
            nonce = ask_data(f"Input {mode} 12-byte nonce", allowed_lengths=(12,), allow_random=True, random_length=12)
        if mode == "CCM":
            nonce = ask_data("Input CCM nonce", min_len=7, max_len=13, allow_random=True, random_length=13)
            tag_length = ask_int("Input CCM tag length", default=16, allowed=(4, 6, 8, 10, 12, 14, 16))
        if mode in AEAD_MODES:
            aad = ask_data_or_file("Input AAD/authenticated data", min_len=0, allow_empty=True)
    else:
        if mode in {"KW", "KWP"}:
            ciphertext = ask_data_or_file("Input wrapped key", default_format="hex", file_format_default="raw", min_len=16)
        elif mode == "GMAC":
            ciphertext = ask_data_or_file("Input GMAC token", default_format="hex", file_format_default="raw", min_len=16)
            has_prefix = ask_yes_no("Does the GMAC token include the 12-byte nonce prefix?", default=True)
            if not has_prefix:
                nonce = ask_data("Input separate GMAC 12-byte nonce", allowed_lengths=(12,))
            aad = ask_data_or_file("Input data to authenticate/verify", min_len=1)
        else:
            ciphertext = ask_data_or_file("Input ciphertext/token", default_format="hex", file_format_default="raw", min_len=1)
            if mode in CLASSIC_IV_MODES:
                has_prefix = ask_yes_no("Does this ciphertext include the 16-byte IV/counter prefix?", default=True)
                if not has_prefix:
                    iv = ask_data(f"Input separate {mode} IV/counter block", allowed_lengths=(16,))
            if mode in {"GCM", "GCM-SIV"}:
                has_prefix = ask_yes_no("Does this token include the 12-byte nonce prefix?", default=True)
                if not has_prefix:
                    nonce = ask_data(f"Input separate {mode} 12-byte nonce", allowed_lengths=(12,))
                aad = ask_data_or_file("Input AAD/authenticated data", min_len=0, allow_empty=True)
            if mode == "CCM":
                has_prefix = ask_yes_no("Does this token include the CCM nonce prefix?", default=True)
                tag_length = ask_int("Input CCM tag length", default=16, allowed=(4, 6, 8, 10, 12, 14, 16))
                if has_prefix:
                    nonce_length = ask_int("Input CCM nonce length used in the token prefix", default=13, allowed=(7, 8, 9, 10, 11, 12, 13))
                else:
                    nonce = ask_data("Input separate CCM nonce", min_len=7, max_len=13)
                    nonce_length = len(nonce)
                aad = ask_data_or_file("Input AAD/authenticated data", min_len=0, allow_empty=True)

    if ask_yes_no("Save primary output to file?", default=False):
        output_file = ask_raw("Output file path: ")
        output_format = ask_raw("Output file format [raw/hex/text] [raw]: ", allow_empty=True).strip().lower() or "raw"
        parse_file_format(output_format)

    return locals()


def show_key_expansion_demo_interactive() -> None:
    key_expansion_module = load_key_expansion_module()
    if key_expansion_module is None:
        print("key_expansion module is not available in this environment.\n")
        return

    key = ask_data("Input AES key for key expansion", allowed_lengths=NORMAL_AES_KEY_LENGTHS)
    if len(key) == 16:
        round_keys = key_expansion_module.key_expansion(key).key_expansion_128()
        aes_name = "AES-128"
    elif len(key) == 24:
        round_keys = key_expansion_module.key_expansion(key).key_expansion_192()
        aes_name = "AES-192"
    else:
        round_keys = key_expansion_module.key_expansion(key).key_expansion_256()
        aes_name = "AES-256"

    print(f"\n{aes_name} round keys:")
    print(round_keys)
    print("Number of words (4 bytes each):", len(round_keys), "\n")


def interactive_main() -> None:
    mode = ask_mode_interactive()
    if mode is None:
        return
    operation = ask_operation_interactive(mode)
    inputs = collect_interactive_inputs(mode, operation)

    if operation == OP_ENCRYPT:
        run_encrypt(
            mode,
            key=inputs.get("key"),
            xts_key=inputs.get("xts_key"),
            plaintext=inputs.get("plaintext", b""),
            iv=inputs.get("iv"),
            nonce=inputs.get("nonce"),
            tweak=inputs.get("tweak"),
            aad=inputs.get("aad", b""),
            segment_size=inputs.get("segment_size", 128),
            tag_length=inputs.get("tag_length", 16),
            verbose=True,
            output_file=inputs.get("output_file"),
            output_format=inputs.get("output_format", "raw"),
        )
    else:
        run_decrypt(
            mode,
            key=inputs.get("key"),
            xts_key=inputs.get("xts_key"),
            ciphertext=inputs.get("ciphertext", b""),
            iv=inputs.get("iv"),
            nonce=inputs.get("nonce"),
            tweak=inputs.get("tweak"),
            aad=inputs.get("aad", b""),
            has_prefix=inputs.get("has_prefix", True),
            nonce_length=inputs.get("nonce_length", 13),
            segment_size=inputs.get("segment_size", 128),
            tag_length=inputs.get("tag_length", 16),
            verbose=True,
            output_file=inputs.get("output_file"),
            output_format=inputs.get("output_format", "raw"),
        )


# -----------------------------------------------------------------------------
# argparse CLI
# -----------------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AES modes demo with separate Encrypt/Decrypt operation selection.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--mode", help="ECB, CBC, CFB, OFB, CTR, GCM, GMAC, CCM, GCM-SIV, XTS, KW, or KWP. Omit for menu.")
    parser.add_argument("--operation", "--op", help="encrypt/decrypt. For GMAC: generate/verify. For KW/KWP: wrap/unwrap.")

    parser.add_argument("--key", help="AES key / KEK. Type text directly, use hex:001122..., or R for random.")
    parser.add_argument("--key-file", help="Read AES key / KEK from file.")
    parser.add_argument("--key-file-format", choices=["raw", "hex", "text"], default="raw")

    parser.add_argument("--xts-key", help="XTS double-length key. Type text directly, use hex:001122..., or R for random.")
    parser.add_argument("--xts-key-file", help="Read XTS double-length key from file.")
    parser.add_argument("--xts-key-file-format", choices=["raw", "hex", "text"], default="raw")

    parser.add_argument("--plaintext", "--input", help="Plaintext/message/key material. Type text directly or use hex:001122...")
    parser.add_argument("--ciphertext", "--token", "--wrapped-key", help="Ciphertext/token/wrapped key as hex bytes.")
    parser.add_argument("--input-file", help="Read plaintext/key-material on encryption, or ciphertext/token/wrapped-key on decryption.")
    parser.add_argument("--input-file-format", choices=["raw", "hex", "text"], default="raw")

    parser.add_argument("--iv", help="CBC/CFB/OFB/CTR IV/counter block. Use hex:001122..., text:..., or R for random on encryption.")
    parser.add_argument("--iv-file", help="Read IV/counter block from file.")
    parser.add_argument("--iv-file-format", choices=["raw", "hex", "text"], default="raw")

    parser.add_argument("--nonce", help="AEAD/GMAC nonce. Use hex:001122..., text:..., or R for random on encryption.")
    parser.add_argument("--nonce-file", help="Read nonce from file.")
    parser.add_argument("--nonce-file-format", choices=["raw", "hex", "text"], default="raw")

    parser.add_argument("--tweak", help="XTS 16-byte tweak. Use hex:001122..., text:..., or R for random on encryption.")
    parser.add_argument("--tweak-file", help="Read XTS tweak from file.")
    parser.add_argument("--tweak-file-format", choices=["raw", "hex", "text"], default="raw")

    parser.add_argument("--aad", help="AAD/authenticated data. Type text directly or use hex:001122...")
    parser.add_argument("--aad-file", help="Read AAD/authenticated data from file.")
    parser.add_argument("--aad-file-format", choices=["raw", "hex", "text"], default="raw")

    parser.add_argument("--output-file", help="Save primary output: ciphertext/token/wrapped-key on encryption, plaintext/unwrapped-key on decryption.")
    parser.add_argument("--output-file-format", choices=["raw", "hex", "text"], default="raw")

    parser.add_argument("--has-prefix", choices=["yes", "no", "true", "false", "1", "0"], help="For decryption: ciphertext/token includes IV/nonce prefix.")
    parser.add_argument("--segment-size", type=int, default=128, help="CFB segment size in bits.")
    parser.add_argument("--tag-length", type=int, default=16, help="CCM tag length in bytes.")
    parser.add_argument("--nonce-length", type=int, default=13, help="CCM nonce length when token includes nonce prefix.")
    parser.add_argument("--show-key-expansion", action="store_true", help="Prompt for an AES key and print its key expansion.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose backend messages where supported.")
    parser.add_argument("--gui", action="store_true", help="Launch the optional PyQt6 graphical interface.")
    return parser


def collect_cli_inputs(args, mode: str, operation: str) -> dict:
    key: Optional[bytes] = None
    xts_key: Optional[bytes] = None
    iv: Optional[bytes] = None
    nonce: Optional[bytes] = None
    tweak: Optional[bytes] = None
    aad = b""
    plaintext = b""
    ciphertext = b""
    has_prefix = True
    nonce_length = args.nonce_length
    tag_length = args.tag_length
    segment_size = args.segment_size

    if mode == "CFB" and segment_size not in (8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128):
        raise ValueError("CFB segment size must be byte-aligned between 8 and 128 bits.")
    if mode == "CCM" and tag_length not in (4, 6, 8, 10, 12, 14, 16):
        raise ValueError("CCM tag length must be one of 4, 6, 8, 10, 12, 14, 16.")

    if mode == "XTS":
        xts_key = value_from_cli_or_prompt(
            cli_value=args.xts_key,
            cli_file=args.xts_key_file,
            cli_file_format=args.xts_key_file_format,
            label="Input XTS double-length key",
            allowed_lengths=XTS_AES_KEY_LENGTHS,
            allow_random=(operation == OP_ENCRYPT),
            random_length=32,
        )
        tweak = value_from_cli_or_prompt(
            cli_value=args.tweak,
            cli_file=args.tweak_file,
            cli_file_format=args.tweak_file_format,
            label="Input XTS 16-byte tweak",
            allowed_lengths=(16,),
            allow_random=(operation == OP_ENCRYPT),
            random_length=16,
        )
        if operation == OP_ENCRYPT:
            plaintext = value_from_cli_or_prompt(
                cli_value=args.plaintext,
                cli_file=args.input_file,
                cli_file_format=args.input_file_format,
                label="Input storage data-unit plaintext",
                min_len=16,
            )
        else:
            ciphertext = value_from_cli_or_prompt(
                cli_value=args.ciphertext,
                cli_file=args.input_file,
                cli_file_format=args.input_file_format,
                label="Input XTS ciphertext data unit",
                default_format="hex",
                min_len=16,
            )
        return locals()

    key = value_from_cli_or_prompt(
        cli_value=args.key,
        cli_file=args.key_file,
        cli_file_format=args.key_file_format,
        label="Input AES key / KEK",
        allowed_lengths=NORMAL_AES_KEY_LENGTHS,
        allow_random=(operation == OP_ENCRYPT),
        random_length=16,
    )

    if operation == OP_ENCRYPT:
        if mode in {"KW", "KWP"}:
            plaintext = value_from_cli_or_prompt(
                cli_value=args.plaintext,
                cli_file=args.input_file,
                cli_file_format=args.input_file_format,
                label="Input key material to wrap",
                min_len=16 if mode == "KW" else 1,
            )
        elif mode == "GMAC":
            aad = value_from_cli_or_prompt(
                cli_value=args.aad,
                cli_file=args.input_file if args.aad_file is None else args.aad_file,
                cli_file_format=args.input_file_format if args.aad_file is None else args.aad_file_format,
                label="Input data to authenticate",
                min_len=1,
            )
        else:
            plaintext = value_from_cli_or_prompt(
                cli_value=args.plaintext,
                cli_file=args.input_file,
                cli_file_format=args.input_file_format,
                label="Input plaintext",
                min_len=0,
                allow_empty=True,
            )

        if mode in CLASSIC_IV_MODES:
            iv = value_from_cli_or_prompt(
                cli_value=args.iv,
                cli_file=args.iv_file,
                cli_file_format=args.iv_file_format,
                label=f"Input {mode} IV/counter block",
                allowed_lengths=(16,),
                allow_random=True,
                random_length=16,
            )
        if mode in {"GCM", "GMAC", "GCM-SIV"}:
            nonce = value_from_cli_or_prompt(
                cli_value=args.nonce,
                cli_file=args.nonce_file,
                cli_file_format=args.nonce_file_format,
                label=f"Input {mode} 12-byte nonce",
                allowed_lengths=(12,),
                allow_random=True,
                random_length=12,
            )
        if mode == "CCM":
            nonce = value_from_cli_or_prompt(
                cli_value=args.nonce,
                cli_file=args.nonce_file,
                cli_file_format=args.nonce_file_format,
                label="Input CCM nonce",
                min_len=7,
                max_len=13,
                allow_random=True,
                random_length=13,
            )
        if mode in AEAD_MODES:
            aad = value_from_cli_or_prompt(
                cli_value=args.aad,
                cli_file=args.aad_file,
                cli_file_format=args.aad_file_format,
                label="Input AAD/authenticated data",
                min_len=0,
                allow_empty=True,
            )
    else:
        if mode in {"KW", "KWP"}:
            ciphertext = value_from_cli_or_prompt(
                cli_value=args.ciphertext,
                cli_file=args.input_file,
                cli_file_format=args.input_file_format,
                label="Input wrapped key",
                default_format="hex",
                min_len=16,
            )
        elif mode == "GMAC":
            ciphertext = value_from_cli_or_prompt(
                cli_value=args.ciphertext,
                cli_file=args.input_file,
                cli_file_format=args.input_file_format,
                label="Input GMAC token",
                default_format="hex",
                min_len=16,
            )
            has_prefix = bool_from_cli_or_prompt(cli_value=args.has_prefix, label="Does the GMAC token include the 12-byte nonce prefix?", default=True)
            if not has_prefix:
                nonce = value_from_cli_or_prompt(
                    cli_value=args.nonce,
                    cli_file=args.nonce_file,
                    cli_file_format=args.nonce_file_format,
                    label="Input separate GMAC 12-byte nonce",
                    allowed_lengths=(12,),
                )
            aad = value_from_cli_or_prompt(
                cli_value=args.aad,
                cli_file=args.aad_file,
                cli_file_format=args.aad_file_format,
                label="Input data to authenticate/verify",
                min_len=1,
            )
        else:
            ciphertext = value_from_cli_or_prompt(
                cli_value=args.ciphertext,
                cli_file=args.input_file,
                cli_file_format=args.input_file_format,
                label="Input ciphertext/token",
                default_format="hex",
                min_len=1,
            )
            if mode in CLASSIC_IV_MODES:
                has_prefix = bool_from_cli_or_prompt(cli_value=args.has_prefix, label="Does ciphertext include the 16-byte IV/counter prefix?", default=True)
                if not has_prefix:
                    iv = value_from_cli_or_prompt(
                        cli_value=args.iv,
                        cli_file=args.iv_file,
                        cli_file_format=args.iv_file_format,
                        label=f"Input separate {mode} IV/counter block",
                        allowed_lengths=(16,),
                    )
            if mode in {"GCM", "GCM-SIV"}:
                has_prefix = bool_from_cli_or_prompt(cli_value=args.has_prefix, label="Does token include the 12-byte nonce prefix?", default=True)
                if not has_prefix:
                    nonce = value_from_cli_or_prompt(
                        cli_value=args.nonce,
                        cli_file=args.nonce_file,
                        cli_file_format=args.nonce_file_format,
                        label=f"Input separate {mode} 12-byte nonce",
                        allowed_lengths=(12,),
                    )
                aad = value_from_cli_or_prompt(
                cli_value=args.aad,
                cli_file=args.aad_file,
                cli_file_format=args.aad_file_format,
                label="Input AAD/authenticated data",
                min_len=0,
                allow_empty=True,
            )
            if mode == "CCM":
                has_prefix = bool_from_cli_or_prompt(cli_value=args.has_prefix, label="Does token include the CCM nonce prefix?", default=True)
                if has_prefix:
                    if not (7 <= nonce_length <= 13):
                        raise ValueError("CCM nonce_length must be 7..13.")
                else:
                    nonce = value_from_cli_or_prompt(
                        cli_value=args.nonce,
                        cli_file=args.nonce_file,
                        cli_file_format=args.nonce_file_format,
                        label="Input separate CCM nonce",
                        min_len=7,
                        max_len=13,
                    )
                    nonce_length = len(nonce)
                aad = value_from_cli_or_prompt(
                cli_value=args.aad,
                cli_file=args.aad_file,
                cli_file_format=args.aad_file_format,
                label="Input AAD/authenticated data",
                min_len=0,
                allow_empty=True,
            )

    return locals()



# -----------------------------------------------------------------------------
# AES primitive teaching helpers: key schedule and one-block round operations
# -----------------------------------------------------------------------------
# These helpers are intentionally self-contained so the teaching tabs work even
# when an external key_expansion module is not available.

_AES_SBOX = (
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
)
_AES_INV_SBOX = [0] * 256
for _i, _v in enumerate(_AES_SBOX):
    _AES_INV_SBOX[_v] = _i
_AES_RCON = (0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a)


def aes_parameters_for_key(key: bytes) -> Tuple[int, int, int]:
    if len(key) == 16:
        return 4, 10, 44
    if len(key) == 24:
        return 6, 12, 52
    if len(key) == 32:
        return 8, 14, 60
    raise ValueError("AES key must be 16, 24, or 32 bytes.")


def _rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def _sub_word(word: list[int]) -> list[int]:
    return [_AES_SBOX[b] for b in word]


def aes_expand_round_keys(key: bytes) -> list[bytes]:
    nk, nr, total_words = aes_parameters_for_key(key)
    words = [list(key[4*i:4*i+4]) for i in range(nk)]
    i = nk
    while len(words) < total_words:
        temp = words[-1][:]
        if i % nk == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= _AES_RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = _sub_word(temp)
        words.append([words[i-nk][j] ^ temp[j] for j in range(4)])
        i += 1
    return [bytes(sum(words[4*r:4*r+4], [])) for r in range(nr + 1)]


def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def aes_sub_bytes(state: bytes) -> bytes:
    require_lengths(state, (16,), "AES state")
    return bytes(_AES_SBOX[b] for b in state)


def aes_inv_sub_bytes(state: bytes) -> bytes:
    require_lengths(state, (16,), "AES state")
    return bytes(_AES_INV_SBOX[b] for b in state)


def _to_matrix(state: bytes) -> list[list[int]]:
    require_lengths(state, (16,), "AES state")
    return [[state[4*c + r] for c in range(4)] for r in range(4)]


def _from_matrix(m: list[list[int]]) -> bytes:
    return bytes(m[r][c] for c in range(4) for r in range(4))


def aes_shift_rows(state: bytes) -> bytes:
    m = _to_matrix(state)
    for r in range(1, 4):
        m[r] = m[r][r:] + m[r][:r]
    return _from_matrix(m)


def aes_inv_shift_rows(state: bytes) -> bytes:
    m = _to_matrix(state)
    for r in range(1, 4):
        m[r] = m[r][-r:] + m[r][:-r]
    return _from_matrix(m)


def aes_mix_columns(state: bytes) -> bytes:
    m = _to_matrix(state)
    for c in range(4):
        a0,a1,a2,a3 = (m[r][c] for r in range(4))
        m[0][c] = _gf_mul(a0,2) ^ _gf_mul(a1,3) ^ a2 ^ a3
        m[1][c] = a0 ^ _gf_mul(a1,2) ^ _gf_mul(a2,3) ^ a3
        m[2][c] = a0 ^ a1 ^ _gf_mul(a2,2) ^ _gf_mul(a3,3)
        m[3][c] = _gf_mul(a0,3) ^ a1 ^ a2 ^ _gf_mul(a3,2)
    return _from_matrix(m)


def aes_inv_mix_columns(state: bytes) -> bytes:
    m = _to_matrix(state)
    for c in range(4):
        a0,a1,a2,a3 = (m[r][c] for r in range(4))
        m[0][c] = _gf_mul(a0,14) ^ _gf_mul(a1,11) ^ _gf_mul(a2,13) ^ _gf_mul(a3,9)
        m[1][c] = _gf_mul(a0,9) ^ _gf_mul(a1,14) ^ _gf_mul(a2,11) ^ _gf_mul(a3,13)
        m[2][c] = _gf_mul(a0,13) ^ _gf_mul(a1,9) ^ _gf_mul(a2,14) ^ _gf_mul(a3,11)
        m[3][c] = _gf_mul(a0,11) ^ _gf_mul(a1,13) ^ _gf_mul(a2,9) ^ _gf_mul(a3,14)
    return _from_matrix(m)


def aes_add_round_key(state: bytes, round_key: bytes) -> bytes:
    require_lengths(state, (16,), "AES state")
    require_lengths(round_key, (16,), "AES round key")
    return bytes(a ^ b for a, b in zip(state, round_key))


def aes_state_grid(state: bytes) -> str:
    m = _to_matrix(state)
    return "\n".join(" ".join(f"{m[r][c]:02x}" for c in range(4)) for r in range(4))


def aes_encrypt_block_trace(block: bytes, key: bytes) -> Tuple[bytes, list[Tuple[str, bytes]]]:
    require_lengths(block, (16,), "AES plaintext block")
    round_keys = aes_expand_round_keys(key)
    nr = len(round_keys) - 1
    state = block
    trace: list[Tuple[str, bytes]] = [("Input plaintext", state)]
    state = aes_add_round_key(state, round_keys[0])
    trace.append(("Round 0 - AddRoundKey", state))
    for rnd in range(1, nr):
        state = aes_sub_bytes(state); trace.append((f"Round {rnd} - SubBytes", state))
        state = aes_shift_rows(state); trace.append((f"Round {rnd} - ShiftRows", state))
        state = aes_mix_columns(state); trace.append((f"Round {rnd} - MixColumns", state))
        state = aes_add_round_key(state, round_keys[rnd]); trace.append((f"Round {rnd} - AddRoundKey", state))
    state = aes_sub_bytes(state); trace.append((f"Round {nr} - SubBytes", state))
    state = aes_shift_rows(state); trace.append((f"Round {nr} - ShiftRows", state))
    state = aes_add_round_key(state, round_keys[nr]); trace.append((f"Round {nr} - AddRoundKey", state))
    trace.append(("Ciphertext", state))
    return state, trace


def aes_decrypt_block_trace(block: bytes, key: bytes) -> Tuple[bytes, list[Tuple[str, bytes]]]:
    require_lengths(block, (16,), "AES ciphertext block")
    round_keys = aes_expand_round_keys(key)
    nr = len(round_keys) - 1
    state = block
    trace: list[Tuple[str, bytes]] = [("Input ciphertext", state)]
    state = aes_add_round_key(state, round_keys[nr])
    trace.append((f"Initial - AddRoundKey K{nr}", state))
    for rnd in range(nr - 1, 0, -1):
        state = aes_inv_shift_rows(state); trace.append((f"Round {rnd} - InvShiftRows", state))
        state = aes_inv_sub_bytes(state); trace.append((f"Round {rnd} - InvSubBytes", state))
        state = aes_add_round_key(state, round_keys[rnd]); trace.append((f"Round {rnd} - AddRoundKey", state))
        state = aes_inv_mix_columns(state); trace.append((f"Round {rnd} - InvMixColumns", state))
    state = aes_inv_shift_rows(state); trace.append(("Round 0 - InvShiftRows", state))
    state = aes_inv_sub_bytes(state); trace.append(("Round 0 - InvSubBytes", state))
    state = aes_add_round_key(state, round_keys[0]); trace.append(("Round 0 - AddRoundKey", state))
    trace.append(("Recovered plaintext", state))
    return state, trace


# -----------------------------------------------------------------------------
# Optional PyQt6 GUI
# -----------------------------------------------------------------------------
def gui_main() -> None:
    """Launch the optional PyQt6 GUI without changing the existing CLI/menu API."""
    try:
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QFont
        from PyQt6.QtWidgets import (
            QApplication,
            QCheckBox,
            QComboBox,
            QFileDialog,
            QFormLayout,
            QGridLayout,
            QGroupBox,
            QHBoxLayout,
            QLabel,
            QLineEdit,
            QMainWindow,
            QMessageBox,
            QPlainTextEdit,
            QPushButton,
            QScrollArea,
            QSizePolicy,
            QSpinBox,
            QTabWidget,
            QVBoxLayout,
            QWidget,
        )
    except ImportError as exc:
        raise ImportError(
            "PyQt6 is required for GUI mode. Install it with: pip install PyQt6"
        ) from exc

    import contextlib
    import io
    import traceback

    class ByteInputWidget(QWidget):
        """Reusable bytes input: text, hex, or file-backed data."""

        def __init__(self, *, multiline: bool = False, random_enabled: bool = False, parent=None):
            super().__init__(parent)
            self.multiline = multiline
            self.random_enabled = random_enabled

            layout = QHBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(6)

            self.source = QComboBox()
            self.source.addItems(["Text", "Hex", "Raw file", "Hex file", "Text file"])
            self.source.setMinimumWidth(92)
            layout.addWidget(self.source)

            if multiline:
                self.editor = QPlainTextEdit()
                self.editor.setMaximumHeight(78)
                self.editor.setPlaceholderText("Enter text/hex here, or choose a file source and browse...")
            else:
                self.editor = QLineEdit()
                self.editor.setPlaceholderText("Enter value, or browse a file...")
            self.editor.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            layout.addWidget(self.editor, 1)

            self.browse_button = QPushButton("Browse")
            self.browse_button.clicked.connect(self.browse_file)
            layout.addWidget(self.browse_button)

            self.random_button = QPushButton("Random")
            self.random_button.setVisible(random_enabled)
            layout.addWidget(self.random_button)

            self.source.currentTextChanged.connect(self._source_changed)
            self._source_changed(self.source.currentText())

        def _source_changed(self, value: str) -> None:
            file_mode = value.endswith("file")
            self.browse_button.setEnabled(file_mode)
            if file_mode:
                self.editor.setPlaceholderText("File path...")
            elif value == "Hex":
                self.editor.setPlaceholderText("Hex bytes, e.g. 001122aabb or hex:001122...")
            else:
                self.editor.setPlaceholderText("UTF-8 text; text:... and hex:... prefixes are also accepted")

        def _get_text(self) -> str:
            if isinstance(self.editor, QPlainTextEdit):
                return self.editor.toPlainText()
            return self.editor.text()

        def _set_text(self, value: str) -> None:
            if isinstance(self.editor, QPlainTextEdit):
                self.editor.setPlainText(value)
            else:
                self.editor.setText(value)

        def clear(self) -> None:
            self._set_text("")

        def set_hex(self, data: bytes) -> None:
            self.source.setCurrentText("Hex")
            self._set_text(data.hex())

        def set_text_value(self, value: str) -> None:
            self.source.setCurrentText("Text")
            self._set_text(value)

        def browse_file(self) -> None:
            path, _ = QFileDialog.getOpenFileName(self, "Select input file")
            if path:
                if not self.source.currentText().endswith("file"):
                    self.source.setCurrentText("Raw file")
                self._set_text(path)

        def get_bytes(
            self,
            label: str,
            *,
            allow_empty: bool = False,
            allowed_lengths: Optional[Tuple[int, ...]] = None,
            min_len: Optional[int] = None,
            max_len: Optional[int] = None,
        ) -> bytes:
            raw = self._get_text()
            if raw == "" and allow_empty:
                value = b""
            else:
                source = self.source.currentText()
                if source == "Text":
                    value = parse_text_or_hex(raw, name=label, default_format="text")
                elif source == "Hex":
                    value = parse_text_or_hex(raw, name=label, default_format="hex")
                elif source == "Raw file":
                    value = read_file_bytes(raw, file_format="raw", name=label)
                elif source == "Hex file":
                    value = read_file_bytes(raw, file_format="hex", name=label)
                elif source == "Text file":
                    value = read_file_bytes(raw, file_format="text", name=label)
                else:
                    raise ValueError(f"Unsupported GUI input source: {source}")

            return validate_data_constraints(
                value,
                label=label,
                allowed_lengths=allowed_lengths,
                min_len=min_len,
                max_len=max_len,
            )

    class AESGuiWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("AES All-Modes Demonstrator — PyQt6")
            self.resize(1180, 900)

            central = QWidget()
            self.setCentralWidget(central)
            root = QVBoxLayout(central)

            title = QLabel("AES Modern Symmetric Cipher Demonstrator")
            title_font = QFont()
            title_font.setPointSize(17)
            title_font.setBold(True)
            title.setFont(title_font)
            title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            root.addWidget(title)

            subtitle = QLabel(
                "ECB, CBC, CFB, OFB, CTR, GCM, GMAC, CCM, GCM-SIV, XTS, KW, KWP"
            )
            subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
            root.addWidget(subtitle)

            self.tabs = QTabWidget()
            root.addWidget(self.tabs, 1)

            modes_tab = QWidget()
            modes_root = QVBoxLayout(modes_tab)
            self.tabs.addTab(modes_tab, "AES Modes")

            top = QHBoxLayout()
            top.addWidget(QLabel("AES mode:"))
            self.mode_combo = QComboBox()
            self.mode_combo.addItems([
                "ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "GMAC",
                "CCM", "GCM-SIV", "XTS", "KW", "KWP"
            ])
            top.addWidget(self.mode_combo)

            top.addSpacing(18)
            top.addWidget(QLabel("Operation:"))
            self.operation_combo = QComboBox()
            top.addWidget(self.operation_combo)

            top.addSpacing(18)
            self.verbose_check = QCheckBox("Verbose backend")
            top.addWidget(self.verbose_check)
            top.addStretch(1)
            modes_root.addLayout(top)

            self.mode_note = QLabel()
            self.mode_note.setWordWrap(True)
            self.mode_note.setStyleSheet(
                "QLabel { padding: 7px; border: 1px solid #8aa4bd; "
                "border-radius: 5px; background: #f5f9fc; }"
            )
            modes_root.addWidget(self.mode_note)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            form_host = QWidget()
            scroll.setWidget(form_host)
            self.form = QFormLayout(form_host)
            self.form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            modes_root.addWidget(scroll, 1)

            # Main byte-oriented fields.
            self.key_field = ByteInputWidget(random_enabled=True)
            self.xts_key_field = ByteInputWidget(random_enabled=True)
            self.iv_field = ByteInputWidget(random_enabled=True)
            self.nonce_field = ByteInputWidget(random_enabled=True)
            self.tweak_field = ByteInputWidget(random_enabled=True)
            self.input_field = ByteInputWidget(multiline=True)
            self.aad_field = ByteInputWidget(multiline=True)

            self.key_size_combo = QComboBox()
            self.key_size_combo.addItems(["16 bytes (AES-128)", "24 bytes (AES-192)", "32 bytes (AES-256)"])
            key_wrap = QWidget()
            key_layout = QVBoxLayout(key_wrap)
            key_layout.setContentsMargins(0, 0, 0, 0)
            key_layout.addWidget(self.key_field)
            key_layout.addWidget(self.key_size_combo)
            self.key_row_label = QLabel("AES key / KEK:")
            self.form.addRow(self.key_row_label, key_wrap)

            self.xts_size_combo = QComboBox()
            self.xts_size_combo.addItems(["32 bytes (AES-128-XTS)", "64 bytes (AES-256-XTS)"])
            xts_wrap = QWidget()
            xts_layout = QVBoxLayout(xts_wrap)
            xts_layout.setContentsMargins(0, 0, 0, 0)
            xts_layout.addWidget(self.xts_key_field)
            xts_layout.addWidget(self.xts_size_combo)
            self.xts_key_row_label = QLabel("XTS double-length key:")
            self.form.addRow(self.xts_key_row_label, xts_wrap)
            self.xts_wrap = xts_wrap

            self.iv_row_label = QLabel("IV / counter block:")
            self.form.addRow(self.iv_row_label, self.iv_field)
            self.nonce_row_label = QLabel("Nonce:")
            self.form.addRow(self.nonce_row_label, self.nonce_field)
            self.tweak_row_label = QLabel("XTS tweak:")
            self.form.addRow(self.tweak_row_label, self.tweak_field)

            self.input_row_label = QLabel("Input:")
            self.form.addRow(self.input_row_label, self.input_field)
            self.aad_row_label = QLabel("AAD / authenticated data:")
            self.form.addRow(self.aad_row_label, self.aad_field)

            # Prefix, CFB and CCM options.
            self.prefix_check = QCheckBox("Input contains the IV/nonce prefix")
            self.prefix_check.setChecked(True)
            self.prefix_row_label = QLabel("Decryption token format:")
            self.form.addRow(self.prefix_row_label, self.prefix_check)

            self.segment_combo = QComboBox()
            self.segment_combo.addItems([str(x) for x in range(8, 129, 8)])
            self.segment_combo.setCurrentText("128")
            self.segment_row_label = QLabel("CFB segment size (bits):")
            self.form.addRow(self.segment_row_label, self.segment_combo)

            self.tag_combo = QComboBox()
            self.tag_combo.addItems(["4", "6", "8", "10", "12", "14", "16"])
            self.tag_combo.setCurrentText("16")
            self.tag_row_label = QLabel("CCM tag length (bytes):")
            self.form.addRow(self.tag_row_label, self.tag_combo)

            self.nonce_length_combo = QComboBox()
            self.nonce_length_combo.addItems([str(x) for x in range(7, 14)])
            self.nonce_length_combo.setCurrentText("13")
            self.nonce_length_row_label = QLabel("CCM nonce length in prefix:")
            self.form.addRow(self.nonce_length_row_label, self.nonce_length_combo)

            # Output controls.
            output_box = QWidget()
            output_layout = QHBoxLayout(output_box)
            output_layout.setContentsMargins(0, 0, 0, 0)
            self.output_file_edit = QLineEdit()
            self.output_file_edit.setPlaceholderText("Optional output file path")
            output_layout.addWidget(self.output_file_edit, 1)
            self.output_browse = QPushButton("Save As...")
            self.output_browse.clicked.connect(self.choose_output_file)
            output_layout.addWidget(self.output_browse)
            self.output_format_combo = QComboBox()
            self.output_format_combo.addItems(["raw", "hex", "text"])
            output_layout.addWidget(self.output_format_combo)
            self.form.addRow("Save primary output:", output_box)

            # Action buttons.
            actions = QHBoxLayout()
            self.run_button = QPushButton("Run")
            self.run_button.setMinimumHeight(38)
            self.run_button.clicked.connect(self.run_operation)
            actions.addWidget(self.run_button)

            self.keyexp_button = QPushButton("Show Key Expansion")
            self.keyexp_button.clicked.connect(self.show_key_expansion)
            actions.addWidget(self.keyexp_button)

            self.clear_button = QPushButton("Clear Inputs")
            self.clear_button.clicked.connect(self.clear_inputs)
            actions.addWidget(self.clear_button)

            self.copy_button = QPushButton("Copy Log")
            self.copy_button.clicked.connect(self.copy_log)
            actions.addWidget(self.copy_button)
            modes_root.addLayout(actions)

            self.log = QPlainTextEdit()
            self.log.setReadOnly(True)
            self.log.setPlaceholderText("Execution report will appear here...")
            self.log.setMinimumHeight(220)
            modes_root.addWidget(self.log)

            # Signals.
            self.mode_combo.currentTextChanged.connect(self.mode_changed)
            self.operation_combo.currentIndexChanged.connect(self.refresh_ui)
            self.prefix_check.toggled.connect(self.refresh_ui)
            self.key_size_combo.currentIndexChanged.connect(self._update_random_handlers)
            self.xts_size_combo.currentIndexChanged.connect(self._update_random_handlers)

            self._update_random_handlers()
            self.mode_changed(self.mode_combo.currentText())

            self._build_round_key_tab()
            self._build_block_round_tab()

        # ---- Teaching tabs -----------------------------------------------
        def _build_round_key_tab(self) -> None:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            self.tabs.addTab(tab, "Round Keys / Key Schedule")

            note = QLabel(
                "AES is a block cipher, so this is a key schedule (round keys), not a stream-cipher keystream. "
                "AES-128 uses 10 rounds, AES-192 uses 12, and AES-256 uses 14. The display includes K0."
            )
            note.setWordWrap(True)
            layout.addWidget(note)

            form = QFormLayout()
            self.rk_key_field = ByteInputWidget(random_enabled=True)
            self.rk_key_size_combo = QComboBox()
            self.rk_key_size_combo.addItems([
                "16 bytes (AES-128)", "24 bytes (AES-192)", "32 bytes (AES-256)"
            ])
            key_box = QWidget()
            key_box_layout = QVBoxLayout(key_box)
            key_box_layout.setContentsMargins(0, 0, 0, 0)
            key_box_layout.addWidget(self.rk_key_field)
            key_box_layout.addWidget(self.rk_key_size_combo)
            form.addRow("Cipher key:", key_box)
            layout.addLayout(form)

            buttons = QHBoxLayout()
            gen = QPushButton("Generate Round Keys")
            gen.clicked.connect(self.generate_round_keys_tab)
            buttons.addWidget(gen)
            clear = QPushButton("Clear")
            clear.clicked.connect(lambda: self.rk_output.clear())
            buttons.addWidget(clear)
            buttons.addStretch(1)
            layout.addLayout(buttons)

            self.rk_output = QPlainTextEdit()
            self.rk_output.setReadOnly(True)
            self.rk_output.setPlaceholderText("K0, K1, ... and word-level key schedule will appear here...")
            layout.addWidget(self.rk_output, 1)

            def set_random_round_key():
                n = (16, 24, 32)[self.rk_key_size_combo.currentIndex()]
                self.rk_key_field.set_hex(secrets.token_bytes(n))
            self._replace_random_connection(self.rk_key_field.random_button, set_random_round_key)

        def generate_round_keys_tab(self) -> None:
            try:
                key = self.rk_key_field.get_bytes(
                    "AES cipher key", allowed_lengths=NORMAL_AES_KEY_LENGTHS
                )
                nk, nr, total_words = aes_parameters_for_key(key)
                round_keys = aes_expand_round_keys(key)
                lines = [
                    f"AES-{len(key) * 8} KEY SCHEDULE",
                    "=" * 72,
                    f"Nk = {nk} words | Nr = {nr} rounds | Expanded words = {total_words}",
                    f"Cipher key = {key.hex()}",
                    "",
                    "Recursive rule:",
                    "If i mod 6 = 0: Wi = W(i-6) XOR SubWord(RotWord(W(i-1))) XOR Rcon",
                    "Otherwise: Wi = W(i-6) XOR W(i-1)",
                    "",
                    "Initial key: W0-W5",
                    f"Expanded key: W0-W{total_words - 1}",
                ]
                for r, rk in enumerate(round_keys):
                    lines.append(f"K{r:02d} = {rk.hex()}")
                    lines.append(aes_state_grid(rk))
                    lines.append("")
                self.rk_output.setPlainText("\n".join(lines))
            except Exception as exc:
                QMessageBox.critical(self, "Round-key generation failed", str(exc))

        def _build_block_round_tab(self) -> None:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            self.tabs.addTab(tab, "AES One-Block / Round Operations")

            note = QLabel(
                "Teaching view for exactly one 16-byte AES block. Encrypt shows SubBytes → ShiftRows → "
                "MixColumns → AddRoundKey for normal rounds; the final encryption round omits MixColumns. "
                "Decrypt shows the inverse transformations in the AES inverse-cipher order."
            )
            note.setWordWrap(True)
            layout.addWidget(note)

            form = QFormLayout()
            self.block_key_field = ByteInputWidget(random_enabled=True)
            self.block_key_size_combo = QComboBox()
            self.block_key_size_combo.addItems([
                "16 bytes (AES-128)", "24 bytes (AES-192)", "32 bytes (AES-256)"
            ])
            key_box = QWidget()
            key_layout = QVBoxLayout(key_box)
            key_layout.setContentsMargins(0, 0, 0, 0)
            key_layout.addWidget(self.block_key_field)
            key_layout.addWidget(self.block_key_size_combo)
            form.addRow("AES key:", key_box)

            self.block_input_field = ByteInputWidget()
            form.addRow("16-byte input block:", self.block_input_field)

            self.block_direction = QComboBox()
            self.block_direction.addItems(["Encrypt one block", "Decrypt one block"])
            form.addRow("Direction:", self.block_direction)
            layout.addLayout(form)

            full_buttons = QHBoxLayout()
            run_full = QPushButton("Run Full One-Block Trace")
            run_full.clicked.connect(self.run_one_block_trace)
            full_buttons.addWidget(run_full)
            copy_result = QPushButton("Copy final result to state playground")
            copy_result.clicked.connect(self.copy_block_result_to_state)
            full_buttons.addWidget(copy_result)
            full_buttons.addStretch(1)
            layout.addLayout(full_buttons)

            playground = QGroupBox("Four AES round operations — state playground")
            pg = QVBoxLayout(playground)
            pg_form = QFormLayout()
            self.state_field = ByteInputWidget()
            pg_form.addRow("Current 16-byte state:", self.state_field)
            self.state_direction = QComboBox()
            self.state_direction.addItems(["Encryption transforms", "Decryption / inverse transforms"])
            pg_form.addRow("Transform direction:", self.state_direction)
            self.round_spin = QSpinBox()
            self.round_spin.setRange(0, 14)
            self.round_spin.setValue(1)
            pg_form.addRow("Round key index for AddRoundKey:", self.round_spin)
            pg.addLayout(pg_form)

            op_buttons = QHBoxLayout()
            self.sub_button = QPushButton("SubBytes")
            self.shift_button = QPushButton("ShiftRows")
            self.mix_button = QPushButton("MixColumns")
            self.addkey_button = QPushButton("AddRoundKey")
            self.sub_button.clicked.connect(lambda: self.apply_state_operation("sub"))
            self.shift_button.clicked.connect(lambda: self.apply_state_operation("shift"))
            self.mix_button.clicked.connect(lambda: self.apply_state_operation("mix"))
            self.addkey_button.clicked.connect(lambda: self.apply_state_operation("addkey"))
            for b in (self.sub_button, self.shift_button, self.mix_button, self.addkey_button):
                op_buttons.addWidget(b)
            pg.addLayout(op_buttons)
            layout.addWidget(playground)

            self.block_output = QPlainTextEdit()
            self.block_output.setReadOnly(True)
            self.block_output.setPlaceholderText("Full AES block trace and individual operation results will appear here...")
            layout.addWidget(self.block_output, 1)

            self.state_direction.currentIndexChanged.connect(self._refresh_state_operation_labels)
            self.block_key_size_combo.currentIndexChanged.connect(self._refresh_block_round_limit)
            self._refresh_state_operation_labels()
            self._refresh_block_round_limit()

            def set_random_block_key():
                n = (16, 24, 32)[self.block_key_size_combo.currentIndex()]
                self.block_key_field.set_hex(secrets.token_bytes(n))
            self._replace_random_connection(self.block_key_field.random_button, set_random_block_key)

            self._last_block_result: Optional[bytes] = None

        def _refresh_block_round_limit(self, *_args) -> None:
            nr = (10, 12, 14)[self.block_key_size_combo.currentIndex()]
            self.round_spin.setMaximum(nr)
            if self.round_spin.value() > nr:
                self.round_spin.setValue(nr)

        def _refresh_state_operation_labels(self, *_args) -> None:
            inverse = self.state_direction.currentIndex() == 1
            self.sub_button.setText("InvSubBytes" if inverse else "SubBytes")
            self.shift_button.setText("InvShiftRows" if inverse else "ShiftRows")
            self.mix_button.setText("InvMixColumns" if inverse else "MixColumns")

        def _block_key(self) -> bytes:
            return self.block_key_field.get_bytes(
                "AES key", allowed_lengths=NORMAL_AES_KEY_LENGTHS
            )

        def run_one_block_trace(self) -> None:
            try:
                key = self._block_key()
                block = self.block_input_field.get_bytes(
                    "AES input block", allowed_lengths=(16,)
                )
                if self.block_direction.currentIndex() == 0:
                    result, trace = aes_encrypt_block_trace(block, key)
                    heading = f"AES-{len(key)*8} ONE-BLOCK ENCRYPTION TRACE"
                else:
                    result, trace = aes_decrypt_block_trace(block, key)
                    heading = f"AES-{len(key)*8} ONE-BLOCK DECRYPTION TRACE"
                self._last_block_result = result
                lines = [heading, "=" * 78, f"Key: {key.hex()}", ""]
                for label, state in trace:
                    lines.append(label)
                    lines.append(f"hex: {state.hex()}")
                    lines.append(aes_state_grid(state))
                    lines.append("")
                lines.append(f"FINAL RESULT: {result.hex()}")
                self.block_output.setPlainText("\n".join(lines))
            except Exception as exc:
                QMessageBox.critical(self, "One-block AES trace failed", str(exc))

        def copy_block_result_to_state(self) -> None:
            if self._last_block_result is None:
                QMessageBox.information(self, "No result", "Run a full one-block trace first.")
                return
            self.state_field.set_hex(self._last_block_result)

        def apply_state_operation(self, operation: str) -> None:
            try:
                state = self.state_field.get_bytes("AES state", allowed_lengths=(16,))
                inverse = self.state_direction.currentIndex() == 1
                label = ""
                if operation == "sub":
                    new_state = aes_inv_sub_bytes(state) if inverse else aes_sub_bytes(state)
                    label = "InvSubBytes" if inverse else "SubBytes"
                elif operation == "shift":
                    new_state = aes_inv_shift_rows(state) if inverse else aes_shift_rows(state)
                    label = "InvShiftRows" if inverse else "ShiftRows"
                elif operation == "mix":
                    new_state = aes_inv_mix_columns(state) if inverse else aes_mix_columns(state)
                    label = "InvMixColumns" if inverse else "MixColumns"
                elif operation == "addkey":
                    key = self._block_key()
                    round_keys = aes_expand_round_keys(key)
                    rnd = self.round_spin.value()
                    if rnd >= len(round_keys):
                        raise ValueError(f"AES-{len(key)*8} has round-key indices 0..{len(round_keys)-1}.")
                    new_state = aes_add_round_key(state, round_keys[rnd])
                    label = f"AddRoundKey(K{rnd})"
                else:
                    raise ValueError("Unsupported AES state operation.")

                self.state_field.set_hex(new_state)
                text = self.block_output.toPlainText()
                entry = (
                    f"\n\nSTATE PLAYGROUND — {label}\n" + "-" * 60 +
                    f"\ninput : {state.hex()}\noutput: {new_state.hex()}\n" +
                    aes_state_grid(new_state)
                )
                self.block_output.setPlainText(text + entry)
                self.block_output.verticalScrollBar().setValue(self.block_output.verticalScrollBar().maximum())
            except Exception as exc:
                QMessageBox.critical(self, "Round operation failed", str(exc))

        # ---- GUI utility -------------------------------------------------
        def _visible_row(self, label_widget: QLabel, field_widget: QWidget, visible: bool) -> None:
            label_widget.setVisible(visible)
            field_widget.setVisible(visible)

        def _normal_key_length(self) -> int:
            return (16, 24, 32)[self.key_size_combo.currentIndex()]

        def _xts_key_length(self) -> int:
            return (32, 64)[self.xts_size_combo.currentIndex()]

        def _ccm_nonce_length(self) -> int:
            return int(self.nonce_length_combo.currentText())

        def _replace_random_connection(self, button, func) -> None:
            try:
                button.clicked.disconnect()
            except Exception:
                pass
            button.clicked.connect(func)

        def _update_random_handlers(self, *_args) -> None:
            self._replace_random_connection(
                self.key_field.random_button,
                lambda: self.key_field.set_hex(secrets.token_bytes(self._normal_key_length())),
            )
            self._replace_random_connection(
                self.xts_key_field.random_button,
                lambda: self.xts_key_field.set_hex(secrets.token_bytes(self._xts_key_length())),
            )
            self._replace_random_connection(
                self.iv_field.random_button,
                lambda: self.iv_field.set_hex(secrets.token_bytes(16)),
            )
            self._replace_random_connection(
                self.tweak_field.random_button,
                lambda: self.tweak_field.set_hex(secrets.token_bytes(16)),
            )
            self._replace_random_connection(
                self.nonce_field.random_button,
                self.generate_nonce,
            )

        def generate_nonce(self) -> None:
            mode = self.mode_combo.currentText()
            n = self._ccm_nonce_length() if mode == "CCM" else 12
            self.nonce_field.set_hex(secrets.token_bytes(n))

        def choose_output_file(self) -> None:
            path, _ = QFileDialog.getSaveFileName(self, "Select output file")
            if path:
                self.output_file_edit.setText(path)

        def copy_log(self) -> None:
            QApplication.clipboard().setText(self.log.toPlainText())

        def clear_inputs(self) -> None:
            for field in (
                self.key_field, self.xts_key_field, self.iv_field,
                self.nonce_field, self.tweak_field, self.input_field, self.aad_field
            ):
                field.clear()
            self.output_file_edit.clear()
            self.log.clear()

        def mode_changed(self, mode: str) -> None:
            previous = self.operation_combo.currentData()
            self.operation_combo.blockSignals(True)
            self.operation_combo.clear()
            if mode == "GMAC":
                self.operation_combo.addItem("Generate tag", OP_ENCRYPT)
                self.operation_combo.addItem("Verify tag", OP_DECRYPT)
            elif mode in {"KW", "KWP"}:
                self.operation_combo.addItem("Wrap", OP_ENCRYPT)
                self.operation_combo.addItem("Unwrap", OP_DECRYPT)
            else:
                self.operation_combo.addItem("Encrypt", OP_ENCRYPT)
                self.operation_combo.addItem("Decrypt", OP_DECRYPT)
            if previous == OP_DECRYPT:
                self.operation_combo.setCurrentIndex(1)
            self.operation_combo.blockSignals(False)
            self.refresh_ui()

        def current_operation(self) -> str:
            data = self.operation_combo.currentData()
            return data if data in ALL_OPERATIONS else OP_ENCRYPT

        def refresh_ui(self, *_args) -> None:
            mode = self.mode_combo.currentText()
            op = self.current_operation()
            decrypting = op == OP_DECRYPT

            # Notes.
            if mode == "ECB":
                note = "Warning: ECB is teaching-only and leaks plaintext patterns."
            elif mode in {"CBC", "CFB", "OFB", "CTR", "XTS"}:
                note = f"{mode} provides confidentiality only; it does not authenticate ciphertext."
            elif mode in AEAD_MODES:
                note = f"{mode} authenticates ciphertext and AAD; decryption fails on an invalid tag/AAD/nonce."
            elif mode == "GMAC":
                note = "GMAC authenticates data only; it does not encrypt plaintext."
            else:
                note = f"{mode} wraps cryptographic key material; it is not a general message-encryption mode."
            self.mode_note.setText(note)

            self._visible_row(self.key_row_label, self.key_field.parentWidget(), mode != "XTS")
            self._visible_row(self.xts_key_row_label, self.xts_wrap, mode == "XTS")
            self._visible_row(self.iv_row_label, self.iv_field, mode in CLASSIC_IV_MODES)
            self._visible_row(self.nonce_row_label, self.nonce_field, mode in AEAD_MODES or mode == "GMAC")
            self._visible_row(self.tweak_row_label, self.tweak_field, mode == "XTS")
            self._visible_row(self.aad_row_label, self.aad_field, mode in AEAD_MODES or mode == "GMAC")
            self._visible_row(self.segment_row_label, self.segment_combo, mode == "CFB")
            self._visible_row(self.tag_row_label, self.tag_combo, mode == "CCM")

            prefix_visible = decrypting and (
                mode in CLASSIC_IV_MODES or mode in AEAD_MODES or mode == "GMAC"
            )
            self._visible_row(self.prefix_row_label, self.prefix_check, prefix_visible)

            nonce_len_visible = decrypting and mode == "CCM" and self.prefix_check.isChecked()
            self._visible_row(
                self.nonce_length_row_label, self.nonce_length_combo, nonce_len_visible
            )

            # Disable separate IV/nonce when it will be read from token prefix.
            if mode in CLASSIC_IV_MODES:
                self.iv_field.setEnabled(not (decrypting and self.prefix_check.isChecked()))
            else:
                self.iv_field.setEnabled(True)
            if mode in AEAD_MODES or mode == "GMAC":
                self.nonce_field.setEnabled(not (decrypting and self.prefix_check.isChecked()))
            else:
                self.nonce_field.setEnabled(True)

            # Input labels.
            if mode == "GMAC":
                if decrypting:
                    self.input_row_label.setText("GMAC token input:")
                    self.aad_row_label.setText("Data to authenticate / verify:")
                else:
                    self.input_row_label.setText("Data to authenticate:")
                    self.aad_row_label.setText("Optional alternate authenticated data:")
            elif mode in {"KW", "KWP"}:
                self.input_row_label.setText(
                    "Wrapped key input:" if decrypting else "Key material to wrap:"
                )
            elif mode == "XTS":
                self.input_row_label.setText(
                    "XTS ciphertext data unit:" if decrypting else "Storage data-unit plaintext:"
                )
            elif decrypting:
                self.input_row_label.setText("Ciphertext / token input:")
            else:
                self.input_row_label.setText("Plaintext input:")

        # ---- Data collection ---------------------------------------------
        def collect_gui_values(self) -> dict:
            mode = self.mode_combo.currentText()
            op = self.current_operation()
            decrypting = op == OP_DECRYPT

            key = None
            xts_key = None
            iv = None
            nonce = None
            tweak = None
            aad = b""
            plaintext = b""
            ciphertext = b""
            has_prefix = self.prefix_check.isChecked()
            segment_size = int(self.segment_combo.currentText())
            tag_length = int(self.tag_combo.currentText())
            nonce_length = int(self.nonce_length_combo.currentText())

            if mode == "XTS":
                xts_key = self.xts_key_field.get_bytes(
                    "XTS double-length key", allowed_lengths=XTS_AES_KEY_LENGTHS
                )
                tweak = self.tweak_field.get_bytes("XTS tweak", allowed_lengths=(16,))
            else:
                key = self.key_field.get_bytes(
                    "AES key / KEK", allowed_lengths=NORMAL_AES_KEY_LENGTHS
                )

            if not decrypting:
                if mode == "GMAC":
                    # For consistency with the existing driver, authenticated data is carried in aad.
                    data = self.input_field.get_bytes("GMAC authenticated data", min_len=1)
                    aad = data
                    plaintext = b""
                elif mode in {"KW", "KWP"}:
                    plaintext = self.input_field.get_bytes(
                        "Key material to wrap", min_len=16 if mode == "KW" else 1
                    )
                elif mode == "XTS":
                    plaintext = self.input_field.get_bytes(
                        "XTS storage data-unit plaintext", min_len=16
                    )
                else:
                    plaintext = self.input_field.get_bytes("Plaintext", allow_empty=True, min_len=0)

                if mode in CLASSIC_IV_MODES:
                    iv = self.iv_field.get_bytes(
                        f"{mode} IV/counter block", allowed_lengths=(16,)
                    )
                if mode in {"GCM", "GMAC", "GCM-SIV"}:
                    nonce = self.nonce_field.get_bytes(
                        f"{mode} nonce", allowed_lengths=(12,)
                    )
                elif mode == "CCM":
                    nonce = self.nonce_field.get_bytes("CCM nonce", min_len=7, max_len=13)
                    nonce_length = len(nonce)

                if mode in AEAD_MODES:
                    aad = self.aad_field.get_bytes("AAD", allow_empty=True, min_len=0)
            else:
                if mode in {"KW", "KWP"}:
                    ciphertext = self.input_field.get_bytes("Wrapped key", min_len=16)
                elif mode == "GMAC":
                    ciphertext = self.input_field.get_bytes("GMAC token", min_len=16)
                    aad = self.aad_field.get_bytes("Data to authenticate / verify", min_len=1)
                elif mode == "XTS":
                    ciphertext = self.input_field.get_bytes("XTS ciphertext data unit", min_len=16)
                else:
                    ciphertext = self.input_field.get_bytes("Ciphertext/token", min_len=1)

                if mode in CLASSIC_IV_MODES and not has_prefix:
                    iv = self.iv_field.get_bytes(
                        f"Separate {mode} IV/counter block", allowed_lengths=(16,)
                    )
                if mode in {"GCM", "GCM-SIV", "GMAC"} and not has_prefix:
                    nonce = self.nonce_field.get_bytes(
                        f"Separate {mode} nonce", allowed_lengths=(12,)
                    )
                if mode == "CCM":
                    if has_prefix:
                        if not 7 <= nonce_length <= 13:
                            raise ValueError("CCM nonce length must be 7..13 bytes.")
                    else:
                        nonce = self.nonce_field.get_bytes("Separate CCM nonce", min_len=7, max_len=13)
                        nonce_length = len(nonce)
                if mode in AEAD_MODES:
                    aad = self.aad_field.get_bytes("AAD", allow_empty=True, min_len=0)

            if mode == "CFB" and segment_size not in tuple(range(8, 129, 8)):
                raise ValueError("CFB segment size must be byte-aligned between 8 and 128 bits.")
            if mode == "CCM" and tag_length not in (4, 6, 8, 10, 12, 14, 16):
                raise ValueError("CCM tag length must be 4, 6, 8, 10, 12, 14, or 16 bytes.")

            output_file = self.output_file_edit.text().strip() or None
            output_format = self.output_format_combo.currentText()

            return {
                "mode": mode,
                "operation": op,
                "key": key,
                "xts_key": xts_key,
                "plaintext": plaintext,
                "ciphertext": ciphertext,
                "iv": iv,
                "nonce": nonce,
                "tweak": tweak,
                "aad": aad,
                "has_prefix": has_prefix,
                "nonce_length": nonce_length,
                "segment_size": segment_size,
                "tag_length": tag_length,
                "verbose": self.verbose_check.isChecked(),
                "output_file": output_file,
                "output_format": output_format,
            }

        # ---- Execution ---------------------------------------------------
        def run_operation(self) -> None:
            try:
                values = self.collect_gui_values()
                capture = io.StringIO()
                with contextlib.redirect_stdout(capture):
                    if values["operation"] == OP_ENCRYPT:
                        result = run_encrypt(
                            values["mode"],
                            key=values["key"],
                            xts_key=values["xts_key"],
                            plaintext=values["plaintext"],
                            iv=values["iv"],
                            nonce=values["nonce"],
                            tweak=values["tweak"],
                            aad=values["aad"],
                            segment_size=values["segment_size"],
                            tag_length=values["tag_length"],
                            verbose=values["verbose"],
                            output_file=values["output_file"],
                            output_format=values["output_format"],
                        )
                    else:
                        result = run_decrypt(
                            values["mode"],
                            key=values["key"],
                            xts_key=values["xts_key"],
                            ciphertext=values["ciphertext"],
                            iv=values["iv"],
                            nonce=values["nonce"],
                            tweak=values["tweak"],
                            aad=values["aad"],
                            has_prefix=values["has_prefix"],
                            nonce_length=values["nonce_length"],
                            segment_size=values["segment_size"],
                            tag_length=values["tag_length"],
                            verbose=values["verbose"],
                            output_file=values["output_file"],
                            output_format=values["output_format"],
                        )

                report = capture.getvalue()
                if result is not None:
                    report += "\nGUI result summary\n" + "-" * 60 + "\n"
                    report += f"Result length: {len(result)} byte(s)\n"
                    report += f"Result hex   : {result.hex()}\n"
                    report += f"Result text  : {decode_bytes_for_display(result)}\n"
                self.log.setPlainText(report)
            except Exception as exc:
                self.log.setPlainText(traceback.format_exc())
                QMessageBox.critical(self, "AES operation failed", str(exc))

        def show_key_expansion(self) -> None:
            try:
                module = load_key_expansion_module()
                if module is None:
                    raise RuntimeError("key_expansion module is not available.")
                key = self.key_field.get_bytes(
                    "AES key", allowed_lengths=NORMAL_AES_KEY_LENGTHS
                )
                if len(key) == 16:
                    round_keys = module.key_expansion(key).key_expansion_128()
                    aes_name = "AES-128"
                elif len(key) == 24:
                    round_keys = module.key_expansion(key).key_expansion_192()
                    aes_name = "AES-192"
                else:
                    round_keys = module.key_expansion(key).key_expansion_256()
                    aes_name = "AES-256"
                self.log.setPlainText(
                    f"{aes_name} round keys:\n{round_keys}\n\n"
                    f"Number of 4-byte words: {len(round_keys)}"
                )
            except Exception as exc:
                QMessageBox.critical(self, "Key expansion failed", str(exc))

    app = QApplication.instance() or QApplication(sys.argv)
    app.setFont(QFont("Arial", 15))
    window = AESGuiWindow()
    window.show()
    app.exec()

def cli_main(argv: Optional[list[str]] = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if getattr(args, "gui", False):
        gui_main()
        return

    if args.show_key_expansion:
        show_key_expansion_demo_interactive()
        return

    if not args.mode:
        interactive_main()
        return

    mode = normalize_mode(args.mode)
    if mode not in ALL_MODES:
        raise ValueError(f"Unsupported AES mode: {mode}")

    if args.operation is None:
        operation = ask_operation_interactive(mode)
    else:
        operation = normalize_operation(args.operation)
    if operation not in ALL_OPERATIONS:
        raise ValueError("Unsupported operation. Use encrypt/decrypt, generate/verify, or wrap/unwrap.")

    inputs = collect_cli_inputs(args, mode, operation)
    if operation == OP_ENCRYPT:
        run_encrypt(
            mode,
            key=inputs.get("key"),
            xts_key=inputs.get("xts_key"),
            plaintext=inputs.get("plaintext", b""),
            iv=inputs.get("iv"),
            nonce=inputs.get("nonce"),
            tweak=inputs.get("tweak"),
            aad=inputs.get("aad", b""),
            segment_size=inputs.get("segment_size", 128),
            tag_length=inputs.get("tag_length", 16),
            verbose=args.verbose,
            output_file=args.output_file,
            output_format=args.output_file_format,
        )
    else:
        run_decrypt(
            mode,
            key=inputs.get("key"),
            xts_key=inputs.get("xts_key"),
            ciphertext=inputs.get("ciphertext", b""),
            iv=inputs.get("iv"),
            nonce=inputs.get("nonce"),
            tweak=inputs.get("tweak"),
            aad=inputs.get("aad", b""),
            has_prefix=inputs.get("has_prefix", True),
            nonce_length=inputs.get("nonce_length", 13),
            segment_size=inputs.get("segment_size", 128),
            tag_length=inputs.get("tag_length", 16),
            verbose=args.verbose,
            output_file=args.output_file,
            output_format=args.output_file_format,
        )


if __name__ == "__main__":
    cli_main()
