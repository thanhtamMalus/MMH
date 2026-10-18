# -*- coding: utf-8 -*-
"""
AES_project_encrypt_decrypt.py

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
    print(f"{label} bytes : {data!r}")
    print(f"{label} hex   : {data.hex()}")
    print(f"{label} length: {len(data)} byte(s)\n")


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
) -> bytes:
    if cli_value is not None:
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
        if max_len is not None:
            require_max_len(value, max_len, label)
        return value

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
) -> None:
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
        print_bytes("Ciphertext data unit", ciphertext)
        print("For XTS decryption, provide the ciphertext hex plus the same XTS key and tweak.\n")
        return

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
        if mode in CLASSIC_IV_MODES:
            print("Output format: IV/counter block || ciphertext body. Use this full hex as decryption input.\n")
        return

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
        print("Output format: nonce || ciphertext || authentication tag. Use this full hex as decryption input.\n")
        return

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
        print("Output format: nonce || GMAC tag. Use this full hex as verification input.\n")
        return

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
        print("Use the wrapped-key hex as decryption/unwrap input.\n")
        return

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
) -> None:
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
        print_bytes("Ciphertext data unit", ciphertext)
        recovered = aes_mode.xts_decrypt(ciphertext, xts_key=xts_key, tweak=tweak, output_encoding=None)
        print_bytes("Recovered data unit", recovered)
        print("Recovered text:", decode_bytes_for_display(recovered))
        return

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
        return

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
        return

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
        print("GMAC verification:", "OK" if ok else "FAILED")
        return

    if mode in {"KW", "KWP"}:
        print_bytes("Wrapped key input", ciphertext)
        unwrapped = aes_mode.key_unwrap(ciphertext, pad=(mode == "KWP"))
        print_bytes("Unwrapped key material", unwrapped)
        print("Unwrapped key text:", decode_bytes_for_display(unwrapped))
        return

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

    if mode == "XTS":
        xts_key = ask_data("Input XTS double-length key", allowed_lengths=XTS_AES_KEY_LENGTHS, allow_random=True, random_length=32)
        tweak = ask_data("Input XTS 16-byte tweak", allowed_lengths=(16,), allow_random=True, random_length=16)
        if operation == OP_ENCRYPT:
            plaintext = ask_data("Input storage data-unit plaintext", min_len=16)
        else:
            ciphertext = ask_ciphertext("Input XTS ciphertext data unit hex", min_len=16)
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
            plaintext = ask_data(label, min_len=16 if mode == "KW" else 1)
        elif mode == "GMAC":
            aad = ask_data("Input data to authenticate", min_len=1)
        else:
            plaintext = ask_data("Input plaintext", min_len=0, allow_empty=True)

        if mode in CLASSIC_IV_MODES:
            iv = ask_data(f"Input {mode} IV/counter block", allowed_lengths=(16,), allow_random=True, random_length=16)
        if mode in {"GCM", "GMAC", "GCM-SIV"}:
            nonce = ask_data(f"Input {mode} 12-byte nonce", allowed_lengths=(12,), allow_random=True, random_length=12)
        if mode == "CCM":
            nonce = ask_data("Input CCM nonce", min_len=7, max_len=13, allow_random=True, random_length=13)
            tag_length = ask_int("Input CCM tag length", default=16, allowed=(4, 6, 8, 10, 12, 14, 16))
        if mode in AEAD_MODES:
            aad = ask_data("Input AAD/authenticated data", min_len=0, allow_empty=True)
    else:
        if mode in {"KW", "KWP"}:
            ciphertext = ask_ciphertext("Input wrapped key hex", min_len=16)
        elif mode == "GMAC":
            ciphertext = ask_ciphertext("Input GMAC token hex", min_len=16)
            has_prefix = ask_yes_no("Does the GMAC token include the 12-byte nonce prefix?", default=True)
            if not has_prefix:
                nonce = ask_data("Input separate GMAC 12-byte nonce", allowed_lengths=(12,))
            aad = ask_data("Input data to authenticate/verify", min_len=1)
        else:
            ciphertext = ask_ciphertext("Input ciphertext/token hex", min_len=1)
            if mode in CLASSIC_IV_MODES:
                has_prefix = ask_yes_no("Does this ciphertext include the 16-byte IV/counter prefix?", default=True)
                if not has_prefix:
                    iv = ask_data(f"Input separate {mode} IV/counter block", allowed_lengths=(16,))
            if mode in {"GCM", "GCM-SIV"}:
                has_prefix = ask_yes_no("Does this token include the 12-byte nonce prefix?", default=True)
                if not has_prefix:
                    nonce = ask_data(f"Input separate {mode} 12-byte nonce", allowed_lengths=(12,))
                aad = ask_data("Input AAD/authenticated data", min_len=0, allow_empty=True)
            if mode == "CCM":
                has_prefix = ask_yes_no("Does this token include the CCM nonce prefix?", default=True)
                tag_length = ask_int("Input CCM tag length", default=16, allowed=(4, 6, 8, 10, 12, 14, 16))
                if has_prefix:
                    nonce_length = ask_int("Input CCM nonce length used in the token prefix", default=13, allowed=(7, 8, 9, 10, 11, 12, 13))
                else:
                    nonce = ask_data("Input separate CCM nonce", min_len=7, max_len=13)
                    nonce_length = len(nonce)
                aad = ask_data("Input AAD/authenticated data", min_len=0, allow_empty=True)

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
    parser.add_argument("--xts-key", help="XTS double-length key. Type text directly, use hex:001122..., or R for random.")

    parser.add_argument("--plaintext", "--input", help="Plaintext/message/key material. Type text directly or use hex:001122...")
    parser.add_argument("--ciphertext", "--token", "--wrapped-key", help="Ciphertext/token/wrapped key as hex bytes.")

    parser.add_argument("--iv", help="CBC/CFB/OFB/CTR IV/counter block. Use hex:001122..., text:..., or R for random on encryption.")
    parser.add_argument("--nonce", help="AEAD/GMAC nonce. Use hex:001122..., text:..., or R for random on encryption.")
    parser.add_argument("--tweak", help="XTS 16-byte tweak. Use hex:001122..., text:..., or R for random on encryption.")
    parser.add_argument("--aad", help="AAD/authenticated data. Type text directly or use hex:001122...")

    parser.add_argument("--has-prefix", choices=["yes", "no", "true", "false", "1", "0"], help="For decryption: ciphertext/token includes IV/nonce prefix.")
    parser.add_argument("--segment-size", type=int, default=128, help="CFB segment size in bits.")
    parser.add_argument("--tag-length", type=int, default=16, help="CCM tag length in bytes.")
    parser.add_argument("--nonce-length", type=int, default=13, help="CCM nonce length when token includes nonce prefix.")
    parser.add_argument("--show-key-expansion", action="store_true", help="Prompt for an AES key and print its key expansion.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose backend messages where supported.")
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
            label="Input XTS double-length key",
            allowed_lengths=XTS_AES_KEY_LENGTHS,
            allow_random=(operation == OP_ENCRYPT),
            random_length=32,
        )
        tweak = value_from_cli_or_prompt(
            cli_value=args.tweak,
            label="Input XTS 16-byte tweak",
            allowed_lengths=(16,),
            allow_random=(operation == OP_ENCRYPT),
            random_length=16,
        )
        if operation == OP_ENCRYPT:
            plaintext = value_from_cli_or_prompt(cli_value=args.plaintext, label="Input storage data-unit plaintext", min_len=16)
        else:
            ciphertext = value_from_cli_or_prompt(cli_value=args.ciphertext, label="Input XTS ciphertext data unit hex", default_format="hex", min_len=16)
        return locals()

    key = value_from_cli_or_prompt(
        cli_value=args.key,
        label="Input AES key / KEK",
        allowed_lengths=NORMAL_AES_KEY_LENGTHS,
        allow_random=(operation == OP_ENCRYPT),
        random_length=16,
    )

    if operation == OP_ENCRYPT:
        if mode in {"KW", "KWP"}:
            plaintext = value_from_cli_or_prompt(
                cli_value=args.plaintext,
                label="Input key material to wrap",
                min_len=16 if mode == "KW" else 1,
            )
        elif mode == "GMAC":
            aad = value_from_cli_or_prompt(cli_value=args.aad, label="Input data to authenticate", min_len=1)
        else:
            plaintext = value_from_cli_or_prompt(cli_value=args.plaintext, label="Input plaintext", min_len=0, allow_empty=True)

        if mode in CLASSIC_IV_MODES:
            iv = value_from_cli_or_prompt(
                cli_value=args.iv,
                label=f"Input {mode} IV/counter block",
                allowed_lengths=(16,),
                allow_random=True,
                random_length=16,
            )
        if mode in {"GCM", "GMAC", "GCM-SIV"}:
            nonce = value_from_cli_or_prompt(
                cli_value=args.nonce,
                label=f"Input {mode} 12-byte nonce",
                allowed_lengths=(12,),
                allow_random=True,
                random_length=12,
            )
        if mode == "CCM":
            nonce = value_from_cli_or_prompt(
                cli_value=args.nonce,
                label="Input CCM nonce",
                min_len=7,
                max_len=13,
                allow_random=True,
                random_length=13,
            )
        if mode in AEAD_MODES:
            aad = value_from_cli_or_prompt(cli_value=args.aad, label="Input AAD/authenticated data", min_len=0, allow_empty=True)
    else:
        if mode in {"KW", "KWP"}:
            ciphertext = value_from_cli_or_prompt(cli_value=args.ciphertext, label="Input wrapped key hex", default_format="hex", min_len=16)
        elif mode == "GMAC":
            ciphertext = value_from_cli_or_prompt(cli_value=args.ciphertext, label="Input GMAC token hex", default_format="hex", min_len=16)
            has_prefix = bool_from_cli_or_prompt(cli_value=args.has_prefix, label="Does the GMAC token include the 12-byte nonce prefix?", default=True)
            if not has_prefix:
                nonce = value_from_cli_or_prompt(cli_value=args.nonce, label="Input separate GMAC 12-byte nonce", allowed_lengths=(12,))
            aad = value_from_cli_or_prompt(cli_value=args.aad, label="Input data to authenticate/verify", min_len=1)
        else:
            ciphertext = value_from_cli_or_prompt(cli_value=args.ciphertext, label="Input ciphertext/token hex", default_format="hex", min_len=1)
            if mode in CLASSIC_IV_MODES:
                has_prefix = bool_from_cli_or_prompt(cli_value=args.has_prefix, label="Does ciphertext include the 16-byte IV/counter prefix?", default=True)
                if not has_prefix:
                    iv = value_from_cli_or_prompt(cli_value=args.iv, label=f"Input separate {mode} IV/counter block", allowed_lengths=(16,))
            if mode in {"GCM", "GCM-SIV"}:
                has_prefix = bool_from_cli_or_prompt(cli_value=args.has_prefix, label="Does token include the 12-byte nonce prefix?", default=True)
                if not has_prefix:
                    nonce = value_from_cli_or_prompt(cli_value=args.nonce, label=f"Input separate {mode} 12-byte nonce", allowed_lengths=(12,))
                aad = value_from_cli_or_prompt(cli_value=args.aad, label="Input AAD/authenticated data", min_len=0, allow_empty=True)
            if mode == "CCM":
                has_prefix = bool_from_cli_or_prompt(cli_value=args.has_prefix, label="Does token include the CCM nonce prefix?", default=True)
                if has_prefix:
                    if not (7 <= nonce_length <= 13):
                        raise ValueError("CCM nonce_length must be 7..13.")
                else:
                    nonce = value_from_cli_or_prompt(cli_value=args.nonce, label="Input separate CCM nonce", min_len=7, max_len=13)
                    nonce_length = len(nonce)
                aad = value_from_cli_or_prompt(cli_value=args.aad, label="Input AAD/authenticated data", min_len=0, allow_empty=True)

    return locals()


def cli_main(argv: Optional[list[str]] = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

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
        )


if __name__ == "__main__":
    cli_main()
