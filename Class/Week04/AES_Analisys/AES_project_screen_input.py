# -*- coding: utf-8 -*-
"""
AES_project_all_modes_screen_input.py

Revised AES project driver with NO hard-coded key/IV/nonce/tweak values.

This file is intended to work with the revised AES modes module, for example:
    from mypackages import modes
or, during local testing:
    import AES_modes_revised as modes

Supported modes:
    1.  ECB       Electronic Codebook                  [teaching only]
    2.  CBC       Cipher Block Chaining
    3.  CFB       Cipher Feedback
    4.  OFB       Output Feedback
    5.  CTR       Counter
    6.  GCM       AEAD: ciphertext + authentication tag
    7.  GMAC      Authentication-only tag over AAD/data
    8.  CCM       AEAD: ciphertext + authentication tag
    9.  GCM-SIV   Misuse-resistant AEAD, backend-dependent
    10. XTS       Storage/data-unit encryption
    11. KW        AES Key Wrap, no padding
    12. KWP       AES Key Wrap with Padding

Important teaching choices in this revision:
    - The user enters the AES key from the screen or CLI.
    - CBC/CFB/OFB/CTR require an IV/counter block from the screen/CLI, or the
      user explicitly chooses random generation by typing R.
    - GCM/GMAC/CCM/GCM-SIV require a nonce from the screen/CLI, or the user
      explicitly chooses random generation by typing R.
    - XTS requires a double-length XTS key and a 16-byte tweak from the
      screen/CLI, or the user explicitly chooses random tweak generation by
      typing R.
    - No demo key, IV, nonce, tweak, plaintext, AAD, or wrapped key material is
      silently hard-coded.

Security notes:
    - ECB is kept only to demonstrate pattern leakage.
    - CBC/CFB/OFB/CTR/XTS do not authenticate ciphertexts.
    - Prefer GCM/CCM/GCM-SIV for authenticated message encryption.
    - XTS is for storage sectors/data units, not general message encryption.
    - KW/KWP wrap cryptographic keys, not ordinary messages.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from typing import Dict, Optional, Tuple, Union

sys.path.append(os.getcwd())

BytesOrStr = Union[bytes, str]
NORMAL_AES_KEY_LENGTHS = (16, 24, 32)
XTS_AES_KEY_LENGTHS = (32, 64)
CLASSIC_IV_MODES = {"CBC", "CFB", "OFB", "CTR"}
AEAD_NONCE_12_MODES = {"GCM", "GMAC", "GCM-SIV"}
ALL_MODES = {
    "ECB", "CBC", "CFB", "OFB", "CTR",
    "GCM", "GMAC", "CCM", "GCM-SIV",
    "XTS", "KW", "KWP",
}


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
# Parsing and display helpers
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


def parse_bytes(value: str, *, data_format: str, name: str) -> bytes:
    """Parse text or hexadecimal into bytes."""
    data_format = data_format.lower().strip()
    if data_format == "hex":
        compact = "".join(value.split())
        try:
            return bytes.fromhex(compact)
        except ValueError as exc:
            raise ValueError(f"{name} is not valid hexadecimal.") from exc
    if data_format == "text":
        return value.encode("utf-8")
    raise ValueError(f"Unsupported {name} format. Use text or hex.")


def decode_bytes_for_display(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return f"<non-UTF8 bytes: {data.hex()}>"


def print_bytes(label: str, data: bytes) -> None:
    print(f"{label} bytes : {data!r}")
    print(f"{label} hex   : {data.hex()}")
    print(f"{label} length: {len(data)} byte(s)\n")


def require_lengths(data: bytes, lengths: Tuple[int, ...], name: str) -> bytes:
    if len(data) not in lengths:
        joined = ", ".join(str(n) for n in lengths)
        raise ValueError(f"{name} must be exactly one of these lengths in bytes: {joined}. Got {len(data)}.")
    return data


def require_range(data: bytes, min_len: int, max_len: int, name: str) -> bytes:
    if not (min_len <= len(data) <= max_len):
        raise ValueError(f"{name} must be {min_len}..{max_len} bytes. Got {len(data)}.")
    return data


def require_min_len(data: bytes, min_len: int, name: str) -> bytes:
    if len(data) < min_len:
        raise ValueError(f"{name} must be at least {min_len} bytes. Got {len(data)}.")
    return data


def message_to_bin(message: str) -> str:
    return "".join(format(byte, "08b") for byte in message.encode("utf-8"))


# -----------------------------------------------------------------------------
# Interactive input helpers
# -----------------------------------------------------------------------------
def ask_raw(prompt: str, *, allow_empty: bool = False) -> str:
    while True:
        value = input(prompt).strip()
        if value or allow_empty:
            return value
        print("Input cannot be empty.")


def ask_format(prompt: str = "Format [text/hex]") -> str:
    while True:
        fmt = ask_raw(f"{prompt}: ").lower()
        if fmt in {"text", "hex"}:
            return fmt
        print("Please enter text or hex.")


def ask_bytes(
    label: str,
    *,
    allowed_lengths: Optional[Tuple[int, ...]] = None,
    min_len: Optional[int] = None,
    max_len: Optional[int] = None,
    allow_random: bool = False,
    random_length: Optional[int] = None,
) -> bytes:
    """Ask for bytes from the screen. User can type R only when allow_random=True."""
    while True:
        rand_note = " or R for random" if allow_random else ""
        fmt = ask_raw(f"{label} format [text/hex]{rand_note}: ").strip().lower()
        if allow_random and fmt in {"r", "random"}:
            if random_length is None:
                raise ValueError("random_length must be provided when random generation is allowed.")
            value = secrets.token_bytes(random_length)
            print_bytes(f"Generated {label}", value)
            return value
        if fmt not in {"text", "hex"}:
            print("Please enter text, hex" + (", or R." if allow_random else "."))
            continue

        raw = ask_raw(f"{label} value: ", allow_empty=(min_len == 0))
        try:
            value = parse_bytes(raw, data_format=fmt, name=label)
            if allowed_lengths is not None:
                require_lengths(value, allowed_lengths, label)
            if min_len is not None and len(value) < min_len:
                raise ValueError(f"{label} must be at least {min_len} bytes. Got {len(value)}.")
            if max_len is not None and len(value) > max_len:
                raise ValueError(f"{label} must be at most {max_len} bytes. Got {len(value)}.")
            return value
        except ValueError as exc:
            print(f"Invalid input: {exc}")


def ask_int(label: str, *, default: Optional[int] = None, allowed: Optional[Tuple[int, ...]] = None) -> int:
    while True:
        suffix = f" [{default}]" if default is not None else ""
        raw = ask_raw(f"{label}{suffix}: ", allow_empty=default is not None)
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


# -----------------------------------------------------------------------------
# CLI value resolution helpers
# -----------------------------------------------------------------------------
def value_from_cli_or_prompt(
    *,
    cli_value: Optional[str],
    cli_format: str,
    label: str,
    allowed_lengths: Optional[Tuple[int, ...]] = None,
    min_len: Optional[int] = None,
    max_len: Optional[int] = None,
    allow_random: bool = False,
    random_length: Optional[int] = None,
) -> bytes:
    """Use CLI value when present; otherwise prompt from the screen."""
    if cli_value is not None:
        if allow_random and cli_value.strip().lower() in {"r", "random"}:
            if random_length is None:
                raise ValueError("random_length must be provided for random generation.")
            value = secrets.token_bytes(random_length)
            print_bytes(f"Generated {label}", value)
        else:
            value = parse_bytes(cli_value, data_format=cli_format, name=label)
        if allowed_lengths is not None:
            require_lengths(value, allowed_lengths, label)
        if min_len is not None:
            require_min_len(value, min_len, label)
        if max_len is not None and len(value) > max_len:
            raise ValueError(f"{label} must be at most {max_len} bytes. Got {len(value)}.")
        return value

    return ask_bytes(
        label,
        allowed_lengths=allowed_lengths,
        min_len=min_len,
        max_len=max_len,
        allow_random=allow_random,
        random_length=random_length,
    )


# -----------------------------------------------------------------------------
# Mode execution helpers
# -----------------------------------------------------------------------------
def run_classic_mode(
    aes_mode,
    mode: str,
    plaintext: bytes,
    *,
    iv: Optional[bytes] = None,
    segment_size: int = 128,
) -> Tuple[bytes, bytes]:
    if mode == "ECB":
        cipher = aes_mode.ecb_encrypt(plaintext)
        recovered = aes_mode.ecb_decrypt(cipher, output_encoding=None)
    elif mode == "CBC":
        cipher = aes_mode.cbc_encrypt(plaintext, iv=iv, prepend_iv=True)
        recovered = aes_mode.cbc_decrypt(cipher, has_iv=True, output_encoding=None)
    elif mode == "CFB":
        cipher = aes_mode.cfb_encrypt(plaintext, iv=iv, segment_size=segment_size, prepend_iv=True)
        recovered = aes_mode.cfb_decrypt(cipher, has_iv=True, segment_size=segment_size, output_encoding=None)
    elif mode == "OFB":
        cipher = aes_mode.ofb_encrypt(plaintext, iv=iv, prepend_iv=True)
        recovered = aes_mode.ofb_decrypt(cipher, has_iv=True, output_encoding=None)
    elif mode == "CTR":
        cipher = aes_mode.ctr_encrypt(plaintext, iv=iv, prepend_iv=True)
        recovered = aes_mode.ctr_decrypt(cipher, has_iv=True, output_encoding=None)
    else:
        raise ValueError(f"Unsupported classic mode: {mode}")
    return cipher, recovered


def run_aead_mode(
    aes_mode,
    mode: str,
    plaintext: bytes,
    *,
    nonce: bytes,
    aad: bytes = b"",
    tag_length: int = 16,
) -> Tuple[bytes, bytes]:
    associated_data = aad if aad else None
    if mode == "GCM":
        token = aes_mode.gcm_encrypt(plaintext, associated_data=associated_data, nonce=nonce, prepend_nonce=True)
        recovered = aes_mode.gcm_decrypt(token, associated_data=associated_data, has_nonce=True, output_encoding=None)
    elif mode == "CCM":
        token = aes_mode.ccm_encrypt(
            plaintext,
            associated_data=associated_data,
            nonce=nonce,
            tag_length=tag_length,
            prepend_nonce=True,
        )
        recovered = aes_mode.ccm_decrypt(
            token,
            associated_data=associated_data,
            has_nonce=True,
            nonce_length=len(nonce),
            tag_length=tag_length,
            output_encoding=None,
        )
    elif mode == "GCM-SIV":
        token = aes_mode.gcm_siv_encrypt(plaintext, associated_data=associated_data, nonce=nonce, prepend_nonce=True)
        recovered = aes_mode.gcm_siv_decrypt(token, associated_data=associated_data, has_nonce=True, output_encoding=None)
    else:
        raise ValueError(f"Unsupported AEAD mode: {mode}")
    return token, recovered


def run_gmac_mode(aes_mode, authenticated_data: bytes, *, nonce: bytes) -> Tuple[bytes, bool]:
    token = aes_mode.gmac(authenticated_data, nonce=nonce, prepend_nonce=True)
    ok = aes_mode.gmac_verify(authenticated_data, token, has_nonce=True)
    return token, ok


def run_xts_mode(
    aes_mode,
    plaintext: bytes,
    *,
    xts_key: bytes,
    tweak: bytes,
) -> Tuple[bytes, bytes]:
    require_min_len(plaintext, 16, "XTS plaintext")
    cipher = aes_mode.xts_encrypt(plaintext, xts_key=xts_key, tweak=tweak)
    recovered = aes_mode.xts_decrypt(cipher, xts_key=xts_key, tweak=tweak, output_encoding=None)
    return cipher, recovered


def run_key_wrap_mode(aes_mode, mode: str, key_to_wrap: bytes) -> Tuple[bytes, bytes]:
    if mode == "KW":
        wrapped = aes_mode.key_wrap(key_to_wrap, pad=False)
        recovered = aes_mode.key_unwrap(wrapped, pad=False)
    elif mode == "KWP":
        wrapped = aes_mode.key_wrap(key_to_wrap, pad=True)
        recovered = aes_mode.key_unwrap(wrapped, pad=True)
    else:
        raise ValueError(f"Unsupported key-wrap mode: {mode}")
    return wrapped, recovered


# -----------------------------------------------------------------------------
# Unified report
# -----------------------------------------------------------------------------
def run_selected_mode(
    mode: str,
    *,
    key: Optional[bytes] = None,
    plaintext: bytes,
    iv: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
    aad: bytes = b"",
    segment_size: int = 128,
    tag_length: int = 16,
    xts_key: Optional[bytes] = None,
    tweak: Optional[bytes] = None,
    verbose: bool = False,
) -> None:
    mode = normalize_mode(mode)
    if mode not in ALL_MODES:
        raise ValueError(f"Unsupported AES mode: {mode}")

    # For XTS, the real encryption key is the double-length XTS key. The modes
    # object still needs any valid AES key for construction, so use the first
    # half of the XTS key; XTS calls receive xts_key explicitly.
    if mode == "XTS":
        if xts_key is None:
            raise ValueError("XTS key is required.")
        require_lengths(xts_key, XTS_AES_KEY_LENGTHS, "XTS key")
        constructor_key = xts_key[: len(xts_key) // 2]
    else:
        if key is None:
            raise ValueError("AES key is required.")
        require_lengths(key, NORMAL_AES_KEY_LENGTHS, "AES key")
        constructor_key = key

    aes_mode = new_aes_modes(constructor_key, verbose=verbose)

    print("\n" + "=" * 78)
    print(f"AES mode: {mode}")
    print("=" * 78)

    if mode == "XTS":
        print_bytes("XTS double-length key", xts_key or b"")
    else:
        print_bytes("AES key", key or b"")

    if mode in {"ECB", "CBC", "CFB", "OFB", "CTR"}:
        print_bytes("Plaintext", plaintext)
        if mode in CLASSIC_IV_MODES:
            if iv is None:
                raise ValueError(f"{mode} requires a 16-byte IV/counter block.")
            print_bytes("IV/counter block", iv)
        if mode == "CFB":
            print(f"CFB segment size: {segment_size} bit(s)\n")
        cipher, recovered = run_classic_mode(aes_mode, mode, plaintext, iv=iv, segment_size=segment_size)
        print_bytes("Ciphertext output", cipher)
        print("Note: for CBC/CFB/OFB/CTR, the output is IV/counter || ciphertext.\n" if mode in CLASSIC_IV_MODES else "")
        print_bytes("Recovered plaintext", recovered)
        print("Recovered text:", decode_bytes_for_display(recovered))

    elif mode in {"GCM", "CCM", "GCM-SIV"}:
        if nonce is None:
            raise ValueError(f"{mode} requires a nonce.")
        print_bytes("Plaintext", plaintext)
        print_bytes("Nonce", nonce)
        print_bytes("AAD", aad)
        if mode == "CCM":
            print(f"CCM tag length: {tag_length} byte(s)\n")
        token, recovered = run_aead_mode(aes_mode, mode, plaintext, nonce=nonce, aad=aad, tag_length=tag_length)
        print_bytes("Ciphertext/token output", token)
        print("Note: token is nonce || ciphertext || authentication tag.\n")
        print_bytes("Recovered plaintext", recovered)
        print("Recovered text:", decode_bytes_for_display(recovered))

    elif mode == "GMAC":
        if nonce is None:
            raise ValueError("GMAC requires a nonce.")
        authenticated_data = aad if aad else plaintext
        print_bytes("Nonce", nonce)
        print_bytes("Authenticated data", authenticated_data)
        token, ok = run_gmac_mode(aes_mode, authenticated_data, nonce=nonce)
        print_bytes("GMAC token", token)
        print("Note: GMAC token is nonce || authentication tag.\n")
        print("GMAC verification:", "OK" if ok else "FAILED")

    elif mode == "XTS":
        if tweak is None:
            raise ValueError("XTS requires a 16-byte tweak.")
        print_bytes("XTS tweak", tweak)
        print_bytes("Plaintext data unit", plaintext)
        cipher, recovered = run_xts_mode(aes_mode, plaintext, xts_key=xts_key or b"", tweak=tweak)
        print_bytes("Ciphertext data unit", cipher)
        print_bytes("Recovered data unit", recovered)
        print("Recovered text:", decode_bytes_for_display(recovered))

    elif mode in {"KW", "KWP"}:
        key_to_wrap = plaintext
        print_bytes("Key material to wrap", key_to_wrap)
        wrapped, recovered = run_key_wrap_mode(aes_mode, mode, key_to_wrap)
        print_bytes("Wrapped key", wrapped)
        print_bytes("Unwrapped key", recovered)
        print("Unwrapped key text:", decode_bytes_for_display(recovered))

    print("\nDone.\n")


# -----------------------------------------------------------------------------
# Key expansion demo without hard-coded keys
# -----------------------------------------------------------------------------
def show_key_expansion_demo_interactive() -> None:
    key_expansion_module = load_key_expansion_module()
    if key_expansion_module is None:
        print("key_expansion module is not available in this environment.\n")
        return

    key = ask_bytes("Input AES key for key expansion", allowed_lengths=NORMAL_AES_KEY_LENGTHS)
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


# -----------------------------------------------------------------------------
# Interactive menu
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


def interactive_main() -> None:
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
    choice = ask_raw("Enter choice: ")
    if choice == "13":
        show_key_expansion_demo_interactive()
        return

    mode = mode_map.get(choice, normalize_mode(choice))
    if mode not in ALL_MODES:
        print("Invalid choice.")
        return

    key: Optional[bytes] = None
    xts_key: Optional[bytes] = None
    iv: Optional[bytes] = None
    nonce: Optional[bytes] = None
    tweak: Optional[bytes] = None
    aad = b""
    tag_length = 16
    segment_size = 128

    if mode == "XTS":
        xts_key = ask_bytes("Input XTS double-length key", allowed_lengths=XTS_AES_KEY_LENGTHS, allow_random=True, random_length=32)
        tweak = ask_bytes("Input XTS 16-byte tweak", allowed_lengths=(16,), allow_random=True, random_length=16)
        plaintext = ask_bytes("Input storage data-unit plaintext", min_len=16)
    else:
        key = ask_bytes("Input AES key", allowed_lengths=NORMAL_AES_KEY_LENGTHS, allow_random=True, random_length=16)

        if mode in {"KW", "KWP"}:
            print("For KW/KWP, input is key material to wrap, not message plaintext.")
            if mode == "KW":
                plaintext = ask_bytes("Input key material to wrap", min_len=16)
                if len(plaintext) % 8 != 0:
                    raise ValueError("AES-KW without padding requires wrapped key material to be a multiple of 8 bytes.")
            else:
                plaintext = ask_bytes("Input key material to wrap", min_len=1)
        elif mode == "GMAC":
            print("GMAC authenticates data and produces a tag; it does not encrypt plaintext.")
            plaintext = b""
            aad = ask_bytes("Input data to authenticate as GMAC AAD", min_len=1)
        else:
            plaintext = ask_bytes("Input plaintext", min_len=0)

        if mode in CLASSIC_IV_MODES:
            iv = ask_bytes(f"Input {mode} IV/counter block", allowed_lengths=(16,), allow_random=True, random_length=16)

        if mode in AEAD_NONCE_12_MODES:
            nonce = ask_bytes(f"Input {mode} 12-byte nonce", allowed_lengths=(12,), allow_random=True, random_length=12)

        if mode == "CCM":
            nonce = ask_bytes("Input CCM nonce", min_len=7, max_len=13, allow_random=True, random_length=13)
            tag_length = ask_int("Input CCM tag length", default=16, allowed=(4, 6, 8, 10, 12, 14, 16))

        if mode in {"GCM", "CCM", "GCM-SIV"}:
            aad = ask_bytes("Input AAD/authenticated data", min_len=0)

        if mode == "CFB":
            segment_size = ask_int("Input CFB segment size in bits", default=128, allowed=(8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128))

    run_selected_mode(
        mode,
        key=key,
        plaintext=plaintext,
        iv=iv,
        nonce=nonce,
        aad=aad,
        segment_size=segment_size,
        tag_length=tag_length,
        xts_key=xts_key,
        tweak=tweak,
        verbose=True,
    )


# -----------------------------------------------------------------------------
# argparse CLI. Missing values are prompted from the screen rather than replaced
# with hard-coded defaults.
# -----------------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AES modes demo with screen/CLI input for key, IV, nonce, tweak, plaintext, and AAD.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--mode", help="ECB, CBC, CFB, OFB, CTR, GCM, GMAC, CCM, GCM-SIV, XTS, KW, or KWP. Omit for menu.")

    parser.add_argument("--key", help="AES key as text/hex, or R for random. Required for all modes except XTS.")
    parser.add_argument("--key-format", choices=["text", "hex"], default="text")

    parser.add_argument("--xts-key", help="XTS double-length key as text/hex, or R for random. Required for XTS.")
    parser.add_argument("--xts-key-format", choices=["text", "hex"], default="text")

    parser.add_argument("--plaintext", help="Plaintext/message/key material as text/hex. Missing value is prompted.")
    parser.add_argument("--input-format", choices=["text", "hex"], default="text")

    parser.add_argument("--iv", help="CBC/CFB/OFB/CTR IV or initial counter block as text/hex, or R for random.")
    parser.add_argument("--iv-format", choices=["text", "hex"], default="hex")

    parser.add_argument("--nonce", help="AEAD/GMAC nonce as text/hex, or R for random.")
    parser.add_argument("--nonce-format", choices=["text", "hex"], default="hex")

    parser.add_argument("--tweak", help="XTS 16-byte tweak as text/hex, or R for random.")
    parser.add_argument("--tweak-format", choices=["text", "hex"], default="hex")

    parser.add_argument("--aad", help="AAD/authenticated data as text/hex. Missing value is prompted for AEAD/GMAC modes.")
    parser.add_argument("--aad-format", choices=["text", "hex"], default="text")

    parser.add_argument("--segment-size", type=int, default=128, help="CFB segment size in bits.")
    parser.add_argument("--tag-length", type=int, default=16, help="CCM tag length in bytes.")
    parser.add_argument("--show-key-expansion", action="store_true", help="Prompt for an AES key and print its key expansion.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose backend messages where supported.")
    return parser


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

    key: Optional[bytes] = None
    xts_key: Optional[bytes] = None
    iv: Optional[bytes] = None
    nonce: Optional[bytes] = None
    tweak: Optional[bytes] = None
    aad = b""

    if mode == "XTS":
        xts_key = value_from_cli_or_prompt(
            cli_value=args.xts_key,
            cli_format=args.xts_key_format,
            label="Input XTS double-length key",
            allowed_lengths=XTS_AES_KEY_LENGTHS,
            allow_random=True,
            random_length=32,
        )
        tweak = value_from_cli_or_prompt(
            cli_value=args.tweak,
            cli_format=args.tweak_format,
            label="Input XTS 16-byte tweak",
            allowed_lengths=(16,),
            allow_random=True,
            random_length=16,
        )
        plaintext = value_from_cli_or_prompt(
            cli_value=args.plaintext,
            cli_format=args.input_format,
            label="Input storage data-unit plaintext",
            min_len=16,
        )
    else:
        key = value_from_cli_or_prompt(
            cli_value=args.key,
            cli_format=args.key_format,
            label="Input AES key",
            allowed_lengths=NORMAL_AES_KEY_LENGTHS,
            allow_random=True,
            random_length=16,
        )

        if mode in {"KW", "KWP"}:
            if mode == "KW":
                plaintext = value_from_cli_or_prompt(
                    cli_value=args.plaintext,
                    cli_format=args.input_format,
                    label="Input key material to wrap",
                    min_len=16,
                )
                if len(plaintext) % 8 != 0:
                    raise ValueError("AES-KW without padding requires key material length to be a multiple of 8 bytes.")
            else:
                plaintext = value_from_cli_or_prompt(
                    cli_value=args.plaintext,
                    cli_format=args.input_format,
                    label="Input key material to wrap",
                    min_len=1,
                )
        elif mode == "GMAC":
            plaintext = b""
        else:
            plaintext = value_from_cli_or_prompt(
                cli_value=args.plaintext,
                cli_format=args.input_format,
                label="Input plaintext",
                min_len=0,
            )

        if mode in CLASSIC_IV_MODES:
            iv = value_from_cli_or_prompt(
                cli_value=args.iv,
                cli_format=args.iv_format,
                label=f"Input {mode} IV/counter block",
                allowed_lengths=(16,),
                allow_random=True,
                random_length=16,
            )

        if mode in AEAD_NONCE_12_MODES:
            nonce = value_from_cli_or_prompt(
                cli_value=args.nonce,
                cli_format=args.nonce_format,
                label=f"Input {mode} 12-byte nonce",
                allowed_lengths=(12,),
                allow_random=True,
                random_length=12,
            )

        if mode == "CCM":
            nonce = value_from_cli_or_prompt(
                cli_value=args.nonce,
                cli_format=args.nonce_format,
                label="Input CCM nonce",
                min_len=7,
                max_len=13,
                allow_random=True,
                random_length=13,
            )

        if mode == "GMAC":
            aad = value_from_cli_or_prompt(
                cli_value=args.aad,
                cli_format=args.aad_format,
                label="Input data to authenticate as GMAC AAD",
                min_len=1,
            )
        elif mode in {"GCM", "CCM", "GCM-SIV"}:
            aad = value_from_cli_or_prompt(
                cli_value=args.aad,
                cli_format=args.aad_format,
                label="Input AAD/authenticated data",
                min_len=0,
            )

    run_selected_mode(
        mode,
        key=key,
        plaintext=plaintext,
        iv=iv,
        nonce=nonce,
        aad=aad,
        segment_size=args.segment_size,
        tag_length=args.tag_length,
        xts_key=xts_key,
        tweak=tweak,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    cli_main()
