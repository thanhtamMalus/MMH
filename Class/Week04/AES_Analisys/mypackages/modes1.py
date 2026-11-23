"""
AES modes of operation - revised teaching/utility module.

What this file keeps:
    * Your local AES block primitive: from .AES import AES
    * Manual implementations of ECB, CBC, CFB, OFB, and CTR.

What this file adds:
    * Safer IV/nonce lifecycle: fresh IV/nonce per encryption unless supplied.
    * Strict PKCS#7 padding validation.
    * Binary-safe API: decrypt can return bytes or decode to text.
    * Optional modern modes using the `cryptography` package:
        - AES-GCM / GMAC          (AEAD; NIST SP 800-38D)
        - AES-CCM                (AEAD; NIST SP 800-38C)
        - AES-GCM-SIV            (misuse-resistant AEAD; RFC 8452, if backend supports it)
        - AES-XTS                (storage encryption; NIST SP 800-38E)
        - AES Key Wrap / KWP     (key wrapping; NIST SP 800-38F / RFC 3394 style API)

Security note:
    ECB, CBC, CFB, OFB, CTR and XTS provide confidentiality only. They do not authenticate
    ciphertexts. For new message/file encryption, prefer GCM, CCM, or GCM-SIV with AAD.
"""

from __future__ import annotations

import os
from typing import Iterable, Optional, Sequence, Tuple, Union

try:  # package import
    from .AES import AES
except ImportError:  # script/local import fallback for classroom demos
    from AES import AES  # type: ignore

BytesLike = Union[bytes, bytearray, memoryview]
DataLike = Union[str, BytesLike]

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM
except Exception:  # pragma: no cover - optional dependency
    AESCCM = None  # type: ignore
    AESGCM = None  # type: ignore

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
except Exception:  # pragma: no cover - optional dependency/version
    AESGCMSIV = None  # type: ignore

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as crypto_modes
except Exception:  # pragma: no cover - optional dependency
    Cipher = None  # type: ignore
    algorithms = None  # type: ignore
    crypto_modes = None  # type: ignore

try:
    from cryptography.hazmat.primitives.keywrap import (
        aes_key_unwrap,
        aes_key_unwrap_with_padding,
        aes_key_wrap,
        aes_key_wrap_with_padding,
    )
except Exception:  # pragma: no cover - optional dependency
    aes_key_wrap = None  # type: ignore
    aes_key_unwrap = None  # type: ignore
    aes_key_wrap_with_padding = None  # type: ignore
    aes_key_unwrap_with_padding = None  # type: ignore


class modes:
    """AES modes wrapper around a local AES block cipher implementation.

    Compatibility:
        The class name remains `modes` to match your original code. A nicer alias
        `AESModes` is provided at the bottom of the file.

    Return values:
        Encrypt methods return bytes. Decrypt methods return UTF-8 text by default
        for compatibility with your earlier code. Pass output_encoding=None to get raw bytes.
    """

    BLOCK_SIZE = 16
    VALID_AES_KEY_BYTES = (16, 24, 32)

    def __init__(self, key: DataLike, *, verbose: bool = False):
        self.key = self._ensure_bytes(key, name="key")
        key_length = len(self.key) * 8
        if len(self.key) not in self.VALID_AES_KEY_BYTES:
            raise ValueError("Invalid AES key length. Supported lengths are 16, 24, or 32 bytes.")

        self.aes = AES(self.key, key_length)
        self.verbose = verbose
        self.iv: Optional[bytes] = None  # last IV/initial counter used; do not reuse as a default

    # -------------------------------------------------------------------------
    # Data conversion helpers
    # -------------------------------------------------------------------------
    @staticmethod
    def _ensure_bytes(data: DataLike, *, name: str = "data") -> bytes:
        if isinstance(data, str):
            # Preserve your original binary-string convenience path.
            if data.startswith("0b"):
                return modes.binary_to_bytes(data[2:])
            return data.encode("utf-8")
        if isinstance(data, (bytes, bytearray, memoryview)):
            return bytes(data)
        raise TypeError(f"{name} must be str, bytes, bytearray, or memoryview.")

    @staticmethod
    def _maybe_decode(data: bytes, output_encoding: Optional[str]) -> Union[str, bytes]:
        if output_encoding is None:
            return data
        return data.decode(output_encoding)

    @staticmethod
    def _xor(a: bytes, b: bytes) -> bytes:
        if len(a) != len(b):
            raise ValueError("XOR operands must have equal length.")
        return bytes(x ^ y for x, y in zip(a, b))

    @staticmethod
    def _chunks(data: bytes, size: int) -> Iterable[bytes]:
        for i in range(0, len(data), size):
            yield data[i : i + size]

    @classmethod
    def _require_block_multiple(cls, data: bytes, *, name: str) -> None:
        if len(data) == 0 or len(data) % cls.BLOCK_SIZE != 0:
            raise ValueError(f"{name} length must be a non-zero multiple of 16 bytes.")

    @classmethod
    def _require_exact_block(cls, data: bytes, *, name: str) -> bytes:
        if len(data) != cls.BLOCK_SIZE:
            raise ValueError(f"{name} must be exactly 16 bytes.")
        return data

    def _fresh_iv(self, iv: Optional[DataLike] = None, *, name: str = "iv") -> bytes:
        value = os.urandom(self.BLOCK_SIZE) if iv is None else self._ensure_bytes(iv, name=name)
        self._require_exact_block(value, name=name)
        self.iv = value
        if self.verbose:
            print(f"{name.upper()}: {value.hex()}")
        return value

    @staticmethod
    def utf8_to_bytes(utf8_str: str) -> bytes:
        return utf8_str.encode("utf-8")

    @staticmethod
    def bytes_to_utf8(bytes_data: BytesLike) -> str:
        return bytes(bytes_data).decode("utf-8")

    @staticmethod
    def binary_to_bytes(binary_str: str) -> bytes:
        """Convert a '0101...' bit string to bytes using reversible 1-bit padding.

        The original code used integer conversion without preserving leading zeros. This
        version builds a fixed-length padded bit stream, so leading zero bits survive.
        """
        if binary_str.startswith("0b"):
            binary_str = binary_str[2:]
        if any(ch not in "01" for ch in binary_str):
            raise ValueError("binary_str must contain only '0' and '1'.")

        pad_len = 8 - (len(binary_str) % 8)
        if pad_len == 0:
            pad_len = 8
        padded = binary_str + "1" + ("0" * (pad_len - 1))
        return int(padded, 2).to_bytes(len(padded) // 8, "big")

    @staticmethod
    def bytes_to_binary(bytes_data: BytesLike) -> str:
        """Inverse of binary_to_bytes(). Returns a '0b...' string."""
        bit_stream = "".join(f"{b:08b}" for b in bytes(bytes_data))
        marker = bit_stream.rfind("1")
        if marker < 0:
            raise ValueError("Invalid reversible binary padding: missing marker bit.")
        return "0b" + bit_stream[:marker]

    # -------------------------------------------------------------------------
    # Padding helpers
    # -------------------------------------------------------------------------
    @classmethod
    def pkcs7_padding(cls, data: DataLike) -> bytes:
        data_bytes = cls._ensure_bytes(data, name="data")
        padding_length = cls.BLOCK_SIZE - (len(data_bytes) % cls.BLOCK_SIZE)
        return data_bytes + bytes([padding_length] * padding_length)

    @classmethod
    def pkcs7_unpadding(cls, data: BytesLike) -> bytes:
        data_bytes = bytes(data)
        if not data_bytes or len(data_bytes) % cls.BLOCK_SIZE != 0:
            raise ValueError("PKCS#7 padded data must be a non-zero multiple of 16 bytes.")
        padding_length = data_bytes[-1]
        if padding_length < 1 or padding_length > cls.BLOCK_SIZE:
            raise ValueError("Invalid PKCS#7 padding length.")
        if data_bytes[-padding_length:] != bytes([padding_length] * padding_length):
            raise ValueError("Invalid PKCS#7 padding bytes.")
        return data_bytes[:-padding_length]

    # -------------------------------------------------------------------------
    # NIST SP 800-38A confidentiality modes: ECB, CBC, CFB, OFB, CTR
    # -------------------------------------------------------------------------
    def ecb_encrypt(self, plaintext: DataLike, *, pad: bool = True) -> bytes:
        """AES-ECB encryption. Not semantically secure; kept only for teaching/testing."""
        data = self._ensure_bytes(plaintext, name="plaintext")
        if pad:
            data = self.pkcs7_padding(data)
        else:
            self._require_block_multiple(data, name="plaintext")

        return b"".join(self.aes.encrypt(block) for block in self._chunks(data, self.BLOCK_SIZE))

    def ecb_decrypt(
        self,
        ciphertext: BytesLike,
        *,
        unpad: bool = True,
        output_encoding: Optional[str] = "utf-8",
    ) -> Union[str, bytes]:
        data = bytes(ciphertext)
        self._require_block_multiple(data, name="ciphertext")

        plaintext = b"".join(self.aes.decrypt(block) for block in self._chunks(data, self.BLOCK_SIZE))
        if unpad:
            plaintext = self.pkcs7_unpadding(plaintext)
        return self._maybe_decode(plaintext, output_encoding)

    def cbc_encrypt(
        self,
        plaintext: DataLike,
        *,
        iv: Optional[DataLike] = None,
        prepend_iv: bool = True,
        pad: bool = True,
    ) -> bytes:
        """AES-CBC encryption with a fresh random IV by default."""
        iv_bytes = self._fresh_iv(iv)
        data = self._ensure_bytes(plaintext, name="plaintext")
        if pad:
            data = self.pkcs7_padding(data)
        else:
            self._require_block_multiple(data, name="plaintext")

        out = []
        previous = iv_bytes
        for block in self._chunks(data, self.BLOCK_SIZE):
            encrypted = self.aes.encrypt(self._xor(block, previous))
            out.append(encrypted)
            previous = encrypted

        body = b"".join(out)
        return iv_bytes + body if prepend_iv else body

    def cbc_decrypt(
        self,
        ciphertext: BytesLike,
        *,
        iv: Optional[DataLike] = None,
        has_iv: bool = True,
        unpad: bool = True,
        output_encoding: Optional[str] = "utf-8",
    ) -> Union[str, bytes]:
        data = bytes(ciphertext)
        if has_iv:
            if len(data) < 2 * self.BLOCK_SIZE or len(data) % self.BLOCK_SIZE != 0:
                raise ValueError("CBC ciphertext with prepended IV must be at least 32 bytes and block-aligned.")
            iv_bytes, data = data[: self.BLOCK_SIZE], data[self.BLOCK_SIZE :]
        else:
            if iv is None:
                raise ValueError("iv is required when has_iv=False.")
            iv_bytes = self._require_exact_block(self._ensure_bytes(iv, name="iv"), name="iv")
            self._require_block_multiple(data, name="ciphertext")

        out = []
        previous = iv_bytes
        for block in self._chunks(data, self.BLOCK_SIZE):
            decrypted = self._xor(self.aes.decrypt(block), previous)
            out.append(decrypted)
            previous = block

        plaintext = b"".join(out)
        if unpad:
            plaintext = self.pkcs7_unpadding(plaintext)
        return self._maybe_decode(plaintext, output_encoding)

    def cfb_encrypt(
        self,
        plaintext: DataLike,
        *,
        iv: Optional[DataLike] = None,
        segment_size: int = 128,
        prepend_iv: bool = True,
    ) -> bytes:
        """AES-CFB encryption.

        segment_size is in bits and must be byte-aligned. Common values are
        8, 64, and 128. No padding is used.
        """
        if segment_size <= 0 or segment_size > 128 or segment_size % 8 != 0:
            raise ValueError("segment_size must be one of the byte-aligned sizes from 8 to 128 bits.")
        segment_bytes = segment_size // 8
        iv_bytes = self._fresh_iv(iv)
        data = self._ensure_bytes(plaintext, name="plaintext")

        out = []
        register = iv_bytes
        for segment in self._chunks(data, segment_bytes):
            stream = self.aes.encrypt(register)
            encrypted = self._xor(segment, stream[: len(segment)])
            out.append(encrypted)
            if len(segment) == segment_bytes:
                register = register[segment_bytes:] + encrypted

        body = b"".join(out)
        return iv_bytes + body if prepend_iv else body

    def cfb_decrypt(
        self,
        ciphertext: BytesLike,
        *,
        iv: Optional[DataLike] = None,
        has_iv: bool = True,
        segment_size: int = 128,
        output_encoding: Optional[str] = "utf-8",
    ) -> Union[str, bytes]:
        if segment_size <= 0 or segment_size > 128 or segment_size % 8 != 0:
            raise ValueError("segment_size must be one of the byte-aligned sizes from 8 to 128 bits.")
        segment_bytes = segment_size // 8
        data = bytes(ciphertext)
        if has_iv:
            if len(data) < self.BLOCK_SIZE:
                raise ValueError("CFB ciphertext with prepended IV must be at least 16 bytes.")
            iv_bytes, data = data[: self.BLOCK_SIZE], data[self.BLOCK_SIZE :]
        else:
            if iv is None:
                raise ValueError("iv is required when has_iv=False.")
            iv_bytes = self._require_exact_block(self._ensure_bytes(iv, name="iv"), name="iv")

        out = []
        register = iv_bytes
        for segment in self._chunks(data, segment_bytes):
            stream = self.aes.encrypt(register)
            decrypted = self._xor(segment, stream[: len(segment)])
            out.append(decrypted)
            if len(segment) == segment_bytes:
                register = register[segment_bytes:] + segment

        return self._maybe_decode(b"".join(out), output_encoding)

    def ofb_encrypt(
        self,
        plaintext: DataLike,
        *,
        iv: Optional[DataLike] = None,
        prepend_iv: bool = True,
    ) -> bytes:
        """AES-OFB encryption. No padding is used."""
        iv_bytes = self._fresh_iv(iv)
        data = self._ensure_bytes(plaintext, name="plaintext")

        out = []
        feedback = iv_bytes
        for block in self._chunks(data, self.BLOCK_SIZE):
            feedback = self.aes.encrypt(feedback)
            out.append(self._xor(block, feedback[: len(block)]))

        body = b"".join(out)
        return iv_bytes + body if prepend_iv else body

    def ofb_decrypt(
        self,
        ciphertext: BytesLike,
        *,
        iv: Optional[DataLike] = None,
        has_iv: bool = True,
        output_encoding: Optional[str] = "utf-8",
    ) -> Union[str, bytes]:
        data = bytes(ciphertext)
        if has_iv:
            if len(data) < self.BLOCK_SIZE:
                raise ValueError("OFB ciphertext with prepended IV must be at least 16 bytes.")
            iv_bytes, data = data[: self.BLOCK_SIZE], data[self.BLOCK_SIZE :]
        else:
            if iv is None:
                raise ValueError("iv is required when has_iv=False.")
            iv_bytes = self._require_exact_block(self._ensure_bytes(iv, name="iv"), name="iv")

        out = []
        feedback = iv_bytes
        for block in self._chunks(data, self.BLOCK_SIZE):
            feedback = self.aes.encrypt(feedback)
            out.append(self._xor(block, feedback[: len(block)]))

        return self._maybe_decode(b"".join(out), output_encoding)

    def ctr_encrypt(
        self,
        plaintext: DataLike,
        *,
        iv: Optional[DataLike] = None,
        prepend_iv: bool = True,
    ) -> bytes:
        """AES-CTR encryption using a 128-bit initial counter block.

        A fresh random initial counter block is generated by default. Never reuse the same
        key + counter-block sequence pair.
        """
        iv_bytes = self._fresh_iv(iv)
        data = self._ensure_bytes(plaintext, name="plaintext")
        counter = int.from_bytes(iv_bytes, byteorder="big")

        out = []
        for block in self._chunks(data, self.BLOCK_SIZE):
            key_stream = self.aes.encrypt(counter.to_bytes(self.BLOCK_SIZE, byteorder="big"))
            out.append(self._xor(block, key_stream[: len(block)]))
            counter = (counter + 1) % (1 << 128)

        body = b"".join(out)
        return iv_bytes + body if prepend_iv else body

    def ctr_decrypt(
        self,
        ciphertext: BytesLike,
        *,
        iv: Optional[DataLike] = None,
        has_iv: bool = True,
        output_encoding: Optional[str] = "utf-8",
    ) -> Union[str, bytes]:
        data = bytes(ciphertext)
        if has_iv:
            if len(data) < self.BLOCK_SIZE:
                raise ValueError("CTR ciphertext with prepended counter block must be at least 16 bytes.")
            iv_bytes, data = data[: self.BLOCK_SIZE], data[self.BLOCK_SIZE :]
        else:
            if iv is None:
                raise ValueError("iv is required when has_iv=False.")
            iv_bytes = self._require_exact_block(self._ensure_bytes(iv, name="iv"), name="iv")

        counter = int.from_bytes(iv_bytes, byteorder="big")
        out = []
        for block in self._chunks(data, self.BLOCK_SIZE):
            key_stream = self.aes.encrypt(counter.to_bytes(self.BLOCK_SIZE, byteorder="big"))
            out.append(self._xor(block, key_stream[: len(block)]))
            counter = (counter + 1) % (1 << 128)

        return self._maybe_decode(b"".join(out), output_encoding)

    # -------------------------------------------------------------------------
    # Modern authenticated modes and specialized modes via `cryptography`.
    # These use audited primitives because AEAD/wrapping/storage modes are easy
    # to implement incorrectly with only a raw AES block function.
    # -------------------------------------------------------------------------
    @staticmethod
    def _require_backend(obj: object, feature: str) -> None:
        if obj is None:
            raise RuntimeError(
                f"{feature} requires the optional 'cryptography' package and a version that supports this primitive."
            )

    def gcm_encrypt(
        self,
        plaintext: DataLike,
        *,
        associated_data: Optional[DataLike] = None,
        nonce: Optional[DataLike] = None,
        prepend_nonce: bool = True,
    ) -> bytes:
        """AES-GCM AEAD encryption. Output body is ciphertext || 16-byte tag."""
        self._require_backend(AESGCM, "AES-GCM")
        nonce_bytes = os.urandom(12) if nonce is None else self._ensure_bytes(nonce, name="nonce")
        if len(nonce_bytes) != 12:
            raise ValueError("AES-GCM nonce should be 12 bytes for the standard fast path.")
        aad = None if associated_data is None else self._ensure_bytes(associated_data, name="associated_data")
        body = AESGCM(self.key).encrypt(nonce_bytes, self._ensure_bytes(plaintext, name="plaintext"), aad)
        return nonce_bytes + body if prepend_nonce else body

    def gcm_decrypt(
        self,
        ciphertext_and_tag: BytesLike,
        *,
        associated_data: Optional[DataLike] = None,
        nonce: Optional[DataLike] = None,
        has_nonce: bool = True,
        output_encoding: Optional[str] = "utf-8",
    ) -> Union[str, bytes]:
        self._require_backend(AESGCM, "AES-GCM")
        data = bytes(ciphertext_and_tag)
        if has_nonce:
            if len(data) < 12 + 16:
                raise ValueError("AES-GCM input with prepended nonce must contain nonce + ciphertext/tag.")
            nonce_bytes, data = data[:12], data[12:]
        else:
            if nonce is None:
                raise ValueError("nonce is required when has_nonce=False.")
            nonce_bytes = self._ensure_bytes(nonce, name="nonce")
            if len(nonce_bytes) != 12:
                raise ValueError("AES-GCM nonce should be 12 bytes.")
        aad = None if associated_data is None else self._ensure_bytes(associated_data, name="associated_data")
        plaintext = AESGCM(self.key).decrypt(nonce_bytes, data, aad)
        return self._maybe_decode(plaintext, output_encoding)

    def gmac(
        self,
        authenticated_data: DataLike,
        *,
        nonce: Optional[DataLike] = None,
        prepend_nonce: bool = True,
    ) -> bytes:
        """GMAC tag over associated data using AES-GCM with empty plaintext."""
        self._require_backend(AESGCM, "GMAC")
        nonce_bytes = os.urandom(12) if nonce is None else self._ensure_bytes(nonce, name="nonce")
        if len(nonce_bytes) != 12:
            raise ValueError("GMAC/AES-GCM nonce should be 12 bytes.")
        tag = AESGCM(self.key).encrypt(nonce_bytes, b"", self._ensure_bytes(authenticated_data, name="authenticated_data"))
        return nonce_bytes + tag if prepend_nonce else tag

    def gmac_verify(
        self,
        authenticated_data: DataLike,
        tag: BytesLike,
        *,
        nonce: Optional[DataLike] = None,
        has_nonce: bool = True,
    ) -> bool:
        """Verify GMAC. Returns True/False instead of raising to simplify teaching demos."""
        self._require_backend(AESGCM, "GMAC")
        token = bytes(tag)
        if has_nonce:
            if len(token) != 28:
                raise ValueError("GMAC token with prepended nonce must be 12-byte nonce + 16-byte tag.")
            nonce_bytes, token = token[:12], token[12:]
        else:
            if nonce is None:
                raise ValueError("nonce is required when has_nonce=False.")
            nonce_bytes = self._ensure_bytes(nonce, name="nonce")
        try:
            AESGCM(self.key).decrypt(nonce_bytes, token, self._ensure_bytes(authenticated_data, name="authenticated_data"))
            return True
        except Exception:
            return False

    def ccm_encrypt(
        self,
        plaintext: DataLike,
        *,
        associated_data: Optional[DataLike] = None,
        nonce: Optional[DataLike] = None,
        tag_length: int = 16,
        prepend_nonce: bool = True,
    ) -> bytes:
        """AES-CCM AEAD encryption. Nonce length must be 7..13 bytes."""
        self._require_backend(AESCCM, "AES-CCM")
        if tag_length not in (4, 6, 8, 10, 12, 14, 16):
            raise ValueError("AES-CCM tag_length must be one of 4, 6, 8, 10, 12, 14, 16.")
        nonce_bytes = os.urandom(13) if nonce is None else self._ensure_bytes(nonce, name="nonce")
        if not (7 <= len(nonce_bytes) <= 13):
            raise ValueError("AES-CCM nonce length must be between 7 and 13 bytes.")
        aad = None if associated_data is None else self._ensure_bytes(associated_data, name="associated_data")
        body = AESCCM(self.key, tag_length=tag_length).encrypt(
            nonce_bytes, self._ensure_bytes(plaintext, name="plaintext"), aad
        )
        return nonce_bytes + body if prepend_nonce else body

    def ccm_decrypt(
        self,
        ciphertext_and_tag: BytesLike,
        *,
        associated_data: Optional[DataLike] = None,
        nonce: Optional[DataLike] = None,
        has_nonce: bool = True,
        nonce_length: int = 13,
        tag_length: int = 16,
        output_encoding: Optional[str] = "utf-8",
    ) -> Union[str, bytes]:
        self._require_backend(AESCCM, "AES-CCM")
        if not (7 <= nonce_length <= 13):
            raise ValueError("nonce_length must be between 7 and 13 bytes.")
        data = bytes(ciphertext_and_tag)
        if has_nonce:
            if len(data) < nonce_length + tag_length:
                raise ValueError("AES-CCM input with prepended nonce must contain nonce + ciphertext/tag.")
            nonce_bytes, data = data[:nonce_length], data[nonce_length:]
        else:
            if nonce is None:
                raise ValueError("nonce is required when has_nonce=False.")
            nonce_bytes = self._ensure_bytes(nonce, name="nonce")
        aad = None if associated_data is None else self._ensure_bytes(associated_data, name="associated_data")
        plaintext = AESCCM(self.key, tag_length=tag_length).decrypt(nonce_bytes, data, aad)
        return self._maybe_decode(plaintext, output_encoding)

    def gcm_siv_encrypt(
        self,
        plaintext: DataLike,
        *,
        associated_data: Optional[DataLike] = None,
        nonce: Optional[DataLike] = None,
        prepend_nonce: bool = True,
    ) -> bytes:
        """AES-GCM-SIV AEAD encryption, if supported by installed cryptography version."""
        self._require_backend(AESGCMSIV, "AES-GCM-SIV")
        nonce_bytes = os.urandom(12) if nonce is None else self._ensure_bytes(nonce, name="nonce")
        if len(nonce_bytes) != 12:
            raise ValueError("AES-GCM-SIV nonce must be 12 bytes.")
        aad = None if associated_data is None else self._ensure_bytes(associated_data, name="associated_data")
        body = AESGCMSIV(self.key).encrypt(nonce_bytes, self._ensure_bytes(plaintext, name="plaintext"), aad)
        return nonce_bytes + body if prepend_nonce else body

    def gcm_siv_decrypt(
        self,
        ciphertext_and_tag: BytesLike,
        *,
        associated_data: Optional[DataLike] = None,
        nonce: Optional[DataLike] = None,
        has_nonce: bool = True,
        output_encoding: Optional[str] = "utf-8",
    ) -> Union[str, bytes]:
        self._require_backend(AESGCMSIV, "AES-GCM-SIV")
        data = bytes(ciphertext_and_tag)
        if has_nonce:
            if len(data) < 12 + 16:
                raise ValueError("AES-GCM-SIV input with prepended nonce must contain nonce + ciphertext/tag.")
            nonce_bytes, data = data[:12], data[12:]
        else:
            if nonce is None:
                raise ValueError("nonce is required when has_nonce=False.")
            nonce_bytes = self._ensure_bytes(nonce, name="nonce")
        aad = None if associated_data is None else self._ensure_bytes(associated_data, name="associated_data")
        plaintext = AESGCMSIV(self.key).decrypt(nonce_bytes, data, aad)
        return self._maybe_decode(plaintext, output_encoding)

    def xts_encrypt(
        self,
        plaintext: DataLike,
        *,
        xts_key: Optional[DataLike] = None,
        tweak: Optional[DataLike] = None,
        data_unit_number: int = 0,
    ) -> bytes:
        """AES-XTS encryption for storage data units.

        XTS uses a double-length key: 32 bytes for AES-128-XTS or 64 bytes for
        AES-256-XTS. AES-192-XTS is not supported by common libraries. This mode
        is for disk/storage sectors, not general message encryption.
        """
        self._require_backend(Cipher, "AES-XTS")
        key_bytes = self._ensure_bytes(xts_key, name="xts_key") if xts_key is not None else self.key
        if len(key_bytes) not in (32, 64):
            raise ValueError("AES-XTS requires a 32-byte or 64-byte double-length XTS key.")
        tweak_bytes = (
            int(data_unit_number).to_bytes(16, "little")
            if tweak is None
            else self._require_exact_block(self._ensure_bytes(tweak, name="tweak"), name="tweak")
        )
        data = self._ensure_bytes(plaintext, name="plaintext")
        if len(data) < 16:
            raise ValueError("AES-XTS requires at least one full 16-byte block.")
        encryptor = Cipher(algorithms.AES(key_bytes), crypto_modes.XTS(tweak_bytes)).encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def xts_decrypt(
        self,
        ciphertext: BytesLike,
        *,
        xts_key: Optional[DataLike] = None,
        tweak: Optional[DataLike] = None,
        data_unit_number: int = 0,
        output_encoding: Optional[str] = None,
    ) -> Union[str, bytes]:
        self._require_backend(Cipher, "AES-XTS")
        key_bytes = self._ensure_bytes(xts_key, name="xts_key") if xts_key is not None else self.key
        if len(key_bytes) not in (32, 64):
            raise ValueError("AES-XTS requires a 32-byte or 64-byte double-length XTS key.")
        tweak_bytes = (
            int(data_unit_number).to_bytes(16, "little")
            if tweak is None
            else self._require_exact_block(self._ensure_bytes(tweak, name="tweak"), name="tweak")
        )
        data = bytes(ciphertext)
        if len(data) < 16:
            raise ValueError("AES-XTS requires at least one full 16-byte block.")
        decryptor = Cipher(algorithms.AES(key_bytes), crypto_modes.XTS(tweak_bytes)).decryptor()
        plaintext = decryptor.update(data) + decryptor.finalize()
        return self._maybe_decode(plaintext, output_encoding)

    def key_wrap(self, key_to_wrap: DataLike, *, pad: bool = False) -> bytes:
        """AES Key Wrap/KWP using self.key as the key-encryption key (KEK)."""
        if pad:
            self._require_backend(aes_key_wrap_with_padding, "AES-KWP")
            return aes_key_wrap_with_padding(self.key, self._ensure_bytes(key_to_wrap, name="key_to_wrap"))
        self._require_backend(aes_key_wrap, "AES-KW")
        data = self._ensure_bytes(key_to_wrap, name="key_to_wrap")
        if len(data) < 16 or len(data) % 8 != 0:
            raise ValueError("AES-KW without padding requires key_to_wrap length >=16 and multiple of 8 bytes.")
        return aes_key_wrap(self.key, data)

    def key_unwrap(self, wrapped_key: BytesLike, *, pad: bool = False) -> bytes:
        """AES Key Unwrap/KWP using self.key as the key-encryption key (KEK)."""
        if pad:
            self._require_backend(aes_key_unwrap_with_padding, "AES-KWP")
            return aes_key_unwrap_with_padding(self.key, bytes(wrapped_key))
        self._require_backend(aes_key_unwrap, "AES-KW")
        return aes_key_unwrap(self.key, bytes(wrapped_key))


AESModes = modes
