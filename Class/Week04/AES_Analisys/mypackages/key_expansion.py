# -*- coding: utf-8 -*-
"""
AES key expansion / key schedule for AES-128, AES-192, and AES-256.

Compatibility:
    - Keeps the original class name: key_expansion
    - Keeps methods: key_expansion_128(), key_expansion_192(), key_expansion_256()

Safer additions:
    - Validates key length before expansion.
    - Provides expand() to choose AES-128/192/256 automatically.
    - Provides round_keys_bytes() and round_keys_hex() helpers for teaching/debugging.

Reference:
    NIST FIPS 197, Advanced Encryption Standard (AES), updated 2023.
"""

from __future__ import annotations

from typing import Iterable, List, Sequence

Word = List[int]
RoundKeys = List[Word]


class key_expansion:
    """AES key schedule with the original project-compatible class name."""

    S_BOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ]

    # Enough for AES-128/192/256 key schedules.
    RCON = [
        [0x01, 0x00, 0x00, 0x00],
        [0x02, 0x00, 0x00, 0x00],
        [0x04, 0x00, 0x00, 0x00],
        [0x08, 0x00, 0x00, 0x00],
        [0x10, 0x00, 0x00, 0x00],
        [0x20, 0x00, 0x00, 0x00],
        [0x40, 0x00, 0x00, 0x00],
        [0x80, 0x00, 0x00, 0x00],
        [0x1B, 0x00, 0x00, 0x00],
        [0x36, 0x00, 0x00, 0x00],
    ]

    KEY_PARAMS = {
        16: (4, 10, 44),  # Nk, Nr, Nb*(Nr+1)
        24: (6, 12, 52),
        32: (8, 14, 60),
    }

    def __init__(self, key: bytes | bytearray | Sequence[int]):
        self.key = self._normalize_key(key)

    @staticmethod
    def _normalize_key(key: bytes | bytearray | Sequence[int]) -> bytes:
        try:
            key_bytes = bytes(key)
        except Exception as exc:
            raise TypeError("key must be bytes-like or a sequence of byte values") from exc
        if len(key_bytes) not in key_expansion.KEY_PARAMS:
            raise ValueError(
                "Invalid AES key length. Expected 16, 24, or 32 bytes "
                f"for AES-128/192/256; got {len(key_bytes)} bytes."
            )
        return key_bytes

    @staticmethod
    def _validate_word(word: Sequence[int]) -> Word:
        if len(word) != 4:
            raise ValueError("AES key schedule word must contain exactly 4 bytes.")
        out: Word = []
        for b in word:
            if not isinstance(b, int) or not 0 <= b <= 0xFF:
                raise ValueError("word entries must be integers in range 0..255")
            out.append(b)
        return out

    def sub_word(self, word: Sequence[int]) -> Word:
        w = self._validate_word(word)
        return [self.S_BOX[b] for b in w]

    @staticmethod
    def rot_word(word: Sequence[int]) -> Word:
        w = key_expansion._validate_word(word)
        return w[1:] + w[:1]

    @staticmethod
    def xor_words(a: Sequence[int], b: Sequence[int]) -> Word:
        aw = key_expansion._validate_word(a)
        bw = key_expansion._validate_word(b)
        return [x ^ y for x, y in zip(aw, bw)]

    def expand(self) -> RoundKeys:
        """Auto-select AES-128/192/256 key expansion from the actual key length."""
        nk, _nr, total_words = self.KEY_PARAMS[len(self.key)]
        return self._expand_generic(nk=nk, total_words=total_words)

    def _expand_generic(self, *, nk: int, total_words: int) -> RoundKeys:
        if len(self.key) != 4 * nk:
            raise ValueError(f"This expansion requires a {4 * nk}-byte key; got {len(self.key)} bytes.")

        words: RoundKeys = [list(self.key[i:i + 4]) for i in range(0, 4 * nk, 4)]

        for i in range(nk, total_words):
            temp = words[i - 1].copy()
            if i % nk == 0:
                temp = self.sub_word(self.rot_word(temp))
                temp = self.xor_words(temp, self.RCON[(i // nk) - 1])
            elif nk > 6 and i % nk == 4:
                # AES-256 special case from FIPS 197 KeyExpansion().
                temp = self.sub_word(temp)
            words.append(self.xor_words(words[i - nk], temp))

        return words

    def key_expansion_128(self) -> RoundKeys:
        return self._expand_generic(nk=4, total_words=44)

    def key_expansion_192(self) -> RoundKeys:
        return self._expand_generic(nk=6, total_words=52)

    def key_expansion_256(self) -> RoundKeys:
        return self._expand_generic(nk=8, total_words=60)

    def round_keys_bytes(self) -> List[bytes]:
        """Return full 16-byte round keys for AddRoundKey(), not 4-byte words."""
        words = self.expand()
        return [b"".join(bytes(w) for w in words[i:i + 4]) for i in range(0, len(words), 4)]

    def round_keys_hex(self) -> List[str]:
        """Return round keys as 32-hex-character strings, useful for teaching output."""
        return [rk.hex() for rk in self.round_keys_bytes()]


# Optional clearer alias for new code while preserving the original class name.
AESKeyExpansion = key_expansion


if __name__ == "__main__":
    # Small smoke demo with the FIPS AES-128 example key.
    k = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    expander = key_expansion(k)
    for i, rk in enumerate(expander.round_keys_hex()):
        print(f"round {i:02d}: {rk}")
