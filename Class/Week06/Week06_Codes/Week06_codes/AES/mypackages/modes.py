import os
from .AES import AES

class modes:
    def __init__(self, key):
        key_length = len(key) * 8  # Convert key length to bits
        if key_length not in [128, 192, 256]:
            raise ValueError("Invalid key length. Supported lengths are 128, 192, and 256 bits.")
        self.aes = AES(key, key_length)  # an AES class that takes a key and key_length
        self.iv = os.urandom(16)
        # This can be set externally (e.g. from your main script):
        self.mode = None

    ############################################################################
    # HELPER METHODS
    ############################################################################

    def utf8_to_bytes(self, utf8_str):
        """Convert a UTF-8 string to bytes."""
        return utf8_str.encode('utf-8')

    def bytes_to_utf8(self, bytes_data):
        """Convert bytes to a UTF-8 string."""
        return bytes_data.decode('utf-8')

    def binary_to_bytes(self, binary_str):
        """
        Convert a binary string (e.g. '1010101...') to bytes.
        - We pad the bit string to a multiple of 8 bits by appending '1' + the needed '0's.
        """
        padding_length = 8 - (len(binary_str) % 8)
        # Append a '1' followed by the necessary '0's to reach a multiple of 8
        binary_str += '1' + '0' * (padding_length - 1)
        n = int(binary_str, 2)
        byte_length = len(binary_str) // 8
        return n.to_bytes(byte_length, 'big')

    def bytes_to_binary(self, bytes_data):
        """
        Convert bytes to a binary string (e.g. '0b101001...'), 
        removing any padding we added (searching for the last '1' bit).
        """
        binary_str = bin(int.from_bytes(bytes_data, 'big'))[2:]  # skip the '0b'
        # Find the last '1' (indicating where our padding started) 
        # and slice off everything after it.
        last_one_index = binary_str.rfind('1')
        return '0b' + binary_str[:last_one_index]

    # --- Normalize AES block-cipher I/O to 16 bytes ---
    def _E(self, block: bytes) -> bytes:
        """One-block AES encrypt that always returns 16 raw bytes."""
        out = self.aes.encrypt(block)
        if isinstance(out, str):
            # Many student AES impls return hex strings
            try:
                out = bytes.fromhex(out)
            except ValueError:
                out = out.encode('latin1')  # last resort
        if not isinstance(out, (bytes, bytearray)):
            raise TypeError(f"AES.encrypt returned type {type(out)}; expected bytes.")
        if len(out) != 16:
            raise ValueError(f"AES.encrypt must return 16 bytes; got {len(out)}.")
        return bytes(out)

    def _D(self, block: bytes) -> bytes:
        """One-block AES decrypt that always returns 16 raw bytes."""
        out = self.aes.decrypt(block)
        if isinstance(out, str):
            try:
                out = bytes.fromhex(out)
            except ValueError:
                out = out.encode('latin1')
        if not isinstance(out, (bytes, bytearray)):
            raise TypeError(f"AES.decrypt returned type {type(out)}; expected bytes.")
        if len(out) != 16:
            raise ValueError(f"AES.decrypt must return 16 bytes; got {len(out)}.")
        return bytes(out)

    ############################################################################
    # PKCS7 PADDING
    ############################################################################

    def pkcs7_padding(self, data, block_size: int = 16):
        """
        Apply PKCS#7 padding to bytes-like data (or str/'0b...' per your interface).
        Always adds at least one block of padding when data is already aligned.
        """
        if isinstance(data, str):
            if data.startswith('0b'):
                data = self.binary_to_bytes(data[2:])
            else:
                data = data.encode('utf-8')
        elif not isinstance(data, (bytes, bytearray)):
            raise TypeError("pkcs7_padding requires data to be str or bytes.")

        if block_size <= 0 or block_size > 255:
            raise ValueError("block_size must be in 1..255")

        pad_len = block_size - (len(data) % block_size)
        return bytes(data) + bytes([pad_len]) * pad_len


    def pkcs7_unpadding(self, data: bytes, block_size: int = 16) -> bytes:
        """
        Remove PKCS#7 padding. Returns raw bytes.
        Validates that all pad bytes match the pad length and sizes are sane.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("pkcs7_unpadding requires bytes.")
        if not data:
            raise ValueError("Invalid PKCS#7 padding: empty input")
        if block_size <= 0 or block_size > 255:
            raise ValueError("block_size must be in 1..255")

        pad_len = data[-1]
        if pad_len < 1 or pad_len > block_size:
            raise ValueError("Invalid PKCS#7 padding length")
        if len(data) < pad_len:
            raise ValueError("Invalid PKCS#7 padding (length too short)")

        # Constant-time-ish check that the last pad_len bytes are all pad_len
        bad = 0
        tail = data[-pad_len:]
        for b in tail:
            bad |= (b ^ pad_len)
        if bad != 0:
            raise ValueError("Invalid PKCS#7 padding bytes")

        return bytes(data[:-pad_len])

    ############################################################################
    # ECB MODE
    ############################################################################

    def ecb_encrypt(self, plaintext):
        """
        Encrypt data in ECB mode.
        'plaintext' can be str or bytes (or '0b...' string).
        Returns raw encrypted bytes.
        """
        padded_data = self.pkcs7_padding(plaintext)

        encrypted_blocks = []
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            encrypted_block = self.aes.encrypt(block)
            encrypted_blocks.append(encrypted_block)
        return b''.join(encrypted_blocks)

    def ecb_decrypt(self, ciphertext):
        """
        Decrypt data in ECB mode. 
        'ciphertext' must be bytes. 
        Returns raw bytes (with PKCS7 unpadding removed).
        """
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16 bytes for ECB mode.")

        decrypted_blocks = []
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = self.aes.decrypt(block)
            decrypted_blocks.append(decrypted_block)

        decrypted_data = self.pkcs7_unpadding(b''.join(decrypted_blocks))
        # Return raw bytes. If you know it's text, decode externally.
        return decrypted_data

    ############################################################################
    # CBC MODE
    ############################################################################

    def cbc_encrypt(self, plaintext, iv: bytes | None = None):
        """
        Encrypt data in CBC mode.
        - plaintext: str / bytes / '0b...' (handled like the rest of your class)
        - iv: optional 16-byte IV; if None, a fresh random IV is generated
        Returns: IV || C
        """
        # Normalize and pad
        padded = self.pkcs7_padding(plaintext, block_size=16)

        # Fresh IV (or use provided)
        if iv is None:
            iv = os.urandom(16)
        if not isinstance(iv, (bytes, bytearray)) or len(iv) != 16:
            raise ValueError("CBC iv must be 16 bytes")

        prev = iv
        out_blocks = []
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            x = bytes(a ^ b for a, b in zip(block, prev))   # P ⊕ prev
            c = self._E(x)                                  # E_K(P ⊕ prev)
            out_blocks.append(c)
            prev = c

        return iv + b''.join(out_blocks)


    def cbc_decrypt(self, ciphertext: bytes):
        """
        Decrypt data in CBC mode.
        Expects: IV (16 bytes) || C (>=1 block)
        Returns: plaintext (bytes) after strict PKCS#7 unpadding.
        """
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("CBC decrypt expects bytes")
        if len(ciphertext) < 32 or (len(ciphertext) % 16) != 0:
            # must have IV (16) + at least 1 block (16)
            raise ValueError("Ciphertext must be IV(16) + N*16 bytes for CBC.")

        iv = ciphertext[:16]
        ct = ciphertext[16:]

        prev = iv
        plain_blocks = []
        for i in range(0, len(ct), 16):
            block = ct[i:i+16]
            d = self._D(block)                              # D_K(C)
            p = bytes(a ^ b for a, b in zip(d, prev))      # D_K(C) ⊕ prev
            plain_blocks.append(p)
            prev = block

        # Strict unpadding (verifies all pad bytes)
        return self.pkcs7_unpadding(b''.join(plain_blocks), block_size=16)

    ############################################################################
    # CFB MODE (64-bit or 128-bit)
    ############################################################################

    def cfb_encrypt(self, plaintext, segment_size=128):
        """
        Encrypt data in CFB mode.
        For text data, 'plaintext' can be str. For arbitrary data, pass bytes.
        segment_size can be 64 or 128 bits.
        """
        if segment_size not in [64, 128]:
            raise ValueError("Segment size must be either 64 or 128 bits for CFB.")

        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        segment_bytes = segment_size // 8
        encrypted_blocks = []
        previous_block = self.iv

        print("The Initial Vector (IV):", previous_block.hex())

        for i in range(0, len(plaintext), segment_bytes):
            segment = plaintext[i:i+segment_bytes]
            encrypted_iv = self.aes.encrypt(previous_block)
            encrypted_segment = bytes([segment[j] ^ encrypted_iv[j] for j in range(len(segment))])
            encrypted_blocks.append(encrypted_segment)

            # Shift register
            if segment_size == 64:
                # Move left by segment_bytes in a 16-byte shift register
                previous_block = previous_block[segment_bytes:] + encrypted_segment
            else:
                # 128-bit shift
                previous_block = encrypted_segment

        return self.iv + b''.join(encrypted_blocks)

    def cfb_decrypt(self, ciphertext, segment_size=128):
        """
        Decrypt data in CFB mode.
        Expects: IV + ciphertext blocks.
        Returns raw bytes. If you know it is text, decode externally.
        """
        if segment_size not in [64, 128]:
            raise ValueError("Segment size must be either 64 or 128 bits for CFB.")

        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        previous_block = iv
        segment_bytes = segment_size // 8

        print("The Initial Vector (IV):", iv.hex())

        decrypted_blocks = []
        for i in range(0, len(ciphertext), segment_bytes):
            segment = ciphertext[i:i+segment_bytes]
            encrypted_iv = self.aes.encrypt(previous_block)
            decrypted_segment = bytes([segment[j] ^ encrypted_iv[j] for j in range(len(segment))])
            decrypted_blocks.append(decrypted_segment)

            # Shift register
            if segment_size == 64:
                previous_block = previous_block[segment_bytes:] + segment
            else:
                previous_block = segment

        return b''.join(decrypted_blocks)

    ############################################################################
    # OFB MODE
    ############################################################################

    def ofb_encrypt(self, plaintext):
        """
        Encrypt data using OFB mode.
        Returns IV + ciphertext bytes.
        """
        padded_data = self.pkcs7_padding(plaintext)
        encrypted_blocks = []
        previous_block = self.iv

        print("The Initial Vector (IV):", previous_block.hex())

        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            encrypted_iv = self.aes.encrypt(previous_block)
            encrypted_block = bytes([block[j] ^ encrypted_iv[j] for j in range(len(block))])
            encrypted_blocks.append(encrypted_block)
            previous_block = encrypted_iv

        return self.iv + b''.join(encrypted_blocks)

    def ofb_decrypt(self, ciphertext):
        """
        Decrypt data using OFB mode.
        Expects: IV (16 bytes) + ciphertext.
        Returns raw unpadded bytes.
        """
        if len(ciphertext) < 16 or (len(ciphertext) % 16) != 0:
            raise ValueError("Ciphertext (including IV) must be multiple of 16 bytes for OFB.")

        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        previous_block = iv

        print("The Initial Vector (IV):", iv.hex())

        decrypted_blocks = []
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            encrypted_iv = self.aes.encrypt(previous_block)
            decrypted_block = bytes([block[j] ^ encrypted_iv[j] for j in range(len(block))])
            decrypted_blocks.append(decrypted_block)
            previous_block = encrypted_iv

        decrypted_data = self.pkcs7_unpadding(b''.join(decrypted_blocks))
        return decrypted_data

    ############################################################################
    # CTR MODE
    ############################################################################

    def ctr_encrypt(self, plaintext):
        """
        Encrypt data in CTR mode.
        No padding is required. Returns IV + encrypted bytes.
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        encrypted_blocks = []
        counter = int.from_bytes(self.iv, byteorder='big')  # convert IV to a big-endian integer
        print("The Initial Vector (IV):", self.iv.hex())

        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            encrypted_counter = self.aes.encrypt(counter.to_bytes(16, byteorder='big'))
            encrypted_block = bytes([block[j] ^ encrypted_counter[j] for j in range(len(block))])
            encrypted_blocks.append(encrypted_block)
            counter += 1

        return self.iv + b''.join(encrypted_blocks)

    def ctr_decrypt(self, ciphertext):
        """
        Decrypt data in CTR mode.
        Expects IV (16 bytes) + ciphertext blocks.
        Returns raw bytes (no padding).
        """
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext is too short for CTR mode (missing IV).")

        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        counter = int.from_bytes(iv, byteorder='big')
        print("The Initial Vector (IV):", iv.hex())

        decrypted_blocks = []
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            encrypted_counter = self.aes.encrypt(counter.to_bytes(16, byteorder='big'))
            decrypted_block = bytes([block[j] ^ encrypted_counter[j] for j in range(len(block))])
            decrypted_blocks.append(decrypted_block)
            counter += 1

        return b''.join(decrypted_blocks)

    ############################################################################
    # AEAD HELPERS (GCM & EAX)
    ############################################################################

    @staticmethod
    def _xor(b1: bytes, b2: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(b1, b2))

    @staticmethod
    def _pad16(data: bytes) -> bytes:
        if len(data) % 16 == 0:
            return data
        return data + b'\\x00' * (16 - (len(data) % 16))

    @staticmethod
    def _ct_eq(x: bytes, y: bytes) -> bool:
        # Constant-time equality
        if len(x) != len(y):
            return False
        acc = 0
        for a, b in zip(x, y):
            acc |= (a ^ b)
        return acc == 0

    @staticmethod
    def _inc32(block16: bytes) -> bytes:
        # Increment last 32 bits modulo 2^32
        if len(block16) != 16:
            raise ValueError("Block must be 16 bytes")
        prefix, ctr = block16[:12], int.from_bytes(block16[12:], 'big')
        ctr = (ctr + 1) % (1 << 32)
        return prefix + ctr.to_bytes(4, 'big')

    # -------- GCM finite-field multiply and GHASH --------

    @staticmethod
    def _gf_mul(x: bytes, y: bytes) -> bytes:
        """
        Multiply two 128-bit elements in GF(2^128) with the polynomial:
        x^128 + x^7 + x^2 + x + 1  (R = 0xE1 << 120)
        """
        if len(x) != 16 or len(y) != 16:
            raise ValueError("GF(2^128) elements must be 16 bytes.")
        R = 0xE1000000000000000000000000000000
        Z = 0
        V = int.from_bytes(x, 'big')
        Y = int.from_bytes(y, 'big')
        for _ in range(128):
            if (Y >> 127) & 1:
                Z ^= V
            Y = (Y << 1) & ((1 << 128) - 1)
            carry = V & 1
            V >>= 1
            if carry:
                V ^= R
        return Z.to_bytes(16, 'big')

    def _ghash(self, H: bytes, aad: bytes, data: bytes) -> bytes:
        """
        GHASH(H, A, C) per NIST SP 800-38D
        """
        if len(H) != 16:
            raise ValueError("H must be 16 bytes.")
        X = b'\\x00' * 16

        def process(buf: bytes):
            nonlocal X
            for i in range(0, len(buf), 16):
                block = buf[i:i+16]
                if len(block) < 16:
                    block = block + b'\\x00' * (16 - len(block))
                X = self._gf_mul(self._xor(X, block), H)

        process(self._pad16(aad))
        process(self._pad16(data))
        # 64-bit lengths of A and C (in bits) concatenated
        len_block = (len(aad) * 8).to_bytes(8, 'big') + (len(data) * 8).to_bytes(8, 'big')
        X = self._gf_mul(self._xor(X, len_block), H)
        return X

    ############################################################################
    # AES-GCM (AEAD)
    ############################################################################

    def gcm_encrypt(self, plaintext, aad=b"", iv=None, tag_len=16):
        """
        AES-GCM encrypt.
        - plaintext: str or bytes
        - aad: additional authenticated data (bytes)
        - iv: 12-byte recommended nonce; if None, random 12-byte nonce is generated
        - tag_len: 16 (default) or shorter (>=12 recommended)
        Returns: iv || ciphertext || tag
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        if not isinstance(aad, (bytes, bytearray)):
            raise TypeError("aad must be bytes.")
        if tag_len <= 0 or tag_len > 16:
            raise ValueError("tag_len must be in 1..16 (use 16 for full 128-bit tag).")

        # Ensure we have a nonce/IV (recommend 12 bytes)
        if not iv:
            iv = os.urandom(12)

        # Hash subkey H = E_K(0^128)
        H = self._E(b'\x00' * 16)

        # Build J0 (initial counter block) per SP 800-38D
        if len(iv) == 12:
            J0 = iv + b'\x00\x00\x00\x01'
        else:
            # J0 = GHASH(H, {}, IV)
            J0 = self._ghash(H, b"", iv)

        if len(J0) != 16:
            raise ValueError(f"GCM internal error: J0 length {len(J0)} != 16 (iv len={len(iv)})")

        # CTR keystream starts from inc32(J0)
        ctr = self._inc32(J0)
        ciphertext_blocks = []

        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            S = self._E(ctr)                        # E(K, ctr)
            C = self._xor(block, S[:len(block)])
            ciphertext_blocks.append(C)
            ctr = self._inc32(ctr)

        ciphertext = b''.join(ciphertext_blocks)

        # Tag: S0 XOR GHASH(H, A, C), where S0 = E(K, J0)
        S0 = self._E(J0)
        auth = self._ghash(H, aad, ciphertext)
        tag = self._xor(S0, auth)[:tag_len]

        # Return layout produced by this implementation: iv || ciphertext || tag
        # (Decryption expects the same format.)
        return iv + ciphertext + tag


    def gcm_decrypt(self, data, aad=b"", tag_len=16):
        """
        AES-GCM decrypt/verify.
        Expects: iv (12 bytes) || ciphertext || tag
        Returns plaintext (bytes) if tag verifies; raises ValueError otherwise.
        """
        if not isinstance(aad, (bytes, bytearray)):
            raise TypeError("aad must be bytes.")
        if len(data) < 12 + tag_len:
            raise ValueError("Data too short for GCM.")
        if tag_len <= 0 or tag_len > 16:
            raise ValueError("tag_len must be in 1..16.")

        iv = data[:12]
        tag = data[-tag_len:]
        ciphertext = data[12:-tag_len]

        # Hash subkey H = E_K(0^128)
        H = self._E(b'\x00' * 16)

        # Rebuild J0 (do NOT inc32 here; that's only for the keystream counter)
        if len(iv) == 12:
            J0 = iv + b'\x00\x00\x00\x01'
        else:
            J0 = self._ghash(H, b"", iv)

        if len(J0) != 16:
            raise ValueError(f"GCM internal error: J0 length {len(J0)} != 16 (iv len={len(iv)})")

        # Recompute expected tag
        S0 = self._E(J0)
        expected_tag = self._xor(S0, self._ghash(H, aad, ciphertext))[:tag_len]
        if not self._ct_eq(expected_tag, tag):
            raise ValueError("GCM tag verification failed.")

        # Decrypt with counter starting at inc32(J0)
        ctr = self._inc32(J0)
        plaintext_blocks = []
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            S = self._E(ctr)
            P = self._xor(block, S[:len(block)])
            plaintext_blocks.append(P)
            ctr = self._inc32(ctr)

        return b''.join(plaintext_blocks)

    ############################################################################
    # EAX (AEAD): CTR + CMAC (OMAC with domain separation)
    ############################################################################

    def _leftshift_one(self, b: bytes) -> bytes:
        x = int.from_bytes(b, 'big')
        x = (x << 1) & ((1 << 128) - 1)
        return x.to_bytes(16, 'big')

    def _cmac_subkeys(self) -> tuple[bytes, bytes]:
        L = self.aes.encrypt(b'\\x00' * 16)
        const_rb = 0x87
        K1 = self._leftshift_one(L)
        if (L[0] & 0x80) != 0:
            K1 = (int.from_bytes(K1, 'big') ^ const_rb).to_bytes(16, 'big')
        K2 = self._leftshift_one(K1)
        if (K1[0] & 0x80) != 0:
            K2 = (int.from_bytes(K2, 'big') ^ const_rb).to_bytes(16, 'big')
        return K1, K2

    def _cmac(self, msg: bytes) -> bytes:
        K1, K2 = self._cmac_subkeys()
        if len(msg) == 0:
            n = 0
        else:
            n = (len(msg) + 15) // 16
        if n == 0:
            n = 1
            last_block = self._xor(b'\\x00' * 16, K2)
        else:
            if (len(msg) % 16) == 0:
                last_block = self._xor(msg[(n - 1) * 16: n * 16], K1)
            else:
                block = msg[(n - 1) * 16:]
                block = block + b'\\x80' + b'\\x00' * (16 - len(block) - 1)
                last_block = self._xor(block, K2)

        X = b'\\x00' * 16
        for i in range(0, (n - 1) * 16, 16):
            X = self.aes.encrypt(self._xor(X, msg[i:i+16]))
        X = self.aes.encrypt(self._xor(X, last_block))
        return X

    def _omac(self, label: int, data: bytes) -> bytes:
        # Domain-separated CMAC: OMAC(label || data), label is a single byte 0,1,2
        return self._cmac(bytes([label]) + data)

    def eax_encrypt(self, plaintext, aad=b"", nonce=None, tag_len=16):
        """
        AES-EAX encrypt.
        - plaintext: str or bytes
        - aad: bytes (associated data authenticated, not encrypted)
        - nonce: bytes (any length, recommended 16); if None, random 16 bytes
        - tag_len: length of returned tag (<=16), default 16
        Returns: nonce || ciphertext || tag
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        if not isinstance(aad, (bytes, bytearray)):
            raise TypeError("aad must be bytes.")
        if nonce is None:
            nonce = os.urandom(16)

        # 1) Compute OMACs with domain separation
        N = self._omac(0, nonce)
        H = self._omac(1, aad)

        # 2) CTR-ENC with initial counter = N
        ctr = N
        ciphertext_blocks = []
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            S = self.aes.encrypt(ctr)  # E(K, ctr)
            C = self._xor(block, S[:len(block)])
            ciphertext_blocks.append(C)
            ctr = self._inc32(ctr)
        ciphertext = b''.join(ciphertext_blocks)

        # 3) Tag = OMAC(2 || ciphertext) XOR N XOR H
        Cmac = self._omac(2, ciphertext)
        tag = self._xor(self._xor(Cmac, N), H)[:tag_len]

        return nonce + ciphertext + tag

    def eax_decrypt(self, data, aad=b"", tag_len=16):
        """
        AES-EAX decrypt/verify.
        Expects: nonce || ciphertext || tag
        Returns plaintext (bytes) if tag verifies; raises ValueError otherwise.
        """
        if not isinstance(aad, (bytes, bytearray)):
            raise TypeError("aad must be bytes.")
        if len(data) < 1 + tag_len:
            raise ValueError("Data too short for EAX.")

        # Heuristic: assume 16-byte nonce unless you manage nonce length externally
        nonce = data[:16]
        tag = data[-tag_len:]
        ciphertext = data[16:-tag_len]

        N = self._omac(0, nonce)
        H = self._omac(1, aad)
        Cmac = self._omac(2, ciphertext)
        expected_tag = self._xor(self._xor(Cmac, N), H)[:tag_len]
        if not self._ct_eq(expected_tag, tag):
            raise ValueError("EAX tag verification failed.")

        # CTR decrypt
        ctr = N
        plaintext_blocks = []
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            S = self.aes.encrypt(ctr)
            P = self._xor(block, S[:len(block)])
            plaintext_blocks.append(P)
            ctr = self._inc32(ctr)

        return b''.join(plaintext_blocks)
