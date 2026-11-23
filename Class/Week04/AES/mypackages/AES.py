# -*- coding: utf-8 -*-
"""
Corrected AES block cipher primitive for AES-128, AES-192, and AES-256.

This version keeps the original teaching-oriented structure but fixes the AES
state mapping: AES maps bytes into state[row][column] column-by-column.
The public API remains compatible with the earlier project:

    aes = AES(key_bytes, 128)
    ciphertext_block = aes.encrypt(plaintext_16_bytes)
    plaintext_block = aes.decrypt(ciphertext_16_bytes)

Only one 16-byte block is processed here. Padding and modes of operation belong
in the modes.py / AES modes layer.
"""

class AES:
    BLOCK_SIZE = 16
    VALID_KEY_LENGTHS = {128: 16, 192: 24, 256: 32}
    NUM_ROUNDS = {128: 10, 192: 12, 256: 14}

    def __init__(self, key, key_length=None):
        """
        AES block cipher primitive.

        Args:
            key: bytes-like AES key. Valid lengths are 16, 24, or 32 bytes.
            key_length: optional key length in bits: 128, 192, or 256.

        This class encrypts/decrypts exactly one 16-byte AES block.
        Modes such as CBC/CFB/OFB/CTR/GCM must be implemented outside this class.
        """
        self.key = bytes(key)
        if key_length is None:
            key_length = len(self.key) * 8
        if key_length not in self.VALID_KEY_LENGTHS:
            raise ValueError("Invalid AES key length. Use 128, 192, or 256 bits.")
        expected_len = self.VALID_KEY_LENGTHS[key_length]
        if len(self.key) != expected_len:
            raise ValueError(
                f"AES-{key_length} requires {expected_len} key bytes; got {len(self.key)}."
            )
        self.key_length = key_length
        self.round_keys = self.key_expansion(self.key, self.key_length)
    ###AES constants
    # S-box constants
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
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    INV_S_BOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]    
    #### Encryption functions
    def sub_bytes(self, state):
        """
        Substitute each byte in the state with its corresponding byte in the S-box.
        """
        for i in range(4):
            for j in range(4):
                # Extract the row and column index for the S-box
                row = state[i][j] // 0x10
                col = state[i][j] % 0x10
                # Substitute the byte using the S-box
                state[i][j] = self.S_BOX[16 * row + col]
        return state

    # shift_rows (permutation)
    def shift_rows(self, state):
        """
        Cyclically shift the rows of the state.
        """
        # Second row: shift left by one byte
        state[1] = [state[1][1], state[1][2], state[1][3], state[1][0]]

        # Third row: shift left by two bytes
        state[2] = [state[2][2], state[2][3], state[2][0], state[2][1]]

        # Fourth row: shift left by three bytes
        state[3] = [state[3][3], state[3][0], state[3][1], state[3][2]]
        return state
    
    # Mix columns (substitution)
    def mix_columns(self, state):
        """
        Mix the columns of the state.
        """
        def gmul(a, b):
            """Galois Field multiplication."""
            p = 0
            for _ in range(8):
                if b & 1:
                    p ^= a
                hi_bit_set = a & 0x80
                a <<= 1
                if hi_bit_set:
                    a ^= 0x1b
                b >>= 1
            return p % 256

        for i in range(4):
            col = [state[j][i] for j in range(4)]
            state[0][i] = gmul(0x02, col[0]) ^ gmul(0x03, col[1]) ^ col[2] ^ col[3]
            state[1][i] = col[0] ^ gmul(0x02, col[1]) ^ gmul(0x03, col[2]) ^ col[3]
            state[2][i] = col[0] ^ col[1] ^ gmul(0x02, col[2]) ^ gmul(0x03, col[3])
            state[3][i] = gmul(0x03, col[0]) ^ col[1] ^ col[2] ^ gmul(0x02, col[3])

        return state
    
    # Add round key (to hide input message)
    def add_round_key(self, state, round_number):
        """
        Add (XOR) the round key to the state.
        """
        for i in range(4):
            #print(f"value at state[:][{i}]: {state[:][i]}")
            #print(f"value at round_keys[{round_number * 4 + i}]: {self.round_keys[round_number * 4 + i]}")
            for j in range(4):
                state[j][i] ^= self.round_keys[round_number * 4 + i][j]
        return state 

    ##### Decryption functions
    def inv_sub_bytes(self, state):
        """Inverse substitute bytes using the inverse S-box."""
        for i in range(4):
            for j in range(4):
                row = state[i][j] // 0x10
                col = state[i][j] % 0x10
                state[i][j] = self.INV_S_BOX[16 * row + col]
        return state

    def inv_shift_rows(self, state):
        """Inverse shift rows to the right."""
        state[1] = [state[1][3], state[1][0], state[1][1], state[1][2]]
        state[2] = [state[2][2], state[2][3], state[2][0], state[2][1]]
        state[3] = [state[3][1], state[3][2], state[3][3], state[3][0]]
        return state
        #Invert Mix columns (substitution for decrypt)
    def inv_mix_columns(self, state):
        """
        Inverse mix the columns of the state.
        """
        def gmul(a, b):
            """Galois Field multiplication."""
            p = 0
            for _ in range(8):
                if b & 1:
                    p ^= a
                hi_bit_set = a & 0x80
                a <<= 1
                if hi_bit_set:
                    a ^= 0x1b
                b >>= 1
            return p % 256

        for i in range(4):
            col = [state[j][i] for j in range(4)]
            state[0][i] = gmul(0x0E, col[0]) ^ gmul(0x0B, col[1]) ^ gmul(0x0D, col[2]) ^ gmul(0x09, col[3])
            state[1][i] = gmul(0x09, col[0]) ^ gmul(0x0E, col[1]) ^ gmul(0x0B, col[2]) ^ gmul(0x0D, col[3])
            state[2][i] = gmul(0x0D, col[0]) ^ gmul(0x09, col[1]) ^ gmul(0x0E, col[2]) ^ gmul(0x0B, col[3])
            state[3][i] = gmul(0x0B, col[0]) ^ gmul(0x0D, col[1]) ^ gmul(0x09, col[2]) ^ gmul(0x0E, col[3])

        return state

    """
    Key generation
    Gennerate keys for diferent rouds in AES (10, 12, 14): words = 4 ∗ (rouds +1)
    Nk= number of words in original keys: 4 (AES-128), 6 (AES-192), 8 (AES-256)
    """
    ####Round constants or 10 fxed words for key expension
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
        [0x36, 0x00, 0x00, 0x00]
        ]
    
    def key_expansion(self, key, length):
        key = bytes(key)
        if length not in self.VALID_KEY_LENGTHS:
            raise ValueError("Invalid key length. Supported lengths are 128, 192, and 256 bits.")
        expected_len = self.VALID_KEY_LENGTHS[length]
        if len(key) != expected_len:
            raise ValueError(f"AES-{length} key expansion requires {expected_len} bytes; got {len(key)}.")
        self.key = key
        if length == 128:
            return self.key_expansion_128()
        elif length == 192:
            return self.key_expansion_192()
        elif length == 256:
            return self.key_expansion_256()
    
        ### Woking on words, 4 bytes for each words (the row or columm vector in state matrix)
        ### Substution word: SUBWORD([a0,...,a3]) = [SBOX(a0),SBOX(a1),SBOX(a2),SBOX(a3)]
    def sub_word(self, word):
        return [self.S_BOX[int(b, 16) if isinstance(b, str) else b] for b in word]
    
    ### Rotation word (<<<1): ROTWORD([a0,a1,a2,a3]) = [a1,a2,a3,a0]
    def rot_word(self, word): 
        return word[1:] + word[:1]
    
    """
    Gennerate keys for diferent rouds in AES (10, 12, 14): words = 4 ∗ (rouds +1)
    Nk= number of words in original keys: 4 (AES-128), 6 (AES-192), 8 (AES-256)
    """
    ################# Gen 10 round keys for AES-128: (44 words x 32 bits)/128 =11 keys)
    def key_expansion_128(self):
        key_size = 16  # Note:len(self.key)
        key_words = 4 #Note: key_size // 4     
        ### The first w[0], w[1], ... w[3] come from original key
        round_keys = [list(self.key[i:i+4]) for i in range(0, key_size, 4)]
        ## Need extend the key upto 44 words (iteration)
        for i in range(key_words, 44):  # 44 words for AES-128
            temp = round_keys[i - 1]
            if i % key_words == 0:
                temp = self.sub_word(self.rot_word(temp))
                temp = [temp[j] ^ self.RCON[(i-key_words) // key_words][j] for j in range(4)]  # Note: ^=⊕, // integer division
            round_keys.append([round_keys[i - key_words][j] ^ temp[j] for j in range(4)])
        return round_keys
    
    ################# Gen 12 round keys for AES-192: (52 words x 32 bits)/128 =13 keys)
    def key_expansion_192(self):
        round_keys = [list(self.key[i:i+4]) for i in range(0, 24, 4)]

        for i in range(6, 52):  # 52 words for AES-192
            temp = round_keys[i - 1]
            if i % 6 == 0:
                temp = self.sub_word(self.rot_word(temp))
                temp = [temp[j] ^ self.RCON[(i-6) // 6][j] for j in range(4)]
            round_keys.append([round_keys[i - 6][j] ^ temp[j] for j in range(4)])
        return round_keys
    ################# Gen 14 round keys for AES-256: (60 words x 32 bits)/128 =15 keys)
    def key_expansion_256(self):
        round_keys = [list(self.key[i:i+4]) for i in range(0, 32, 4)]

        for i in range(8, 60):  # 60 words for AES-256
            temp = round_keys[i - 1]
            if i % 8 == 0:
                temp = self.sub_word(self.rot_word(temp))
                temp = [temp[j] ^ self.RCON[(i-8) // 8][j] for j in range(4)]
            elif i % 8 == 4:
                temp = self.sub_word(temp)
            round_keys.append([round_keys[i - 8][j] ^ temp[j] for j in range(4)])

        return round_keys

    
    # -------------------------------------------------------------------------
    # AES state conversion helpers
    # -------------------------------------------------------------------------
    @staticmethod
    def _bytes_to_state(block):
        """Map a 16-byte block to AES state[row][column] in column-major order."""
        block = bytes(block)
        if len(block) != 16:
            raise ValueError(f"AES block must be exactly 16 bytes; got {len(block)}.")
        return [[block[4 * column + row] for column in range(4)] for row in range(4)]

    @staticmethod
    def _state_to_bytes(state):
        """Serialize AES state[row][column] back to a 16-byte block in column-major order."""
        return bytes(state[row][column] for column in range(4) for row in range(4))

    def _num_rounds(self):
        return self.NUM_ROUNDS[self.key_length]

    ################ Encryt one block (128 bits) 

    def encrypt(self, data):
        """Encrypt exactly one 16-byte block using AES-128/192/256."""
        if not hasattr(self, 'round_keys') or not self.round_keys:
            self.round_keys = self.key_expansion(self.key, self.key_length)

        state = self._bytes_to_state(data)
        num_rounds = self._num_rounds()

        # Initial AddRoundKey
        self.add_round_key(state, 0)

        # Nr - 1 full rounds
        for round_number in range(1, num_rounds):
            self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            self.add_round_key(state, round_number)

        # Final round: no MixColumns
        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, num_rounds)

        return self._state_to_bytes(state)

    ################ Decrypt one block (128 bits) 

    def decrypt(self, ciphertext):
        """Decrypt exactly one 16-byte block using AES-128/192/256."""
        if not hasattr(self, 'round_keys') or not self.round_keys:
            self.round_keys = self.key_expansion(self.key, self.key_length)

        state = self._bytes_to_state(ciphertext)
        num_rounds = self._num_rounds()

        # Initial inverse round starts with AddRoundKey(Nr)
        self.add_round_key(state, num_rounds)

        # Nr - 1 inverse full rounds
        for round_number in range(num_rounds - 1, 0, -1):
            self.inv_shift_rows(state)
            self.inv_sub_bytes(state)
            self.add_round_key(state, round_number)
            self.inv_mix_columns(state)

        # Final inverse round: no InvMixColumns
        self.inv_shift_rows(state)
        self.inv_sub_bytes(state)
        self.add_round_key(state, 0)

        return self._state_to_bytes(state)

    