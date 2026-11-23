# cbc_padding_oracle_demo.py
# Educational demo: CBC padding-oracle attack against PKCS#7
import os
from typing import List, Callable
from mypackages import modes  # uses your AES + modes implementation

BLOCK = 16  # AES block size

# ---- strict check for a single block's PKCS#7 padding (no global unpad) ----
def pkcs7_block_valid(block: bytes) -> bool:
    if len(block) != BLOCK:
        return False
    pad = block[-1]
    if pad < 1 or pad > BLOCK:
        return False
    tail = block[-pad:]
    # constant-time-ish compare
    bad = 0
    for b in tail:
        bad |= (b ^ pad)
    return bad == 0

# -----------------------------------------------------------------------------
# Victim side (unknown key). The oracle is the only function an attacker sees.
# -----------------------------------------------------------------------------
class Victim:
    def __init__(self, key: bytes):
        self.m = modes.modes(key)
        self.m.mode = "CBC"

    def encrypt(self, plaintext: bytes) -> bytes:
        # Returns IV || C   (uses your CBC implementation with PKCS#7 padding)
        return self.m.cbc_encrypt(plaintext)

    def padding_oracle(self, forged: bytes) -> bool:
        """
        Returns True iff the **last block** has valid PKCS#7 padding.
        Only requires exactly two blocks: IV' || Ck (32 bytes total).
        No full decryption/unpadding is done; this isolates the oracle behavior.
        """
        try:
            if not isinstance(forged, (bytes, bytearray)) or len(forged) != 32:
                return False
            ivp = forged[:16]
            ck  = forged[16:32]
            # One-block AES decrypt using the same normalized block API as your modes:
            # We assume your modes class has the _D helper (16 raw bytes).
            dec = self.m._D(ck)                   # D_K(Ck)
            last_plain = bytes(a ^ b for a, b in zip(dec, ivp))  # Pk = D(Ck) XOR IV'
            return pkcs7_block_valid(last_plain)
        except Exception:
            return False

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def split_blocks(b: bytes, size: int = BLOCK) -> List[bytes]:
    if len(b) % size != 0:
        raise ValueError("cipher not aligned")
    return [b[i:i+size] for i in range(0, len(b), size)]

# -----------------------------------------------------------------------------
# Core attack (canonical construction)
# -----------------------------------------------------------------------------
def recover_block(oracle: Callable[[bytes], bool], prev_block: bytes, target_block: bytes,
                  *, verbose: bool = False) -> bytes:
    """
    Recover plaintext of one block using a CBC PKCS#7 padding oracle.
    We directly forge IV′ for the pair (IV′ || Ck). Tail j>i must satisfy:
        Dec(Ck)[j] XOR IV′[j] == padlen  =>  IV′[j] = I[j] XOR padlen
    """
    assert len(prev_block) == BLOCK and len(target_block) == BLOCK

    I = bytearray(BLOCK)  # intermediate Dec_K(Ck)
    P = bytearray(BLOCK)  # plaintext block

    for padlen in range(1, BLOCK + 1):
        i = BLOCK - padlen

        # IV′ bắt đầu là all-zero (có thể là bất kỳ giá trị nào)
        ivp = bytearray(BLOCK)

        # Ép đuôi j>i: IV′[j] = I[j] XOR padlen
        for j in range(i + 1, BLOCK):
            ivp[j] = I[j] ^ padlen

        # Brute-force byte i của IV′
        hit_x = None
        for x in range(256):
            ivp[i] = x
            if oracle(bytes(ivp) + target_block):  # gửi đúng 2 khối: IV′ || Ck
                hit_x = x
                break

        if hit_x is None:
            raise RuntimeError(f"Padding oracle failed at byte index {i} (pad={padlen}).")

        # Suy ra I[i] và P[i]
        I[i] = hit_x ^ padlen
        P[i] = I[i] ^ prev_block[i]

        if verbose:
            print(f"[recover] pad={padlen:02d} idx={i:02d} I={I[i]:02x} P={P[i]:02x}")

    return bytes(P)

def padding_oracle_attack(oracle: Callable[[bytes], bool], iv: bytes, ciphertext: bytes, *,
                          verbose: bool = False) -> bytes:
    blocks = [iv] + split_blocks(ciphertext, BLOCK)
    recovered = bytearray()
    for k in range(1, len(blocks)):
        if verbose:
            print(f"[info] Recovering block {k}/{len(blocks)-1}")
        Pk = recover_block(oracle, blocks[k-1], blocks[k], verbose=verbose)
        recovered.extend(Pk)
    # Remove padding at the end with strict single-block validator re-used globally
    # (You can use your library unpad too; this keeps the demo self-contained.)
    # Global unpad:
    pad = recovered[-1]
    if not (1 <= pad <= BLOCK) or recovered[-pad:] != bytes([pad]) * pad:
        # not strictly necessary for the demo; just return bytes
        return bytes(recovered)
    return bytes(recovered[:-pad])

# -----------------------------------------------------------------------------
# Demo
# -----------------------------------------------------------------------------
def main():
    # Secret key unknown to the attacker
    key = os.urandom(16)
    victim = Victim(key)

    # Target message
    msg = (b"A Galois field, also known as a finite field, is a mathematical structure with a finite, countable number of elements where the operations of addition, subtraction, multiplication, and division (by non-zero elements) are defined and follow specific rules.")
    ct = victim.encrypt(msg)          # IV || C
    print(f"Victim Cipher {ct}")
    iv, C = ct[:BLOCK], ct[BLOCK:]
    print(f"[Victim] IV = {iv.hex()}")
    print(f"[Victim] C len = {len(C)} bytes ({len(C)//BLOCK} blocks)")

    # Attacker only gets oracle access + (IV||C)
    plaintext = padding_oracle_attack(victim.padding_oracle, iv, C, verbose=False)
    print(f"[Attacker] Recovered plaintext ({len(plaintext)} bytes):\n{plaintext!r}")

if __name__ == "__main__":
    main()
