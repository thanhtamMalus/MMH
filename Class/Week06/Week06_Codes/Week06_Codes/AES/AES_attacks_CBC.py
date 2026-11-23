# cbc_oracle_with_pycryptodome.py
# Demo: (1) Encrypt with AES-CBC/PKCS7 using PyCryptodome
#       (2) Decrypt WITHOUT the key using ONLY a padding oracle (attack)
#
# pip install pycryptodome

import os
from typing import List, Callable

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK = 16  # AES block size

# ----------------------------- Victim service -------------------------------
def pkcs7_block_valid(block: bytes) -> bool:
    """Strict single-block PKCS#7 check (no global unpad)."""
    if len(block) != BLOCK:
        return False
    padval = block[-1]
    if not (1 <= padval <= BLOCK):
        return False
    # constant-time-ish tail check
    tail = block[-padval:]
    bad = 0
    for b in tail:
        bad |= (b ^ padval)
    return bad == 0

class Victim:
    """
    Keeps a secret AES key internally. Attacker cannot read it.
    Exposes:
      - encrypt(plaintext) -> IV||C  (AES-CBC/PKCS7)
      - padding_oracle(forged_two_blocks) -> bool
        True iff the LAST block has valid PKCS#7 padding.
        Input must be exactly 32 bytes: IV' || Ck
    """
    def __init__(self, key: bytes | None = None):
        if key is None:
            key = os.urandom(16)  # 128-bit demo key
        self._key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = os.urandom(16)
        cipher = AES.new(self._key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, BLOCK))
        return iv + ct  # IV||C

    def _D_block(self, cblock: bytes) -> bytes:
        """
        Decrypt a single ciphertext block like D_K(Ck).
        We emulate single-block CBC decrypt step with a zero IV, then XOR outside.
        Implementation detail: build a cipher with zero IV and decrypt one block.
        """
        if len(cblock) != 16:
            raise ValueError("cblock must be 16 bytes")
        zero_iv = b"\x00" * 16
        cipher = AES.new(self._key, AES.MODE_CBC, zero_iv)
        # Decrypt one block by feeding a single block; CBC subtracts IV (= zero)
        return cipher.decrypt(cblock)

    def padding_oracle(self, forged: bytes) -> bool:
        """
        True iff the last block has correct PKCS#7 padding.
        forged must be exactly two blocks (32 bytes): IV' || Ck
        """
        try:
            if not isinstance(forged, (bytes, bytearray)) or len(forged) != 32:
                return False
            ivp = forged[:16]
            ck  = forged[16:]

            dec = self._D_block(ck)  # D_K(Ck) (16 bytes)
            last_plain = bytes(a ^ b for a, b in zip(dec, ivp))  # Pk
            return pkcs7_block_valid(last_plain)
        except Exception:
            return False

# ----------------------------- Attacker code --------------------------------
def split_blocks(b: bytes, size: int = BLOCK) -> List[bytes]:
    if len(b) % size != 0:
        raise ValueError("cipher not aligned")
    return [b[i:i+size] for i in range(0, len(b), size)]

def recover_block(oracle: Callable[[bytes], bool], prev_block: bytes, ck: bytes,
                  *, verbose: bool = False) -> bytes:
    """
    Recover Pk given prev_block (IV or C_{k-1}) and Ck, using a padding oracle.
    We fully control the forged IV' and query oracle(IV'||Ck).
    """
    assert len(prev_block) == BLOCK and len(ck) == BLOCK
    I = bytearray(BLOCK)  # Dec_K(Ck)
    P = bytearray(BLOCK)  # plaintext block

    for padlen in range(1, BLOCK + 1):
        i = BLOCK - padlen
        ivp = bytearray(BLOCK)
        for j in range(i + 1, BLOCK):
            ivp[j] = I[j] ^ padlen

        hit = None
        for x in range(256):
            ivp[i] = x
            if oracle(bytes(ivp) + ck):
                hit = x
                break
        if hit is None:
            raise RuntimeError(f"Oracle failed at byte {i}, pad={padlen}")

        I[i] = hit ^ padlen
        P[i] = I[i] ^ prev_block[i]
        if verbose:
            print(f"[recover] pad={padlen:02d} i={i:02d} I={I[i]:02x} P={P[i]:02x}")
    return bytes(P)

def padding_oracle_attack(oracle: Callable[[bytes], bool], iv: bytes, C: bytes,
                          *, verbose: bool = False) -> bytes:
    blocks = [iv] + split_blocks(C, BLOCK)
    out = bytearray()
    for k in range(1, len(blocks)):
        if verbose:
            print(f"[info] recovering block {k}/{len(blocks)-1}")
        out += recover_block(oracle, blocks[k-1], blocks[k], verbose=verbose)
    # strip PKCS#7
    padval = out[-1]
    if 1 <= padval <= BLOCK and out[-padval:] == bytes([padval]) * padval:
        out = out[:-padval]
    return bytes(out)

# ------------------------------ UI helpers ----------------------------------
def ask_yn(prompt: str, default=False) -> bool:
    s = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    if not s:
        return default
    return s in ("y", "yes")

def hex_clean(s: str) -> str:
    import re
    return re.sub(r"[^0-9a-fA-F]", "", s or "")

def h2b(s: str) -> bytes:
    s = hex_clean(s)
    if len(s) % 2 != 0:
        raise ValueError("hex string must have even length")
    return bytes.fromhex(s)

def b2h(b: bytes) -> str:
    return b.hex()

def print_hex_preview(b: bytes, maxlen: int = 64):
    h = b[:maxlen].hex()
    if len(b) > maxlen:
        h += f"...(+{len(b)-maxlen}B)"
    print(h)

# ---------------------------------- Main ------------------------------------
def main():
    victim = Victim()      # secret key known only to victim
    last_iv = None         # so we can attack the last ciphertext quickly
    last_C  = None

    while True:
        print("\n=== AES-CBC Padding-Oracle Demo (PyCryptodome) ===")
        print("1) Encrypt (CBC/PKCS7): input as UTF-8 text or binary file")
        print("2) Attack WITHOUT key (paste IV/C or IV||C) using padding oracle")
        print("3) Attack LAST ciphertext (from this session)")
        print("4) Exit")
        choice = input("Choose 1/2/3/4: ").strip()

        if choice == "1":
            if ask_yn("Encrypt a binary FILE instead of typing text?", default=False):
                path = input("File path: ").strip()
                with open(path, "rb") as f:
                    data = f.read()
                print(f"[info] read {len(data)} bytes")
            else:
                data = input("Enter plaintext (UTF-8): ").encode("utf-8")

            ct = victim.encrypt(data)  # IV||C
            iv, C = ct[:16], ct[16:]
            last_iv, last_C = iv, C
            print(f"[Victim] IV = {b2h(iv)}")
            print(f"[Victim] C  = {b2h(C)}")
            print("Tip: choose option 3 to attack this ciphertext immediately (same key).")

        elif choice == "2":
            print("\n[Attack] Paste IV/C (hex), or leave IV blank and paste IV||C as ciphertext.")
            iv_hex = input("IV (hex) [leave blank if pasting IV||C below]: ")
            c_hex  = input("C  (hex) OR IV||C (hex): ")
            try:
                if iv_hex.strip():
                    iv = h2b(iv_hex)
                    C  = h2b(c_hex)
                else:
                    raw = h2b(c_hex)
                    if len(raw) < 32:
                        raise ValueError("IV||C must be at least 32 bytes (64 hex chars)")
                    iv, C = raw[:16], raw[16:]
                    print("[hint] Detected IV||C combined; parsed automatically.")
                if len(iv) != 16:
                    raise ValueError("IV must be exactly 16 bytes")
                if len(C) == 0 or len(C) % 16 != 0:
                    raise ValueError("C must be a non-empty multiple of 16 bytes")
            except Exception as e:
                print(f"[!] Input error: {e}")
                continue

            print("\n[Attacker] Running padding-oracle attack (no key, oracle only)...")
            recovered = padding_oracle_attack(victim.padding_oracle, iv, C, verbose=False)

            # Try UTF-8 first
            try:
                txt = recovered.decode("utf-8")
                print(f"\n[OK] Recovered UTF-8 ({len(recovered)} bytes)")
                print("----------------------------------------------")
                print(txt)
                print("----------------------------------------------")
            except UnicodeDecodeError:
                print(f"\n[Bytes] Recovered ({len(recovered)} bytes) is NOT valid UTF-8")
                print("hex preview: ", end=""); print_hex_preview(recovered)
                if ask_yn("Save recovered BYTES to file?", default=True):
                    out = input("Output filename [recovered.bin]: ").strip() or "recovered.bin"
                    with open(out, "wb") as f:
                        f.write(recovered)
                    print(f"[OK] saved {len(recovered)} bytes -> {out}")

            print("\n>>> WARNING: CBC + PKCS#7 is vulnerable if a padding oracle exists.")
            print(">>> Prefer AEAD (GCM, EAX, ChaCha20-Poly1305) in real applications.")

        elif choice == "3":
            if last_iv is None:
                print("No ciphertext yet. Choose 1 first.")
                continue
            print("\n[Attacker] Attacking last ciphertext from this session...")
            recovered = padding_oracle_attack(victim.padding_oracle, last_iv, last_C, verbose=False)
            try:
                txt = recovered.decode("utf-8")
                print(f"\n[OK] Recovered UTF-8 ({len(recovered)} bytes)")
                print("----------------------------------------------")
                print(txt)
                print("----------------------------------------------")
            except UnicodeDecodeError:
                print(f"\n[Bytes] Recovered ({len(recovered)} bytes) is NOT valid UTF-8")
                print("hex preview: ", end=""); print_hex_preview(recovered)
                if ask_yn("Save recovered BYTES to file?", default=True):
                    out = input("Output filename [recovered.bin]: ").strip() or "recovered.bin"
                    with open(out, "wb") as f:
                        f.write(recovered)
                    print(f"[OK] saved {len(recovered)} bytes -> {out}")

            print("\n>>> WARNING: CBC + PKCS#7 is vulnerable if a padding oracle exists.")
            print(">>> Prefer AEAD (GCM, EAX, ChaCha20-Poly1305).")

        elif choice == "4":
            break
        else:
            print("Choose 1/2/3/4.")

if __name__ == "__main__":
    main()
