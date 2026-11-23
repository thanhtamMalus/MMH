# cbc_padding_oracle_demo.py
import os
from typing import List, Callable
from mypackages import modes   # AES của bạn

BLOCK = 16

def pkcs7_block_valid(b: bytes) -> bool:
    if len(b) != BLOCK: return False
    pad = b[-1]
    if not (1 <= pad <= BLOCK): return False
    tail = b[-pad:]
    bad = 0
    for x in tail: bad |= (x ^ pad)
    return bad == 0

class Victim:
    """Nạn nhân GIỮ KEY bên trong; kẻ tấn công KHÔNG thấy key."""
    def __init__(self):
        key = os.urandom(16)
        self._m = modes.modes(key)  # <- key ở đây, attacker không thấy
        self._m.mode = "CBC"

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._m.cbc_encrypt(plaintext)  # trả về IV||C

    def padding_oracle(self, forged_two_blocks: bytes) -> bool:
        """API duy nhất attacker được gọi: True nếu block cuối có PKCS#7 hợp lệ."""
        try:
            if len(forged_two_blocks) != 32: return False
            ivp, ck = forged_two_blocks[:16], forged_two_blocks[16:]
            dec = self._m._D(ck)  # D_K(Ck) (chỉ Victim gọi được)
            last_plain = bytes(a ^ b for a,b in zip(dec, ivp))
            return pkcs7_block_valid(last_plain)
        except Exception:
            return False

# ---------------- Attacker code: KHÔNG DÙNG KEY, chỉ dùng oracle ----------------
def split_blocks(b: bytes) -> List[bytes]:
    if len(b) % BLOCK: raise ValueError("cipher not aligned")
    return [b[i:i+BLOCK] for i in range(0, len(b), BLOCK)]

def recover_block(oracle: Callable[[bytes], bool], prev: bytes, ck: bytes) -> bytes:
    I = bytearray(BLOCK); P = bytearray(BLOCK)
    for pad in range(1, BLOCK+1):
        i = BLOCK - pad
        ivp = bytearray(BLOCK)
        for j in range(i+1, BLOCK):
            ivp[j] = I[j] ^ pad
        hit = None
        for x in range(256):
            ivp[i] = x
            if oracle(bytes(ivp)+ck):
                hit = x; break
        if hit is None:
            raise RuntimeError(f"oracle fail at byte {i}, pad={pad}")
        I[i] = hit ^ pad
        P[i] = I[i] ^ prev[i]
    return bytes(P)

def attack(oracle: Callable[[bytes], bool], iv: bytes, C: bytes) -> bytes:
    blocks = [iv] + split_blocks(C)
    out = bytearray()
    for k in range(1, len(blocks)):
        out += recover_block(oracle, blocks[k-1], blocks[k])
    pad = out[-1]
    if 1 <= pad <= BLOCK and out[-pad:] == bytes([pad])*pad:
        out = out[:-pad]
    return bytes(out)

# ---------------------- I/O helpers (không đụng tới key) ----------------------
def yN(prompt, default=False):
    s = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return (s in ("y","yes")) if s else default
def hx(s): s=s.strip().lower(); return bytes.fromhex(s[2:] if s.startswith("0x") else s)
def show_hex(b, n=64):
    h=b[:n].hex(); print(h + (f"...(+{len(b)-n}B)" if len(b)>n else ""))

# ------------------------------- Main menu -----------------------------------
def main():
    victim = Victim()         # 1 process = 1 key (attacker không thấy key này)
    last = None               # (iv, C) cuối cùng để attack ngay không cần dán

    while True:
        print("\n=== CBC Padding-Oracle Demo ===")
        print("1) Encrypt (CBC, text UTF-8 hoặc file)")
        print("2) Attack WITHOUT key (dán IV/C hoặc IV||C)")
        print("3) Attack LAST ciphertext (cùng process)")
        print("4) Exit")
        ch = input("Choose 1/2/3/4: ").strip()

        if ch == "1":
            if yN("Dùng FILE (thay vì gõ text)?", False):
                p = input("Đường dẫn file: ").strip()
                with open(p, "rb") as f: data = f.read()
                print(f"[info] đọc {len(data)} bytes")
            else:
                data = input("Nhập plaintext (UTF-8): ").encode("utf-8")
            ct = victim.encrypt(data)          # IV||C
            iv, C = ct[:16], ct[16:]
            last = (iv, C)
            print(f"[Victim] IV = {iv.hex()}")
            print(f"[Victim] C  = {C.hex()}")
            print("→ Chọn 3 để tấn công ngay ciphertext này (không cần dán).")
            print("  Hoặc chọn 2 và dán IV/C (hoặc IV||C).")

        elif ch == "2":
            iv_hex = input("IV (hex) — để trống nếu sẽ dán IV||C ở dưới: ").strip()
            c_hex  = input("C (hex)  — hoặc dán IV||C nếu trên để trống: ").strip()
            try:
                if iv_hex and c_hex:
                    iv, C = hx(iv_hex), hx(c_hex)
                elif (not iv_hex) and c_hex:
                    raw = hx(c_hex)
                    if len(raw) < 32: raise ValueError("IV||C phải ≥ 32 bytes (64 hex).")
                    iv, C = raw[:16], raw[16:]
                    print("[hint] Đã tự tách IV||C.")
                else:
                    raise ValueError("Cần (IV và C) hoặc một chuỗi IV||C.")
                if len(iv)!=16 or len(C)%16!=0 or len(C)==0: raise ValueError("IV 16B; C bội số 16B.")
            except Exception as e:
                print(f"[!] Lỗi input: {e}"); continue

            print("\n[Attacker] Đang tấn công (không biết key, chỉ oracle)...")
            rec = attack(victim.padding_oracle, iv, C)   # ← CHỈ oracle, KHÔNG key
            try:
                s = rec.decode("utf-8")
                print(f"\n[OK] UTF-8 ({len(rec)}B):\n{s}")
            except UnicodeDecodeError:
                print(f"\n[Bytes] ({len(rec)}B) không phải UTF-8; xem hex preview:")
                show_hex(rec)
                if yN("Lưu bytes ra file .bin?", True):
                    out = input("Tên file [recovered.bin]: ").strip() or "recovered.bin"
                    with open(out,"wb") as f: f.write(rec)
                    print(f"[OK] saved {len(rec)}B -> {out}")

            print("\n[WARNING] CBC + PKCS#7 nguy hiểm nếu lộ padding oracle.")
            print("→ Dùng AEAD (GCM/EAX/ChaCha20-Poly1305) hoặc Encrypt-then-MAC + lỗi đồng nhất.")

        elif ch == "3":
            if not last:
                print("Chưa có ciphertext. Chọn 1 trước."); continue
            iv, C = last
            print("\n[Attacker] Tấn công ciphertext cuối (không dán gì)...")
            rec = attack(victim.padding_oracle, iv, C)   # ← CHỈ oracle
            try:
                s = rec.decode("utf-8")
                print(f"\n[OK] UTF-8 ({len(rec)}B):\n{s}")
            except UnicodeDecodeError:
                print(f"\n[Bytes] ({len(rec)}B) không phải UTF-8; xem hex preview:")
                show_hex(rec)
                if yN("Lưu bytes ra file .bin?", True):
                    out = input("Tên file [recovered.bin]: ").strip() or "recovered.bin"
                    with open(out,"wb") as f: f.write(rec)
                    print(f"[OK] saved {len(rec)}B -> {out}")

            print("\n[WARNING] CBC + PKCS#7 nguy hiểm nếu lộ padding oracle.")
            print("→ Dùng AEAD (GCM/EAX/ChaCha20-Poly1305) hoặc Encrypt-then-MAC + lỗi đồng nhất.")

        elif ch == "4":
            break
        else:
            print("Chọn 1/2/3/4.")
if __name__ == "__main__":
    main()
