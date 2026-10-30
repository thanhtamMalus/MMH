import argparse
import string
import math
from typing import List

ALPHABET = string.ascii_uppercase
M = len(ALPHABET)

# --- 1. Vigenere Cipher ---
def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    key = ''.join(ch for ch in key.upper() if ch in ALPHABET)
    if not key:
        raise ValueError("Key must contain alphabetic characters.")
    key_indices = [ALPHABET.index(k) for k in key]
    result = []
    j = 0
    for ch in text.upper():
        if ch in ALPHABET:
            shift = key_indices[j % len(key_indices)]
            if decrypt:
                shift = -shift
            idx = (ALPHABET.index(ch) + shift) % M
            result.append(ALPHABET[idx])
            j += 1
        else:
            result.append(ch)
    return ''.join(result)

# --- 2. Beaufort Cipher ---
def beaufort(text: str, key: str) -> str:
    key = ''.join(ch for ch in key.upper() if ch in ALPHABET)
    if not key:
        raise ValueError("Key must contain alphabetic characters.")
    key_indices = [ALPHABET.index(k) for k in key]
    result = []
    j = 0
    for ch in text.upper():
        if ch in ALPHABET:
            shift = key_indices[j % len(key_indices)]
            idx = (shift - ALPHABET.index(ch)) % M
            result.append(ALPHABET[idx])
            j += 1
        else:
            result.append(ch)
    return ''.join(result)

# --- 3. Autokey Cipher ---
def autokey(text: str, key: str, decrypt: bool = False) -> str:
    text = text.upper()
    key = ''.join(ch for ch in key.upper() if ch in ALPHABET)
    if not key:
        raise ValueError("Key must contain alphabetic characters.")
    result = []

    if decrypt:
        # Decryption: recover plaintext progressively
        j = 0
        recovered = []
        for ch in text:
            if ch in ALPHABET:
                shift = ALPHABET.index(key[j]) if j < len(key) else ALPHABET.index(recovered[j - len(key)])
                p_idx = (ALPHABET.index(ch) - shift) % M
                p = ALPHABET[p_idx]
                recovered.append(p)
                j += 1
            else:
                recovered.append(ch)
        return ''.join(recovered)
    else:
        # Encryption: use key followed by plaintext as running key
        j = 0
        running = list(key)
        out = []
        for i, ch in enumerate(text):
            if ch in ALPHABET:
                shift = ALPHABET.index(running[j])
                c_idx = (ALPHABET.index(ch) + shift) % M
                out.append(ALPHABET[c_idx])
                running.append(ch)  # plaintext extends the running key
                j += 1
            else:
                out.append(ch)
        return ''.join(out)

# --- 4. Playfair Cipher ---
# Uses 5x5 square combining I/J into one cell (I)

def build_playfair_square(key: str) -> List[List[str]]:
    # clean key: uppercase, remove non-letters, map J->I, remove duplicates
    key = key.upper()
    filtered = []
    for ch in key:
        if ch == 'J':
            ch = 'I'
        if ch in ALPHABET and ch not in filtered:
            filtered.append(ch)
    # fill rest of alphabet (skip J)
    for ch in ALPHABET:
        if ch == 'J':
            continue
        if ch not in filtered:
            filtered.append(ch)
    # build 5x5
    square = [filtered[i*5:(i+1)*5] for i in range(5)]
    return square

def playfair_preprocess(text: str) -> List[str]:
    # remove non-letters, map J->I, split into digraphs with X padding
    cleaned = []
    for ch in text.upper():
        if ch in ALPHABET:
            if ch == 'J':
                cleaned.append('I')
            else:
                cleaned.append(ch)
    digraphs = []
    i = 0
    while i < len(cleaned):
        a = cleaned[i]
        b = cleaned[i+1] if i+1 < len(cleaned) else None
        if b is None:
            digraphs.append(a + 'X')
            i += 1
        elif a == b:
            digraphs.append(a + 'X')
            i += 1
        else:
            digraphs.append(a + b)
            i += 2
    return digraphs

def find_in_square(square: List[List[str]], ch: str):
    for r in range(5):
        for c in range(5):
            if square[r][c] == ch:
                return r, c
    raise ValueError(f"Character {ch} not found in Playfair square")

def playfair_encrypt(text: str, key: str) -> str:
    square = build_playfair_square(key)
    digraphs = playfair_preprocess(text)
    out = []
    for pair in digraphs:
        a, b = pair[0], pair[1]
        r1, c1 = find_in_square(square, a)
        r2, c2 = find_in_square(square, b)
        if r1 == r2:
            # same row -> take right
            out.append(square[r1][(c1 + 1) % 5])
            out.append(square[r2][(c2 + 1) % 5])
        elif c1 == c2:
            # same column -> take below
            out.append(square[(r1 + 1) % 5][c1])
            out.append(square[(r2 + 1) % 5][c2])
        else:
            # rectangle
            out.append(square[r1][c2])
            out.append(square[r2][c1])
    return ''.join(out)

def playfair_decrypt(text: str, key: str) -> str:
    square = build_playfair_square(key)
    # assume cipher text is in correct digraphs (even length)
    cleaned = [ch for ch in text.upper() if ch in ALPHABET]
    if len(cleaned) % 2 != 0:
        raise ValueError("Playfair ciphertext length must be even")
    out = []
    for i in range(0, len(cleaned), 2):
        a = cleaned[i]
        b = cleaned[i+1]
        r1, c1 = find_in_square(square, a)
        r2, c2 = find_in_square(square, b)
        if r1 == r2:
            out.append(square[r1][(c1 - 1) % 5])
            out.append(square[r2][(c2 - 1) % 5])
        elif c1 == c2:
            out.append(square[(r1 - 1) % 5][c1])
            out.append(square[(r2 - 1) % 5][c2])
        else:
            out.append(square[r1][c2])
            out.append(square[r2][c1])
    return ''.join(out)

# --- 5. Hill Cipher (generalized affine via matrix multiplication) ---
# Key: square matrix K (n x n) invertible mod 26


def _parse_hill_key(key_str: str) -> List[List[int]]:
    # Accept comma/space/semi-colon separated integers
    parts = [p for p in key_str.replace(';',',').replace('\n',',').split(',') if p.strip() != '']
    nums = [int(p.strip()) % M for p in parts]
    ln = len(nums)
    n = int(math.isqrt(ln))
    if n * n != ln:
        raise ValueError('Hill key length must be a perfect square (n*n integers).')
    # build matrix row-major
    matrix = [nums[i*n:(i+1)*n] for i in range(n)]
    return matrix


def _mat_det(matrix: List[List[int]], mod: int) -> int:
    # recursive determinant (small n expected)
    n = len(matrix)
    if n == 1:
        return matrix[0][0] % mod
    if n == 2:
        return (matrix[0][0]*matrix[1][1] - matrix[0][1]*matrix[1][0]) % mod
    det = 0
    for c in range(n):
        sign = -1 if (c % 2) else 1
        # build minor
        minor = [row[:c] + row[c+1:] for row in matrix[1:]]
        det += sign * matrix[0][c] * _mat_det(minor, mod)
    return det % mod


def _mat_cofactor(matrix: List[List[int]], mod: int) -> List[List[int]]:
    n = len(matrix)
    cof = [[0]*n for _ in range(n)]
    for r in range(n):
        for c in range(n):
            minor = [row[:c] + row[c+1:] for i,row in enumerate(matrix) if i != r]
            sign = -1 if ((r+c) % 2) else 1
            cof[r][c] = (sign * _mat_det(minor, mod)) % mod
    return cof


def _mat_transpose(matrix: List[List[int]]) -> List[List[int]]:
    return [list(row) for row in zip(*matrix)]


def _modinv(a: int, mod: int) -> int:
    # modular inverse via extended Euclid
    a = a % mod
    if a == 0:
        raise ValueError('Inverse does not exist')
    lm, hm = 1, 0
    low, high = a, mod
    while low > 1:
        r = high // low
        nm = hm - lm * r
        new = high - low * r
        hm, lm = lm, nm
        high, low = low, new
    return lm % mod


def _mat_mul_vec(matrix: List[List[int]], vec: List[int], mod: int) -> List[int]:
    n = len(matrix)
    return [sum(matrix[i][j] * vec[j] for j in range(n)) % mod for i in range(n)]


def _mat_mul(matrix_a: List[List[int]], matrix_b: List[List[int]], mod: int) -> List[List[int]]:
    n = len(matrix_a)
    out = [[0]*n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            out[i][j] = sum(matrix_a[i][k] * matrix_b[k][j] for k in range(n)) % mod
    return out


def _mat_inv(matrix: List[List[int]], mod: int) -> List[List[int]]:
    n = len(matrix)
    det = _mat_det(matrix, mod)
    if math.gcd(det, mod) != 1:
        raise ValueError('Key matrix determinant not invertible modulo {}'.format(mod))
    det_inv = _modinv(det, mod)
    cof = _mat_cofactor(matrix, mod)
    adj = _mat_transpose(cof)  # adjugate
    # multiply adj by det_inv
    inv = [[(det_inv * adj[i][j]) % mod for j in range(n)] for i in range(n)]
    return inv


def hill_encrypt(text: str, key_matrix: List[List[int]]) -> str:
    n = len(key_matrix)
    # preprocess text: keep only letters
    cleaned = [ch for ch in text.upper() if ch in ALPHABET]
    # pad
    while len(cleaned) % n != 0:
        cleaned.append('X')
    out = []
    for i in range(0, len(cleaned), n):
        block = cleaned[i:i+n]
        vec = [ALPHABET.index(ch) for ch in block]
        res = _mat_mul_vec(key_matrix, vec, M)
        out.extend(ALPHABET[num] for num in res)
    return ''.join(out)


def hill_decrypt(text: str, key_matrix: List[List[int]]) -> str:
    inv = _mat_inv(key_matrix, M)
    # cleaned
    cleaned = [ch for ch in text.upper() if ch in ALPHABET]
    n = len(inv)
    if len(cleaned) % n != 0:
        raise ValueError('Ciphertext length must be multiple of key size')
    out = []
    for i in range(0, len(cleaned), n):
        block = cleaned[i:i+n]
        vec = [ALPHABET.index(ch) for ch in block]
        res = _mat_mul_vec(inv, vec, M)
        out.extend(ALPHABET[num] for num in res)
    return ''.join(out)

# --- CLI Parser ---

def main():
    parser = argparse.ArgumentParser(description="Polyalphabetic & matrix-based ciphers CLI Tool")
    parser.add_argument("cipher", choices=["vigenere", "beaufort", "autokey", "playfair", "hill"], help="Cipher to use")
    parser.add_argument("text", help="Input text")
    parser.add_argument("--key", type=str, help="Key (keyword) for Vigenere/Beaufort/Autokey")
    parser.add_argument("--playfairkey", type=str, help="Key string for Playfair (builds 5x5 square)")
    parser.add_argument("--hillkey", type=str, help="Comma-separated integers for Hill key matrix (row-major). Length must be n*n")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt instead of encrypt")

    args = parser.parse_args()

    if args.cipher in ("vigenere", "beaufort", "autokey") and not args.key:
        raise ValueError('Please provide --key for this cipher')

    if args.cipher == "vigenere":
        print(vigenere(args.text, key=args.key, decrypt=args.decrypt))
    elif args.cipher == "beaufort":
        print(beaufort(args.text, key=args.key))
    elif args.cipher == "autokey":
        print(autokey(args.text, key=args.key, decrypt=args.decrypt))
    elif args.cipher == "playfair":
        if not args.playfairkey:
            raise ValueError('Please provide --playfairkey for Playfair cipher')
        if args.decrypt:
            print(playfair_decrypt(args.text, args.playfairkey))
        else:
            print(playfair_encrypt(args.text, args.playfairkey))
    elif args.cipher == "hill":
        if not args.hillkey:
            raise ValueError('Please provide --hillkey for Hill cipher (comma-separated ints)')
        matrix = _parse_hill_key(args.hillkey)
        if args.decrypt:
            print(hill_decrypt(args.text, matrix))
        else:
            print(hill_encrypt(args.text, matrix))

if __name__ == "__main__":
    main()
