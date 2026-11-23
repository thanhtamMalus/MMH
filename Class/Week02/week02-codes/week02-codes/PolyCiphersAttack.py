#!/usr/bin/env python3
import argparse
import math
import random
import string
from collections import Counter, defaultdict
from typing import List, Tuple, Dict, Iterable

ALPHABET = string.ascii_uppercase
M = len(ALPHABET)
IDX = {ch:i for i,ch in enumerate(ALPHABET)}

# -------------------------------------------------------------
# Text utilities
# -------------------------------------------------------------
def only_letters(s: str) -> str:
    return ''.join(ch for ch in s.upper() if ch in ALPHABET)

def to_indices(s: str) -> List[int]:
    return [IDX[ch] for ch in only_letters(s)]

def from_indices(v: Iterable[int]) -> str:
    return ''.join(ALPHABET[i % 26] for i in v)

def ngrams(s: str, n: int) -> List[str]:
    s = only_letters(s)
    return [s[i:i+n] for i in range(len(s)-n+1)]

# -------------------------------------------------------------
# English statistics
# -------------------------------------------------------------
ENGLISH_FREQ = {
    'E': 12.70,'T': 9.06,'A': 8.17,'O': 7.51,'I': 6.97,'N': 6.75,
    'S': 6.33,'H': 6.09,'R': 5.99,'D': 4.25,'L': 4.03,'C': 2.78,
    'U': 2.76,'M': 2.41,'W': 2.36,'F': 2.23,'G': 2.02,'Y': 1.97,
    'P': 1.93,'B': 1.49,'V': 0.98,'K': 0.77,'J': 0.15,'X': 0.15,
    'Q': 0.10,'Z': 0.07
}
ENG_ORDER = [k for k,_ in sorted(ENGLISH_FREQ.items(), key=lambda kv: kv[1], reverse=True)]

# Tetragram log probabilities (short list; fallback to small value)
# Source condensed; in practice use full table for better results.
TETRA = {
    "TION": -2.7, "NTHE": -2.9, "THER": -3.0, "ETHE": -3.1, "THAT": -3.2,
    "OFTH": -3.2, "THIS": -3.3, "TING": -3.3, "THEM": -3.4, "HERE": -3.4,
    "ATIO": -3.4, "THEI": -3.5, "WITH": -3.5, "MENT": -3.5, "IONS": -3.5,
}
TETRA_FALLBACK = -6.0

def tetragram_score(text: str) -> float:
    text = only_letters(text)
    if len(text) < 4:
        return TETRA_FALLBACK * 2
    score = 0.0
    for i in range(len(text)-3):
        score += TETRA.get(text[i:i+4], TETRA_FALLBACK)
    return score

def chi_squared_score(text: str) -> float:
    s = only_letters(text)
    N = len(s)
    if N == 0:
        return float('inf')
    counts = Counter(s)
    chi = 0.0
    for letter, expected_pct in ENGLISH_FREQ.items():
        observed = counts.get(letter, 0)
        expected = expected_pct * N / 100
        chi += (observed - expected)**2 / (expected + 1e-9)
    return chi

# -------------------------------------------------------------
# Caesar helpers (used when splitting columns by key length)
# -------------------------------------------------------------
def caesar_decrypt_column(col: List[int], shift: int) -> List[int]:
    return [ (c - shift) % 26 for c in col ]

def caesar_best_shift(col: List[int]) -> int:
    # Try all 26 shifts and choose the one that minimizes chi-squared
    best_shift, best_score = 0, float('inf')
    for k in range(26):
        pt = from_indices(caesar_decrypt_column(col, k))
        sc = chi_squared_score(pt)
        if sc < best_score:
            best_score, best_shift = sc, k
    return best_shift

# -------------------------------------------------------------
# Friedman / Kasiski for key length
# -------------------------------------------------------------
def index_of_coincidence(text: str) -> float:
    s = only_letters(text)
    N = len(s)
    if N <= 1:
        return 0.0
    counts = Counter(s)
    num = sum(c*(c-1) for c in counts.values())
    den = N*(N-1)
    return num/den if den else 0.0

def friedman_estimate_keylen(text: str) -> float:
    # K_r (random) ≈ 0.0385, K_p (English) ≈ 0.065
    s = only_letters(text)
    N = len(s)
    if N < 2:
        return 1.0
    IC = index_of_coincidence(s)
    Kr, Kp = 0.0385, 0.065
    if IC - Kr <= 1e-9:
        return 1.0
    return (Kp - Kr) / (IC - Kr)

def kasiski_candidates(text: str, min_len: int = 3, max_len: int = 5, top: int = 5) -> List[int]:
    s = only_letters(text)
    distances = []
    for n in range(min_len, max_len+1):
        pos = defaultdict(list)
        for i in range(len(s)-n+1):
            g = s[i:i+n]
            pos[g].append(i)
        for g, idxs in pos.items():
            if len(idxs) >= 2:
                for i in range(len(idxs)-1):
                    distances.append(idxs[i+1] - idxs[i])
    # factor analysis
    factors = Counter()
    for d in distances:
        for f in range(2, 21):  # reasonable factor range
            if d % f == 0:
                factors[f] += 1
    return [k for k,_ in factors.most_common(top)] or [1]

def split_columns_by_len(indices: List[int], L: int) -> List[List[int]]:
    cols = [[] for _ in range(L)]
    for i, c in enumerate(indices):
        cols[i % L].append(c)
    return cols

# -------------------------------------------------------------
# Vigenere / Beaufort attacks
# -------------------------------------------------------------
def vigenere_recover_key(cipher: str, key_len: int) -> str:
    idx = to_indices(cipher)
    cols = split_columns_by_len(idx, key_len)
    key = []
    for col in cols:
        shift = caesar_best_shift(col)  # c - k -> p; best shift k gives English plaintext
        key.append(shift % 26)
    return from_indices(key)

def vigenere_decrypt(cipher: str, key: str) -> str:
    s = only_letters(cipher)
    key_idx = to_indices(key)
    out = []
    for i, c in enumerate(to_indices(s)):
        k = key_idx[i % len(key_idx)]
        out.append((c - k) % 26)
    return from_indices(out)

def beaufort_decrypt(cipher: str, key: str) -> str:
    # Beaufort: C = K - P  =>  P = K - C
    s_idx = to_indices(cipher)
    k_idx = to_indices(key)
    out = []
    for i, c in enumerate(s_idx):
        k = k_idx[i % len(k_idx)]
        out.append((k - c) % 26)
    return from_indices(out)

def vigenere_attack(cipher: str, max_keylen: int = 16) -> Tuple[str, str, int]:
    # Combine Kasiski + Friedman, then try candidates up to max_keylen
    cand_lens = list(dict.fromkeys(kasiski_candidates(cipher) + [round(friedman_estimate_keylen(cipher))]))
    cand_lens = [L for L in cand_lens if 1 <= L <= max_keylen]
    if not cand_lens:
        cand_lens = list(range(1, min(12, max_keylen)+1))
    best_plain, best_key, best_score = "", "", float('inf')
    for L in cand_lens:
        key = vigenere_recover_key(cipher, L)
        pt = vigenere_decrypt(cipher, key)
        sc = chi_squared_score(pt)
        if sc < best_score:
            best_plain, best_key, best_score = pt, key, sc
    return best_plain, best_key, len(best_key)

def beaufort_attack(cipher: str, max_keylen: int = 16) -> Tuple[str, str, int]:
    # Same key-length pipeline; reuse Vigenere recovery (columns solved by Caesar)
    cand_lens = list(dict.fromkeys(kasiski_candidates(cipher) + [round(friedman_estimate_keylen(cipher))]))
    cand_lens = [L for L in cand_lens if 1 <= L <= max_keylen]
    if not cand_lens:
        cand_lens = list(range(1, min(12, max_keylen)+1))
    best_plain, best_key, best_score = "", "", float('inf')
    for L in cand_lens:
        # For Beaufort, the best Caesar shift per column corresponds to key value k that makes P English:
        # P = K - C => for a guess k, P_i = (k - C_i). We choose k that minimizes chi2 over column.
        idx = to_indices(cipher)
        cols = split_columns_by_len(idx, L)
        key_vals = []
        for col in cols:
            best_k, best_col_score = 0, float('inf')
            for k in range(26):
                pt_col = from_indices([(k - c) % 26 for c in col])
                sc = chi_squared_score(pt_col)
                if sc < best_col_score:
                    best_col_score, best_k = sc, k
            key_vals.append(best_k)
        key = from_indices(key_vals)
        pt = beaufort_decrypt(cipher, key)
        sc_total = chi_squared_score(pt)
        if sc_total < best_score:
            best_plain, best_key, best_score = pt, key, sc_total
    return best_plain, best_key, len(best_key)

# -------------------------------------------------------------
# Autokey (heuristic greedy attack)
# -------------------------------------------------------------
def autokey_decrypt(cipher: str, key: str) -> str:
    # Standard autokey: running key = keyword + plaintext
    c_idx = to_indices(cipher)
    k_idx = to_indices(key)
    out = []
    j = 0
    for i, c in enumerate(c_idx):
        shift = k_idx[j] if j < len(k_idx) else out[i - len(k_idx)]
        p = (c - shift) % 26
        out.append(p)
        j += 1
    return from_indices(out)

def autokey_attack_greedy(cipher: str, max_keylen: int = 12) -> Tuple[str,str,int]:
    # Greedy: choose keyword length L from 1..max, then choose each key letter to best match English on the fly.
    s_idx = to_indices(cipher)
    best_plain, best_key, best_score = "", "", float('inf')
    for L in range(1, max_keylen+1):
        key_vals = []
        # For positions j in [0, L-1], plaintext depends only on key[j] (no recovered plaintext yet)
        for j in range(L):
            # Consider every 26 possibilities for key[j]; evaluate based on every L-th letter starting at j
            best_kj, best_col_score = 0, float('inf')
            col = s_idx[j::L]
            for k in range(26):
                # decrypt those positions as if using only keyword (autokey hasn't started yet for those slots)
                pt_col = [ (c - k) % 26 for c in col ]
                sc = chi_squared_score(from_indices(pt_col))
                if sc < best_col_score:
                    best_col_score, best_kj = sc, k
            key_vals.append(best_kj)
        key = from_indices(key_vals)
        # Now decrypt fully using autokey and evaluate
        pt = autokey_decrypt(cipher, key)
        sc_full = chi_squared_score(pt)
        if sc_full < best_score:
            best_plain, best_key, best_score = pt, key, sc_full
    return best_plain, best_key, len(best_key)

# -------------------------------------------------------------
# Playfair heuristic attack (hill-climbing over key square)
# -------------------------------------------------------------
def build_playfair_square_from_key(key: str) -> List[str]:
    # Returns 25-char string (I/J merged as I)
    key = key.upper()
    seen = set()
    seq = []
    for ch in key:
        if ch == 'J': ch = 'I'
        if ch in ALPHABET and ch != 'J' and ch not in seen:
            seen.add(ch); seq.append(ch)
    for ch in ALPHABET:
        if ch == 'J': continue
        if ch not in seen:
            seen.add(ch); seq.append(ch)
    return ''.join(seq)

def playfair_prepare_pairs(text: str) -> List[Tuple[int,int]]:
    s = []
    for ch in text.upper():
        if ch in ALPHABET:
            s.append('I' if ch == 'J' else ch)
    # create digraphs with X padding rule
    pairs = []
    i = 0
    while i < len(s):
        a = s[i]
        b = s[i+1] if i+1 < len(s) else 'X'
        if a == b:
            pairs.append((IDX[a], IDX['X']))
            i += 1
        else:
            pairs.append((IDX[a], IDX[b]))
            i += 2
    if len(pairs) and len(pairs[-1]) != 2:
        pairs[-1] = (pairs[-1][0], IDX['X'])
    return pairs

def playfair_encrypt_with_square_pairs(pairs: List[Tuple[int,int]], square25: str, decrypt=False) -> str:
    # square25 is 25-length string; map char -> (r,c) on 5x5 with I/J merged
    pos = {}
    for i,ch in enumerate(square25):
        pos[ch] = (i//5, i%5)
    inv = [['']*5 for _ in range(5)]
    for ch,(r,c) in pos.items():
        inv[r][c] = ch
    out = []
    for a,b in pairs:
        ca = 'I' if ALPHABET[a]=='J' else ALPHABET[a]
        cb = 'I' if ALPHABET[b]=='J' else ALPHABET[b]
        r1,c1 = pos[ca]
        r2,c2 = pos[cb]
        if r1 == r2:
            if decrypt:
                out.append(inv[r1][(c1-1)%5])
                out.append(inv[r2][(c2-1)%5])
            else:
                out.append(inv[r1][(c1+1)%5])
                out.append(inv[r2][(c2+1)%5])
        elif c1 == c2:
            if decrypt:
                out.append(inv[(r1-1)%5][c1])
                out.append(inv[(r2-1)%5][c2])
            else:
                out.append(inv[(r1+1)%5][c1])
                out.append(inv[(r2+1)%5][c2])
        else:
            out.append(inv[r1][c2])
            out.append(inv[r2][c1])
    return ''.join(out)

def playfair_attack(cipher: str, iters: int = 4000, restarts: int = 10) -> Tuple[str, str, float]:
    pairs = playfair_prepare_pairs(cipher)
    best_score, best_sq = -1e9, None
    # random restarts with hill-climbing
    base_key = "KEYWORD"  # seed bias; not required
    for _ in range(restarts):
        sq = list(build_playfair_square_from_key(base_key))
        random.shuffle(sq)
        sq = ''.join(sq)
        curr_sq = sq
        curr_txt = playfair_encrypt_with_square_pairs(pairs, curr_sq, decrypt=True)
        curr_score = tetragram_score(curr_txt)
        improved = True
        steps = 0
        while improved and steps < iters:
            improved = False
            steps += 1
            a, b = random.sample(range(25), 2)
            cand = list(curr_sq)
            cand[a], cand[b] = cand[b], cand[a]
            cand = ''.join(cand)
            txt = playfair_encrypt_with_square_pairs(pairs, cand, decrypt=True)
            sc = tetragram_score(txt)
            if sc > curr_score:
                curr_sq, curr_score = cand, sc
                improved = True
        if curr_score > best_score:
            best_score, best_sq = curr_score, curr_sq
    plaintext = playfair_encrypt_with_square_pairs(pairs, best_sq, decrypt=True)
    return plaintext, best_sq, best_score

# -------------------------------------------------------------
# Hill cipher known-plaintext attack
# -------------------------------------------------------------
def mat_mod_inv(a: int, mod: int) -> int:
    a %= mod
    if a == 0:
        raise ValueError("No inverse")
    lm, hm = 1, 0
    low, high = a, mod
    while low > 1:
        r = high // low
        nm = hm - lm * r
        new = high - low * r
        hm, lm = lm, nm
        high, low = low, new
    return lm % mod

def mat_det_mod(A: List[List[int]], mod: int) -> int:
    # small n; use recursive expansion
    n = len(A)
    if n == 1: return A[0][0] % mod
    if n == 2: return (A[0][0]*A[1][1] - A[0][1]*A[1][0]) % mod
    det = 0
    for c in range(n):
        sign = -1 if (c % 2) else 1
        minor = [row[:c] + row[c+1:] for row in A[1:]]
        det = (det + sign * A[0][c] * mat_det_mod(minor, mod)) % mod
    return det % mod

def mat_cofactor(A: List[List[int]], mod: int) -> List[List[int]]:
    n = len(A)
    C = [[0]*n for _ in range(n)]
    for r in range(n):
        for c in range(n):
            minor = [row[:c] + row[c+1:] for i,row in enumerate(A) if i != r]
            sign = -1 if ((r+c) % 2) else 1
            C[r][c] = (sign * mat_det_mod(minor, mod)) % mod
    return C

def mat_transpose(A: List[List[int]]) -> List[List[int]]:
    return [list(row) for row in zip(*A)]

def mat_inv_mod(A: List[List[int]], mod: int) -> List[List[int]]:
    det = mat_det_mod(A, mod)
    if math.gcd(det, mod) != 1:
        raise ValueError("Matrix not invertible mod {}".format(mod))
    det_inv = mat_mod_inv(det, mod)
    C = mat_cofactor(A, mod)
    Adj = mat_transpose(C)
    n = len(A)
    return [[(det_inv * Adj[i][j]) % mod for j in range(n)] for i in range(n)]

def mat_mul(A: List[List[int]], B: List[List[int]], mod: int) -> List[List[int]]:
    n = len(A); m = len(B[0]); k = len(B)
    out = [[0]*m for _ in range(n)]
    for i in range(n):
        for j in range(m):
            out[i][j] = sum(A[i][t]*B[t][j] for t in range(k)) % mod
    return out

def blocks_to_matrix(blocks: List[List[int]]) -> List[List[int]]:
    # Build square matrix from list of blocks (each length n), stacked as columns
    n = len(blocks[0])
    if len(blocks) < n:
        raise ValueError("Need at least n plaintext/ciphertext blocks for known-plaintext attack")
    # Use first n blocks
    B = [[blocks[col][row] for col in range(n)] for row in range(n)]
    return B

def hill_recover_key_from_known_plain(plain: str, cipher: str, n: int) -> List[List[int]]:
    p = to_indices(plain)
    c = to_indices(cipher)
    if len(p) < n*n or len(c) < n*n:
        raise ValueError("Need at least {} letters ({} blocks) of known plaintext and ciphertext".format(n*n, n))
    # form first n blocks
    p_blocks = [p[i*n:(i+1)*n] for i in range(n)]
    c_blocks = [c[i*n:(i+1)*n] for i in range(n)]
    P = blocks_to_matrix(p_blocks)  # n x n
    C = blocks_to_matrix(c_blocks)  # n x n
    P_inv = mat_inv_mod(P, 26)
    K = mat_mul(C, P_inv, 26)  # K = C * P^{-1}
    return K

def hill_decrypt_with_key(cipher: str, K: List[List[int]]) -> str:
    K_inv = mat_inv_mod(K, 26)
    idx = to_indices(cipher)
    n = len(K)
    if len(idx) % n != 0:
        idx = idx + [IDX['X']] * ((n - (len(idx)%n)) % n)
    out = []
    for i in range(0, len(idx), n):
        vec = [[idx[i+j]] for j in range(n)]
        res = mat_mul(K_inv, vec, 26)
        out.extend([res[j][0] for j in range(n)])
    return from_indices(out)

# -------------------------------------------------------------
# CLI
# -------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="week01_poly_attack.py — Cryptanalysis for polyalphabetic & matrix ciphers")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Vigenere
    p_v = sub.add_parser("vigenere", help="Ciphertext-only attack (Kasiski + Friedman + per-column frequency)")
    p_v.add_argument("ciphertext", help="Ciphertext")

    # Beaufort
    p_b = sub.add_parser("beaufort", help="Ciphertext-only attack analogous to Vigenere")
    p_b.add_argument("ciphertext", help="Ciphertext")

    # Autokey
    p_a = sub.add_parser("autokey", help="Heuristic greedy ciphertext-only attack for Autokey")
    p_a.add_argument("ciphertext", help="Ciphertext")
    p_a.add_argument("--maxlen", type=int, default=12, help="Max keyword length to try (default: 12)")

    # Playfair
    p_pf = sub.add_parser("playfair", help="Heuristic attack with hill-climbing (tetragram scoring)")
    p_pf.add_argument("ciphertext", help="Ciphertext")
    p_pf.add_argument("--iters", type=int, default=4000, help="Max steps per restart")
    p_pf.add_argument("--restarts", type=int, default=12, help="Random restarts")

    # Hill known-plaintext
    p_h = sub.add_parser("hill_known", help="Known-plaintext attack to recover Hill key (then decrypt)")
    p_h.add_argument("plaintext_known", help="Known plaintext (at least n*n letters)")
    p_h.add_argument("ciphertext_known", help="Corresponding ciphertext")
    p_h.add_argument("ciphertext_full", help="Ciphertext to decrypt (can be longer)")
    p_h.add_argument("--n", type=int, required=True, help="Hill block size (e.g., 2 or 3)")

    args = parser.parse_args()

    if args.cmd == "vigenere":
        ct = args.ciphertext
        pt, key, L = vigenere_attack(ct)
        print("=== Vigenere Attack ===")
        print(f"Estimated key length: {L}")
        print(f"Recovered key: {key}")
        print("Decryption:")
        print(pt)

    elif args.cmd == "beaufort":
        ct = args.ciphertext
        pt, key, L = beaufort_attack(ct)
        print("=== Beaufort Attack ===")
        print(f"Estimated key length: {L}")
        print(f"Recovered key: {key}")
        print("Decryption:")
        print(pt)

    elif args.cmd == "autokey":
        ct = args.ciphertext
        pt, key, L = autokey_attack_greedy(ct, max_keylen=args.maxlen)
        print("=== Autokey Heuristic Attack ===")
        print(f"Estimated key length: {L}")
        print(f"Recovered keyword (heuristic): {key}")
        print("Decryption:")
        print(pt)

    elif args.cmd == "playfair":
        ct = args.ciphertext
        pt, sq, score = playfair_attack(ct, iters=args.iters, restarts=args.restarts)
        print("=== Playfair Heuristic Attack ===")
        print(f"Recovered key square (I/J merged): {sq}")
        print(f"Score: {score:.2f}")
        print("Decryption:")
        print(pt)

    elif args.cmd == "hill_known":
        n = args.n
        K = hill_recover_key_from_known_plain(args.plaintext_known, args.ciphertext_known, n)
        print("=== Hill Known-Plaintext Attack ===")
        print("Recovered key matrix:")
        for row in K:
            print(' '.join(f"{x:2d}" for x in row))
        print("\nDecryption:")
        print(hill_decrypt_with_key(args.ciphertext_full, K))

if __name__ == "__main__":
    main()
