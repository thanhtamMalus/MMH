#!/usr/bin/env python3
"""
week01_permute_attack.py
Cryptanalysis CLI for permutation/transposition ciphers:
- Rail Fence (rails unknown): brute-force rails sweep + n-gram scoring
- Scytale (diameter unknown): brute-force diameter sweep + n-gram scoring
- Columnar transposition (keyword order unknown):
    * exhaustive permutation search for small column counts
    * hill-climbing with restarts for larger column counts
Scoring: tetragram log-probability with fallback; chi-squared and bigram optional.

Author: Session 2 – Cryptanalysis track
"""

import argparse
import math
import random
import string
from collections import Counter
from typing import List, Tuple

ALPHABET = string.ascii_uppercase
IDX = {ch:i for i,ch in enumerate(ALPHABET)}

# ------------------------------------------------------------------
# Text utilities
# ------------------------------------------------------------------
def clean(s: str) -> str:
    return ''.join(ch for ch in s.upper() if ch in ALPHABET)

def chunk(s: str, n: int) -> List[str]:
    return [s[i:i+n] for i in range(0, len(s), n)]

# ------------------------------------------------------------------
# N-gram scoring (compact tetragram table; good enough for class demos)
# ------------------------------------------------------------------
TETRA = {
    "TION": -2.7, "NTHE": -2.9, "THER": -3.0, "ETHE": -3.1, "THAT": -3.2,
    "OFTH": -3.2, "THIS": -3.3, "TING": -3.3, "THEM": -3.4, "HERE": -3.4,
    "ATIO": -3.4, "THEI": -3.5, "WITH": -3.5, "MENT": -3.5, "IONS": -3.5,
}
TETRA_FALLBACK = -6.0

def tetragram_score(text: str) -> float:
    s = clean(text)
    if len(s) < 4:
        return TETRA_FALLBACK * 2
    sc = 0.0
    for i in range(len(s)-3):
        sc += TETRA.get(s[i:i+4], TETRA_FALLBACK)
    return sc

def chi2_score(text: str) -> float:
    EN_FREQ = {
        'E':12.70,'T':9.06,'A':8.17,'O':7.51,'I':6.97,'N':6.75,'S':6.33,'H':6.09,'R':5.99,
        'D':4.25,'L':4.03,'C':2.78,'U':2.76,'M':2.41,'W':2.36,'F':2.23,'G':2.02,'Y':1.97,
        'P':1.93,'B':1.49,'V':0.98,'K':0.77,'J':0.15,'X':0.15,'Q':0.10,'Z':0.07
    }
    s = clean(text)
    N = len(s)
    if N == 0: return float('inf')
    counts = Counter(s)
    chi = 0.0
    for ch, pct in EN_FREQ.items():
        expected = pct * N / 100.0
        observed = counts.get(ch, 0)
        chi += (observed - expected)**2 / (expected + 1e-9)
    return chi

# ------------------------------------------------------------------
# Rail Fence (attack by rails sweep)
# ------------------------------------------------------------------
def rail_fence_decrypt(cipher: str, rails: int) -> str:
    cipher = clean(cipher)
    if rails < 2 or rails >= len(cipher):
        return cipher
    # Build zigzag indices
    pattern = list(range(rails)) + list(range(rails-2, 0, -1))
    pat_len = len(pattern)
    n = len(cipher)
    indices = [pattern[i % pat_len] for i in range(n)]
    # Count letters per rail
    rail_counts = [indices.count(r) for r in range(rails)]
    # Split cipher into rails
    pos = 0
    rail_strs = []
    for count in rail_counts:
        rail_strs.append(list(cipher[pos:pos+count]))
        pos += count
    # Reconstruct by walking indices
    result = []
    rail_pos = [0]*rails
    for r in indices:
        result.append(rail_strs[r][rail_pos[r]])
        rail_pos[r] += 1
    return ''.join(result)

def attack_railfence(cipher: str, max_rails: int = 20, top: int = 5):
    cipher = clean(cipher)
    n = len(cipher)
    max_rails = min(max_rails, max(2, n-1))
    cands = []
    for r in range(2, max_rails+1):
        pt = rail_fence_decrypt(cipher, r)
        sc = tetragram_score(pt)
        cands.append((sc, r, pt))
    cands.sort(reverse=True, key=lambda t: t[0])
    return cands[:top]

# ------------------------------------------------------------------
# Scytale (attack by diameter sweep)
# ------------------------------------------------------------------
def scytale_decrypt(cipher: str, diameter: int) -> str:
    cipher = clean(cipher)
    if diameter < 2: return cipher
    nrows = math.ceil(len(cipher) / diameter)
    grid = [[None]*diameter for _ in range(nrows)]
    pos = 0
    for c in range(diameter):
        for r in range(nrows):
            if pos < len(cipher):
                grid[r][c] = cipher[pos]
                pos += 1
    out = []
    for r in range(nrows):
        for c in range(diameter):
            if grid[r][c]:
                out.append(grid[r][c])
    return ''.join(out).rstrip('X')

def attack_scytale(cipher: str, max_diameter: int = 60, top: int = 5):
    cipher = clean(cipher)
    n = len(cipher)
    max_diameter = max(2, min(max_diameter, n-1))
    cands = []
    for d in range(2, max_diameter+1):
        pt = scytale_decrypt(cipher, d)
        sc = tetragram_score(pt)
        cands.append((sc, d, pt))
    cands.sort(reverse=True, key=lambda t: t[0])
    return cands[:top]

# ------------------------------------------------------------------
# Columnar transposition
# We do decryption given a column order (permutation of 0..ncols-1)
# ------------------------------------------------------------------
def columnar_decrypt_with_order(cipher: str, order: List[int]) -> str:
    cipher = clean(cipher)
    ncols = len(order)
    nrows = math.ceil(len(cipher) / ncols)
    matrix = [[None]*ncols for _ in range(nrows)]
    pos = 0
    for c in order:
        for r in range(nrows):
            if pos < len(cipher):
                matrix[r][c] = cipher[pos]
                pos += 1
    out = ''.join(matrix[r][c] or '' for r in range(nrows) for c in range(ncols))
    return out.rstrip('X')

def _perm_score(cipher: str, order: List[int]) -> float:
    pt = columnar_decrypt_with_order(cipher, order)
    return tetragram_score(pt)

def _random_perm(n: int) -> List[int]:
    arr = list(range(n))
    random.shuffle(arr)
    return arr

def attack_columnar_exhaustive(cipher: str, ncols: int, top: int = 5):
    """Exhaustive permutation search; suitable for ncols <= 9."""
    from itertools import permutations
    cands = []
    for order in permutations(range(ncols)):
        sc = _perm_score(cipher, list(order))
        cands.append((sc, list(order)))
    cands.sort(reverse=True, key=lambda t: t[0])
    results = []
    for sc, order in cands[:top]:
        pt = columnar_decrypt_with_order(cipher, order)
        results.append((sc, order, pt))
    return results

def attack_columnar_hill(cipher: str, ncols: int, restarts: int = 20, iters: int = 4000, temp: float = 1.5, cooling: float = 0.999):
    """Hill-climbing with simulated annealing over column permutations."""
    best_sc, best_order = -1e18, None
    for _ in range(restarts):
        curr = _random_perm(ncols)
        curr_sc = _perm_score(cipher, curr)
        T = temp
        for _ in range(iters):
            a, b = random.sample(range(ncols), 2)
            cand = curr[:]
            cand[a], cand[b] = cand[b], cand[a]
            cand_sc = _perm_score(cipher, cand)
            if cand_sc > curr_sc or random.random() < math.exp((cand_sc - curr_sc) / max(1e-6, T)):
                curr, curr_sc = cand, cand_sc
            T *= cooling
        if curr_sc > best_sc:
            best_sc, best_order = curr_sc, curr
    pt = columnar_decrypt_with_order(cipher, best_order)
    return best_sc, best_order, pt

def attack_columnar(cipher: str, min_cols: int = 3, max_cols: int = 12, top: int = 3, exhaustive_limit: int = 9, restarts: int = 30, iters: int = 6000):
    """Try a range of column counts and pick best candidates."""
    results = []
    for ncols in range(min_cols, max_cols+1):
        if ncols <= exhaustive_limit:
            cands = attack_columnar_exhaustive(cipher, ncols, top=top)
            for sc, order, pt in cands:
                results.append((sc, ncols, order, pt))
        else:
            sc, order, pt = attack_columnar_hill(cipher, ncols, restarts=restarts, iters=iters)
            results.append((sc, ncols, order, pt))
    results.sort(reverse=True, key=lambda t: t[0])
    return results[:top]

# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="week01_permute_attack.py — Cryptanalysis for permutation/transposition ciphers")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Rail Fence
    p_rf = sub.add_parser("railfence", help="Brute-force rails sweep with n-gram scoring")
    p_rf.add_argument("ciphertext")
    p_rf.add_argument("--max-rails", type=int, default=20)
    p_rf.add_argument("--top", type=int, default=5)

    # Scytale
    p_sc = sub.add_parser("scytale", help="Brute-force diameter sweep with n-gram scoring")
    p_sc.add_argument("ciphertext")
    p_sc.add_argument("--max-diameter", type=int, default=60)
    p_sc.add_argument("--top", type=int, default=5)

    # Columnar
    p_col = sub.add_parser("columnar", help="Attack columnar transposition (unknown key permutation)")
    p_col.add_argument("ciphertext")
    p_col.add_argument("--min-cols", type=int, default=3)
    p_col.add_argument("--max-cols", type=int, default=12)
    p_col.add_argument("--top", type=int, default=3, help="Top overall results to print")
    p_col.add_argument("--exhaustive-limit", type=int, default=9, help="Use exhaustive search up to this #columns, else hill-climb")
    p_col.add_argument("--restarts", type=int, default=30)
    p_col.add_argument("--iters", type=int, default=6000)

    args = parser.parse_args()

    if args.cmd == "railfence":
        cands = attack_railfence(args.ciphertext, max_rails=args.max_rails, top=args.top)
        print("=== Rail Fence — top candidates ===")
        for sc, r, pt in cands:
            print(f"[rails={r}][score={sc:.2f}] {pt}")

    elif args.cmd == "scytale":
        cands = attack_scytale(args.ciphertext, max_diameter=args.max_diameter, top=args.top)
        print("=== Scytale — top candidates ===")
        for sc, d, pt in cands:
            print(f"[diameter={d}][score={sc:.2f}] {pt}")

    elif args.cmd == "columnar":
        cands = attack_columnar(args.ciphertext, min_cols=args.min_cols, max_cols=args.max_cols,
                                top=args.top, exhaustive_limit=args.exhaustive_limit,
                                restarts=args.restarts, iters=args.iters)
        print("=== Columnar — top candidates ===")
        for sc, ncols, order, pt in cands:
            order_str = ' '.join(map(str, order))
            print(f"[cols={ncols}][score={sc:.2f}][order={order_str}] {pt}")


if __name__ == "__main__":
    main()
