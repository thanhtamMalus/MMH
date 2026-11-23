# Rail Fence (unknown rails) — try up to 20 rails, show top 5
python week01_permute_attack.py railfence "CIPHERTEXT..." --max-rails 20 --top 5

# Scytale (unknown diameter) — try up to 60, show top 5
python week01_permute_attack.py scytale "CIPHERTEXT..." --max-diameter 60 --top 5

# Columnar (unknown columns/permutation)
# Try 3..12 columns: exhaustive ≤ 9 cols, else hill-climb; show top 3
python week01_permute_attack.py columnar "CIPHERTEXT..." --min-cols 3 --max-cols 12 --top 3

# Tuning examples
python week01_permute_attack.py columnar "CIPHERTEXT..." --min-cols 7 --max-cols 10 --exhaustive-limit 8
python week01_permute_attack.py columnar "CIPHERTEXT..." --max-cols 14 --restarts 40 --iters 8000
