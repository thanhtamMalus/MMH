# Vigenère ciphertext-only attack
python week01_poly_attack.py vigenere "LXFOPVEFRNHR"

# Beaufort ciphertext-only attack
python week01_poly_attack.py beaufort "ZJQSUQ..." 

# Autokey heuristic (try up to 12-letter keyword)
python week01_poly_attack.py autokey "RTKFFK..." --maxlen 12

# Playfair heuristic (increase restarts/iters for tougher texts)
python week01_poly_attack.py playfair "BMNDZBXDKYBEJVDMUIX" --iters 5000 --restarts 20

# Hill known-plaintext (e.g., 2x2 key)
python week01_poly_attack.py hill_known "HELP" "HIAT" "FULLCIPHERTEXT..." --n 2
