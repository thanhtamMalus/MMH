import argparse
import math

# --- 1. Rail Fence Cipher ---
def rail_fence_encrypt(text: str, rails: int) -> str:
    text = text.replace(" ", "").upper()
    fence = [[] for _ in range(rails)]
    rail = 0
    var = 1
    for ch in text:
        fence[rail].append(ch)
        rail += var
        if rail == 0 or rail == rails - 1:
            var = -var
    return ''.join(''.join(row) for row in fence)

def rail_fence_decrypt(cipher: str, rails: int) -> str:
    cipher = cipher.upper()
    # Build zigzag pattern indices
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
    # Reconstruct
    result = []
    rail_positions = [0]*rails
    for r in indices:
        result.append(rail_strs[r][rail_positions[r]])
        rail_positions[r] += 1
    return ''.join(result)

# --- 2. Columnar Transposition Cipher ---
def columnar_encrypt(text: str, key: str) -> str:
    text = text.replace(" ", "").upper()
    key = key.upper()
    ncols = len(key)
    nrows = math.ceil(len(text) / ncols)
    # pad with X
    padded = text.ljust(nrows*ncols, 'X')
    # build matrix
    matrix = [list(padded[i*ncols:(i+1)*ncols]) for i in range(nrows)]
    # order columns by key
    order = sorted(range(len(key)), key=lambda i: key[i])
    out = []
    for c in order:
        for r in range(nrows):
            out.append(matrix[r][c])
    return ''.join(out)

def columnar_decrypt(cipher: str, key: str) -> str:
    key = key.upper()
    ncols = len(key)
    nrows = math.ceil(len(cipher) / ncols)
    order = sorted(range(len(key)), key=lambda i: key[i])
    # allocate matrix
    matrix = [[None]*ncols for _ in range(nrows)]
    pos = 0
    for c in order:
        for r in range(nrows):
            if pos < len(cipher):
                matrix[r][c] = cipher[pos]
                pos += 1
    # read row-wise
    out = ''.join(matrix[r][c] for r in range(nrows) for c in range(ncols))
    return out.rstrip('X')

# --- 3. Scytale Cipher (simple shift by diameter) ---
def scytale_encrypt(text: str, diameter: int) -> str:
    text = text.replace(" ", "").upper()
    nrows = math.ceil(len(text) / diameter)
    padded = text.ljust(nrows*diameter, 'X')
    out = []
    for c in range(diameter):
        for r in range(nrows):
            out.append(padded[r*diameter + c])
    return ''.join(out)

def scytale_decrypt(cipher: str, diameter: int) -> str:
    nrows = math.ceil(len(cipher) / diameter)
    out = []
    pos = 0
    grid = [[None]*diameter for _ in range(nrows)]
    for c in range(diameter):
        for r in range(nrows):
            if pos < len(cipher):
                grid[r][c] = cipher[pos]
                pos += 1
    for r in range(nrows):
        for c in range(diameter):
            if grid[r][c]:
                out.append(grid[r][c])
    return ''.join(out).rstrip('X')

# --- CLI Parser ---
def main():
    parser = argparse.ArgumentParser(description="Transposition Ciphers CLI Tool")
    parser.add_argument("cipher", choices=["railfence", "columnar", "scytale"], help="Cipher to use")
    parser.add_argument("text", help="Input text")
    parser.add_argument("--rails", type=int, help="Number of rails (Rail Fence)")
    parser.add_argument("--key", type=str, help="Keyword (Columnar)")
    parser.add_argument("--diameter", type=int, help="Diameter (Scytale)")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt instead of encrypt")

    args = parser.parse_args()

    if args.cipher == "railfence":
        if not args.rails:
            raise ValueError("Please provide --rails for Rail Fence")
        if args.decrypt:
            print(rail_fence_decrypt(args.text, args.rails))
        else:
            print(rail_fence_encrypt(args.text, args.rails))

    elif args.cipher == "columnar":
        if not args.key:
            raise ValueError("Please provide --key for Columnar")
        if args.decrypt:
            print(columnar_decrypt(args.text, args.key))
        else:
            print(columnar_encrypt(args.text, args.key))

    elif args.cipher == "scytale":
        if not args.diameter:
            raise ValueError("Please provide --diameter for Scytale")
        if args.decrypt:
            print(scytale_decrypt(args.text, args.diameter))
        else:
            print(scytale_encrypt(args.text, args.diameter))

if __name__ == "__main__":
    main()
