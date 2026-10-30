import string
import random

def print_homophonic_mapping_table(key):
    """
    Displays the Homophonic cipher key mapping in a two-line table:
    
     A  B  C  D  ...  Z
     --+--+--+--+ ... 
     Q/W/E  R/T  Y/U  I/O  ...  :/;
    """
    plain_letters = list(string.ascii_uppercase)
    mapping_strs = []
    for letter in plain_letters:
        symbols = key.get(letter, [])
        # Join multiple symbols with a "/" separator
        mapping_str = "/".join(symbols)
        mapping_strs.append(mapping_str)
    
    # Determine a column width based on the longest mapping string (at least 2 characters)
    col_width = max(2, max(len(s) for s in mapping_strs))
    
    # Build the first row: plain letters
    row1 = " ".join(f"{letter:^{col_width}}" for letter in plain_letters)
    # Build the border row: a series of dashes separated by plus signs
    row2 = " " + "+".join(["-" * col_width for _ in plain_letters]) + " "
    # Build the third row: corresponding cipher symbols for each plaintext letter
    row3 = " ".join(f"{mapping_strs[i]:^{col_width}}" for i in range(len(plain_letters)))
    
    print(row1)
    print(row2)
    print(row3)

def homophonic_encrypt(text, key):
    """
    Encrypts the input text using the Homophonic Substitution Cipher.
    For each letter, one cipher symbol is chosen at random from its list.
    Non-alphabet characters are left unchanged.
    """
    result = []
    for char in text:
        if char.isalpha():
            # Use uppercase for key lookup, then adjust case as needed.
            possibilities = key.get(char.upper(), [char.upper()])
            chosen = random.choice(possibilities)
            result.append(chosen if char.isupper() else chosen.lower())
        else:
            result.append(char)
    return ''.join(result)

def build_homophonic_reverse_mapping(key):
    """
    Builds and returns the reverse mapping for decryption.
    Each cipher symbol (as defined in the key) maps to its plaintext letter.
    """
    reverse = {}
    for plain, symbols in key.items():
        for symbol in symbols:
            reverse[symbol.upper()] = plain  # store keys as uppercase
    return reverse

def homophonic_decrypt(text, key):
    """
    Decrypts the ciphertext using the reverse mapping.
    For each character in the text, it converts the character to uppercase
    and looks up the corresponding plaintext letter. The case is preserved.
    """
    reverse = build_homophonic_reverse_mapping(key)
    result = []
    for char in text:
        symbol = char.upper()
        if symbol in reverse:
            plain_letter = reverse[symbol]
            result.append(plain_letter if char.isupper() else plain_letter.lower())
        else:
            result.append(char)
    return ''.join(result)

def main():
    # Sample homophonic key mapping.
    # Each plaintext letter maps to a list of possible one-character cipher symbols.
    homophonic_key = {
        'A': ['Q', 'W', 'E'],
        'B': ['R', 'T'],
        'C': ['Y', 'U'],
        'D': ['I', 'O'],
        'E': ['P', 'A', 'S', 'D'],
        'F': ['F', 'G'],
        'G': ['H', 'J'],
        'H': ['K', 'L'],
        'I': ['Z', 'X'],
        'J': ['C', 'V'],
        'K': ['B', 'N'],
        'L': ['M', '1'],
        'M': ['2', '3'],
        'N': ['4', '5'],
        'O': ['6', '7', '8'],
        'P': ['9', '0'],
        'Q': ['!', '@'],
        'R': ['#', '$'],
        'S': ['%', '^', '&'],
        'T': ['*', '('],
        'U': [')', '-'],
        'V': ['_', '+'],
        'W': ['=', '{'],
        'X': ['}', '['],
        'Y': [']', '|'],
        'Z': [':', ';']
    }
    
    print("Homophonic Substitution Cipher Key Mapping:")
    print_homophonic_mapping_table(homophonic_key)
    
    plaintext = input("\nEnter the text to encrypt: ")
    encrypted_text = homophonic_encrypt(plaintext, homophonic_key)
    print("\nEncrypted text:")
    print(encrypted_text)
    
    input("\nPress Enter to continue to decryption...")
    
    decrypted_text = homophonic_decrypt(encrypted_text, homophonic_key)
    print("\nDecrypted text:")
    print(decrypted_text)

if __name__ == "__main__":
    main()
