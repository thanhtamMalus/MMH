import string

def generate_unknown_keyword_mapping(length):
    """
    Generates a candidate mapping for a Keyword Cipher when the keyword is unknown.
    We assume that the unknown keyword accounts for the first 'length' positions in the cipher alphabet.
    For these positions, the cipher letter is unknown (represented by '-').
    For the remaining positions, we assume an identity mapping.
    """
    mapping = {}
    alphabets = string.ascii_uppercase
    for i, letter in enumerate(alphabets):
        if i < length:
            mapping[letter] = '-'  # unknown mapping for the first 'length' letters
        else:
            mapping[letter] = alphabets[i]
    return mapping

def print_unknown_keyword_mapping_table(length):
    """
    Displays a two-line table for the candidate mapping:
      - Top row: Plain letters (A–Z)
      - Bottom row: Candidate cipher letters (first 'length' positions are '-' placeholders,
        the rest are identity)
    """
    mapping = generate_unknown_keyword_mapping(length)
    alphabets = string.ascii_uppercase
    plain_row = " " + " ".join(letter for letter in alphabets) + " "
    # A simple border (optional)
    border = " " + "+".join(["-" for _ in alphabets]) + " "
    cipher_row = " " + " ".join(mapping[letter] for letter in alphabets) + " "
    print(plain_row)
    print(border)
    print(cipher_row)

def keyword_decrypt_unknown(ciphertext, length):
    """
    "Decrypts" the ciphertext using the candidate mapping for an unknown keyword of the given length.
    (Letters that should be decrypted using the unknown keyword part will become '-'.)
    """
    mapping = generate_unknown_keyword_mapping(length)
    # Build a reverse mapping.
    # Note: Since many plain letters map to '-' when length > 0, any ciphertext letter 
    # that does not match a known cipher letter will be left as '-' in the decryption.
    reverse_mapping = {}
    # For positions with a known mapping, invert it.
    for plain, cipher in mapping.items():
        if cipher != '-':
            reverse_mapping[cipher] = plain
    result = []
    for char in ciphertext:
        # Only process alphabetic characters.
        if char.upper() in reverse_mapping:
            dec = reverse_mapping[char.upper()]
            result.append(dec if char.isupper() else dec.lower())
        elif char.upper() in mapping and mapping[char.upper()] == '-':
            # This letter falls in the unknown portion.
            result.append('-')
        else:
            result.append(char)
    return ''.join(result)

def cryptanalysis_unknown_keyword_length(ciphertext):
    """
    Tries candidate keyword lengths from 0 to 25.
    For each length, it displays:
      - The candidate keyword length (shown as a line of '-' of that length)
      - The mapping table (plain letters and candidate cipher letters)
      - The "decrypted" text using the candidate mapping
    The program pauses after each candidate so you can review the output.
    """
    print("\nTrying candidate keyword lengths (unknown keyword shown as '-' placeholders):\n")
    for length in range(26):
        print(f"\nCandidate keyword length: {length}  (Keyword: {'-' * length})")
        print_unknown_keyword_mapping_table(length)
        decrypted_text = keyword_decrypt_unknown(ciphertext, length)
        print(f"Decrypted text: {decrypted_text}")
        print("-" * 40)
        input("Press Enter to try the next candidate length...")

def main():
    ciphertext = input("Enter the ciphertext for cryptanalysis: ")
    cryptanalysis_unknown_keyword_length(ciphertext)

if __name__ == "__main__":
    main()
