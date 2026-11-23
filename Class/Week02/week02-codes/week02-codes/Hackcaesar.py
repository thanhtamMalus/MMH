import string

def generate_mapping(key):
    """
    Generates a dictionary mapping for uppercase letters based on the Caesar cipher key.
    """
    key = key % 26  # ensure the key is within 0-25
    alphabets = string.ascii_uppercase
    mapping = {alphabet: alphabets[(i + key) % 26] for i, alphabet in enumerate(alphabets)}
    return mapping

def print_mapping_table(key):
    """
    Prints the Caesar cipher mapping in a two-row table:
    First row displays the plain letters, and the second row displays the corresponding cipher letters.
    """
    mapping = generate_mapping(key)
    alphabets = string.ascii_uppercase
    col_width = 2  # width for each column for clarity

    # Build the border line
    border = " " + "+".join(["-" * col_width] * len(alphabets)) + " "

    # Build the row for plain letters
    plain_row = " " + " ".join(letter.center(col_width) for letter in alphabets) + " "
    # Build the row for cipher letters
    cipher_row = " " + " ".join(mapping[letter].center(col_width) for letter in alphabets) + " "

    #print(border)
    print(plain_row)
    print(border)
    print(cipher_row)
   #print(border)

def caesar_encrypt(text, key):
    """
    Encrypts the input text using the Caesar cipher with the given key.
    Handles both uppercase and lowercase letters.
    Non-alphabet characters remain unchanged.
    """
    key = key % 26
    result = []
    for char in text:
        if char.isupper():
            result.append(chr((ord(char) - ord('A') + key) % 26 + ord('A')))
        elif char.islower():
            result.append(chr((ord(char) - ord('a') + key) % 26 + ord('a')))
        else:
            result.append(char)
    return ''.join(result)

def caesar_decrypt(text, key):
    """
    Decrypts the input text using the Caesar cipher with the given key.
    """
    # Reuse encryption with the negative key for decryption.
    return caesar_encrypt(text, -key)

def cryptanalysis_caesar(ciphertext):
    """
    Attempts to decrypt the ciphertext by trying all 26 possible keys.
    For each candidate key, it prints the guessed key (including the shift number),
    the key mapping table (plain letters to cipher letters), and the resulting decryption.
    Then it waits for the user to press Enter before continuing.
    """
    print("\nStarting cryptanalysis on the ciphertext...\n")
    for key in range(26):
        guessed_text = caesar_decrypt(ciphertext, key)
        print(f"\nCandidate key (Shift {key}):")
        print_mapping_table(key)
        print(f"Decrypted text: {guessed_text}")
        print("-" * 40)
        input("Press Enter to try the next candidate key...")

def main():
    ciphertext = input("Enter the ciphertext for cryptanalysis: ")
    cryptanalysis_caesar(ciphertext)

if __name__ == "__main__":
    main()
