import string

def atbash_mapping():
    """
    Generates a dictionary mapping for the Atbash cipher for uppercase letters.
    Each letter is mapped to its reverse (A↔Z, B↔Y, etc.).
    """
    plain = string.ascii_uppercase
    cipher = plain[::-1]
    mapping = {plain[i]: cipher[i] for i in range(len(plain))}
    return mapping

def print_mapping_table():
    """
    Prints the Atbash cipher mapping in a two-line table:
      - First row: Plain letters (A–Z)
      - Second row: Corresponding Atbash letters (Z–A)
    """
    mapping = atbash_mapping()
    plain_letters = string.ascii_uppercase
    cipher_letters = "".join(mapping[letter] for letter in plain_letters)
    
    col_width = 2  # Adjust width for clarity
    plain_row = " " + " ".join(letter.center(col_width) for letter in plain_letters) + " "
    border = " " + "+".join(["-" * col_width] * len(plain_letters)) + " "
    cipher_row = " " + " ".join(letter.center(col_width) for letter in cipher_letters) + " "
    
    print(plain_row)
    print(border)
    print(cipher_row)

def atbash_encrypt(text):
    """
    Encrypts the input text using the Atbash cipher.
    Works for both uppercase and lowercase letters. Non-alphabet characters remain unchanged.
    """
    mapping = atbash_mapping()
    result = []
    for char in text:
        if char.isupper():
            result.append(mapping[char])
        elif char.islower():
            # Convert to uppercase, map, then convert back to lowercase.
            result.append(mapping[char.upper()].lower())
        else:
            result.append(char)
    return ''.join(result)

def atbash_decrypt(text):
    """
    Decrypts the input text using the Atbash cipher.
    (Atbash is symmetric so encryption and decryption are the same.)
    """
    return atbash_encrypt(text)

def main():
    print("Atbash Cipher Mapping:")
    print_mapping_table()
    
    text = input("\nEnter the text to encrypt using Atbash: ")
    encrypted_text = atbash_encrypt(text)
    print("\nEncrypted text:")
    print(encrypted_text)
    
    input("\nPress Enter to decrypt...")
    
    decrypted_text = atbash_decrypt(encrypted_text)
    print("\nDecrypted text:")
    print(decrypted_text)

if __name__ == "__main__":
    main()
