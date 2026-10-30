import string
import random

def generate_random_mapping():
    """
    Generates a random substitution mapping for uppercase letters.
    Each letter A-Z is mapped to a unique letter (random permutation).
    """
    plain = list(string.ascii_uppercase)
    cipher = plain.copy()
    random.shuffle(cipher)
    mapping = {plain[i]: cipher[i] for i in range(26)}
    return mapping

def generate_mapping_from_key(key):
    """
    Generates a substitution mapping for uppercase letters using the provided key.
    The key must be a 26-letter permutation of the alphabet.
    """
    key = key.upper()
    if len(key) != 26 or len(set(key)) != 26:
        print("Invalid key: It must contain 26 unique letters (A-Z).")
        return None
    plain = string.ascii_uppercase
    mapping = {plain[i]: key[i] for i in range(26)}
    return mapping

def print_mapping_table(mapping):
    """
    Prints the key mapping in a two-line table:
      - Top row: Plain letters (A-Z)
      - Bottom row: Corresponding cipher letters
    """
    plain_letters = string.ascii_uppercase
    cipher_letters = "".join(mapping[letter] for letter in plain_letters)
    col_width = 2  # Adjust width for clarity
    plain_row = " " + " ".join(letter.center(col_width) for letter in plain_letters) + " "
    border = " " + "+".join(["-" * col_width] * len(plain_letters)) + " "
    cipher_row = " " + " ".join(letter.center(col_width) for letter in cipher_letters) + " "
    print(plain_row)
    print(border)
    print(cipher_row)

def simple_substitution_encrypt(text, mapping):
    """
    Encrypts the input text using the provided substitution mapping.
    Handles both uppercase and lowercase letters while preserving non-alphabet characters.
    """
    result = []
    for char in text:
        if char.isupper():
            result.append(mapping.get(char, char))
        elif char.islower():
            # Map using uppercase then convert back to lowercase.
            result.append(mapping.get(char.upper(), char.upper()).lower())
        else:
            result.append(char)
    return "".join(result)

def simple_substitution_decrypt(text, mapping):
    """
    Decrypts the input text using the provided substitution mapping.
    (It uses the reverse mapping.)
    """
    # Build reverse mapping: cipher letter -> plain letter
    reverse_mapping = {v: k for k, v in mapping.items()}
    result = []
    for char in text:
        if char.isupper():
            result.append(reverse_mapping.get(char, char))
        elif char.islower():
            result.append(reverse_mapping.get(char.upper(), char.upper()).lower())
        else:
            result.append(char)
    return "".join(result)

def main():
    print("Simple Substitution Cipher")
    user_key = input("Enter a 26-letter key for the substitution cipher (or press Enter to generate a random key): ").strip()
    if user_key == "":
        mapping = generate_random_mapping()
        print("\nGenerated Random Key Mapping:")
    else:
        mapping = generate_mapping_from_key(user_key)
        if mapping is None:
            return
        print("\nCustom Key Mapping:")
    
    print_mapping_table(mapping)
    
    plaintext = input("\nEnter the text to encrypt: ")
    encrypted_text = simple_substitution_encrypt(plaintext, mapping)
    print("\nEncrypted text:")
    print(encrypted_text)
    
    input("\nPress Enter to decrypt the text...")
    
    decrypted_text = simple_substitution_decrypt(encrypted_text, mapping)
    print("\nDecrypted text:")
    print(decrypted_text)

if __name__ == "__main__":
    main()
