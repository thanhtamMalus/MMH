import string

def generate_mapping_rot13():
    """
    Generates a dictionary mapping for uppercase letters based on ROT13.
    """
    key = 13
    alphabets = string.ascii_uppercase
    mapping = {alphabets[i]: alphabets[(i + key) % 26] for i in range(26)}
    return mapping

def print_mapping_rot13():
    """
    Prints the mapping of each uppercase letter to its ROT13 cipher equivalent.
    """
    mapping = generate_mapping_rot13()
    print("ROT13 Mapping for uppercase letters:")
    for letter in string.ascii_uppercase:
        print(f"{letter} -> {mapping[letter]}")

def rot13(text):
    """
    Encrypts/Decrypts the input text using ROT13.
    Since ROT13 is symmetric, the same function can be used for both encryption and decryption.
    """
    key = 13
    result = []
    for char in text:
        if char.isupper():
            result.append(chr((ord(char) - ord('A') + key) % 26 + ord('A')))
        elif char.islower():
            result.append(chr((ord(char) - ord('a') + key) % 26 + ord('a')))
        else:
            result.append(char)
    return ''.join(result)

def main():
    print_mapping_rot13()
    
    plaintext = input("\nEnter the text to encrypt using ROT13: ")
    encrypted_text = rot13(plaintext)
    print("\nEncrypted text:")
    print(encrypted_text)
    
    # Pause after encryption until user is ready to continue
    input("\nPress Enter to continue to decryption...")
    
    decrypted_text = rot13(encrypted_text)
    print("\nDecrypted text:")
    print(decrypted_text)

if __name__ == "__main__":
    main()
