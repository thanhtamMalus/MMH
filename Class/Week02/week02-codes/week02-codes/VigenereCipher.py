import string
from collections import Counter

def generate_vigenere_mapping(key_letter):
    """
    Generates a mapping for a single key letter.
    For a given key letter (A-Z), it creates a Caesar cipher mapping with a shift 
    equal to the letter's position in the alphabet (A=0, B=1, …, Z=25).
    """
    shift = ord(key_letter) - ord('A')
    alphabets = string.ascii_uppercase
    mapping = {alphabets[i]: alphabets[(i + shift) % 26] for i in range(26)}
    return mapping

def print_vigenere_mapping_table(key):
    """
    For each letter in the Vigenère key, print its mapping table.
    The table shows:
      - First row: Plain alphabet (A-Z)
      - Second row: A border (using '--+')
      - Third row: The cipher alphabet for that key letter.
    """
    key = key.upper()
    for letter in key:
        mapping = generate_vigenere_mapping(letter)
        plain_letters = list(string.ascii_uppercase)
        row1 = " ".join(f"{l:2}" for l in plain_letters)
        row2 = " " + "--" + "+--" * (len(plain_letters) - 1) + " "
        row3 = " ".join(f"{mapping[l]:2}" for l in plain_letters)
        print(f"Mapping for key letter '{letter}':")
        print(row1)
        print(row2)
        print(row3)
        print()

def vigenere_encrypt(plaintext, key):
    """
    Encrypts the plaintext using the Vigenère cipher.
    The key is repeated as needed. For each letter in the plaintext,
    a Caesar mapping corresponding to the appropriate key letter is used.
    Non-alphabet characters are left unchanged.
    """
    key = key.upper()
    result = []
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            mapping = generate_vigenere_mapping(key[key_index % len(key)])
            if char.isupper():
                result.append(mapping[char])
            else:
                # For lowercase letters: convert, map, then convert back to lowercase.
                result.append(mapping[char.upper()].lower())
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)

def vigenere_decrypt(ciphertext, key):
    """
    Decrypts the ciphertext encrypted using the Vigenère cipher.
    For each letter, the shift (based on the corresponding key letter) is reversed.
    Non-alphabet characters are left unchanged.
    """
    key = key.upper()
    result = []
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            if char.isupper():
                plain_ord = (ord(char) - ord('A') - shift) % 26 + ord('A')
                result.append(chr(plain_ord))
            else:
                plain_ord = (ord(char.upper()) - ord('A') - shift) % 26 + ord('A')
                result.append(chr(plain_ord).lower())
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)

def count_cipher_frequencies(text):
    """
    Counts and returns the frequencies of alphabetic characters in the given text,
    ignoring case and non-letter characters.
    """
    # Convert text to uppercase and filter out non-alphabet characters.
    letters_only = ''.join(filter(str.isalpha, text.upper()))
    return Counter(letters_only)

def main():
    key = input("Enter the Vigenère Cipher key (alphabetic): ").strip()
    if not key.isalpha():
        print("The key must contain only letters.")
        return

    print("\nVigenère Cipher Mapping Tables:")
    print_vigenere_mapping_table(key)
    
    plaintext = input("\nEnter the text to encrypt: ")
    encrypted_text = vigenere_encrypt(plaintext, key)
    print("\nEncrypted text:")
    print(encrypted_text)
    
    # Count and display the cipher letter frequencies.
    freqs = count_cipher_frequencies(encrypted_text)
    print("\nCiphertext Letter Frequencies (sorted by most common):")
    for letter, count in freqs.most_common():
        print(f"{letter}: {count}")
    
    input("\nPress Enter to continue to decryption...")
    decrypted_text = vigenere_decrypt(encrypted_text, key)
    print("\nDecrypted text:")
    print(decrypted_text)

if __name__ == "__main__":
    main()
