import string

def generate_keyword_mapping(keyword):
    """
    Generates a substitution mapping (plaintext -> cipher text) for a Keyword Cipher.
    The cipher alphabet is built by writing the keyword (removing duplicate letters) 
    and then appending the remaining unused letters of the alphabet.
    """
    # Normalize the keyword to uppercase and remove duplicates while preserving order.
    keyword = "".join(dict.fromkeys(keyword.upper()))
    # Build the cipher alphabet: keyword letters then remaining letters in alphabetical order.
    remaining = "".join(letter for letter in string.ascii_uppercase if letter not in keyword)
    cipher_alphabet = keyword + remaining
    # Map each plain letter (A-Z) to the corresponding cipher letter.
    mapping = {plain: cipher for plain, cipher in zip(string.ascii_uppercase, cipher_alphabet)}
    return mapping

def print_keyword_mapping_table(keyword):
    """
    Prints the key mapping in a two-row table:
    First row displays the plain letters (A-Z),
    and the second row displays the corresponding cipher letters.
    """
    mapping = generate_keyword_mapping(keyword)
    plain_letters = string.ascii_uppercase
    cipher_letters = "".join(mapping[letter] for letter in plain_letters)
    col_width = 2  # Adjust column width as needed
    
    # Build the plain letters row.
    plain_row = " " + " ".join(letter.center(col_width) for letter in plain_letters) + " "
    # Build a border line.
    border = " " + "+".join(["-" * col_width] * len(plain_letters)) + " "
    # Build the cipher letters row.
    cipher_row = " " + " ".join(letter.center(col_width) for letter in cipher_letters) + " "
    
    print(plain_row)
    print(border)
    print(cipher_row)

def keyword_encrypt(text, keyword):
    """
    Encrypts the input text using the Keyword Cipher with the provided keyword.
    Handles both uppercase and lowercase letters; non-alphabet characters remain unchanged.
    """
    mapping = generate_keyword_mapping(keyword)
    result = []
    for char in text:
        if char.isupper():
            result.append(mapping.get(char, char))
        elif char.islower():
            # Convert to uppercase, map, then convert back to lowercase.
            mapped = mapping.get(char.upper(), char.upper())
            result.append(mapped.lower())
        else:
            result.append(char)
    return ''.join(result)

def keyword_decrypt(text, keyword):
    """
    Decrypts the input text using the Keyword Cipher with the provided keyword.
    """
    mapping = generate_keyword_mapping(keyword)
    # Create the reverse mapping (cipher letter -> plaintext letter).
    reverse_mapping = {v: k for k, v in mapping.items()}
    result = []
    for char in text:
        if char.isupper():
            result.append(reverse_mapping.get(char, char))
        elif char.islower():
            mapped = reverse_mapping.get(char.upper(), char.upper())
            result.append(mapped.lower())
        else:
            result.append(char)
    return ''.join(result)

def main():
    keyword = input("Enter the keyword for the Keyword Cipher: ")
    print("\nKey Mapping (Plain -> Cipher):")
    print_keyword_mapping_table(keyword)
    
    plaintext = input("\nEnter the text to encrypt: ")
    encrypted_text = keyword_encrypt(plaintext, keyword)
    print("\nEncrypted text:")
    print(encrypted_text)
    
    input("\nPress Enter to continue to decryption...")
    decrypted_text = keyword_decrypt(encrypted_text, keyword)
    print("\nDecrypted text:")
    print(decrypted_text)

if __name__ == "__main__":
    main()
