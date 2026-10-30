import string

def generate_mapping(key):
    """
    Generates a dictionary mapping for uppercase letters based on the Caesar cipher key.
    Each letter is shifted by the given key (mod 26).
    """
    key = key % 26  # ensure the key is within 0-25
    alphabets = string.ascii_uppercase
    mapping = {alphabets[i]: alphabets[(i + key) % 26] for i in range(26)}
    return mapping

def print_mapping_table(key):
    """
    Displays the key mapping in the following table format:
    
     A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z
     --+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--
     R  A  T  X  U  K  E  Y  H  O  I  D  V  F  G  M  P  L  Z  W  S  Q  J  C  B  N
    
    In this example, if the key entered is 17 then A shifts to R, B shifts to A, etc.
    """
    mapping = generate_mapping(key)
    plain_letters = list(string.ascii_uppercase)
    
    # Build the first row: plain letters, each with a width of 2 characters.
    row1 = " ".join(f"{letter:2}" for letter in plain_letters)
    
    # Build the border row: a sequence of "--" separated by plus signs.
    row2 = " " + "--" + "+--" * (len(plain_letters)-1) + " "
    
    # Build the third row: cipher letters from the mapping.
    row3 = " ".join(f"{mapping[letter]:2}" for letter in plain_letters)
    
    print(row1)
    print(row2)
    print(row3)

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
    return caesar_encrypt(text, -key)

def main():
    try:
        key = int(input("Enter the Caesar Cipher key (an integer): "))
    except ValueError:
        print("Invalid input. Please enter an integer key.")
        return

    print("\nKey Mapping:")
    print_mapping_table(key)
    
    plaintext = input("\nEnter the text to encrypt: ")
    encrypted_text = caesar_encrypt(plaintext, key)
    print("\nEncrypted text:")
    print(encrypted_text)
    
    # Pause after encryption until the user is ready to continue
    input("\nPress Enter to continue to decryption...")
    
    decrypted_text = caesar_decrypt(encrypted_text, key)
    print("\nDecrypted text:")
    print(decrypted_text)

if __name__ == "__main__":
    main()
