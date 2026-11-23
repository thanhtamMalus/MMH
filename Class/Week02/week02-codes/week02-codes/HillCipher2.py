import string
from collections import Counter

def mod_inverse(a, m):
    """
    Returns the modular inverse of a modulo m if it exists, else None.
    """
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def get_inverse_key_matrix(key_matrix):
    """
    Given a 2x2 key matrix [[a, b], [c, d]], computes its inverse modulo 26.
    The inverse is computed as:
       det = a*d - b*c  (mod 26)
       inv_det = mod_inverse(det, 26)
       inverse = inv_det * [[d, -b], [-c, a]] mod 26
    Returns the inverse matrix as a list of lists.
    """
    a, b = key_matrix[0]
    c, d = key_matrix[1]
    det = (a * d - b * c) % 26
    inv_det = mod_inverse(det, 26)
    if inv_det is None:
        return None
    inv_matrix = [
        [(d * inv_det) % 26, ((-b) * inv_det) % 26],
        [((-c) * inv_det) % 26, (a * inv_det) % 26]
    ]
    return inv_matrix

def hill_encrypt(plaintext, key_matrix):
    """
    Encrypts the plaintext using the Hill cipher with the provided 2x2 key matrix.
    Plaintext is split into blocks of 2 letters (padding with 'X' if needed).
    Non-alphabet characters are preserved in their positions.
    """
    plaintext = plaintext.upper()
    # Extract only letters for block processing.
    letters = [char for char in plaintext if char in string.ascii_uppercase]
    if len(letters) % 2 != 0:
        letters.append('X')
    
    ciphertext = ""
    letter_idx = 0
    # Reconstruct ciphertext preserving non-letters.
    for char in plaintext:
        if char not in string.ascii_uppercase:
            ciphertext += char
        else:
            if letter_idx % 2 == 0:
                block = letters[letter_idx:letter_idx+2]
                block_vector = [ord(block[0]) - ord('A'), ord(block[1]) - ord('A')]
                encrypted_vector = [
                    (key_matrix[0][0] * block_vector[0] + key_matrix[0][1] * block_vector[1]) % 26,
                    (key_matrix[1][0] * block_vector[0] + key_matrix[1][1] * block_vector[1]) % 26,
                ]
                cipher_block = "".join(chr(num + ord('A')) for num in encrypted_vector)
                ciphertext += cipher_block
            letter_idx += 1
    return ciphertext

def hill_decrypt(ciphertext, key_matrix):
    """
    Decrypts the ciphertext using the Hill cipher with the provided 2x2 key matrix.
    Computes the inverse key matrix and processes blocks of 2 letters.
    """
    inv_key = get_inverse_key_matrix(key_matrix)
    if inv_key is None:
        raise ValueError("The key matrix is not invertible modulo 26.")
    
    ciphertext = ciphertext.upper()
    letters = [char for char in ciphertext if char in string.ascii_uppercase]
    if len(letters) % 2 != 0:
        letters.append('X')
    
    plaintext = ""
    letter_idx = 0
    for char in ciphertext:
        if char not in string.ascii_uppercase:
            plaintext += char
        else:
            if letter_idx % 2 == 0:
                block = letters[letter_idx:letter_idx+2]
                block_vector = [ord(block[0]) - ord('A'), ord(block[1]) - ord('A')]
                decrypted_vector = [
                    (inv_key[0][0] * block_vector[0] + inv_key[0][1] * block_vector[1]) % 26,
                    (inv_key[1][0] * block_vector[0] + inv_key[1][1] * block_vector[1]) % 26,
                ]
                plain_block = "".join(chr(num + ord('A')) for num in decrypted_vector)
                plaintext += plain_block
            letter_idx += 1
    return plaintext

def count_cipher_frequencies(text):
    """
    Counts the frequencies of alphabetic characters in text (ignoring case).
    Returns a list of tuples sorted by descending frequency.
    """
    # Convert text to uppercase and filter out non-letters.
    letters = ''.join(filter(str.isalpha, text.upper()))
    counts = Counter(letters)
    return counts.most_common()

def print_key_matrix(matrix):
    """
    Prints a 2x2 matrix in a formatted manner.
    """
    for row in matrix:
        print(" ".join(f"{num:3}" for num in row))

def main():
    print("Hill Cipher (2x2 Matrix)")
    print("Enter 4 integers (space-separated) to form the key matrix (a b c d):")
    try:
        a, b, c, d = map(int, input("Key: ").split())
    except ValueError:
        print("Invalid input. Please enter 4 integers separated by spaces.")
        return
    
    key_matrix = [[a, b], [c, d]]
    print("\nKey Matrix:")
    print_key_matrix(key_matrix)
    
    inv_matrix = get_inverse_key_matrix(key_matrix)
    if inv_matrix is None:
        print("The key matrix is not invertible modulo 26. Please choose a different key.")
        return
    
    print("\nInverse Key Matrix:")
    print_key_matrix(inv_matrix)
    
    plaintext = input("\nEnter the plaintext to encrypt: ")
    encrypted_text = hill_encrypt(plaintext, key_matrix)
    print("\nEncrypted Text:")
    print(encrypted_text)
    
    # Count and display the cipher letter frequencies.
    freqs = count_cipher_frequencies(encrypted_text)
    print("\nCipher Letter Frequencies (most common first):")
    for letter, count in freqs:
        print(f"{letter}: {count}")
    
    input("\nPress Enter to continue to decryption...")
    decrypted_text = hill_decrypt(encrypted_text, key_matrix)
    print("\nDecrypted Text:")
    print(decrypted_text)

if __name__ == "__main__":
    main()
