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
    Given a 3x3 key matrix, computes its inverse modulo 26.
    For a 3x3 matrix:
         M = [ [a, b, c],
               [d, e, f],
               [g, h, i] ]
    The determinant is:
         det = a*(e*i - f*h) - b*(d*i - f*g) + c*(d*h - e*g)
    The adjugate is the transpose of the cofactor matrix.
    The inverse is (inv_det * adjugate) mod 26.
    Returns the inverse matrix as a list of lists.
    """
    a, b, c = key_matrix[0]
    d, e, f = key_matrix[1]
    g, h, i = key_matrix[2]
    
    det = (a*(e*i - f*h) - b*(d*i - f*g) + c*(d*h - e*g)) % 26
    inv_det = mod_inverse(det, 26)
    if inv_det is None:
        return None

    # Compute cofactors (with proper sign, then take mod 26)
    A = (e*i - f*h) % 26
    B = (- (d*i - f*g)) % 26
    C = (d*h - e*g) % 26
    D = (- (b*i - c*h)) % 26
    E = (a*i - c*g) % 26
    F = (- (a*h - b*g)) % 26
    G = (b*f - c*e) % 26
    H = (- (a*f - c*d)) % 26
    I = (a*e - b*d) % 26

    # The adjugate is the transpose of the cofactor matrix.
    adjugate = [
        [A, D, G],
        [B, E, H],
        [C, F, I]
    ]
    
    # Multiply each element by inv_det modulo 26.
    inv_matrix = [[(adjugate[row][col] * inv_det) % 26 for col in range(3)]
                  for row in range(3)]
    return inv_matrix

def hill_encrypt(plaintext, key_matrix):
    """
    Encrypts the plaintext using the Hill cipher with the provided 3x3 key matrix.
    The plaintext is split into blocks of 3 letters (padding with 'X' if needed).
    Non-alphabet characters are preserved in their positions.
    """
    plaintext = plaintext.upper()
    # Extract letters for block processing.
    letters = [char for char in plaintext if char in string.ascii_uppercase]
    # Pad with 'X' until the number of letters is a multiple of 3.
    while len(letters) % 3 != 0:
        letters.append('X')
    
    ciphertext = ""
    letter_idx = 0  # counts only alphabetic characters
    for char in plaintext:
        if char not in string.ascii_uppercase:
            ciphertext += char
        else:
            # When at the beginning of a block (block size = 3)
            if letter_idx % 3 == 0:
                block = letters[letter_idx: letter_idx+3]
                block_vector = [ord(block[0]) - ord('A'),
                                ord(block[1]) - ord('A'),
                                ord(block[2]) - ord('A')]
                # Multiply key matrix by block_vector modulo 26.
                encrypted_vector = [
                    (key_matrix[0][0]*block_vector[0] +
                     key_matrix[0][1]*block_vector[1] +
                     key_matrix[0][2]*block_vector[2]) % 26,
                    (key_matrix[1][0]*block_vector[0] +
                     key_matrix[1][1]*block_vector[1] +
                     key_matrix[1][2]*block_vector[2]) % 26,
                    (key_matrix[2][0]*block_vector[0] +
                     key_matrix[2][1]*block_vector[1] +
                     key_matrix[2][2]*block_vector[2]) % 26
                ]
                cipher_block = "".join(chr(num + ord('A')) for num in encrypted_vector)
                ciphertext += cipher_block
            letter_idx += 1
    return ciphertext

def hill_decrypt(ciphertext, key_matrix):
    """
    Decrypts the ciphertext using the Hill cipher with the provided 3x3 key matrix.
    Computes the inverse key matrix and processes blocks of 3 letters.
    """
    inv_key = get_inverse_key_matrix(key_matrix)
    if inv_key is None:
        raise ValueError("The key matrix is not invertible modulo 26.")
    
    ciphertext = ciphertext.upper()
    letters = [char for char in ciphertext if char in string.ascii_uppercase]
    while len(letters) % 3 != 0:
        letters.append('X')
    
    plaintext = ""
    letter_idx = 0
    for char in ciphertext:
        if char not in string.ascii_uppercase:
            plaintext += char
        else:
            if letter_idx % 3 == 0:
                block = letters[letter_idx: letter_idx+3]
                block_vector = [ord(block[0]) - ord('A'),
                                ord(block[1]) - ord('A'),
                                ord(block[2]) - ord('A')]
                decrypted_vector = [
                    (inv_key[0][0]*block_vector[0] + inv_key[0][1]*block_vector[1] + inv_key[0][2]*block_vector[2]) % 26,
                    (inv_key[1][0]*block_vector[0] + inv_key[1][1]*block_vector[1] + inv_key[1][2]*block_vector[2]) % 26,
                    (inv_key[2][0]*block_vector[0] + inv_key[2][1]*block_vector[1] + inv_key[2][2]*block_vector[2]) % 26
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
    letters = ''.join(filter(str.isalpha, text.upper()))
    counts = Counter(letters)
    return counts.most_common()

def print_key_matrix(matrix):
    """
    Prints a matrix in a formatted manner.
    """
    for row in matrix:
        print(" ".join(f"{num:3}" for num in row))

def main():
    print("Hill Cipher (3x3 Matrix)")
    print("Enter 9 integers (space-separated) to form the key matrix (row-wise):")
    try:
        values = list(map(int, input("Key: ").split()))
        if len(values) != 9:
            print("Please enter exactly 9 integers.")
            return
    except ValueError:
        print("Invalid input. Please enter 9 integers separated by spaces.")
        return
    
    # Build the 3x3 key matrix.
    key_matrix = [values[0:3], values[3:6], values[6:9]]
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
