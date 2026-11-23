import random
import base64
from sympy import randprime, mod_inverse, primitive_root

def find_primitive_root(p):
    """Find a primitive root modulo p more efficiently."""
    for g in range(2, p):
        if pow(g, (p-1)//2, p) != 1:  # Basic check for generator
            return g
    return None

def generate_keys(bits=1024):
    """Generate ElGamal public and private keys more efficiently."""
    p = randprime(2**(bits-1), 2**bits)  # Faster prime generation
    g = find_primitive_root(p)  # More efficient generator search

    x = random.randint(2, p - 2)  # Private key
    y = pow(g, x, p)  # Public key component

    print("\nGenerated Keys:")
    print(f"Prime (p): {p}")
    print(f"Generator (g): {g}")
    print(f"Public Key (y): {y}")
    print(f"Private Key (x): {x}")

    return p, g, y, x

def encrypt(plain_text, p, g, y, output_format="base64"):
    """Encrypts a message using ElGamal and returns Base64 or Hex-encoded cipher."""
    numeric_text = [ord(char) for char in plain_text]  # Convert characters to ASCII
    k = random.randint(2, p - 2)  # Random ephemeral key
    c1 = pow(g, k, p)  # Compute first part of ciphertext

    cipher_text = [(pow(y, k, p) * num) % p for num in numeric_text]

    # Correct the bytes conversion
    cipher_bytes = b"".join([c1.to_bytes((p.bit_length() + 7) // 8, 'big')]) + \
                   b"".join(num.to_bytes((p.bit_length() + 7) // 8, 'big') for num in cipher_text)

    if output_format == "base64":
        encoded_cipher = base64.b64encode(cipher_bytes).decode()
    else:
        encoded_cipher = cipher_bytes.hex()

    print(f"\nCipher ({output_format}): {encoded_cipher}")
    return encoded_cipher

def decrypt(encoded_cipher, p, x, input_format="base64"):
    """Decrypts Base64 or Hex-encoded cipher and returns plaintext."""
    if input_format == "base64":
        cipher_bytes = base64.b64decode(encoded_cipher)
    else:
        cipher_bytes = bytes.fromhex(encoded_cipher)

    block_size = (p.bit_length() + 7) // 8
    c1 = int.from_bytes(cipher_bytes[:block_size], 'big')  # Extract c1
    cipher_blocks = [int.from_bytes(cipher_bytes[i:i+block_size], 'big') for i in range(block_size, len(cipher_bytes), block_size)]

    s = pow(c1, x, p)  # Compute shared secret s = c1^x mod p
    s_inv = mod_inverse(s, p)  # Compute modular inverse of s

    numeric_text = [(num * s_inv) % p for num in cipher_blocks]
    decrypted_text = ''.join(chr(num) for num in numeric_text)

    print(f"\nDecrypted Message: {decrypted_text}")
    return decrypted_text

# Main Menu
def main():
    while True:
        print("\nElGamal Cipher Implementation")
        print("1. Generate Keys")
        print("2. Encrypt a Message")
        print("3. Decrypt a Cipher")
        print("4. Exit")

        choice = input("Select an option: ").strip()

        if choice == "1":
            p, g, y, x = generate_keys(1024)

        elif choice == "2":
            message = input("Enter message to encrypt: ")
            p = int(input("Enter prime modulus (p): ").strip())
            g = int(input("Enter generator (g): ").strip())
            y = int(input("Enter public key (y): ").strip())
            output_format = input("Output format (base64/hex, default=base64): ").strip().lower() or "base64"
            encrypt(message, p, g, y, output_format)

        elif choice == "3":
            encoded_cipher = input("Enter cipher text: ").strip()
            p = int(input("Enter prime modulus (p): ").strip())
            x = int(input("Enter private key (x): ").strip())
            input_format = input("Cipher format (base64/hex, default=base64): ").strip().lower() or "base64"
            decrypt(encoded_cipher, p, x, input_format)

        elif choice == "4":
            print("Exiting...")
            break

        else:
            print("Invalid option. Please try again.")

# Run the main function
if __name__ == "__main__":
    main()
