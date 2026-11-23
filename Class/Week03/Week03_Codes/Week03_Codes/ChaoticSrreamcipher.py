#!/usr/bin/env python3
import os

def logistic_map_keygen(length: int, x0: float, r: float) -> bytes:
    """
    Generate a keystream of 'length' bytes using the Logistic map.
    
    :param length: number of bytes in the keystream
    :param x0: initial seed (0 < x0 < 1) for the Logistic map
    :param r: parameter (commonly near 3.99 for chaotic behavior)
    :return: keystream as bytes
    """
    x = x0
    key = bytearray(length)
    for i in range(length):
        # Logistic map iteration
        x = r * x * (1.0 - x)
        # Map x from (0..1) to a byte (0..255)
        key[i] = int(x * 256) & 0xFF
    return bytes(key)

def chaotic_encrypt_decrypt(input_path: str, output_path: str, x0: float, r: float):
    """
    Encrypt or decrypt a file (any binary) using a Logistic map-based keystream.
    XOR is used for both encryption and decryption.
    
    :param input_path: path to the input file
    :param output_path: path to the output file
    :param x0: initial seed for the Logistic map
    :param r: parameter for the Logistic map
    """
    # Read entire file in binary mode
    with open(input_path, 'rb') as f_in:
        data = f_in.read()

    length = len(data)
    # Generate keystream of the same length
    key = logistic_map_keygen(length, x0, r)
    
    # XOR each byte
    result = bytes(d ^ k for d, k in zip(data, key))
    
    # Write result to output
    with open(output_path, 'wb') as f_out:
        f_out.write(result)

def main():
    print("=== Chaotic Map (Logistic) Stream Cipher Demo ===")
    print("This script uses a simple XOR-based scheme with a Logistic map keystream.")
    print("Disclaimer: Not secure for real-world cryptography.\n")
    
    mode = input("Enter mode (encrypt/decrypt): ").strip().lower()
    if mode not in ("encrypt", "decrypt"):
        print("Invalid mode. Use 'encrypt' or 'decrypt'.")
        return
    
    input_file = input("Enter path to input file: ").strip()
    output_file = input("Enter path to output file: ").strip()
    
    # Get seed x0 (0 < x0 < 1) and parameter r (commonly near 3.99)
    try:
        x0 = float(input("Enter logistic map seed x0 (0 < x0 < 1): ").strip())
        r = float(input("Enter logistic map parameter r (e.g., 3.99): ").strip())
    except ValueError:
        print("Invalid x0 or r. Must be float.")
        return
    
    if not (0 < x0 < 1):
        print("x0 must be between 0 and 1.")
        return
    
    # Perform the XOR-based operation
    # (Encryption and decryption are identical in this scheme.)
    chaotic_encrypt_decrypt(input_file, output_file, x0, r)
    
    print(f"\nDone. {'Encrypted' if mode=='encrypt' else 'Decrypted'} file saved to '{output_file}'.")

if __name__ == "__main__":
    main()
