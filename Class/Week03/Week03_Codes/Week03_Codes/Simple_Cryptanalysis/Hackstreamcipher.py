def xor_bytes(b1, b2):
    """
    XOR two byte sequences.
    If b2 is shorter than b1, b2 is repeated as needed.
    """
    # We'll assume b1 and b2 have the same length for the keystream case.
    return bytes(a ^ b for a, b in zip(b1, b2))


def read_binary_file(file_path):
    """
    Read the content of a binary file.
    """
    with open(file_path, "rb") as f:
        return f.read()


def write_binary_file(file_path, data):
    """
    Write binary data to a file.
    """
    with open(file_path, "wb") as f:
        f.write(data)


def interactive_file_mode():
    # Input file paths for the known plaintext and ciphertext
    known_plaintext_path = input("Enter path for known plaintext file: ").strip()
    known_ciphertext_path = input("Enter path for known ciphertext file: ").strip()

    try:
        known_plaintext = read_binary_file(known_plaintext_path)
        known_ciphertext = read_binary_file(known_ciphertext_path)
    except Exception as e:
        print("Error reading files:", e)
        return

    # Check that lengths match; they should be the same for a proper stream cipher pair.
    if len(known_plaintext) != len(known_ciphertext):
        print("Error: The known plaintext and ciphertext files must be of the same size.")
        return

    # Compute the keystream: K = P ⊕ C
    keystream = xor_bytes(known_plaintext, known_ciphertext)
    print("\nKeystream computed from the known pair.")

    # Option to save the computed keystream to a file
    save_key = input("Save keystream to file? (y/n): ").strip().lower()
    if save_key == 'y':
        key_filename = input("Enter filename for keystream output: ").strip()
        write_binary_file(key_filename, keystream)
        print(f"Keystream saved to {key_filename}")

    # Input file path for the ciphertext to decrypt
    while True:
        other_cipher_path = input("\nEnter path for ciphertext file to decrypt (or press Enter to exit): ").strip()
        if not other_cipher_path:
            break

        try:
            other_cipher = read_binary_file(other_cipher_path)
        except Exception as e:
            print("Error reading file:", e)
            continue

        # Use only as many keystream bytes as needed for decryption
        key_segment = keystream[:len(other_cipher)]
        decrypted_bytes = xor_bytes(other_cipher, key_segment)
        # Optionally, you could try to save decrypted_bytes as a file.
        output_path = input("Enter output filename to save the decrypted data: ").strip()
        try:
            write_binary_file(output_path, decrypted_bytes)
            print(f"Decrypted data saved to {output_path}")
        except Exception as e:
            print("Error writing decrypted file:", e)


if __name__ == "__main__":
    interactive_file_mode()
