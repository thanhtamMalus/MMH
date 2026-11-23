# gray_ecb_visual.py
import sys
import os
import secrets
import numpy as np
import matplotlib.pyplot as plt
from PIL import Image
from mypackages import modes  # Your AES modes implementation

# ------------------------ Key Input ------------------------

def read_or_generate_key() -> bytes:
    """
    Prompt user for a key in hex or 'random' (16/24/32 bytes).
    Returns the key as raw bytes.
    """
    while True:
        user_input = input(
            "\nEnter AES key in hex (16,24,32 bytes => 32,48,64 hex chars)\n"
            "or 'random' for a new random key:\n> "
        ).strip().lower()
        if user_input == "random":
            key = secrets.token_bytes(16)  # 128-bit for example
            print(f"Generated random 128-bit key (hex): {key.hex()}")
            return key
        else:
            try:
                key_bytes = bytes.fromhex(user_input)
                if len(key_bytes) not in [16, 24, 32]:
                    print("Key must be 16, 24, or 32 bytes. Try again.\n")
                    continue
                print(f"Using user-provided key (hex): {key_bytes.hex()}")
                return key_bytes
            except ValueError:
                print("Invalid hex input. Try again.\n")

# ------------------------ Mode Selection ------------------------

def select_mode() -> str:
    """
    Prompt user for AES mode (ECB, CBC, CFB, OFB, CTR, GCM, EAX).
    """
    print("\nSelect AES mode:")
    print("1. ECB")
    print("2. CBC")
    print("3. CFB")
    print("4. OFB")
    print("5. CTR")
    print("6. GCM (AEAD)")
    print("7. EAX (AEAD)")

    mode_map = {
        "1": "ECB",
        "2": "CBC",
        "3": "CFB",
        "4": "OFB",
        "5": "CTR",
        "6": "GCM",
        "7": "EAX",
    }
    while True:
        choice = input("Enter choice (1/2/3/4/5/6/7): ").strip()
        if choice in mode_map:
            return mode_map[choice]
        print("Invalid choice.")

# ------------------------ AEAD Helpers ------------------------

def _looks_like_yes(s: str) -> bool:
    s = s.strip().lower()
    # accept common yes forms incl. "co" (Vietnamese 'có' without tone)
    return s.startswith(("y", "yes", "t", "true", "1", "co"))

def maybe_get_aad() -> bytes:
    """
    Ask whether to include AAD and how to supply it.
    Returns bytes (possibly empty).
    """
    use_aad = _looks_like_yes(input("\nUse AAD (associated data)? (y/N): "))
    if not use_aad:
        return b""
    how = input("AAD as (1) text or (2) hex? [1/2]: ").strip()
    if how == "2":
        aad_hex = input("Enter AAD (hex): ").strip()
        try:
            return bytes.fromhex(aad_hex)
        except ValueError:
            print("Invalid hex; using empty AAD.")
            return b""
    else:
        aad_text = input("Enter AAD (text): ").strip()
        return aad_text.encode("utf-8")

# ------------------------ Main Program ------------------------

def main():
    # 1) Get key + mode
    key_bytes = read_or_generate_key()
    mode_str = select_mode()
    print(f"Selected AES mode: {mode_str}")

    # 2) Create the AES mode object
    aes_mode = modes.modes(key_bytes)
    aes_mode.mode = mode_str

    # 3) Ask for input image
    input_file = input("\nEnter path to an image file (JPG, PNG, BMP): ").strip()
    if not os.path.isfile(input_file):
        print(f"Error: File '{input_file}' does not exist.")
        sys.exit(1)

    # 4) Load + convert to 8-bit grayscale
    img = Image.open(input_file).convert('L')
    w, h = img.size
    raw_data = img.tobytes()  # uncompressed grayscale data

    print(f"Loaded image '{input_file}': {w}x{h}, total {len(raw_data)} bytes in grayscale.")

    # 5) Display the original grayscale for reference
    original_arr = np.frombuffer(raw_data, dtype=np.uint8).reshape((h, w))

    # 6) Encrypt the raw grayscale data
    # For AEAD, also collect AAD (optional) and use fixed-size nonces so we can parse for visualization.
    display_bytes = None
    full_output = None
    tag_len = 16

    if mode_str == "ECB":
        full_output = aes_mode.ecb_encrypt(raw_data)
        display_bytes = full_output  # direct
    elif mode_str == "CBC":
        full_output = aes_mode.cbc_encrypt(raw_data)
        display_bytes = full_output  # includes IV prepended; OK to visualize as-is
    elif mode_str == "CFB":
        full_output = aes_mode.cfb_encrypt(raw_data, segment_size=128)
        display_bytes = full_output  # includes IV prepended
    elif mode_str == "OFB":
        full_output = aes_mode.ofb_encrypt(raw_data)
        display_bytes = full_output  # includes IV prepended
    elif mode_str == "CTR":
        full_output = aes_mode.ctr_encrypt(raw_data)
        display_bytes = full_output  # includes IV prepended
    elif mode_str == "GCM":
        aad = maybe_get_aad()
        iv = secrets.token_bytes(12)  # fixed 12 byte IV for parseability & best practice
        full_output = aes_mode.gcm_encrypt(raw_data, aad=aad, iv=iv, tag_len=tag_len)
        # Layout: iv (12) || ciphertext || tag (16)
        if len(full_output) < 12 + tag_len:
            print("Unexpected GCM output size; cannot visualize.")
            sys.exit(1)
        display_bytes = full_output[12:-tag_len]  # visualize ciphertext only
    elif mode_str == "EAX":
        aad = maybe_get_aad()
        nonce = secrets.token_bytes(16)  # fixed 16 byte nonce for parseability
        full_output = aes_mode.eax_encrypt(raw_data, aad=aad, nonce=nonce, tag_len=tag_len)
        # Layout: nonce (16) || ciphertext || tag (16)
        if len(full_output) < 16 + tag_len:
            print("Unexpected EAX output size; cannot visualize.")
            sys.exit(1)
        display_bytes = full_output[16:-tag_len]  # visualize ciphertext only
    else:
        raise ValueError(f"Unsupported mode: {mode_str}")

    print(f"Ciphertext (bytes used for visualization) length = {len(display_bytes)}")

    # 7) For visualization, interpret the (ciphertext-only) bytes as a 2D array
    needed = w * h
    vis = display_bytes
    if len(vis) < needed:
        print("Cipher visual is smaller than image plane. Zero-padding for visualization.")
        vis = vis + b"\x00" * (needed - len(vis))
    elif len(vis) > needed:
        print("Cipher visual is larger than image plane. Truncating for visualization.")
        vis = vis[:needed]

    cipher_arr = np.frombuffer(vis, dtype=np.uint8).reshape((h, w))

    # 8) Show side by side in matplotlib
    fig, axes = plt.subplots(1, 2, figsize=(10, 5))
    ax_left, ax_right = axes.ravel()

    ax_left.imshow(original_arr, cmap='gray', vmin=0, vmax=255)
    ax_left.set_title("Original Grayscale")
    ax_left.axis("off")

    ax_right.imshow(cipher_arr, cmap='gray', vmin=0, vmax=255)
    ax_right.set_title(f"{mode_str} Cipher Visual")
    ax_right.axis("off")

    plt.show()

    # 9) Save the full encryption output (including IV/nonce and tag for AEAD or IV for stream modes)
    out_file = f"cipher_grayscale_{mode_str.lower()}.bin"
    with open(out_file, "wb") as f_out:
        # store width, height for potential decryption/round-trip later
        f_out.write(w.to_bytes(4, 'big'))
        f_out.write(h.to_bytes(4, 'big'))
        f_out.write(full_output)
    print(f"Full output saved to '{out_file}' with (width, height) prepended.")
    if mode_str in ("GCM", "EAX"):
        print("Note: file contains nonce/IV + ciphertext + tag (appended). Keep AAD (if used) for decryption.")

if __name__ == "__main__":
    main()
