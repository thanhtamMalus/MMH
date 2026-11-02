#!/usr/bin/env python3
"""
Cross-validation script: compares AES-128-CTR output of aestool against OpenSSL CLI.
Works on Windows, Linux, and macOS.
"""

import os
import sys
import argparse
import subprocess
import tempfile
import shutil

def run_command(cmd_args):
    result = subprocess.run(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode, result.stdout, result.stderr

def main():
    parser = argparse.ArgumentParser(description="Cross-validation against OpenSSL CLI")
    parser.add_argument("--aestool", default="", help="Path to aestool binary")
    parser.add_argument("--openssl", default="openssl", help="Path or name of openssl executable")
    args = parser.parse_args()

    aestool_path = args.aestool
    if not aestool_path:
        # Auto-detect aestool in build directories
        candidates = [
            "bin/aestool", "bin/aestool.exe",
            "bin/Release/aestool.exe", "bin/Debug/aestool.exe",
            "build/bin/aestool", "build/bin/aestool.exe",
            "build/bin/Release/aestool.exe", "build/bin/Debug/aestool.exe"
        ]
        for c in candidates:
            if os.path.exists(c):
                aestool_path = os.path.abspath(c)
                break

    if not aestool_path or not os.path.exists(aestool_path):
        print(f"[ERROR] Cannot find aestool executable at '{aestool_path}'.", file=sys.stderr)
        return 1

    # Check openssl
    rc, out, err = run_command([args.openssl, "version"])
    if rc != 0:
        print(f"[SKIP] OpenSSL not found or failed to run: {err.decode('utf-8', errors='ignore')}")
        return 0 # Skip cleanly if openssl not present

    openssl_version = out.decode("utf-8", errors="ignore").strip()
    print("=" * 60)
    print("Cross-Validation: aestool vs OpenSSL")
    print(f"aestool: {aestool_path}")
    print(f"OpenSSL: {openssl_version}")
    print("=" * 60)

    test_sizes = [0, 1, 15, 16, 17, 31, 32, 33, 1000, 65536, 1024 * 1024] # up to 1 MiB
    temp_dir = tempfile.mkdtemp(prefix="aes_cross_val_")

    all_passed = True

    try:
        for idx, size in enumerate(test_sizes):
            key = os.urandom(16)
            iv = os.urandom(16)
            msg = os.urandom(size) if size > 0 else b""

            key_hex = key.hex()
            iv_hex = iv.hex()

            key_file = os.path.join(temp_dir, f"k_{idx}.bin")
            iv_file  = os.path.join(temp_dir, f"iv_{idx}.bin")
            msg_file = os.path.join(temp_dir, f"msg_{idx}.bin")
            openssl_out = os.path.join(temp_dir, f"openssl_{idx}.bin")
            aestool_out = os.path.join(temp_dir, f"aestool_{idx}.bin")
            decrypted_out = os.path.join(temp_dir, f"dec_{idx}.bin")

            with open(key_file, "wb") as f: f.write(key)
            with open(iv_file, "wb") as f: f.write(iv)
            with open(msg_file, "wb") as f: f.write(msg)

            # 1. Run OpenSSL: openssl enc -aes-128-ctr -K <hex> -iv <hex> -in msg -out ref
            rc_ossl, _, err_ossl = run_command([
                args.openssl, "enc", "-aes-128-ctr",
                "-K", key_hex,
                "-iv", iv_hex,
                "-in", msg_file,
                "-out", openssl_out
            ])
            if rc_ossl != 0:
                print(f"[FAIL] OpenSSL error on size {size}: {err_ossl.decode('utf-8', errors='ignore')}")
                all_passed = False
                continue

            # 2. Run aestool encrypt
            rc_aes, _, err_aes = run_command([
                aestool_path, "encrypt",
                "--mode", "ctr",
                "--key", key_file,
                "--iv", iv_file,
                "--in", msg_file,
                "--out", aestool_out
            ])
            if rc_aes != 0:
                print(f"[FAIL] aestool error on size {size}: {err_aes.decode('utf-8', errors='ignore')}")
                all_passed = False
                continue

            # 3. Compare ciphertext bytes
            with open(openssl_out, "rb") as f: ossl_data = f.read()
            with open(aestool_out, "rb") as f: aes_data = f.read()

            if ossl_data != aes_data:
                print(f"[FAIL] Size {size}: Ciphertext mismatch! (OpenSSL len: {len(ossl_data)}, aestool len: {len(aes_data)})")
                all_passed = False
                continue

            # 4. Run aestool decrypt and compare with original plaintext
            rc_dec, _, _ = run_command([
                aestool_path, "decrypt",
                "--mode", "ctr",
                "--key", key_file,
                "--iv", iv_file,
                "--in", aestool_out,
                "--out", decrypted_out
            ])
            with open(decrypted_out, "rb") as f: dec_data = f.read()

            if dec_data != msg:
                print(f"[FAIL] Size {size}: Decrypted plaintext does not match original!")
                all_passed = False
                continue

            print(f"  [PASS] Size {size:7d} bytes: 100% Match with OpenSSL (Encrypt & Decrypt)")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    print("=" * 60)
    if all_passed:
        print("[SUCCESS] All cross-validation tests passed with 100% exact match!")
        return 0
    else:
        print("[FAILURE] Cross-validation failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
