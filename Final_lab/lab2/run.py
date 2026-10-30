#!/usr/bin/env python3
"""
================================================================================
Unified Cross-Platform Runner Script for Lab 2: AES-128 (CTR Mode)
Supports: Windows 10/11 (MSVC & MinGW-w64) and Linux/macOS (GCC & Clang)
================================================================================
"""

import os
import sys
import subprocess
import platform
import shutil
import argparse

def get_script_dir():
    return os.path.dirname(os.path.abspath(__file__))

def get_binary_path(binary_name):
    script_dir = get_script_dir()
    exe_suffix = ".exe" if platform.system().lower() == "windows" else ""
    full_name = binary_name + exe_suffix

    search_paths = [
        os.path.join(script_dir, "build", "bin", "Release", full_name),
        os.path.join(script_dir, "build", "bin", full_name),
        os.path.join(script_dir, "bin", "Release", full_name),
        os.path.join(script_dir, "bin", full_name),
        os.path.join(script_dir, "dist", f"{'windows' if platform.system().lower() == 'windows' else 'linux'}-x86_64", full_name)
    ]
    for p in search_paths:
        if os.path.exists(p):
            return p
    return None

def execute_cmd(cmd, cwd=None):
    print(f"\n[RUNNING] {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    res = subprocess.run(cmd, cwd=cwd or get_script_dir(), shell=isinstance(cmd, str))
    if res.returncode != 0:
        print(f"[ERROR] Command exited with code {res.returncode}", file=sys.stderr)
        return False
    return True

def cmd_build(clean=False, build_type="Release"):
    script_dir = get_script_dir()
    build_dir = os.path.join(script_dir, "build")

    if clean and os.path.exists(build_dir):
        print(f"[CLEAN] Removing {build_dir}...")
        shutil.rmtree(build_dir, ignore_errors=True)

    os.makedirs(build_dir, exist_ok=True)

    cmake_args = ["cmake", "..", f"-DCMAKE_BUILD_TYPE={build_type}"]

    # On Windows, check available generator if not already configured
    if platform.system().lower() == "windows":
        # Check if cmake already configured
        if not os.path.exists(os.path.join(build_dir, "CMakeCache.txt")):
            # If cl.exe is not in PATH but g++ is, recommend/use MinGW Makefiles
            cl_found = shutil.which("cl") is not None
            gcc_found = shutil.which("g++") is not None
            if not cl_found and gcc_found:
                cmake_args.extend(["-G", "MinGW Makefiles"])

    if not execute_cmd(cmake_args, cwd=build_dir):
        return False

    build_cmd = ["cmake", "--build", ".", "--config", build_type]
    if not execute_cmd(build_cmd, cwd=build_dir):
        return False

    print("\n[SUCCESS] Build completed successfully.")
    return True

def cmd_test():
    script_dir = get_script_dir()
    build_dir = os.path.join(script_dir, "build")
    if not os.path.exists(build_dir):
        print("[ERROR] Build directory does not exist. Please run 'build' first.", file=sys.stderr)
        return False

    # Run ctest
    ctest_cmd = ["ctest", "-C", "Release", "--output-on-failure"]
    if not execute_cmd(ctest_cmd, cwd=build_dir):
        return False

    print("\n[SUCCESS] All unit tests passed.")
    return True

def cmd_kat():
    script_dir = get_script_dir()
    aestool = get_binary_path("aestool")
    if not aestool:
        print("[ERROR] aestool binary not found. Please run 'build' first.", file=sys.stderr)
        return False

    vector_file = os.path.join(script_dir, "vectors", "vectors.json")
    cmd = [aestool, "--kat", vector_file]
    return execute_cmd(cmd)

def cmd_cross_val():
    script_dir = get_script_dir()
    aestool = get_binary_path("aestool")
    if not aestool:
        print("[ERROR] aestool binary not found. Please run 'build' first.", file=sys.stderr)
        return False

    script_path = os.path.join(script_dir, "scripts", "cross_validate.py")
    cmd = [sys.executable, script_path, "--aestool", aestool]
    return execute_cmd(cmd)

def cmd_bench(sizes="1MiB,100MiB", runs=5, sbox="both"):
    script_dir = get_script_dir()
    aes_bench = get_binary_path("aes_bench")
    if not aes_bench:
        print("[ERROR] aes_bench binary not found. Please run 'build' first.", file=sys.stderr)
        return False

    os_sub = "windows" if platform.system().lower() == "windows" else "linux"
    out_dir = os.path.join(script_dir, "docs", "results", os_sub)
    os.makedirs(out_dir, exist_ok=True)
    csv_path = os.path.join(out_dir, "benchmark.csv")
    workdir = os.path.join(out_dir, "bench_work")

    cmd = [
        aes_bench,
        "--sizes", sizes,
        "--runs", str(runs),
        "--sbox", sbox,
        "--csv", csv_path,
        "--workdir", workdir
    ]
    res = execute_cmd(cmd)
    if os.path.exists(workdir):
        shutil.rmtree(workdir, ignore_errors=True)
    return res

def cmd_demo():
    script_dir = get_script_dir()
    aestool = get_binary_path("aestool")
    if not aestool:
        print("[ERROR] aestool binary not found. Please run 'build' first.", file=sys.stderr)
        return False

    demo_dir = os.path.join(script_dir, "demo_workspace")
    os.makedirs(demo_dir, exist_ok=True)

    key_file = os.path.join(demo_dir, "key.bin")
    iv_file  = os.path.join(demo_dir, "iv.bin")
    msg_file = os.path.join(demo_dir, "message.txt")
    ct_file  = os.path.join(demo_dir, "cipher.bin")
    dec_file = os.path.join(demo_dir, "decrypted.txt")

    print("\n--- [DEMO STEP 1] Generating 16-byte cryptographic key via OS CSPRNG ---")
    if not execute_cmd([aestool, "keygen", "--out", key_file]): return False

    print("\n--- [DEMO STEP 2] Generating 16-byte initial counter block (IV) via OS CSPRNG ---")
    if not execute_cmd([aestool, "ivgen", "--out", iv_file]): return False

    print("\n--- [DEMO STEP 3] Creating sample plaintext file ---")
    sample_text = (
        "Pure C++ AES-128 CTR Mode Demonstration!\n"
        "Compliant with FIPS-197 and NIST SP 800-38A.\n"
        "Cross-platform execution on Windows & Linux.\n"
    )
    with open(msg_file, "w", encoding="utf-8") as f:
        f.write(sample_text)
    print(f"Created {msg_file} ({os.path.getsize(msg_file)} bytes)")

    print("\n--- [DEMO STEP 4] Encrypting with aestool ---")
    if not execute_cmd([aestool, "encrypt", "--mode", "ctr", "--key", key_file, "--iv", iv_file, "--in", msg_file, "--out", ct_file]):
        return False
    print(f"Ciphertext written to {ct_file} ({os.path.getsize(ct_file)} bytes)")

    print("\n--- [DEMO STEP 5] Decrypting with aestool ---")
    if not execute_cmd([aestool, "decrypt", "--mode", "ctr", "--key", key_file, "--iv", iv_file, "--in", ct_file, "--out", dec_file]):
        return False

    print("\n--- [DEMO STEP 6] Verifying integrity ---")
    with open(msg_file, "rb") as f1, open(dec_file, "rb") as f2:
        if f1.read() == f2.read():
            print("[SUCCESS] Decrypted message perfectly matches original plaintext!")
        else:
            print("[FAIL] Mismatch between plaintext and decrypted file!", file=sys.stderr)
            return False

    return True

def cmd_package():
    script_dir = get_script_dir()
    pkg_script = os.path.join(script_dir, "scripts", "package_dist.py")
    return execute_cmd([sys.executable, pkg_script])

def print_menu():
    print("""
================================================================================
Lab 2: AES-128 (CTR Mode) - Interactive Runner Menu
Current OS: {os} ({platform})
================================================================================
  1. Build project (Release mode)
  2. Run Unit Tests (ctest)
  3. Run Known Answer Tests (KAT: vectors.json)
  4. Run Cross-Validation against OpenSSL
  5. Run Benchmark (aes_bench)
  6. Run Quick E2E Demo (keygen -> ivgen -> encrypt -> decrypt)
  7. Package Binary to dist/ (with SHA-256)
  0. Exit
================================================================================
""".format(os=platform.system(), platform=platform.platform()))

def interactive_loop():
    while True:
        print_menu()
        try:
            choice = input("Select an option (0-7): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if choice == "1":
            cmd_build()
        elif choice == "2":
            cmd_test()
        elif choice == "3":
            cmd_kat()
        elif choice == "4":
            cmd_cross_val()
        elif choice == "5":
            sizes = input("Enter sizes to benchmark (default: 1MiB,100MiB): ").strip() or "1MiB,100MiB"
            runs_str = input("Enter number of runs (default: 5): ").strip() or "5"
            cmd_bench(sizes=sizes, runs=int(runs_str))
        elif choice == "6":
            cmd_demo()
        elif choice == "7":
            cmd_package()
        elif choice == "0":
            print("Exiting.")
            break
        else:
            print("Invalid selection. Please choose 0 to 7.")
        input("\nPress Enter to continue...")

def main():
    parser = argparse.ArgumentParser(description="Lab 2 Cross-Platform Runner")
    subparsers = parser.add_subparsers(dest="command")

    build_p = subparsers.add_parser("build", help="Build project with CMake")
    build_p.add_argument("--clean", action="store_true", help="Clean build directory first")
    build_p.add_argument("--type", default="Release", help="Build type (Release/Debug)")

    subparsers.add_parser("test", help="Run unit tests via ctest")
    subparsers.add_parser("kat", help="Run KAT known answer tests")
    subparsers.add_parser("cross-val", help="Run OpenSSL cross-validation")

    bench_p = subparsers.add_parser("bench", help="Run benchmark suite")
    bench_p.add_argument("--sizes", default="1MiB,100MiB", help="Comma-separated sizes (e.g. 1MiB,100MiB,1GiB)")
    bench_p.add_argument("--runs", type=int, default=5, help="Number of runs per configuration")
    bench_p.add_argument("--sbox", default="both", help="S-Box mode (table/computed/both)")

    subparsers.add_parser("demo", help="Run end-to-end quick demo")
    subparsers.add_parser("package", help="Package compiled binary to dist/ with SHA256")

    args = parser.parse_args()

    if not args.command:
        interactive_loop()
        return 0

    if args.command == "build":
        return 0 if cmd_build(clean=args.clean, build_type=args.type) else 1
    elif args.command == "test":
        return 0 if cmd_test() else 1
    elif args.command == "kat":
        return 0 if cmd_kat() else 1
    elif args.command == "cross-val":
        return 0 if cmd_cross_val() else 1
    elif args.command == "bench":
        return 0 if cmd_bench(sizes=args.sizes, runs=args.runs, sbox=args.sbox) else 1
    elif args.command == "demo":
        return 0 if cmd_demo() else 1
    elif args.command == "package":
        return 0 if cmd_package() else 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
