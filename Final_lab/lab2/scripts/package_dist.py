#!/usr/bin/env python3
"""
Packaging script: copies compiled binary into dist/ directory with SHA-256 checksum.
"""

import os
import sys
import hashlib
import shutil
import platform

def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dist_dir = os.path.join(repo_root, "dist")
    os.makedirs(dist_dir, exist_ok=True)

    current_os = platform.system().lower()

    if "windows" in current_os:
        target_dir = os.path.join(dist_dir, "windows-x86_64")
        other_dir  = os.path.join(dist_dir, "linux-x86_64")
        binary_name = "aestool.exe"
        candidates = [
            os.path.join(repo_root, "build", "bin", "Release", binary_name),
            os.path.join(repo_root, "build", "bin", binary_name),
            os.path.join(repo_root, "bin", "Release", binary_name),
            os.path.join(repo_root, "bin", binary_name)
        ]
    else:
        target_dir = os.path.join(dist_dir, "linux-x86_64")
        other_dir  = os.path.join(dist_dir, "windows-x86_64")
        binary_name = "aestool"
        candidates = [
            os.path.join(repo_root, "build", "bin", binary_name),
            os.path.join(repo_root, "bin", binary_name)
        ]

    os.makedirs(target_dir, exist_ok=True)
    os.makedirs(other_dir, exist_ok=True)

    found_binary = None
    for c in candidates:
        if os.path.exists(c):
            found_binary = c
            break

    if not found_binary:
        print(f"[ERROR] Could not find compiled binary '{binary_name}'. Please build the project first.", file=sys.stderr)
        return 1

    dest_binary = os.path.join(target_dir, binary_name)
    shutil.copy2(found_binary, dest_binary)
    print(f"[PACKAGE] Copied {found_binary} -> {dest_binary}")

    chk = sha256_file(dest_binary)
    checksum_file = dest_binary + ".sha256"
    with open(checksum_file, "w", encoding="utf-8") as f:
        f.write(f"{chk}  {binary_name}\n")
    print(f"[PACKAGE] Generated {checksum_file}: {chk}")

    # Note for the other OS if missing
    other_binary_name = "aestool" if "windows" in current_os else "aestool.exe"
    other_binary_path = os.path.join(other_dir, other_binary_name)
    if not os.path.exists(other_binary_path):
        readme_missing = os.path.join(other_dir, "README_MISSING.txt")
        with open(readme_missing, "w", encoding="utf-8") as f:
            f.write(
                f"Binary {other_binary_name} was not built locally on this system because "
                f"the build was performed on native {platform.system()} ({platform.platform()}).\n\n"
                f"To build {other_binary_name} on its native platform:\n"
                f"1. Clone the repository\n"
                f"2. mkdir build && cd build\n"
                f"3. cmake .. -DCMAKE_BUILD_TYPE=Release\n"
                f"4. cmake --build . --config Release\n"
                f"5. python ../scripts/package_dist.py\n\n"
                f"Alternatively, check GitHub Actions CI artifacts for automated cross-platform releases.\n"
            )
        print(f"[PACKAGE] Created {readme_missing} explaining native build instructions.")

    print("[SUCCESS] Distribution package completed successfully.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
