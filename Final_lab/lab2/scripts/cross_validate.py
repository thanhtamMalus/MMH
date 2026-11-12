#!/usr/bin/env python3
"""
Cross-validation script: compares AES-128-CTR output of aestool against the
OpenSSL *command-line tool* (never linked into aestool).

Works on Windows, Linux and macOS, and targets OpenSSL >= 4.0 by default.

Exit codes (compatible with CTest SKIP_RETURN_CODE 77):
    0   all comparisons matched
    1   mismatch / runtime failure
    77  SKIPPED (no suitable OpenSSL CLI found, or version below --min-version)

How the OpenSSL executable is located (first usable match wins):
    1. --openssl <path-or-name>          (explicit, authoritative)
    2. env OPENSSL_EXECUTABLE            (full path to openssl / openssl.exe)
    3. env OPENSSL_ROOT_DIR              (<root>/bin/openssl[.exe])
    4. "openssl" found on PATH
    5. well-known install folders (Windows installers, Git for Windows, MSYS2,
       vcpkg, FireDaemon, /usr/local, /opt, ~/.local, Homebrew)
Candidates older than --min-version are passed over in favour of a newer one.
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_SKIP = 77

DEFAULT_MIN_VERSION = "4.0"
IS_WINDOWS = os.name == "nt"
EXE = ".exe" if IS_WINDOWS else ""


# --------------------------------------------------------------------------- #
# OpenSSL discovery
# --------------------------------------------------------------------------- #
def parse_version_tuple(text):
    """'4.0' -> (4, 0, 0); '4.0.2' -> (4, 0, 2)."""
    parts = [int(p) for p in re.findall(r"\d+", text)[:3]]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def parse_openssl_version(output):
    """Return (major, minor, patch) for genuine OpenSSL, or None (e.g. LibreSSL)."""
    m = re.match(r"\s*OpenSSL\s+(\d+)\.(\d+)(?:\.(\d+))?", output)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def runtime_env_for(exe_path):
    """
    Environment so a *relocated* OpenSSL (installed under a custom prefix such
    as ~/.local/openssl-4.0) can find its own libcrypto/libssl.
    Needed on Linux/macOS; harmless elsewhere.
    """
    env = os.environ.copy()
    exe_dir = os.path.dirname(os.path.abspath(exe_path))
    if IS_WINDOWS:
        # DLLs (libcrypto-4-x64.dll) normally sit next to openssl.exe.
        env["PATH"] = exe_dir + os.pathsep + env.get("PATH", "")
        return env

    prefix = os.path.dirname(exe_dir)
    lib_dirs = [d for d in (os.path.join(prefix, "lib64"),
                            os.path.join(prefix, "lib"),
                            os.path.join(prefix, "lib", "x86_64-linux-gnu"))
                if os.path.isdir(d)]
    if lib_dirs:
        var = "DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"
        old = env.get(var, "")
        env[var] = os.pathsep.join(lib_dirs + ([old] if old else []))
    return env


def probe_openssl(candidate):
    """Run '<candidate> version'. Return (path, env, version_text, version_tuple) or None."""
    resolved = shutil.which(candidate) or (candidate if os.path.isfile(candidate) else None)
    if not resolved:
        return None
    env = runtime_env_for(resolved)
    try:
        res = subprocess.run([resolved, "version"], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    text = res.stdout.decode("utf-8", errors="ignore").strip()
    return resolved, env, text, parse_openssl_version(text)


def well_known_candidates():
    c = []
    if IS_WINDOWS:
        roots = {os.environ.get("ProgramFiles", r"C:\Program Files"),
                 os.environ.get("ProgramW6432", r"C:\Program Files"),
                 os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")}
        for r in sorted(roots):
            c += sorted(glob.glob(os.path.join(r, "OpenSSL*", "bin", "openssl.exe")), reverse=True)
            c += sorted(glob.glob(os.path.join(r, "FireDaemon OpenSSL*", "bin", "openssl.exe")), reverse=True)
            c.append(os.path.join(r, "Git", "usr", "bin", "openssl.exe"))
            c.append(os.path.join(r, "Git", "mingw64", "bin", "openssl.exe"))
        for msys in (r"C:\msys64", r"C:\msys32"):
            for sub in ("ucrt64", "mingw64", "clang64", "usr"):
                c.append(os.path.join(msys, sub, "bin", "openssl.exe"))
        vcpkg = os.environ.get("VCPKG_ROOT")
        if vcpkg:
            c += glob.glob(os.path.join(vcpkg, "installed", "*", "tools", "openssl", "openssl.exe"))
        c.append(os.path.join(os.path.expanduser("~"), "scoop", "apps", "openssl", "current", "bin", "openssl.exe"))
    else:
        home = os.path.expanduser("~")
        c += ["/usr/local/bin/openssl", "/usr/local/ssl/bin/openssl"]
        c += sorted(glob.glob("/opt/openssl*/bin/openssl"), reverse=True)
        c += sorted(glob.glob(os.path.join(home, ".local", "openssl*", "bin", "openssl")), reverse=True)
        c += sorted(glob.glob(os.path.join(home, "openssl*", "bin", "openssl")), reverse=True)
        c += sorted(glob.glob("/opt/homebrew/opt/openssl@*/bin/openssl"), reverse=True)
        c += sorted(glob.glob("/usr/local/opt/openssl@*/bin/openssl"), reverse=True)
    return c


def find_openssl(explicit, min_version):
    """
    Returns (found, best_seen). `found` is a probe tuple meeting min_version
    (or None); `best_seen` is the newest genuine-OpenSSL probe (for messages).
    """
    user_given = bool(explicit) and explicit != "openssl"
    ordered = []
    if user_given:
        ordered.append(explicit)          # authoritative: no silent fallback
    else:
        if os.environ.get("OPENSSL_EXECUTABLE"):
            ordered.append(os.environ["OPENSSL_EXECUTABLE"])
        if os.environ.get("OPENSSL_ROOT_DIR"):
            ordered.append(os.path.join(os.environ["OPENSSL_ROOT_DIR"], "bin", "openssl" + EXE))
        ordered.append("openssl")
        ordered += well_known_candidates()

    seen, best = set(), None
    for cand in ordered:
        probe = probe_openssl(cand)
        if not probe:
            continue
        key = os.path.normcase(os.path.realpath(probe[0]))
        if key in seen:
            continue
        seen.add(key)
        ver = probe[3]
        if ver is None:
            continue  # LibreSSL / unknown flavour
        if best is None or ver > best[3]:
            best = probe
        if ver >= min_version:
            return probe, best
    return None, best


# --------------------------------------------------------------------------- #
# Test body
# --------------------------------------------------------------------------- #
def run_command(cmd_args, env=None):
    result = subprocess.run(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    return result.returncode, result.stdout, result.stderr


def autodetect_aestool():
    candidates = [
        "bin/aestool", "bin/aestool.exe",
        "bin/Release/aestool.exe", "bin/Debug/aestool.exe",
        "build/bin/aestool", "build/bin/aestool.exe",
        "build/bin/Release/aestool.exe", "build/bin/Debug/aestool.exe",
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)
    return ""


def main():
    parser = argparse.ArgumentParser(description="Cross-validation against OpenSSL CLI")
    parser.add_argument("--aestool", default="", help="Path to aestool binary")
    parser.add_argument("--openssl", default="openssl",
                        help="Path or name of openssl executable (default: auto-detect)")
    parser.add_argument("--min-version", default=DEFAULT_MIN_VERSION,
                        help="Minimum OpenSSL version required (default: %(default)s). "
                             "Use 0 to accept any OpenSSL.")
    args = parser.parse_args()
    min_version = parse_version_tuple(args.min_version)
    min_text = args.min_version

    aestool_path = args.aestool or autodetect_aestool()
    if not aestool_path or not os.path.exists(aestool_path):
        print(f"[ERROR] Cannot find aestool executable at '{aestool_path}'.", file=sys.stderr)
        return EXIT_FAIL

    found, best = find_openssl(args.openssl, min_version)
    if found is None:
        if best is None:
            print(f"[SKIP] No OpenSSL command-line tool found (need OpenSSL >= {min_text}). "
                  "Cross-validation NOT executed.")
        else:
            print(f"[SKIP] Newest OpenSSL found is '{best[2]}' at {best[0]}, "
                  f"but OpenSSL >= {min_text} is required. Cross-validation NOT executed.")
        print("       Install OpenSSL >= 4.0 (see README, section 5.7) or point to it with\n"
              "       --openssl <path> / env OPENSSL_EXECUTABLE. "
              "Use --min-version 3.0 to accept older releases.")
        return EXIT_SKIP

    openssl_path, ossl_env, openssl_version, _ = found
    print("=" * 60)
    print("Cross-Validation: aestool vs OpenSSL")
    print(f"aestool: {aestool_path}")
    print(f"OpenSSL: {openssl_version}")
    print(f"Binary : {openssl_path}")
    print("=" * 60)

    test_sizes = [0, 1, 15, 16, 17, 31, 32, 33, 1000, 65536, 1024 * 1024]  # up to 1 MiB
    temp_dir = tempfile.mkdtemp(prefix="aes_cross_val_")
    all_passed = True

    try:
        for idx, size in enumerate(test_sizes):
            key = os.urandom(16)
            iv = os.urandom(16)
            msg = os.urandom(size) if size > 0 else b""

            key_file = os.path.join(temp_dir, f"k_{idx}.bin")
            iv_file = os.path.join(temp_dir, f"iv_{idx}.bin")
            msg_file = os.path.join(temp_dir, f"msg_{idx}.bin")
            openssl_out = os.path.join(temp_dir, f"openssl_{idx}.bin")
            aestool_out = os.path.join(temp_dir, f"aestool_{idx}.bin")
            decrypted_out = os.path.join(temp_dir, f"dec_{idx}.bin")

            with open(key_file, "wb") as f:
                f.write(key)
            with open(iv_file, "wb") as f:
                f.write(iv)
            with open(msg_file, "wb") as f:
                f.write(msg)

            # 1. OpenSSL reference: openssl enc -aes-128-ctr -K <hex> -iv <hex> -in msg -out ref
            rc_ossl, _, err_ossl = run_command([
                openssl_path, "enc", "-aes-128-ctr",
                "-K", key.hex(), "-iv", iv.hex(),
                "-in", msg_file, "-out", openssl_out,
            ], env=ossl_env)
            if rc_ossl != 0:
                print(f"[FAIL] OpenSSL error on size {size}: {err_ossl.decode('utf-8', errors='ignore')}")
                all_passed = False
                continue

            # 2. aestool encrypt
            rc_aes, _, err_aes = run_command([
                aestool_path, "encrypt", "--mode", "ctr",
                "--key", key_file, "--iv", iv_file,
                "--in", msg_file, "--out", aestool_out,
            ])
            if rc_aes != 0:
                print(f"[FAIL] aestool error on size {size}: {err_aes.decode('utf-8', errors='ignore')}")
                all_passed = False
                continue

            # 3. Compare ciphertext bytes
            with open(openssl_out, "rb") as f:
                ossl_data = f.read()
            with open(aestool_out, "rb") as f:
                aes_data = f.read()
            if ossl_data != aes_data:
                print(f"[FAIL] Size {size}: Ciphertext mismatch! "
                      f"(OpenSSL len: {len(ossl_data)}, aestool len: {len(aes_data)})")
                all_passed = False
                continue

            # 4. aestool decrypt must give back the plaintext
            rc_dec, _, err_dec = run_command([
                aestool_path, "decrypt", "--mode", "ctr",
                "--key", key_file, "--iv", iv_file,
                "--in", aestool_out, "--out", decrypted_out,
            ])
            if rc_dec != 0 or not os.path.exists(decrypted_out):
                print(f"[FAIL] aestool decrypt error on size {size}: {err_dec.decode('utf-8', errors='ignore')}")
                all_passed = False
                continue
            with open(decrypted_out, "rb") as f:
                dec_data = f.read()
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
        return EXIT_OK
    print("[FAILURE] Cross-validation failed!")
    return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
