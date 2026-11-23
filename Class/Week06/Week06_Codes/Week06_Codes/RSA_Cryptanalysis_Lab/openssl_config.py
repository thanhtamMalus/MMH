"""
openssl_config.py
=================

Shared OpenSSL configuration module for the RSA Cryptanalysis Laboratory.

Purpose
-------
All RSA demonstration scripts import this module instead of duplicating
OpenSSL paths and subprocess logic.

Students normally need to edit only:

    OPENSSL_BIN
    OPENSSL_CONF

Examples
--------
Windows:
    OPENSSL_BIN  = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
    OPENSSL_CONF = r"C:\Program Files\OpenSSL-Win64\bin\openssl.cfg"

Linux:
    OPENSSL_BIN  = "/usr/bin/openssl"
    OPENSSL_CONF = "/etc/ssl/openssl.cnf"

macOS (Homebrew examples):
    OPENSSL_BIN  = "/opt/homebrew/bin/openssl"
    OPENSSL_CONF = "/opt/homebrew/etc/openssl@3/openssl.cnf"

Usage
-----
    from openssl_config import run_openssl, print_openssl_info

    print_openssl_info()

    run_openssl([
        "genpkey",
        "-algorithm", "RSA",
        "-pkeyopt", "rsa_keygen_bits:2048",
        "-out", "private.pem"
    ])
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Optional, Union


# =====================================================================
# 1. OPENSSL PATHS
# =====================================================================

if os.name == "nt":
    # Windows — change these paths if OpenSSL is installed elsewhere.
    OPENSSL_BIN = Path(
        r"D:\\msys64\\mingw64\\bin\\openssl.exe"
    )
    OPENSSL_CONF = Path(
        r"D:\\msys64\\usr\\ssl\\openssl.cnf"
    )

elif sys.platform == "darwin":
    # macOS — common Homebrew paths.
    OPENSSL_BIN = Path("/opt/homebrew/bin/openssl")
    OPENSSL_CONF = Path(
        "/opt/homebrew/etc/openssl@3/openssl.cnf"
    )

else:
    # Linux — common system paths.
    OPENSSL_BIN = Path("/usr/bin/openssl")
    OPENSSL_CONF = Path("/etc/ssl/openssl.cnf")


# =====================================================================
# 2. LAB DEFAULTS
# =====================================================================

LAB_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = LAB_ROOT / "output"

DEFAULT_RSA_BITS = 2048
DEFAULT_PUBLIC_EXPONENT = 65537

# Standard algorithms used by the secure comparison experiments.
DEFAULT_HASH = "sha256"
DEFAULT_OAEP_HASH = "sha256"
DEFAULT_MGF1_HASH = "sha256"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# =====================================================================
# 3. PATH DISCOVERY
# =====================================================================

def find_openssl() -> Path:
    """
    Return a usable OpenSSL executable.

    Priority:
        1. Explicit OPENSSL_BIN above
        2. 'openssl' found in the operating-system PATH
    """
    if OPENSSL_BIN.is_file():
        return OPENSSL_BIN

    discovered = shutil.which("openssl")
    if discovered:
        return Path(discovered)

    raise FileNotFoundError(
        "\nOpenSSL executable was not found.\n\n"
        f"Configured path:\n  {OPENSSL_BIN}\n\n"
        "Install OpenSSL or edit OPENSSL_BIN in openssl_config.py."
    )


def find_config() -> Optional[Path]:
    """
    Return the configured OpenSSL configuration file if it exists.

    The configuration path is explicit for reproducibility, but some
    OpenSSL installations can operate without manually setting it.
    """
    if OPENSSL_CONF.is_file():
        return OPENSSL_CONF

    return None


# =====================================================================
# 4. OPENSSL ENVIRONMENT
# =====================================================================

def openssl_environment() -> dict[str, str]:
    """
    Build the environment used for every OpenSSL subprocess.

    OPENSSL_CONF is explicitly supplied when the configured file exists.
    """
    env = os.environ.copy()

    conf = find_config()
    if conf is not None:
        env["OPENSSL_CONF"] = str(conf)

    return env


# =====================================================================
# 5. COMMON OPENSSL RUNNER
# =====================================================================

PathLike = Union[str, Path]


def run_openssl(
    args: Iterable[PathLike],
    *,
    input_bytes: Optional[bytes] = None,
    check: bool = True,
    capture_output: bool = True,
    verbose: bool = True,
) -> subprocess.CompletedProcess:
    """
    Execute an OpenSSL command using the common laboratory configuration.

    Parameters
    ----------
    args:
        OpenSSL arguments WITHOUT the executable name.

        Example:
            ["version", "-a"]

    input_bytes:
        Optional binary data supplied to stdin.

    check:
        Raise RuntimeError when OpenSSL returns a non-zero exit status.

    capture_output:
        Capture stdout/stderr. Normally True for laboratory scripts.

    verbose:
        Print the exact command and OPENSSL_CONF path.

    Returns
    -------
    subprocess.CompletedProcess
        stdout and stderr are bytes when capture_output=True.
    """

    openssl = find_openssl()

    command = [str(openssl)] + [str(arg) for arg in args]
    env = openssl_environment()

    if verbose:
        print("\n[OpenSSL command]")
        print(subprocess.list2cmdline(command))

        conf = env.get("OPENSSL_CONF")
        if conf:
            print(f"OPENSSL_CONF={conf}")
        else:
            print(
                "OPENSSL_CONF=<not explicitly set "
                "(configured file not found)>"
            )

    result = subprocess.run(
        command,
        input=input_bytes,
        stdout=subprocess.PIPE if capture_output else None,
        stderr=subprocess.PIPE if capture_output else None,
        env=env,
        check=False,
    )

    if check and result.returncode != 0:
        stderr = ""
        if result.stderr:
            stderr = result.stderr.decode(
                "utf-8", errors="replace"
            )

        raise RuntimeError(
            "\nOpenSSL command failed.\n"
            f"Exit code: {result.returncode}\n"
            f"Command: {subprocess.list2cmdline(command)}\n"
            f"stderr:\n{stderr}"
        )

    return result


# =====================================================================
# 6. TEXT HELPER
# =====================================================================

def run_openssl_text(
    args: Iterable[PathLike],
    *,
    input_text: Optional[str] = None,
    check: bool = True,
    verbose: bool = True,
) -> str:
    """
    Convenience wrapper for OpenSSL commands that return textual output.
    """
    data = None
    if input_text is not None:
        data = input_text.encode("utf-8")

    result = run_openssl(
        args,
        input_bytes=data,
        check=check,
        capture_output=True,
        verbose=verbose,
    )

    return result.stdout.decode("utf-8", errors="replace")


# =====================================================================
# 7. INSTALLATION / VERSION INFORMATION
# =====================================================================

def get_openssl_version() -> str:
    """Return the first line of 'openssl version -a'."""
    text = run_openssl_text(
        ["version", "-a"],
        verbose=False,
    )
    return text.splitlines()[0] if text else "Unknown"


def print_openssl_info() -> None:
    """Print the common laboratory OpenSSL configuration."""
    print("=" * 72)
    print("RSA CRYPTANALYSIS LAB — OPENSSL CONFIGURATION")
    print("=" * 72)

    try:
        executable = find_openssl()
        print(f"OpenSSL executable : {executable}")
    except FileNotFoundError as exc:
        print(exc)
        return

    config = find_config()

    print(
        "OpenSSL config     : "
        + (str(config) if config else "not found / not explicitly set")
    )
    print(f"OpenSSL version    : {get_openssl_version()}")
    print(f"Lab root           : {LAB_ROOT}")
    print(f"Output directory   : {OUTPUT_DIR}")
    print(f"Default RSA bits   : {DEFAULT_RSA_BITS}")
    print(f"Public exponent    : {DEFAULT_PUBLIC_EXPONENT}")
    print(f"Default hash       : {DEFAULT_HASH}")
    print("=" * 72)


# =====================================================================
# 8. SIMPLE KEY HELPERS
# =====================================================================

def generate_rsa_keypair(
    private_key: PathLike,
    public_key: PathLike,
    *,
    bits: int = DEFAULT_RSA_BITS,
    verbose: bool = True,
) -> tuple[Path, Path]:
    """
    Generate a real RSA private key and extract the corresponding public key.

    This helper is for normal OpenSSL-generated comparison/control keys.
    Individual cryptanalysis labs may deliberately construct vulnerable
    parameters separately.
    """
    private_key = Path(private_key)
    public_key = Path(public_key)

    private_key.parent.mkdir(parents=True, exist_ok=True)
    public_key.parent.mkdir(parents=True, exist_ok=True)

    run_openssl(
        [
            "genpkey",
            "-algorithm", "RSA",
            "-pkeyopt", f"rsa_keygen_bits:{bits}",
            "-out", private_key,
        ],
        verbose=verbose,
    )

    run_openssl(
        [
            "pkey",
            "-in", private_key,
            "-pubout",
            "-out", public_key,
        ],
        verbose=verbose,
    )

    return private_key, public_key


def verify_private_key(
    private_key: PathLike,
    *,
    verbose: bool = True,
) -> bool:
    """Ask OpenSSL to check the internal consistency of a private key."""
    result = run_openssl(
        [
            "pkey",
            "-in", private_key,
            "-check",
            "-noout",
        ],
        check=False,
        verbose=verbose,
    )

    return result.returncode == 0


def inspect_public_key(
    public_key: PathLike,
    *,
    verbose: bool = True,
) -> str:
    """Return OpenSSL's textual representation of an RSA public key."""
    return run_openssl_text(
        [
            "pkey",
            "-pubin",
            "-in", public_key,
            "-text",
            "-noout",
        ],
        verbose=verbose,
    )


def inspect_private_key(
    private_key: PathLike,
    *,
    verbose: bool = True,
) -> str:
    """Return OpenSSL's textual representation of RSA private components."""
    return run_openssl_text(
        [
            "pkey",
            "-in", private_key,
            "-text",
            "-noout",
        ],
        verbose=verbose,
    )


# =====================================================================
# 9. SELF-TEST
# =====================================================================

def self_test() -> None:
    """
    Verify the OpenSSL configuration.

    No key is generated during this self-test.
    """
    print_openssl_info()

    try:
        result = run_openssl(
            ["version", "-a"],
            verbose=True,
        )

        print("\n[OpenSSL output]")
        print(
            result.stdout.decode(
                "utf-8", errors="replace"
            )
        )

        print("[RESULT] OpenSSL configuration: OK")

    except Exception as exc:
        print("\n[RESULT] OpenSSL configuration: FAILED")
        print(exc)
        raise


if __name__ == "__main__":
    self_test()
