#!/usr/bin/env python3
"""aestool - one window, three tabs:  [Self-test]  [Encrypt]  [Decrypt]

All cryptography is done by the compiled library (libaescore.so / aescore.dll) through
ctypes - nothing is re-implemented here.

Supported AES modes (exactly the ones implemented in src/aescore.cpp):
    ecb  cbc  ofb  cfb  ctr  xts   (confidentiality only)
    ccm  gcm                       (AEAD: authentication tag + optional AAD)

Run:   python3 aestool_gui_tabs.py                        GUI
       python3 aestool_gui_tabs.py --selftest             no window, full test-suite
       python3 aestool_gui_tabs.py --selftest --mode gcm,cbc --quick -v --report out.txt
       AESCORE_LIB=/path/to/libaescore.so                 to point at a specific library

Exit code of --selftest: 0 = every test passed, 1 = something failed.
"""
import ctypes
import json
import os
import queue
import random
import shutil
import subprocess
import sys
import threading
import time

try:                                    # headless machines: the CLI self-test still works
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import filedialog, messagebox, simpledialog, ttk
except ImportError:                     # pragma: no cover
    tk = None

HERE = os.path.dirname(os.path.abspath(__file__))
# The script may live in the project root (CMakeLists.txt next to it) or in a gui/ sub-folder.
ROOT = HERE if os.path.isfile(os.path.join(HERE, "CMakeLists.txt")) else os.path.dirname(HERE)


# name -> (is_aead, allowed key sizes in bits, IV/nonce description)
# Must stay in sync with valid_key_len()/valid_iv_len() in src/aescore.cpp.
MODE_INFO = {
    "gcm": (True,  (256, 192, 128), "AEAD - 12-byte nonce, 16-byte tag (random nonce is generated)"),
    "ccm": (True,  (256, 192, 128), "AEAD - 12-byte nonce, 16-byte tag (random nonce is generated)"),
    "ctr": (False, (256, 192, 128), "16-byte counter block (random). NO authentication"),
    "cbc": (False, (256, 192, 128), "16-byte IV (random), PKCS#7 padding. NO authentication"),
    "cfb": (False, (256, 192, 128), "16-byte IV (random). NO authentication"),
    "ofb": (False, (256, 192, 128), "16-byte IV (random). NO authentication"),
    "xts": (False, (512, 256),      "16-byte tweak (random). Key = 2 AES keys (256 or 512 bit), min. 16 bytes of data"),
    "ecb": (False, (256, 192, 128), "no IV. INSECURE - identical blocks give identical ciphertext"),
}
MODES = list(MODE_INFO)

RC_AUTH = 2
MODE_BY_ID = {1: "ecb", 2: "cbc", 3: "ofb", 4: "cfb", 5: "ctr", 6: "xts", 7: "ccm", 8: "gcm"}  # enum Mode in aescore.h
MAX_FILE = 512 * 1024 * 1024            # the whole file is loaded in memory


# =====================================================================================
#  Library loading (ctypes) - unchanged logic from the original tools
# =====================================================================================
def _lib_names():
    if os.name == "nt":
        return ["aescore.dll", "libaescore.dll"]
    if sys.platform == "darwin":
        return ["libaescore.dylib"]
    return ["libaescore.so"]


def _search_library():
    env = os.environ.get("AESCORE_LIB")
    if env and os.path.isfile(env):
        return env
    roots = []
    for r in (ROOT, HERE, os.path.dirname(HERE), os.getcwd()):
        if r not in roots:
            roots.append(r)
    dirs = []
    for r in roots:
        dirs += [os.path.join(r, "build", "bin", c) for c in ("", "Release", "Debug")]
        dirs += [os.path.join(r, "build", c) for c in ("", "Release", "Debug")]
        dirs += [os.path.join(r, "bin"), r]
    for d in dirs:
        for n in _lib_names():
            p = os.path.join(d, n)
            if os.path.isfile(p):
                return p
    return None


def _auto_build():
    """Build the project with CMake the first time the GUI is started."""
    if not os.path.isfile(os.path.join(ROOT, "CMakeLists.txt")):
        return
    cmake = shutil.which("cmake")
    if not cmake:
        print("cmake not found in PATH - cannot build automatically.")
        return
    build = os.path.join(ROOT, "build")
    print("aescore library not found - building the project with CMake (first run only)...")
    cfg = [cmake, "-S", ROOT, "-B", build, "-DAESTOOL_BUILD_TESTS=OFF", "-DAESTOOL_BUILD_SHARED=ON"]
    if os.name == "nt" and not os.path.isfile(os.path.join(build, "CMakeCache.txt")):
        # MinGW produces a fully static aescore.dll that Python ctypes can load; MSVC is the fallback.
        if shutil.which("g++") and shutil.which("mingw32-make"):
            cfg += ["-G", "MinGW Makefiles"]
        elif shutil.which("g++") and shutil.which("ninja"):
            cfg += ["-G", "Ninja"]
    try:
        subprocess.run(cfg, check=True)
        subprocess.run([cmake, "--build", build, "--config", "Release", "--target", "aescore_shared"],
                       check=True)
    except (subprocess.CalledProcessError, OSError) as e:
        print("Automatic build failed:", e)


def find_library():
    p = _search_library()
    if p:
        return p
    _auto_build()
    p = _search_library()
    if p:
        return p
    raise FileNotFoundError("aescore library not found and the automatic build failed.\n"
                            "Build manually: cmake -S . -B build && cmake --build build\n"
                            "or set AESCORE_LIB=<path to aescore.dll / libaescore.so>.")


def _preload_cryptopp():
    """libaescore.so needs libcryptopp.so.8. CMake already stores an RPATH to ./crypto_libs/lib,
    this is only a safety net if the project folder was moved after building."""
    if os.name == "nt":
        return
    libdir = os.path.join(ROOT, "crypto_libs", "lib")
    for n in ("libcryptopp.so.8", "libcryptopp.so", "libcryptopp.dylib"):
        p = os.path.join(libdir, n)
        if os.path.isfile(p):
            try:
                ctypes.CDLL(p, mode=ctypes.RTLD_GLOBAL)
                return
            except OSError:
                pass


def load_lib():
    path = find_library()
    dll_dirs = [os.path.dirname(os.path.abspath(path)), os.path.join(ROOT, "crypto_libs", "lib"),
                os.path.join(ROOT, "crypto_libs", "bin"), HERE]
    if os.name == "nt" and hasattr(os, "add_dll_directory"):
        for d in dll_dirs:
            if os.path.isdir(d):
                os.add_dll_directory(d)
    try:
        lib = ctypes.CDLL(path)
    except OSError:
        _preload_cryptopp()
        lib = ctypes.CDLL(path)
    u8p = ctypes.POINTER(ctypes.c_uint8)
    lib.aescore_version.restype = ctypes.c_char_p
    lib.aescore_encrypt.restype = ctypes.c_int
    lib.aescore_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                                    ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                                    ctypes.c_size_t, ctypes.c_int, ctypes.POINTER(u8p),
                                    ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t]
    lib.aescore_decrypt.restype = ctypes.c_int
    lib.aescore_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                                    ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int,
                                    ctypes.POINTER(u8p), ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p,
                                    ctypes.c_size_t]
    lib.aescore_random.restype = ctypes.c_int
    lib.aescore_random.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.aescore_free.restype = None
    lib.aescore_free.argtypes = [u8p]
    return lib


class AuthError(RuntimeError):
    pass


class Core:
    """Thin ctypes wrapper (no UI, usable from tests)."""

    def __init__(self):
        self.lib = load_lib()
        self.path = getattr(self.lib, "_name", "")

    def version(self):
        return self.lib.aescore_version().decode()

    def random(self, n):
        buf = ctypes.create_string_buffer(n)
        if self.lib.aescore_random(buf, n) != 0:
            raise RuntimeError("random generator failed")
        return buf.raw

    def _call(self, fn, *args):
        u8p = ctypes.POINTER(ctypes.c_uint8)
        out = u8p()
        out_len = ctypes.c_size_t(0)
        err = ctypes.create_string_buffer(512)
        rc = fn(*args, ctypes.byref(out), ctypes.byref(out_len), err, 512)
        if rc != 0:
            msg = err.value.decode(errors="replace")
            if rc == RC_AUTH:
                raise AuthError("AUTHENTICATION FAILED - " + msg)
            raise RuntimeError(msg)
        data = ctypes.string_at(out, out_len.value)
        self.lib.aescore_free(out)
        return data

    def encrypt(self, mode, key, data, aad=b"", allow_ecb=False):
        return self._call(self.lib.aescore_encrypt, mode.encode(), key, len(key), None, 0,
                          aad if aad else None, len(aad), data, len(data), int(allow_ecb))

    def decrypt(self, key, data, aad=b"", mode=None, allow_ecb=False):
        """mode=None: taken from the AEST container header. aad empty: AAD taken from the header."""
        return self._call(self.lib.aescore_decrypt, mode.encode() if mode else None, key, len(key),
                          aad if aad else None, len(aad), data, len(data), int(allow_ecb))


def container_mode(data):
    """Mode stored in an AEST container header (or None if it is not one)."""
    if len(data) >= 6 and data[:4] == b"AEST":
        return MODE_BY_ID.get(data[5])
    return None


def check_key(mode, key):
    bits = len(key) * 8
    if bits not in MODE_INFO[mode][1]:
        want = " or ".join(str(b // 8) for b in sorted(MODE_INFO[mode][1])) + " bytes"
        raise ValueError(f"{mode.upper()} needs a key of {want} "
                         f"({' / '.join(str(b // 4) for b in sorted(MODE_INFO[mode][1]))} hex digits); "
                         f"yours is {len(key)} bytes")


# =====================================================================================
#  Key vault (plain JSON in the home folder, as in the original GUI)
# =====================================================================================
KEYFILE = os.path.join(os.path.expanduser("~"), ".aestool_keys.json")


def load_keys():
    try:
        with open(KEYFILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def store_keys(d):
    with open(KEYFILE, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    try:
        os.chmod(KEYFILE, 0o600)
    except OSError:
        pass


# =====================================================================================
#  SELF-TEST SUITE  (pure Python, no UI - used by the CLI and by the Self-test tab)
# =====================================================================================
MSG = ("Xin chào – AES self-test ✓ ".encode("utf-8")) * 5        # multi-byte UTF-8 payload
MSG48 = bytes(range(48))                                           # tamper sweep payload
PATTERN = bytes(range(16)) * 8                                     # 8 identical 16-byte blocks
SIZES = (1, 2, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000, 4096)
LONG_AAD = ("Tiêu đề / header ✓ ".encode("utf-8")) * 20


class Skip(Exception):
    """Raised by a test that does not apply to the current mode / library."""


def _errtxt(e):
    s = str(e).strip().splitlines()
    return type(e).__name__ + (": " + s[0][:90] if s else "")


def _expect_error(fn, what):
    """Run fn(); return the exception it raised, FAIL if it was accepted."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return e
    raise AssertionError(f"{what} was accepted but must be rejected")


class Ctx:
    """Per (mode, key size) test context."""

    def __init__(self, core, mode, bits):
        self.core, self.mode, self.bits = core, mode, bits
        self.aead = MODE_INFO[mode][0]
        self.key = core.random(bits // 8)
        self.min_len = 16 if mode == "xts" else 1

    def enc(self, data, aad=b"", key=None, allow_ecb=None):
        if allow_ecb is None:
            allow_ecb = self.mode == "ecb"
        return self.core.encrypt(self.mode, key or self.key, data, aad, allow_ecb)

    def dec(self, ct, aad=b"", key=None, mode=None, allow_ecb=True):
        return self.core.decrypt(key or self.key, ct, aad, mode, allow_ecb)


MODE_TESTS = []     # (name, fn(ctx), applies(mode), slow)
CORE_TESTS = []     # (name, fn(core), slow)


def mode_test(name, applies=None, slow=False):
    def deco(fn):
        MODE_TESTS.append((name, fn, applies or (lambda m: True), slow))
        return fn
    return deco


def core_test(name, slow=False):
    def deco(fn):
        CORE_TESTS.append((name, fn, slow))
        return fn
    return deco


AEAD_ONLY = lambda m: MODE_INFO[m][0]                      # noqa: E731
PLAIN_ONLY = lambda m: not MODE_INFO[m][0]                 # noqa: E731
STREAMLIKE = lambda m: m in ("ctr", "ofb", "cfb", "gcm", "ccm", "xts")   # noqa: E731


# ---------------------------------------------------------------- per-mode tests
@mode_test("Round-trip, 22 sizes 1 B..4 KiB (mode read from header)")
def t_roundtrip_sizes(c):
    done, bad = 0, []
    for n in SIZES:
        if n < c.min_len:
            continue
        pt = os.urandom(n)
        if c.dec(c.enc(pt)) != pt:
            bad.append(n)
        done += 1
    if bad:
        raise AssertionError(f"wrong plaintext for sizes {bad}")
    return f"{done} sizes OK"


@mode_test("Round-trip, mode passed explicitly")
def t_roundtrip_explicit(c):
    if c.dec(c.enc(MSG), mode=c.mode) != MSG:
        raise AssertionError("plaintext differs")


@mode_test("Round-trip, UTF-8 / Vietnamese text")
def t_unicode(c):
    pt = c.dec(c.enc(MSG))
    if pt != MSG:
        raise AssertionError("plaintext differs")
    pt.decode("utf-8")
    return f"{len(MSG)} bytes"


@mode_test("Round-trip, empty input (OK or clean error)", applies=lambda m: m != "xts")
def t_empty(c):
    try:
        ct = c.enc(b"")
    except Exception as e:  # noqa: BLE001
        return "rejected cleanly - " + _errtxt(e)
    if c.dec(ct) != b"":
        raise AssertionError("empty input did not round-trip")
    return "accepted and round-trips"


@mode_test("Round-trip, 1 MiB", slow=True)
def t_large(c):
    pt = os.urandom(1 << 20)
    if c.dec(c.enc(pt)) != pt:
        raise AssertionError("1 MiB plaintext differs")
    return "1 048 576 bytes OK"


@mode_test("Container header: magic 'AEST' + mode id")
def t_header(c):
    ct = c.enc(MSG)
    if ct[:4] != b"AEST":
        raise AssertionError(f"bad magic {ct[:4]!r}")
    got = container_mode(ct)
    if got != c.mode:
        raise AssertionError(f"header says {got}, expected {c.mode}")
    return f"id={ct[5]} -> {got}"


@mode_test("Randomised IV: two encryptions differ", applies=lambda m: m != "ecb")
def t_random_iv(c):
    a, b = c.enc(MSG), c.enc(MSG)
    if a == b:
        raise AssertionError("two encryptions of the same data are identical (IV/nonce reused?)")
    if len(a) != len(b):
        raise AssertionError("container length changes between runs")


@mode_test("ECB is deterministic (no IV)", applies=lambda m: m == "ecb")
def t_ecb_deterministic(c):
    if c.enc(MSG) != c.enc(MSG):
        raise AssertionError("ECB output differs between runs")


@mode_test("Pattern test: repeated plaintext blocks")
def t_pattern(c):
    ct = c.enc(PATTERN)
    leak = any(ct[i:i + 16] == ct[i + 16:i + 32] for i in range(len(ct) - 32))
    if c.mode == "ecb":
        if not leak:
            raise AssertionError("ECB should repeat identical blocks but did not")
        return "repeated blocks visible (ECB is insecure - expected)"
    if leak:
        raise AssertionError("identical plaintext blocks produce identical ciphertext blocks")
    return "no repeated blocks"


@mode_test("Wrong key is not accepted")
def t_wrong_key(c):
    ct = c.enc(MSG)
    k2 = c.core.random(len(c.key))
    if k2 == c.key:
        raise Skip("random key collided")
    if c.aead:
        try:
            c.dec(ct, key=k2)
        except AuthError:
            return "AuthError (tag check failed)"
        except Exception as e:  # noqa: BLE001
            raise AssertionError("expected AuthError, got " + _errtxt(e))
        raise AssertionError("wrong key was accepted")
    try:
        pt = c.dec(ct, key=k2)
    except Exception as e:  # noqa: BLE001
        return "error - " + _errtxt(e)
    if pt == MSG:
        raise AssertionError("wrong key returned the original plaintext")
    return "garbage output (mode has no authentication)"


@mode_test("Wrong key length rejected by the library")
def t_key_len(c):
    n = c.bits // 8
    msgs = []
    for bad in (n - 1, n + 1):
        k = c.core.random(bad)
        msgs.append(_errtxt(_expect_error(lambda k=k: c.core.encrypt(c.mode, k, MSG, b"", True),
                                          f"{bad}-byte key (encrypt)")))
    ct = c.enc(MSG)
    _expect_error(lambda: c.core.decrypt(c.core.random(n + 1), ct, b"", None, True), f"{n + 1}-byte key (decrypt)")
    return f"{n - 1} / {n + 1} byte keys rejected"


@mode_test("Explicit wrong mode never returns the plaintext")
def t_cross_mode(c):
    cands = [m for m in MODES if m != c.mode and c.bits in MODE_INFO[m][1]]
    if not cands:
        raise Skip("no other mode takes this key size")
    other = cands[0]
    ct = c.enc(MSG)
    try:
        pt = c.dec(ct, mode=other)
    except Exception as e:  # noqa: BLE001
        return f"as {other.upper()}: rejected - {_errtxt(e)}"
    if pt == MSG:
        raise AssertionError(f"{c.mode.upper()} container decrypted as {other.upper()} gave the plaintext")
    return f"as {other.upper()}: garbage output"


@mode_test("Bad magic / truncated header rejected")
def t_bad_container(c):
    ct = c.enc(MSG)
    _expect_error(lambda: c.dec(b"XXXX" + ct[4:]), "bad magic")
    _expect_error(lambda: c.dec(ct[:3]), "3-byte input")
    _expect_error(lambda: c.dec(b""), "empty input")
    _expect_error(lambda: c.dec(os.urandom(64)), "random bytes")
    return "4 malformed inputs rejected"


@mode_test("Truncated container (half) never yields the plaintext")
def t_truncated(c):
    ct = c.enc(MSG)
    try:
        pt = c.dec(ct[:len(ct) // 2])
    except Exception as e:  # noqa: BLE001
        return "rejected - " + _errtxt(e)
    if c.aead:
        raise AssertionError("truncated AEAD container was accepted")
    if pt == MSG:
        raise AssertionError("truncated container returned the full plaintext")
    return "shorter / garbage output (mode has no authentication)"


@mode_test("Ciphertext length / padding behaviour", applies=lambda m: m == "cbc" or STREAMLIKE(m))
def t_lengths(c):
    L = lambda n: len(c.enc(os.urandom(n)))   # noqa: E731
    if c.mode == "cbc":                       # PKCS#7: 1..15 -> one block, 16 -> two blocks
        a, b, d = L(1), L(15), L(16)
        if not (a == b and d == a + 16):
            raise AssertionError(f"len(1)={a} len(15)={b} len(16)={d}: not PKCS#7 block padding")
        return "padded to 16-byte blocks (PKCS#7)"
    a, b = L(20), L(21)
    if b != a + 1:
        raise AssertionError(f"len(20)={a}, len(21)={b}: expected +1 byte (no padding)")
    return "length-preserving (+1 byte per byte)"


@mode_test("Bit-flip in ciphertext changes the output", applies=PLAIN_ONLY)
def t_bitflip_plain(c):
    ct = bytearray(c.enc(MSG))
    ct[-1] ^= 1
    try:
        pt = c.dec(bytes(ct))
    except Exception as e:  # noqa: BLE001
        return "error - " + _errtxt(e)
    if pt == MSG:
        raise AssertionError("modified ciphertext still decrypts to the same plaintext")
    return "plaintext differs (no integrity protection in this mode)"


@mode_test("XTS rejects data shorter than 16 bytes", applies=lambda m: m == "xts")
def t_xts_short(c):
    _expect_error(lambda: c.enc(os.urandom(15)), "15-byte XTS input")
    c.dec(c.enc(os.urandom(16)))
    return "15 B rejected, 16 B accepted"


@mode_test("ECB > 16 KiB refused unless explicitly allowed", applies=lambda m: m == "ecb")
def t_ecb_limit(c):
    big = os.urandom(20000)
    _expect_error(lambda: c.enc(big, allow_ecb=False), "20 000-byte ECB input without the allow flag")
    if c.dec(c.enc(big, allow_ecb=True)) != big:
        raise AssertionError("ECB 20 000 bytes with the flag does not round-trip")
    return "refused without flag, round-trips with flag"


# AEAD only
@mode_test("Tamper: last byte (tag) -> AuthError", applies=AEAD_ONLY)
def t_tamper_tag(c):
    ct = bytearray(c.enc(MSG))
    ct[-1] ^= 1
    try:
        c.dec(bytes(ct))
    except AuthError:
        return "AuthError"
    except Exception as e:  # noqa: BLE001
        raise AssertionError("expected AuthError, got " + _errtxt(e))
    raise AssertionError("tampered tag was accepted")


@mode_test("Tamper sweep: flip every byte of ciphertext+tag", applies=AEAD_ONLY)
def t_tamper_sweep(c):
    ct = c.enc(MSG48)
    start = len(ct) - (len(MSG48) + 16)
    accepted = []
    for i in range(start, len(ct)):
        bad = bytearray(ct)
        bad[i] ^= 0x01
        try:
            c.dec(bytes(bad))
            accepted.append(i)
        except Exception:  # noqa: BLE001
            pass
    if accepted:
        raise AssertionError(f"{len(accepted)} tampered positions accepted, e.g. offsets {accepted[:5]}")
    return f"{len(ct) - start} single-bit flips, all rejected"


@mode_test("AAD: bound to the data (header / explicit / wrong)", applies=AEAD_ONLY)
def t_aad(c):
    aad = b"header-v1"
    ct = c.enc(MSG, aad)
    if c.dec(ct) != MSG:
        raise AssertionError("AAD stored in the header was not used")
    if c.dec(ct, aad) != MSG:
        raise AssertionError("explicit correct AAD failed")
    _expect_error(lambda: c.dec(ct, b"header-v2"), "wrong AAD")
    return "header AAD OK, explicit AAD OK, wrong AAD rejected"


@mode_test("AAD: long UTF-8 AAD (~500 B)", applies=AEAD_ONLY)
def t_aad_long(c):
    ct = c.enc(MSG, LONG_AAD)
    if c.dec(ct) != MSG or c.dec(ct, LONG_AAD) != MSG:
        raise AssertionError("long AAD does not round-trip")
    _expect_error(lambda: c.dec(ct, LONG_AAD[:-1] + b"X"), "modified long AAD")
    return f"{len(LONG_AAD)}-byte AAD OK"


# ---------------------------------------------------------------- library-wide tests
@core_test("Library loaded, version string present")
def tc_version(core):
    v = core.version()
    if not v:
        raise AssertionError("empty version string")
    return f"{v}  [{core.path}]"


@core_test("Random: requested lengths 1 / 16 / 32 / 64 / 1024")
def tc_random_len(core):
    for n in (1, 16, 32, 64, 1024):
        if len(core.random(n)) != n:
            raise AssertionError(f"random({n}) returned a different length")


@core_test("Random: successive draws differ and are not all zero")
def tc_random_diff(core):
    a, b = core.random(32), core.random(32)
    if a == b:
        raise AssertionError("two 32-byte draws are identical")
    if not any(a):
        raise AssertionError("draw is all zero")


@core_test("Random: 4096 bytes contain >= 240 distinct byte values")
def tc_random_spread(core):
    n = len(set(core.random(4096)))
    if n < 240:
        raise AssertionError(f"only {n} distinct byte values - generator looks biased")
    return f"{n} / 256 distinct"


@core_test("container_mode(): all 8 ids mapped, junk rejected")
def tc_container_mode(core):
    for i, m in MODE_BY_ID.items():
        if container_mode(b"AEST\x01" + bytes([i]) + b"\0" * 8) != m:
            raise AssertionError(f"id {i} should map to {m}")
    for junk in (b"", b"AEST", b"AEST\x01", b"XXXX\x01\x08", b"AEST\x01\x00", b"AEST\x01\x63"):
        if container_mode(junk) is not None:
            raise AssertionError(f"{junk!r} should not be recognised")
    return "8 ids OK, 6 junk inputs rejected"


@core_test("check_key(): valid sizes accepted, all others rejected")
def tc_check_key(core):
    for m in MODES:
        for n in range(0, 70):
            try:
                check_key(m, bytes(n))
                ok = True
            except ValueError:
                ok = False
            if ok != (n * 8 in MODE_INFO[m][1]):
                raise AssertionError(f"{m}: key of {n} bytes classified wrongly")


@core_test("Invalid arguments: unknown mode / empty key rejected")
def tc_bad_args(core):
    key = core.random(32)
    _expect_error(lambda: core.encrypt("foo", key, MSG), "unknown mode 'foo'")
    _expect_error(lambda: core.encrypt("gcm", b"", MSG), "empty key")
    ct = core.encrypt("gcm", key, MSG)
    _expect_error(lambda: core.decrypt(key, ct, b"", "foo", True), "decrypt with unknown mode 'foo'")


@core_test("No nonce/IV reuse: 7 modes x 100 encryptions")
def tc_nonce_unique(core):
    for m in ("gcm", "ccm", "ctr", "cbc", "cfb", "ofb", "xts"):
        key = core.random(MODE_INFO[m][1][-1] // 8)
        seen = {core.encrypt(m, key, MSG48) for _ in range(100)}
        if len(seen) != 100:
            raise AssertionError(f"{m.upper()}: only {len(seen)} distinct containers out of 100")
    return "700 containers, all distinct"


@core_test("Stress: 300 random round-trips across all modes", slow=True)
def tc_stress(core):
    rnd = random.Random(1234)
    for i in range(300):
        m = MODES[i % len(MODES)]
        bits = rnd.choice(MODE_INFO[m][1])
        key = core.random(bits // 8)
        pt = os.urandom(rnd.randint(16, 3000))
        ct = core.encrypt(m, key, pt, b"", m == "ecb")
        if core.decrypt(key, ct, b"", None, m == "ecb") != pt:
            raise AssertionError(f"round {i}: {m.upper()}/{bits} mismatch")
    return "300 / 300 OK"


# ---------------------------------------------------------------- runner
def build_plan(core, modes=None, quick=False, include_core=True):
    """modes: iterable of mode names to test (None = all). quick: skip 1 MiB / stress tests."""
    plan = []
    if include_core:
        for name, fn, slow in CORE_TESTS:
            if quick and slow:
                continue
            plan.append({"group": "CORE", "bits": "", "name": name, "run": (lambda f=fn: f(core))})
    for m in MODES:
        if modes is not None and m not in modes:
            continue
        for bits in MODE_INFO[m][1]:
            ctx = Ctx(core, m, bits)
            for name, fn, applies, slow in MODE_TESTS:
                if not applies(m) or (quick and slow):
                    continue
                plan.append({"group": m.upper(), "bits": bits, "name": name, "run": (lambda f=fn, c=ctx: f(c))})
    return plan


def run_item(item):
    t0 = time.perf_counter()
    try:
        detail, status = item["run"]() or "", "PASS"
    except Skip as e:
        detail, status = str(e), "SKIP"
    except AssertionError as e:
        detail, status = str(e), "FAIL"
    except Exception as e:  # noqa: BLE001
        detail, status = _errtxt(e), "ERROR"
    return {"group": item["group"], "bits": item["bits"], "name": item["name"], "status": status,
            "ms": (time.perf_counter() - t0) * 1000.0, "detail": detail}


def summarize(results):
    s = {"PASS": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0}
    for r in results:
        s[r["status"]] += 1
    s["bad"] = s["FAIL"] + s["ERROR"]
    s["total"] = len(results)
    return s


def format_report(core, results):
    s = summarize(results)
    lines = ["aestool self-test report", time.strftime("%Y-%m-%d %H:%M:%S"),
             f"Library : {core.path}", f"Version : {core.version()}",
             f"Result  : {s['total']} tests, {s['PASS']} pass, {s['bad']} fail, {s['SKIP']} skip",
             "-" * 78]
    for r in results:
        key = f"{r['bits']}-bit" if r["bits"] else "-"
        lines.append(f"[{r['status']:5}] {r['group']:4} {key:8} {r['name']}  ({r['ms']:.1f} ms)")
        if r["detail"]:
            lines.append(f"         {r['detail']}")
    lines.append("-" * 78)
    lines.append("ALL OK" if s["bad"] == 0 else f"FAILED ({s['bad']} failing tests)")
    return "\n".join(lines)


def selftest(modes=None, quick=False, verbose=False, report=None):
    core = Core()
    print(core.version())
    plan = build_plan(core, modes, quick, include_core=modes is None)
    results, cur = [], None
    for item in plan:
        r = run_item(item)
        results.append(r)
        if r["group"] != cur:
            cur = r["group"]
            print(f"[{cur}]")
        if verbose or r["status"] != "PASS":
            key = f"{r['bits']:>3}-bit" if r["bits"] else "      -"
            print(f"  {r['status']:5} {key}  {r['name']}" + (f"  -> {r['detail']}" if r["detail"] else ""))
    s = summarize(results)
    print(f"{s['total']} tests: {s['PASS']} pass, {s['bad']} fail, {s['SKIP']} skip")
    if report:
        with open(report, "w", encoding="utf-8") as f:
            if report.lower().endswith(".json"):
                json.dump({"version": core.version(), "summary": s, "results": results}, f, indent=2,
                          ensure_ascii=False)
            else:
                f.write(format_report(core, results))
        print("report written to", report)
    print("ALL OK" if s["bad"] == 0 else "FAILED")
    return 0 if s["bad"] == 0 else 1


# =====================================================================================
#  GUI
# =====================================================================================
ACC, ACC_D, BG, CARD = "#2563EB", "#1D4ED8", "#F8FAFC", "#FFFFFF"
BORDER, TXT, MUTED = "#E2E8F0", "#0F172A", "#64748B"
GOOD, WARN, BAD = "#16A34A", "#D97706", "#DC2626"
# security badge shown under the slider
SECURITY = {"gcm": ("Authenticated - recommended", GOOD), "ccm": ("Authenticated", GOOD),
            "ecb": ("INSECURE - avoid", BAD)}
DEFAULT_SEC = ("Confidentiality only (no tamper check)", WARN)


if tk is not None:

    class SelfTestTab(ttk.Frame):
        """Tab 1: run the whole test-suite in a worker thread, show results as a tree."""

        def __init__(self, app):
            super().__init__(app.nb)
            self.app = app
            self.q = queue.Queue()
            self.stop_ev = threading.Event()
            self.thread = None
            self.results = []
            self.row_res = {}
            self.gcount = {}
            self.total = 0
            self.sel = {m: tk.BooleanVar(value=True) for m in MODES}
            self.sel_core = tk.BooleanVar(value=True)
            self.quick = tk.BooleanVar(value=False)
            self.only_fail = tk.BooleanVar(value=False)
            self.summary = tk.StringVar(value="Not run yet")
            self.build()

        def build(self):
            app = self.app
            top = ttk.Labelframe(self, text=" Scope ", style="Card.TLabelframe", padding=(12, 8, 12, 10))
            top.pack(fill="x", padx=14, pady=(10, 0))
            ttk.Label(top, text=f"Library: {app.core.path}    |    {app.core.version()}",
                      style="CardMuted.TLabel").pack(anchor="w")
            ttk.Label(top, style="CardMuted.TLabel", justify="left", wraplength=860,
                      text="Per mode and key size: round-trip (22 sizes, 1 MiB, UTF-8, empty), header, random IV, "
                           "ECB pattern leak, wrong key / mode / key length, malformed & truncated containers, "
                           "padding, AEAD tamper sweep, AAD binding.  CORE: random generator, helpers, "
                           "nonce uniqueness, invalid arguments, stress.").pack(anchor="w", pady=(2, 6))
            row = ttk.Frame(top, style="Card.TFrame")
            row.pack(fill="x")
            for m in MODES:
                ttk.Checkbutton(row, text=m.upper(), variable=self.sel[m], style="Card.TCheckbutton").pack(
                    side="left", padx=(0, 8))
            ttk.Checkbutton(row, text="CORE", variable=self.sel_core, style="Card.TCheckbutton").pack(side="left")
            ttk.Button(row, text="None", command=lambda: self.set_all(False)).pack(side="right")
            ttk.Button(row, text="All", command=lambda: self.set_all(True)).pack(side="right", padx=4)
            row2 = ttk.Frame(top, style="Card.TFrame")
            row2.pack(fill="x", pady=(6, 0))
            ttk.Checkbutton(row2, text="Quick (skip 1 MiB and stress tests)", variable=self.quick,
                            style="Card.TCheckbutton").pack(side="left")
            ttk.Checkbutton(row2, text="Show only problems", variable=self.only_fail, style="Card.TCheckbutton",
                            command=self.render).pack(side="left", padx=16)

            ctl = ttk.Frame(self)
            ctl.pack(fill="x", padx=14, pady=8)
            self.run_btn = ttk.Button(ctl, text="Run self-test", style="Accent.TButton", command=self.start)
            self.run_btn.pack(side="left")
            self.stop_btn = ttk.Button(ctl, text="Stop", command=self.stop, state="disabled")
            self.stop_btn.pack(side="left", padx=6)
            ttk.Button(ctl, text="Export report...", command=self.export).pack(side="left", padx=6)
            ttk.Button(ctl, text="Collapse", command=lambda: self.expand(False)).pack(side="right")
            ttk.Button(ctl, text="Expand", command=lambda: self.expand(True)).pack(side="right", padx=6)
            self.sum_lbl = ttk.Label(ctl, textvariable=self.summary, font=app.bold)
            self.sum_lbl.pack(side="left", padx=14)

            self.bar = ttk.Progressbar(self, mode="determinate")
            self.bar.pack(fill="x", padx=14)

            tf = ttk.Frame(self)
            tf.pack(fill="both", expand=True, padx=14, pady=(8, 0))
            cols = ("key", "status", "ms", "detail")
            self.tree = ttk.Treeview(tf, columns=cols, show="tree headings", selectmode="browse")
            for c, t, w, a in (("#0", "Test", 360, "w"), ("key", "Key", 70, "center"), ("status", "Result", 70, "center"),
                               ("ms", "ms", 70, "e"), ("detail", "Detail", 320, "w")):
                self.tree.heading(c, text=t, anchor="w" if a == "w" else "center")
                self.tree.column(c, width=w, anchor=a, stretch=(c in ("#0", "detail")))
            sb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
            self.tree.configure(yscrollcommand=sb.set)
            self.tree.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            self.tree.tag_configure("PASS", foreground=GOOD)
            self.tree.tag_configure("FAIL", foreground=BAD)
            self.tree.tag_configure("ERROR", foreground=BAD)
            self.tree.tag_configure("SKIP", foreground=WARN)
            self.tree.tag_configure("grp_ok", foreground=GOOD, font=app.bold)
            self.tree.tag_configure("grp_bad", foreground=BAD, font=app.bold)
            self.tree.bind("<<TreeviewSelect>>", self.on_select)

            self.detail = tk.Text(self, height=4, wrap="word", font=app.mono, relief="flat", bg="white", fg=TXT,
                                  highlightthickness=1, highlightbackground=BORDER, padx=8, pady=6, state="disabled")
            self.detail.pack(fill="x", padx=14, pady=8)

        # ---- helpers
        def set_all(self, v):
            for var in self.sel.values():
                var.set(v)
            self.sel_core.set(v)

        def expand(self, v):
            for g in self.tree.get_children():
                self.tree.item(g, open=v)

        def on_select(self, _e=None):
            s = self.tree.selection()
            txt = ""
            if s:
                r = self.row_res.get(s[0])
                if r:
                    key = f"{r['bits']}-bit" if r["bits"] else "-"
                    txt = f"{r['group']}  {key}  [{r['status']}]  {r['name']}\n{r['detail']}"
            self.detail.configure(state="normal")
            self.detail.delete("1.0", "end")
            self.detail.insert("1.0", txt)
            self.detail.configure(state="disabled")

        # ---- run control
        def start(self):
            if self.thread and self.thread.is_alive():
                return
            modes = [m for m in MODES if self.sel[m].get()]
            if not modes and not self.sel_core.get():
                return messagebox.showinfo("aestool", "Select at least one mode (or CORE).")
            try:
                plan = build_plan(self.app.core, modes, self.quick.get(), self.sel_core.get())
            except Exception as e:  # noqa: BLE001
                return self.app.fail(e)
            self.results, self.total = [], len(plan)
            self.stop_ev.clear()
            self.render()
            self.bar.configure(maximum=max(1, self.total), value=0)
            self.sum_lbl.configure(foreground=TXT)
            self.summary.set(f"Running 0 / {self.total} ...")
            self.run_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.app.nb.tab(self, text="  Self-test ...  ")
            self.thread = threading.Thread(target=self.worker, args=(plan,), daemon=True)
            self.thread.start()
            self.after(40, self.poll)

        def stop(self):
            self.stop_ev.set()

        def worker(self, plan):
            err = None
            try:
                for item in plan:
                    if self.stop_ev.is_set():
                        break
                    self.q.put(("result", run_item(item)))
            except Exception as e:  # noqa: BLE001
                err = e
            self.q.put(("done", err))

        def poll(self):
            try:
                while True:
                    kind, payload = self.q.get_nowait()
                    if kind == "result":
                        self.add_result(payload)
                    else:
                        return self.finish(payload)
            except queue.Empty:
                pass
            self.after(40, self.poll)

        def add_result(self, r):
            self.results.append(r)
            self.insert_row(r)
            self.bar.configure(value=len(self.results))
            s = summarize(self.results)
            self.summary.set(f"Running {s['total']} / {self.total}   pass {s['PASS']}   fail {s['bad']}   skip {s['SKIP']}")

        def finish(self, err):
            self.run_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            s = summarize(self.results)
            stopped = self.stop_ev.is_set()
            if err:
                self.app.fail(err)
            ok = s["bad"] == 0 and not err and not stopped
            head = "ALL OK" if ok else ("STOPPED" if stopped and s["bad"] == 0 else "FAILED")
            self.summary.set(f"{head}   {s['total']} tests   pass {s['PASS']}   fail {s['bad']}   skip {s['SKIP']}")
            self.sum_lbl.configure(foreground=GOOD if ok else BAD)
            self.app.nb.tab(self, text="  Self-test " + ("✓" if ok else "✗") + "  ")
            self.app.status.set("Self-test: " + self.summary.get())
            self.app.show_toast("Self-test passed" if ok else "Self-test finished with problems")

        # ---- tree
        def render(self):
            self.tree.delete(*self.tree.get_children())
            self.row_res.clear()
            self.gcount = {}
            for r in self.results:
                self.insert_row(r)

        def insert_row(self, r):
            g = r["group"]
            if not self.tree.exists(g):
                self.tree.insert("", "end", iid=g, text=g, open=False, tags=("grp_ok",))
                self.gcount[g] = [0, 0, 0]
            c = self.gcount[g]
            if r["status"] == "PASS":
                c[0] += 1
            elif r["status"] == "SKIP":
                c[2] += 1
            else:
                c[1] += 1
            if not self.only_fail.get() or r["status"] != "PASS":
                key = f"{r['bits']}-bit" if r["bits"] else ""
                iid = self.tree.insert(g, "end", text=r["name"], tags=(r["status"],),
                                       values=(key, r["status"], f"{r['ms']:.1f}", r["detail"].splitlines()[0] if r["detail"] else ""))
                self.row_res[iid] = r
            n = sum(c)
            txt = f"{g}    {c[0]} / {n} passed" + (f"    -  {c[1]} FAILED" if c[1] else "") + (f"    ({c[2]} skipped)" if c[2] else "")
            self.tree.item(g, text=txt, tags=("grp_bad" if c[1] else "grp_ok",))
            if c[1]:
                self.tree.item(g, open=True)

        def export(self):
            if not self.results:
                return self.app.show_toast("Nothing to export - run the self-test first")
            p = filedialog.asksaveasfilename(title="Save self-test report", defaultextension=".txt",
                                             initialfile="aestool_selftest.txt",
                                             filetypes=[("Text report", "*.txt"), ("JSON", "*.json")])
            if not p:
                return
            try:
                with open(p, "w", encoding="utf-8") as f:
                    if p.lower().endswith(".json"):
                        json.dump({"version": self.app.core.version(), "summary": summarize(self.results),
                                   "results": self.results}, f, indent=2, ensure_ascii=False)
                    else:
                        f.write(format_report(self.app.core, self.results))
            except OSError as e:
                return self.app.fail(e)
            self.app.show_toast("Report saved")

    class CryptoTab(ttk.Frame):
        """Tab 2 (Encrypt) and tab 3 (Decrypt): same widgets, different behaviour."""

        def __init__(self, app, action):
            super().__init__(app.nb)
            self.app, self.core = app, app.core
            self.enc = action == "enc"
            self.mode = tk.StringVar(value="gcm")
            self.bits = tk.StringVar(value="256")
            self.key = tk.StringVar()
            self.aad = tk.StringVar()
            self.show_key = tk.BooleanVar(value=False)
            self.allow_ecb = tk.BooleanVar()
            self.auto = tk.BooleanVar(value=True)      # decrypt: take the mode from the container header
            self.src = tk.StringVar(value="text")
            self.key_info = tk.StringVar()
            self.info = tk.StringVar()
            self.sec = tk.StringVar()
            self.detected = tk.StringVar()
            self.file_in = tk.StringVar()
            self.file_out = tk.StringVar()
            self._out_manual = False
            self.last_out = None
            self.mismatch = None
            self.build()
            self.key.trace_add("write", lambda *_: self.update_key_info())
            self.file_in.trace_add("write", lambda *_: self.on_file_in())
            self.on_mode()
            self.on_src()

        # ---------------------------------------------------------------- layout
        def card(self, title, expand=False):
            f = ttk.Labelframe(self, text=" " + title + " ", style="Card.TLabelframe", padding=(12, 8, 12, 10))
            f.pack(fill="both" if expand else "x", expand=expand, padx=14, pady=(10, 0))
            return f

        def build(self):
            app, enc = self.app, self.enc

            # 1. mode slider
            mc = self.card(("1.  Encryption" if enc else "1.  Decryption") + " mode  -  drag the slider or click a mode")
            mc.columnconfigure(0, weight=1)
            self.cv = tk.Canvas(mc, height=62, bg=CARD, highlightthickness=0, cursor="hand2", takefocus=True)
            self.cv.grid(row=0, column=0, sticky="we")
            self.cv.bind("<Configure>", lambda _e: self.draw_slider())
            self.cv.bind("<Button-1>", self.slide_click)
            self.cv.bind("<B1-Motion>", self.slide_click)
            self.cv.bind("<Left>", lambda _e: self.step_mode(-1))
            self.cv.bind("<Right>", lambda _e: self.step_mode(1))
            self.sec_lbl = ttk.Label(mc, textvariable=self.sec, style="Card.TLabel", font=app.bold)
            self.sec_lbl.grid(row=1, column=0, pady=(4, 0))
            ttk.Label(mc, textvariable=self.info, style="CardMuted.TLabel", wraplength=840,
                      justify="center").grid(row=2, column=0)
            if not enc:
                ttk.Checkbutton(mc, text="Auto-detect the mode from the AEST container header (recommended)",
                                variable=self.auto, style="Card.TCheckbutton", command=self.on_auto
                                ).grid(row=3, column=0, pady=(4, 0))
                ttk.Label(mc, textvariable=self.detected, style="Card.TLabel", foreground=ACC,
                          font=app.bold).grid(row=4, column=0)

            # 2. key + vault
            kc = self.card("2.  Key")
            kc.columnconfigure(1, weight=1)
            ttk.Label(kc, text="Saved keys", style="Card.TLabel").grid(row=0, column=0, sticky="w")
            self.saved_cb = ttk.Combobox(kc, state="readonly", values=sorted(app.vault))
            self.saved_cb.grid(row=0, column=1, sticky="we", padx=6, pady=2)
            self.saved_cb.bind("<<ComboboxSelected>>", lambda _e: self.load_saved())
            bt = ttk.Frame(kc, style="Card.TFrame")
            bt.grid(row=0, column=2, columnspan=3, sticky="e")
            ttk.Button(bt, text="Save key...", command=self.save_key).pack(side="left", padx=2)
            ttk.Button(bt, text="Delete", command=self.delete_saved).pack(side="left", padx=2)

            ttk.Label(kc, text="Key (hex)", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=4)
            self.key_entry = ttk.Entry(kc, textvariable=self.key, show="*")
            self.key_entry.grid(row=1, column=1, sticky="we", padx=6)
            ttk.Label(kc, textvariable=self.key_info, style="CardMuted.TLabel", width=14).grid(row=1, column=2)
            ttk.Checkbutton(kc, text="show", variable=self.show_key, command=self.toggle_key,
                            style="Card.TCheckbutton").grid(row=1, column=3, padx=4)
            ttk.Button(kc, text="Copy", command=lambda: app.copy(self.key.get(), "Key")).grid(row=1, column=4)

            r = 2
            self.bits_frame = None
            if enc:
                ttk.Label(kc, text="Key size (bits)", style="Card.TLabel").grid(row=r, column=0, sticky="w")
                row2 = ttk.Frame(kc, style="Card.TFrame")
                row2.grid(row=r, column=1, columnspan=4, sticky="we", padx=6, pady=2)
                self.bits_frame = ttk.Frame(row2, style="Card.TFrame")
                self.bits_frame.pack(side="left")
                ttk.Button(row2, text="Generate random key", command=self.gen_key).pack(side="left", padx=8)
                r += 1
            ttk.Label(kc, text="AAD (text)", style="Card.TLabel").grid(row=r, column=0, sticky="w")
            self.aad_entry = ttk.Entry(kc, textvariable=self.aad)
            self.aad_entry.grid(row=r, column=1, sticky="we", padx=6, pady=2)
            self.ecb_chk = ttk.Checkbutton(kc, text="allow ECB > 16 KiB", variable=self.allow_ecb,
                                           style="Card.TCheckbutton")
            self.ecb_chk.grid(row=r, column=2, columnspan=3, padx=4)
            r += 1
            note = "Saved keys are stored in plain text in " + KEYFILE
            if not enc:
                note = "AAD empty = use the AAD stored in the container.   " + note
            ttk.Label(kc, text=note, style="CardMuted.TLabel").grid(row=r, column=0, columnspan=5, sticky="w",
                                                                    pady=(4, 0))

            # 3. data (text / file)
            dc = self.card("3.  Data", expand=True)
            head = ttk.Frame(dc, style="Card.TFrame")
            head.pack(fill="x", pady=(0, 6))
            ttk.Label(head, text="Source:", style="Card.TLabel").pack(side="left", padx=(0, 6))
            for t, v in (("Text", "text"), ("File", "file")):
                ttk.Radiobutton(head, text=t, value=v, variable=self.src, style="SegS.Toolbutton",
                                command=self.on_src).pack(side="left")
            self.body = ttk.Frame(dc, style="Card.TFrame")
            self.body.pack(fill="both", expand=True)

            # --- text source
            tf = self.text_frame = ttk.Frame(self.body, style="Card.TFrame")
            ttk.Label(tf, style="CardMuted.TLabel",
                      text="Plain text to encrypt" if enc else "Hex container to decrypt (starts with 41455354)"
                      ).pack(anchor="w")
            self.inp = app.textbox(tf, 4)
            self.inp.pack(fill="both", expand=True, pady=(2, 6))
            if not enc:
                self.inp.bind("<KeyRelease>", lambda _e: self.detect())
                self.inp.bind("<<Paste>>", lambda _e: self.after(60, self.detect))
            btns = ttk.Frame(tf, style="Card.TFrame")
            btns.pack(fill="x")
            ttk.Button(btns, text="Encrypt text" if enc else "Decrypt text", style="Accent.TButton",
                       command=self.run_text).pack(side="left")
            ttk.Button(btns, text="Clear", command=lambda: self.inp.delete("1.0", "end")).pack(side="left", padx=8)
            ttk.Label(tf, text="Result", style="CardMuted.TLabel").pack(anchor="w", pady=(8, 0))
            self.out = app.textbox(tf, 4)
            self.out.pack(fill="both", expand=True, pady=(2, 6))
            ob = ttk.Frame(tf, style="Card.TFrame")
            ob.pack(fill="x")
            ttk.Button(ob, text="Copy result", command=lambda: app.copy(self.out.get("1.0", "end-1c"), "Result")
                       ).pack(side="left")
            ttk.Button(ob, text="Use result as input", command=self.out_to_in).pack(side="left", padx=8)
            if enc:
                ttk.Button(ob, text="Send to Decrypt tab  >", command=self.send_to_decrypt).pack(side="right")

            # --- file source
            fc = self.file_frame = ttk.Frame(self.body, style="Card.TFrame")
            fc.columnconfigure(1, weight=1)
            ttk.Label(fc, text="Input file", style="Card.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Entry(fc, textvariable=self.file_in).grid(row=0, column=1, sticky="we", padx=6, pady=2)
            ttk.Button(fc, text="Browse...", command=self.pick_in).grid(row=0, column=2)
            ttk.Label(fc, text="Save output as", style="Card.TLabel").grid(row=1, column=0, sticky="w")
            oe = ttk.Entry(fc, textvariable=self.file_out)
            oe.grid(row=1, column=1, sticky="we", padx=6, pady=2)
            oe.bind("<Key>", lambda _e: setattr(self, "_out_manual", True))
            ttk.Button(fc, text="Save as...", command=self.pick_out).grid(row=1, column=2)
            fb = ttk.Frame(fc, style="Card.TFrame")
            fb.grid(row=2, column=1, sticky="w", padx=6, pady=(8, 0))
            ttk.Button(fb, text="Encrypt file" if enc else "Decrypt file", style="Accent.TButton",
                       command=self.run_file).pack(side="left")
            self.open_btn = ttk.Button(fb, text="Open folder", command=self.open_folder)
            self.file_hint = ttk.Label(fc, textvariable=self.detected if not enc else self.sec, style="Card.TLabel",
                                       foreground=ACC, font=app.bold)
            if not enc:
                self.file_hint.grid(row=3, column=1, sticky="w", padx=6, pady=(6, 0))

        def on_src(self):
            if self.src.get() == "text":
                self.file_frame.pack_forget()
                self.text_frame.pack(fill="both", expand=True)
            else:
                self.text_frame.pack_forget()
                self.file_frame.pack(fill="x")

        # ---------------------------------------------------------------- slider
        def cur_mode(self):
            return self.mode.get()

        def slider_xs(self):
            w = max(self.cv.winfo_width(), 300)
            pad = 48
            n = len(MODES)
            return [pad + i * (w - 2 * pad) / (n - 1) for i in range(n)]

        def draw_slider(self):
            cv, bold = self.cv, self.app.bold
            cv.delete("all")
            xs = self.slider_xs()
            idx = MODES.index(self.cur_mode())
            y = 18
            cv.create_line(xs[0], y, xs[-1], y, width=8, fill="#CBD5E1", capstyle="round")
            cv.create_line(xs[0], y, xs[idx], y, width=8, fill=ACC, capstyle="round")
            for i, (x, m) in enumerate(zip(xs, MODES)):
                cv.create_oval(x - 6, y - 6, x + 6, y + 6, fill="white", outline=ACC if i <= idx else "#94A3B8", width=2)
                cv.create_text(x, 48, text=m.upper(), font=bold, fill=ACC if i == idx else MUTED)
            x = xs[idx]
            cv.create_oval(x - 14, y - 14, x + 14, y + 14, fill=ACC, outline="white", width=3)
            cv.create_oval(x - 4, y - 4, x + 4, y + 4, fill="white", outline="")

        def slide_click(self, e):
            self.cv.focus_set()
            xs = self.slider_xs()
            m = MODES[min(range(len(xs)), key=lambda i: abs(xs[i] - e.x))]
            if m != self.cur_mode():
                self.user_set_mode(m)

        def step_mode(self, d):
            i = MODES.index(self.cur_mode()) + d
            if 0 <= i < len(MODES):
                self.user_set_mode(MODES[i])

        def user_set_mode(self, m):
            """A manual choice on the Decrypt tab means 'force this mode' -> auto-detect is switched off."""
            if not self.enc and self.auto.get():
                self.auto.set(False)
                self.on_auto()
            self.set_mode(m)

        def set_mode(self, m):
            self.mode.set(m)
            self.on_mode()

        def on_mode(self):
            m = self.cur_mode()
            aead, sizes, text = MODE_INFO[m]
            if self.bits.get() not in [str(b) for b in sizes]:
                self.bits.set(str(sizes[0]))
            if self.bits_frame is not None:
                for w in self.bits_frame.winfo_children():
                    w.destroy()
                for b in sizes:
                    ttk.Radiobutton(self.bits_frame, text=f"{b}-bit", value=str(b), variable=self.bits,
                                    style="SegS.Toolbutton").pack(side="left")
            self.aad_entry.configure(state="normal" if aead else "disabled")
            self.ecb_chk.configure(state="normal" if m == "ecb" else "disabled")
            self.info.set(text)
            label, color = SECURITY.get(m, DEFAULT_SEC)
            self.sec.set(f"{m.upper()}  -  {label}")
            self.sec_lbl.configure(foreground=color)
            self.draw_slider()
            self.update_key_info()

        # ---------------------------------------------------------------- decrypt: detection
        def on_auto(self):
            if self.auto.get():
                self.detect()
            else:
                self.hint_mode(self.peek_mode())

        def peek_mode(self):
            """Container mode of the current input (text box or chosen file) or None."""
            if self.src.get() == "file":
                p = self.file_in.get().strip().strip('"')
                try:
                    with open(p, "rb") as f:
                        return container_mode(f.read(8))
                except OSError:
                    return None
            h = "".join(self.inp.get("1.0", "end-1c").split())
            try:
                return container_mode(bytes.fromhex(h[:12])) if len(h) >= 12 else None
            except ValueError:
                return None

        def detect(self):
            if self.enc:
                return
            m = self.peek_mode()
            if m and self.auto.get() and m != self.cur_mode():
                self.set_mode(m)
            self.hint_mode(m)

        def hint_mode(self, detected):
            if not detected:
                self.detected.set("")
            elif self.auto.get():
                self.detected.set(f"Detected container mode: {detected.upper()}  (used automatically)")
            elif detected == self.cur_mode():
                self.detected.set(f"Detected container mode: {detected.upper()}  (matches your selection)")
            else:
                self.detected.set(f"Detected container mode: {detected.upper()}  - you forced "
                                  f"{self.cur_mode().upper()}, decrypting will give garbage / an error")

        # ---------------------------------------------------------------- key helpers
        def toggle_key(self):
            self.key_entry.configure(show="" if self.show_key.get() else "*")

        def update_key_info(self):
            try:
                n = len(bytes.fromhex("".join(self.key.get().split())))
                ok = n * 8 in MODE_INFO[self.cur_mode()][1]
                self.key_info.set(f"{n} bytes " + ("OK" if ok else "!"))
            except ValueError:
                self.key_info.set("not hex")

        def key_bytes(self):
            try:
                return bytes.fromhex("".join(self.key.get().split()))
            except ValueError:
                raise ValueError("Key must be a hex string")

        def gen_key(self):
            self.key.set(self.core.random(int(self.bits.get()) // 8).hex())
            self.app.show_toast("New key generated")

        def refresh_saved(self, select=None):
            self.saved_cb["values"] = sorted(self.app.vault)
            self.saved_cb.set(select or "")

        def save_key(self):
            try:
                kb = self.key_bytes()
            except ValueError as e:
                return self.app.fail(e)
            if not kb:
                return self.app.fail("Nothing to save - the key field is empty")
            name = simpledialog.askstring("Save key", "Name for this key:", parent=self)
            if not name or not name.strip():
                return
            name = name.strip()
            vault = self.app.vault
            if name in vault and not messagebox.askyesno("Overwrite?", f"'{name}' already exists. Overwrite?"):
                return
            try:
                vault[name] = {"key": kb.hex(), "bits": len(kb) * 8, "mode": self.cur_mode(),
                               "saved": time.strftime("%Y-%m-%d %H:%M")}
                store_keys(vault)
            except OSError as e:
                return self.app.fail(e)
            self.app.refresh_vaults(name if self else None)
            self.app.show_toast("Key saved")

        def load_saved(self):
            e = self.app.vault.get(self.saved_cb.get())
            if not e:
                return
            self.key.set(e["key"])
            bits = str(e.get("bits", ""))
            if bits in [str(b) for b in MODE_INFO[self.cur_mode()][1]]:
                self.bits.set(bits)
            self.app.show_toast("Key loaded")

        def delete_saved(self):
            name, vault = self.saved_cb.get(), self.app.vault
            if not name or name not in vault:
                return
            if messagebox.askyesno("Delete key", f"Delete saved key '{name}'?"):
                del vault[name]
                try:
                    store_keys(vault)
                except OSError as e:
                    return self.app.fail(e)
                self.app.refresh_vaults()
                self.app.show_toast("Key deleted")

        # ---------------------------------------------------------------- crypto actions
        def do_encrypt(self, data):
            m = self.cur_mode()
            key = self.key_bytes()
            check_key(m, key)
            aad = self.aad.get().encode("utf-8") if MODE_INFO[m][0] else b""
            return self.core.encrypt(m, key, data, aad, self.allow_ecb.get())

        def do_decrypt(self, data):
            key = self.key_bytes()
            detected = container_mode(data)
            if detected is None:
                raise ValueError("Input is not an AEST container (wrong file / bad hex)")
            self.mismatch = None
            if self.auto.get():
                m, explicit = detected, None             # the library reads the mode from the header
                if m != self.cur_mode():
                    self.set_mode(m)
            else:
                m, explicit = self.cur_mode(), self.cur_mode()   # respect the user's choice, only warn
                if m != detected:
                    self.mismatch = detected
            self.hint_mode(detected)
            check_key(m, key)
            aad = self.aad.get().encode("utf-8") if MODE_INFO[m][0] else b""     # empty => AAD from the header
            return self.core.decrypt(key, data, aad, explicit, self.allow_ecb.get())

        def run_text(self):
            (self.enc_text if self.enc else self.dec_text)()

        def run_file(self):
            self.process_file(self.enc)

        def show(self, text):
            self.out.delete("1.0", "end")
            self.out.insert("1.0", text)

        def enc_text(self):
            try:
                data = self.inp.get("1.0", "end-1c").encode("utf-8")
                ct = self.do_encrypt(data)
                self.show(ct.hex())
                self.app.status.set(f"{self.cur_mode().upper()}: encrypted {len(data)} bytes -> {len(ct)} bytes (hex shown)")
            except Exception as e:  # noqa: BLE001
                self.app.fail(e)

        def dec_text(self):
            try:
                ct = bytes.fromhex("".join(self.inp.get("1.0", "end-1c").split()))
                pt = self.do_decrypt(ct)
                try:
                    self.show(pt.decode("utf-8"))
                except UnicodeDecodeError:
                    if self.mismatch:
                        self.show(pt.decode("utf-8", errors="replace") + "\n\n[hex] " + pt.hex())
                    else:
                        self.show("[not valid UTF-8] " + pt.hex())
                self.app.status.set(f"{self.cur_mode().upper()}: decrypted {len(pt)} bytes")
                if self.mismatch:
                    self.app.status.set(f"WARNING: decrypted with {self.cur_mode().upper()} but data was encrypted "
                                        f"with {self.mismatch.upper()} - output is probably garbage")
            except Exception as e:  # noqa: BLE001
                self.app.fail(e)

        def out_to_in(self):
            t = self.out.get("1.0", "end-1c")
            self.inp.delete("1.0", "end")
            self.inp.insert("1.0", t)
            self.detect()

        def send_to_decrypt(self):
            ct = self.out.get("1.0", "end-1c").strip()
            if not ct:
                return self.app.show_toast("Nothing to send - encrypt something first")
            d = self.app.dec_tab
            d.src.set("text")
            d.on_src()
            d.inp.delete("1.0", "end")
            d.inp.insert("1.0", ct)
            d.key.set(self.key.get())
            d.aad.set(self.aad.get())
            d.allow_ecb.set(self.allow_ecb.get())
            d.auto.set(True)
            d.detect()
            self.app.nb.select(d)
            self.app.show_toast("Sent to Decrypt tab")

        # ---------------------------------------------------------------- files
        def on_file_in(self):
            self.suggest_out()
            if not self.enc:
                self.detect()

        def suggest_out(self):
            """Default output path (only while the user has not typed their own)."""
            if self._out_manual:
                return
            p = self.file_in.get().strip().strip('"')
            if not p:
                self.file_out.set("")
            elif self.enc:
                self.file_out.set(p + ".aest")
            else:
                self.file_out.set(p[:-5] if p.endswith(".aest") else p + ".dec")

        def pick_in(self):
            p = filedialog.askopenfilename(title="File to encrypt" if self.enc else "File to decrypt (.aest)")
            if p:
                self._out_manual = False
                self.file_in.set(os.path.normpath(p))

        def pick_out(self):
            cur = self.file_out.get().strip()
            p = filedialog.asksaveasfilename(title="Save output as", initialdir=os.path.dirname(cur) or None,
                                             initialfile=os.path.basename(cur))
            if p:
                self._out_manual = True
                self.file_out.set(os.path.normpath(p))

        def open_folder(self):
            if not self.last_out:
                return
            d = os.path.dirname(os.path.abspath(self.last_out))
            try:
                if os.name == "nt":
                    os.startfile(d)  # noqa: S606
                elif sys.platform == "darwin":
                    subprocess.run(["open", d], check=False)
                else:
                    subprocess.run(["xdg-open", d], check=False)
            except OSError as e:
                self.app.fail(e)

        def process_file(self, enc):
            src = self.file_in.get().strip().strip('"')
            if not src:
                self.pick_in()
                src = self.file_in.get().strip()
                if not src:
                    return
            dst = self.file_out.get().strip().strip('"')
            try:
                if not os.path.isfile(src):
                    raise ValueError("Input file not found: " + src)
                if not dst:
                    raise ValueError("Choose where to save the output (Save as...)")
                if os.path.abspath(dst) == os.path.abspath(src):
                    raise ValueError("Output file must be different from the input file")
                if os.path.getsize(src) > MAX_FILE:
                    raise ValueError(f"File is larger than {MAX_FILE // (1 << 20)} MiB (it is loaded in memory)")
                if os.path.exists(dst) and not messagebox.askyesno("Overwrite?", f"{dst}\nalready exists. Overwrite?"):
                    return
                with open(src, "rb") as f:
                    data = f.read()
                self.mismatch = None
                res = self.do_encrypt(data) if enc else self.do_decrypt(data)
                os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
                with open(dst, "wb") as f:       # only reached when the crypto call succeeded
                    f.write(res)
                self.last_out = dst
                self.open_btn.pack(side="left", padx=8)
                self.app.status.set(f"{self.cur_mode().upper()}: {'encrypted' if enc else 'decrypted'} "
                                    f"{len(data)} -> {len(res)} bytes, saved to {dst}")
                if self.mismatch:
                    self.app.status.set(f"WARNING: wrote {dst} using {self.cur_mode().upper()} but data was "
                                        f"encrypted with {self.mismatch.upper()} - file is probably garbage")
                else:
                    self.app.show_toast("File saved")
            except Exception as e:  # noqa: BLE001
                self.app.fail(e)

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("aestool - AES Self-test / Encrypt / Decrypt (Crypto++ core)")
            self.geometry("940x900")
            self.minsize(860, 640)
            self.configure(bg=BG)
            self.core = Core()
            self.vault = load_keys()
            self._toast_job = None
            self.status = tk.StringVar(value=self.core.version())
            self.toast = tk.StringVar()
            self.build_style()

            head = ttk.Frame(self)
            head.pack(fill="x", padx=14, pady=(10, 6))
            ttk.Label(head, text="AES Tool", font=self.title_font).pack(side="left")
            ttk.Label(head, text="  AES-GCM / CCM / CBC / CTR / CFB / OFB / XTS / ECB", style="Muted.TLabel").pack(
                side="left", pady=(8, 0))

            bar = ttk.Frame(self)
            bar.pack(fill="x", side="bottom")
            tk.Label(bar, textvariable=self.status, anchor="w", bg="#E2E8F0", fg=TXT, padx=10, pady=4).pack(
                side="left", fill="x", expand=True)
            tk.Label(bar, textvariable=self.toast, bg="#E2E8F0", fg=GOOD, padx=10, font=self.bold).pack(side="right")

            self.nb = ttk.Notebook(self)
            self.nb.pack(fill="both", expand=True, padx=8, pady=(0, 6))
            self.selftest_tab = SelfTestTab(self)
            self.enc_tab = CryptoTab(self, "enc")
            self.dec_tab = CryptoTab(self, "dec")
            self.nb.add(self.selftest_tab, text="  Self-test  ")
            self.nb.add(self.enc_tab, text="  Encrypt  ")
            self.nb.add(self.dec_tab, text="  Decrypt  ")

        def build_style(self):
            s = ttk.Style(self)
            s.theme_use("clam")
            base = tkfont.nametofont("TkDefaultFont")
            base.configure(size=10)
            self.bold = base.copy()
            self.bold.configure(weight="bold")
            self.title_font = base.copy()
            self.title_font.configure(size=18, weight="bold")
            self.mono = tkfont.nametofont("TkFixedFont").copy()
            self.mono.configure(size=10)
            s.configure(".", background=BG, foreground=TXT)
            s.configure("TFrame", background=BG)
            s.configure("TLabel", background=BG, foreground=TXT)
            s.configure("Muted.TLabel", background=BG, foreground=MUTED)
            s.configure("Card.TFrame", background=CARD)
            s.configure("Card.TLabel", background=CARD, foreground=TXT)
            s.configure("CardMuted.TLabel", background=CARD, foreground=MUTED)
            s.configure("Card.TCheckbutton", background=CARD, foreground=TXT)
            s.configure("Card.TLabelframe", background=CARD, bordercolor=BORDER, relief="solid", borderwidth=1)
            s.configure("Card.TLabelframe.Label", background=CARD, foreground=ACC, font=self.bold)
            s.configure("TButton", padding=(10, 6), background="#EEF2F7", bordercolor=BORDER, focuscolor="none")
            s.map("TButton", background=[("active", "#E2E8F0"), ("disabled", "#F1F5F9")])
            s.configure("Accent.TButton", background=ACC, foreground="white", padding=(16, 8),
                        bordercolor=ACC, font=self.bold, focuscolor="none")
            s.map("Accent.TButton", background=[("active", ACC_D), ("disabled", "#93C5FD")],
                  foreground=[("disabled", "white")])
            s.configure("SegS.Toolbutton", padding=(14, 5), background="#E2E8F0", foreground=MUTED,
                        bordercolor="#E2E8F0", font=self.bold, focuscolor="none")
            s.map("SegS.Toolbutton", background=[("selected", ACC), ("active", "#CBD5E1")],
                  foreground=[("selected", "white")])
            s.configure("TEntry", fieldbackground="white", bordercolor=BORDER, padding=5)
            s.configure("TCombobox", fieldbackground="white", bordercolor=BORDER, padding=4)
            s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(4, 4, 4, 0))
            s.configure("TNotebook.Tab", padding=(22, 9), background="#E2E8F0", foreground=MUTED, font=self.bold)
            s.map("TNotebook.Tab", background=[("selected", ACC), ("active", "#CBD5E1")],
                  foreground=[("selected", "white")])
            s.configure("Treeview", rowheight=24, background="white", fieldbackground="white", bordercolor=BORDER)
            s.configure("Treeview.Heading", font=self.bold, background="#EEF2F7", padding=4)
            s.configure("Horizontal.TProgressbar", background=ACC, troughcolor="#E2E8F0", bordercolor=BORDER)

            def fixed_map(opt):       # Tk 8.6.9 bug: tag colours ignored in Treeview
                return [e for e in s.map("Treeview", query_opt=opt) if e[:2] != ("!disabled", "!selected")]
            s.map("Treeview", foreground=fixed_map("foreground"), background=fixed_map("background"))

        def textbox(self, parent, height):
            return tk.Text(parent, height=height, wrap="word", font=self.mono, relief="flat", bg="white", fg=TXT,
                           insertbackground=TXT, highlightthickness=1, highlightbackground=BORDER,
                           highlightcolor=ACC, padx=8, pady=6)

        # ---- shared helpers used by the tabs
        def refresh_vaults(self, select=None):
            for t in (self.enc_tab, self.dec_tab):
                t.refresh_saved(select)

        def show_toast(self, text):
            self.toast.set(text)
            if self._toast_job:
                self.after_cancel(self._toast_job)
            self._toast_job = self.after(1800, lambda: self.toast.set(""))

        def copy(self, text, what):
            if not text:
                return self.show_toast("Nothing to copy")
            self.clipboard_clear()
            self.clipboard_append(text)
            self.show_toast(f"{what} copied!")

        def fail(self, e):
            self.status.set("ERROR: " + str(e))
            messagebox.showerror("aestool", str(e))


def run_gui():
    if tk is None:
        raise RuntimeError("tkinter is not installed - use --selftest for the command-line test-suite")
    App().mainloop()


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="aestool GUI (Self-test / Encrypt / Decrypt) on top of aescore")
    ap.add_argument("--selftest", action="store_true", help="run the test-suite without a window")
    ap.add_argument("--mode", help="comma-separated modes to test, e.g. gcm,cbc (default: all + CORE)")
    ap.add_argument("--quick", action="store_true", help="skip the slow tests (1 MiB, stress)")
    ap.add_argument("-v", "--verbose", action="store_true", help="print passing tests too")
    ap.add_argument("--report", metavar="FILE", help="write a report (.txt or .json)")
    a = ap.parse_args(argv)
    if a.selftest:
        modes = None
        if a.mode:
            modes = [m.strip().lower() for m in a.mode.split(",") if m.strip()]
            bad = [m for m in modes if m not in MODE_INFO]
            if bad:
                ap.error("unknown mode(s): " + ", ".join(bad))
        return selftest(modes, a.quick, a.verbose, a.report)
    run_gui()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        print("Cannot start:", exc)
        sys.exit(1)