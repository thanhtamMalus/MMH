#!/usr/bin/env python3
"""GUI for aescore (bonus). All cryptography is done by the compiled library
(libaescore.so / aescore.dll) through ctypes - nothing is re-implemented here.

Supported AES modes (exactly the ones implemented in src/aescore.cpp):
    ecb  cbc  ofb  cfb  ctr  xts   (confidentiality only)
    ccm  gcm                       (AEAD: authentication tag + optional AAD)

Run:   python3 gui/aestool_gui.py              (after building the project)
       python3 gui/aestool_gui.py --selftest   (no window: round-trip test of all 8 modes)
       AESCORE_LIB=/path/to/libaescore.so      to point at a specific library.
"""
import ctypes
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

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


def find_library():
    if os.name == "nt":
        names = ["aescore.dll", "libaescore.dll"]
    elif sys.platform == "darwin":
        names = ["libaescore.dylib"]
    else:
        names = ["libaescore.so"]
    env = os.environ.get("AESCORE_LIB")
    if env:
        return env
    dirs = [os.path.join(ROOT, "build", "bin", c) for c in ("", "Release", "Debug")]
    dirs += [os.path.join(ROOT, "bin"), HERE, os.getcwd()]
    for d in dirs:
        for n in names:
            p = os.path.join(d, n)
            if os.path.isfile(p):
                return p
    raise FileNotFoundError("aescore library not found. Build the project first "
                            "(cmake -S . -B build && cmake --build build) or set AESCORE_LIB.")


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
                os.path.join(ROOT, "crypto_libs", "bin")]
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


def selftest():
    core = Core()
    print(core.version())
    msg = "Xin chào – AES self-test ✓ ".encode("utf-8") * 5
    ok = True
    for m in MODES:
        for bits in MODE_INFO[m][1]:
            key = core.random(bits // 8)
            aad = b"header-v1" if MODE_INFO[m][0] else b""
            ct = core.encrypt(m, key, msg, aad)
            detected = container_mode(ct)
            pt = core.decrypt(key, ct) # mode auto-detected from the container
            good = pt == msg and detected == m
            if MODE_INFO[m][0]:  # tampered ciphertext must be rejected
                bad = bytearray(ct)
                bad[-1] ^= 1
                try:
                    core.decrypt(key, bytes(bad))
                    good = False
                except AuthError:
                    pass
            ok &= good
            print(f"  {m.upper():3} key={bits:3}  container-mode={detected}  {'OK' if good else 'FAIL'}")
    print("ALL OK" if ok else "FAILED")
    return 0 if ok else 1


def run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("aestool GUI (Crypto++ core)")
            self.geometry("820x660")
            self.core = Core()

            top = ttk.Frame(self, padding=8)
            top.pack(fill="x")
            ttk.Label(top, text="Mode").grid(row=0, column=0, sticky="w")
            self.mode = tk.StringVar(value="gcm")
            cb = ttk.Combobox(top, textvariable=self.mode, values=[m.upper() for m in MODES], width=7,
                              state="readonly")
            cb.grid(row=0, column=1, padx=4, sticky="w")
            cb.bind("<<ComboboxSelected>>", lambda _e: self.on_mode())
            ttk.Label(top, text="Key size (bits)").grid(row=0, column=2, padx=(12, 0))
            self.bits = tk.StringVar(value="256")
            self.bits_cb = ttk.Combobox(top, textvariable=self.bits, width=5, state="readonly")
            self.bits_cb.grid(row=0, column=3, padx=4, sticky="w")
            ttk.Button(top, text="Generate key", command=self.gen_key).grid(row=0, column=4, padx=4)
            self.show_key = tk.BooleanVar(value=False)
            ttk.Checkbutton(top, text="show", variable=self.show_key, command=self.toggle_key).grid(row=0, column=5)

            ttk.Label(top, text="Key (hex)").grid(row=1, column=0, sticky="w", pady=4)
            self.key = tk.StringVar()
            self.key_entry = ttk.Entry(top, textvariable=self.key, show="*")
            self.key_entry.grid(row=1, column=1, columnspan=4, sticky="we", padx=4)
            self.key_info = tk.StringVar()
            ttk.Label(top, textvariable=self.key_info, width=12).grid(row=1, column=5)
            self.key.trace_add("write", lambda *_: self.update_key_info())

            ttk.Label(top, text="AAD (text)").grid(row=2, column=0, sticky="w")
            self.aad = tk.StringVar()
            self.aad_entry = ttk.Entry(top, textvariable=self.aad)
            self.aad_entry.grid(row=2, column=1, columnspan=4, sticky="we", padx=4)
            self.allow_ecb = tk.BooleanVar()
            self.ecb_chk = ttk.Checkbutton(top, text="allow ECB > 16 KiB", variable=self.allow_ecb)
            self.ecb_chk.grid(row=2, column=5, padx=4)
            top.columnconfigure(4, weight=1)

            self.info = tk.StringVar()
            ttk.Label(self, textvariable=self.info, foreground="#555", wraplength=790).pack(anchor="w", padx=8)

            ttk.Label(self, text="Input (plain text for Encrypt, hex container for Decrypt)").pack(anchor="w", padx=8)
            self.inp = tk.Text(self, height=9)
            self.inp.pack(fill="both", expand=True, padx=8)
            btns = ttk.Frame(self, padding=8)
            btns.pack(fill="x")
            ttk.Button(btns, text="Encrypt text", command=self.enc_text).pack(side="left", padx=4)
            ttk.Button(btns, text="Decrypt text", command=self.dec_text).pack(side="left", padx=4)
            ttk.Button(btns, text="Encrypt file...", command=self.enc_file).pack(side="left", padx=16)
            ttk.Button(btns, text="Decrypt file...", command=self.dec_file).pack(side="left", padx=4)
            ttk.Button(btns, text="Self-test all modes", command=self.run_selftest).pack(side="right", padx=4)
            ttk.Label(self, text="Output").pack(anchor="w", padx=8)
            self.out = tk.Text(self, height=9)
            self.out.pack(fill="both", expand=True, padx=8, pady=(0, 8))
            self.status = tk.StringVar(value=self.core.version())
            ttk.Label(self, textvariable=self.status, relief="sunken").pack(fill="x")
            self.on_mode()

        # ---- helpers
        def cur_mode(self):
            return self.mode.get().lower()

        def on_mode(self):
            m = self.cur_mode()
            aead, sizes, text = MODE_INFO[m]
            self.bits_cb["values"] = [str(b) for b in sizes]
            if self.bits.get() not in [str(b) for b in sizes]:
                self.bits.set(str(sizes[0]))
            self.aad_entry.configure(state="normal" if aead else "disabled")
            self.ecb_chk.configure(state="normal" if m == "ecb" else "disabled")
            self.info.set(f"{m.upper()}: {text}")
            self.update_key_info()

        def toggle_key(self):
            self.key_entry.configure(show="" if self.show_key.get() else "*")

        def update_key_info(self):
            try:
                n = len(bytes.fromhex("".join(self.key.get().split())))
                self.key_info.set(f"{n} bytes")
            except ValueError:
                self.key_info.set("not hex")

        def key_bytes(self):
            try:
                return bytes.fromhex("".join(self.key.get().split()))
            except ValueError:
                raise ValueError("Key must be a hex string")

        def gen_key(self):
            self.key.set(self.core.random(int(self.bits.get()) // 8).hex())

        def show(self, text):
            self.out.delete("1.0", "end")
            self.out.insert("1.0", text)

        def fail(self, e):
            self.status.set("ERROR: " + str(e))
            messagebox.showerror("aestool", str(e))

        def encrypt(self, data):
            m = self.cur_mode()
            key = self.key_bytes()
            check_key(m, key)
            aad = self.aad.get().encode("utf-8") if MODE_INFO[m][0] else b""
            return self.core.encrypt(m, key, data, aad, self.allow_ecb.get())

        def decrypt(self, data):
            key = self.key_bytes()
            m = container_mode(data)             # mode is read from the container header
            if m is None:
                raise ValueError("Input is not an AEST container (wrong file / bad hex)")
            check_key(m, key)
            self.mode.set(m.upper())
            self.on_mode()
            aad = self.aad.get().encode("utf-8") if MODE_INFO[m][0] else b""   # empty => AAD from the header
            return self.core.decrypt(key, data, aad, None, self.allow_ecb.get())

        # ---- actions
        def enc_text(self):
            try:
                data = self.inp.get("1.0", "end-1c").encode("utf-8")
                ct = self.encrypt(data)
                self.show(ct.hex())
                self.status.set(f"{self.cur_mode().upper()}: encrypted {len(data)} bytes -> {len(ct)} bytes (hex shown)")
            except Exception as e:  # noqa: BLE001
                self.fail(e)

        def dec_text(self):
            try:
                ct = bytes.fromhex("".join(self.inp.get("1.0", "end-1c").split()))
                pt = self.decrypt(ct)
                try:
                    self.show(pt.decode("utf-8"))
                except UnicodeDecodeError:
                    self.show("[not valid UTF-8] " + pt.hex())
                self.status.set(f"{self.cur_mode().upper()}: decrypted {len(pt)} bytes")
            except Exception as e:  # noqa: BLE001
                self.fail(e)

        def enc_file(self):
            p = filedialog.askopenfilename(title="File to encrypt")
            if not p:
                return
            try:
                with open(p, "rb") as f:
                    ct = self.encrypt(f.read())
                with open(p + ".aest", "wb") as f:
                    f.write(ct)
                self.status.set(f"{self.cur_mode().upper()}: wrote {p}.aest")
            except Exception as e:  # noqa: BLE001
                self.fail(e)

        def dec_file(self):
            p = filedialog.askopenfilename(title="File to decrypt (.aest)")
            if not p:
                return
            try:
                with open(p, "rb") as f:
                    pt = self.decrypt(f.read())
                outp = p[:-5] if p.endswith(".aest") else p + ".dec"
                with open(outp, "wb") as f:   # only reached when authentication succeeded
                    f.write(pt)
                self.status.set(f"{self.cur_mode().upper()}: wrote {outp}")
            except Exception as e:  # noqa: BLE001
                self.fail(e)

        def run_selftest(self):
            import contextlib
            import io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = selftest()
            self.show(buf.getvalue())
            self.status.set("Self-test: " + ("ALL OK" if rc == 0 else "FAILED"))

    App().mainloop()


if __name__ == "__main__":
    try:
        if "--selftest" in sys.argv:
            sys.exit(selftest())
        run_gui()
    except Exception as exc:  # noqa: BLE001
        print("Cannot start GUI:", exc)
        sys.exit(1)