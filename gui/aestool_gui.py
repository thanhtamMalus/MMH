#!/usr/bin/env python3
"""Minimal GUI for aescore (bonus). All cryptography is done by the compiled
library (aescore.dll / libaescore.so) through ctypes - nothing is re-implemented here.

Run:  python gui/aestool_gui.py            (after building the project)
      set AESCORE_LIB=path\\to\\aescore.dll  to point at a specific library.
"""
import ctypes
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MODES = ["gcm", "ccm", "ctr", "cbc", "cfb", "ofb", "xts", "ecb"]


def find_library():
    names = ["aescore.dll", "libaescore.dll"] if os.name == "nt" else (
        ["libaescore.dylib"] if sys.platform == "darwin" else ["libaescore.so"])
    env = os.environ.get("AESCORE_LIB")
    if env:
        return env
    dirs = [os.path.join(ROOT, "build", "bin", c) for c in ("", "Release", "Debug")] + [HERE, os.getcwd()]
    for d in dirs:
        for n in names:
            p = os.path.join(d, n)
            if os.path.isfile(p):
                return p
    raise FileNotFoundError("aescore library not found. Build the project first or set AESCORE_LIB.")


def load_lib():
    path = find_library()
    if os.name == "nt" and hasattr(os, "add_dll_directory"):
        os.add_dll_directory(os.path.dirname(os.path.abspath(path)))
    lib = ctypes.CDLL(path)
    u8p = ctypes.POINTER(ctypes.c_uint8)
    lib.aescore_version.restype = ctypes.c_char_p
    lib.aescore_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                                    ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                                    ctypes.c_size_t, ctypes.c_int, ctypes.POINTER(u8p),
                                    ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t]
    lib.aescore_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                                    ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int,
                                    ctypes.POINTER(u8p), ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p,
                                    ctypes.c_size_t]
    lib.aescore_random.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.aescore_free.argtypes = [u8p]
    return lib


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("aestool GUI (Crypto++ core)")
        self.geometry("760x600")
        self.lib = load_lib()

        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Mode").grid(row=0, column=0, sticky="w")
        self.mode = tk.StringVar(value="gcm")
        ttk.Combobox(top, textvariable=self.mode, values=MODES, width=8, state="readonly").grid(row=0, column=1, padx=4)
        ttk.Label(top, text="Key (hex)").grid(row=0, column=2, padx=(12, 0))
        self.key = tk.StringVar()
        ttk.Entry(top, textvariable=self.key, width=70, show="*").grid(row=0, column=3, padx=4)
        ttk.Button(top, text="Generate 256-bit", command=self.gen_key).grid(row=0, column=4)
        ttk.Label(top, text="AAD (text, AEAD)").grid(row=1, column=0, columnspan=2, sticky="w", pady=4)
        self.aad = tk.StringVar()
        ttk.Entry(top, textvariable=self.aad, width=70).grid(row=1, column=3, sticky="w", padx=4)
        self.allow_ecb = tk.BooleanVar()
        ttk.Checkbutton(top, text="allow ECB > 16 KiB", variable=self.allow_ecb).grid(row=1, column=4)

        ttk.Label(self, text="Input (plain text for Encrypt, hex container for Decrypt)").pack(anchor="w", padx=8)
        self.inp = tk.Text(self, height=9)
        self.inp.pack(fill="both", expand=True, padx=8)
        btns = ttk.Frame(self, padding=8)
        btns.pack(fill="x")
        ttk.Button(btns, text="Encrypt text", command=self.enc_text).pack(side="left", padx=4)
        ttk.Button(btns, text="Decrypt text", command=self.dec_text).pack(side="left", padx=4)
        ttk.Button(btns, text="Encrypt file...", command=self.enc_file).pack(side="left", padx=16)
        ttk.Button(btns, text="Decrypt file...", command=self.dec_file).pack(side="left", padx=4)
        ttk.Label(self, text="Output").pack(anchor="w", padx=8)
        self.out = tk.Text(self, height=9)
        self.out.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.status = tk.StringVar(value=self.lib.aescore_version().decode())
        ttk.Label(self, textvariable=self.status, relief="sunken").pack(fill="x")

    # ---- helpers
    def key_bytes(self):
        try:
            return bytes.fromhex(self.key.get().strip())
        except ValueError:
            raise ValueError("Key must be a hex string")

    def gen_key(self):
        n = 64 if self.mode.get() == "xts" else 32
        buf = ctypes.create_string_buffer(n)
        self.lib.aescore_random(buf, n)
        self.key.set(buf.raw.hex())

    def call(self, fn, *args):
        u8p = ctypes.POINTER(ctypes.c_uint8)
        out = u8p()
        out_len = ctypes.c_size_t(0)
        err = ctypes.create_string_buffer(512)
        rc = fn(*args, ctypes.byref(out), ctypes.byref(out_len), err, 512)
        if rc != 0:
            msg = err.value.decode(errors="replace")
            raise RuntimeError(("AUTHENTICATION FAILED - " if rc == 2 else "") + msg)
        data = ctypes.string_at(out, out_len.value)
        self.lib.aescore_free(out)
        return data

    def encrypt(self, data):
        key = self.key_bytes()
        aad = self.aad.get().encode("utf-8")
        return self.call(self.lib.aescore_encrypt, self.mode.get().encode(), key, len(key), None, 0, aad,
                         len(aad), data, len(data), int(self.allow_ecb.get()))

    def decrypt(self, data):
        key = self.key_bytes()
        aad = self.aad.get().encode("utf-8")
        return self.call(self.lib.aescore_decrypt, None, key, len(key), aad if aad else None, len(aad), data,
                         len(data), int(self.allow_ecb.get()))

    def show(self, text):
        self.out.delete("1.0", "end")
        self.out.insert("1.0", text)

    def fail(self, e):
        self.status.set("ERROR: " + str(e))
        messagebox.showerror("aestool", str(e))

    # ---- actions
    def enc_text(self):
        try:
            data = self.inp.get("1.0", "end-1c").encode("utf-8")
            ct = self.encrypt(data)
            self.show(ct.hex())
            self.status.set(f"Encrypted {len(data)} bytes -> {len(ct)} bytes (hex shown)")
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
            self.status.set(f"Decrypted {len(pt)} bytes")
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
            self.status.set(f"Wrote {p}.aest")
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
            self.status.set(f"Wrote {outp}")
        except Exception as e:  # noqa: BLE001
            self.fail(e)


if __name__ == "__main__":
    try:
        App().mainloop()
    except Exception as exc:  # noqa: BLE001
        print("Cannot start GUI:", exc)
        sys.exit(1)
