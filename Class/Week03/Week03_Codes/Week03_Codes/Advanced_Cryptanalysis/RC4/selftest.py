#!/usr/bin/env python3
from rc4_core import selftest, rc4_crypt

selftest()
key = b"classroom-key"
pt = b"RC4 round-trip test"
ct = rc4_crypt(key, pt)
assert rc4_crypt(key, ct) == pt
print("RC4 core + round-trip self-test: PASS")
