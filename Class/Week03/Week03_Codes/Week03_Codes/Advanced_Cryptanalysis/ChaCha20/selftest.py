#!/usr/bin/env python3
from chacha20_core import rfc8439_selftest, chacha_xor
from chacha20_malleability_controlled_patch import patch_ciphertext

assert rfc8439_selftest()

key = bytes(range(32))
nonce = bytes.fromhex('000000000000000000000002')
counter = 1
p = b'uid=1001;role=user;expires=2026-12-31'
old = b'user'
new = b'root'
off = p.index(old)

c = chacha_xor(key, nonce, counter, p)
forged, delta = patch_ciphertext(c, off, old, new)
p2 = chacha_xor(key, nonce, counter, forged)

assert p2 == b'uid=1001;role=root;expires=2026-12-31'
assert delta == bytes(a ^ b for a, b in zip(old, new))

print('RFC 8439 ChaCha20 core test       : PASS')
print('Controlled ciphertext patch test : PASS')
