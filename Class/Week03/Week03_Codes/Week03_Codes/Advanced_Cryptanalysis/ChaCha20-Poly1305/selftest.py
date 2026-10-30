#!/usr/bin/env python3
from chacha20_poly1305_core import selftest
from aead_controlled_tamper_rejection import demo as tamper_demo
from poly1305_nonce_reuse_forgery_lab import demo as forgery_demo
from unsafe_release_before_verify_lab import demo as unsafe_demo

assert selftest(verbose=True)
print("\n--- Tamper rejection ---")
assert tamper_demo()
print("\n--- Nonce-reuse forgery ---")
assert forgery_demo()
print("\n--- Verify-before-release ---")
assert unsafe_demo()
print("\nAll ChaCha20-Poly1305 cryptanalysis lab self-tests: PASS")
