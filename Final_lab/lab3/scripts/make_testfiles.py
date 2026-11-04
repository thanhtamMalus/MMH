#!/usr/bin/env python3
"""Create test data files for unit tests."""
import os
import sys

# Create testdata directory
testdata_dir = "testdata"
os.makedirs(testdata_dir, exist_ok=True)

# Small test messages (100 bytes)
msg_small = os.urandom(100)
with open(os.path.join(testdata_dir, "msg_small.bin"), "wb") as f:
    f.write(msg_small)

# Edge case: 318 bytes (max for RSA-3072 OAEP)
msg_edge318 = os.urandom(318)
with open(os.path.join(testdata_dir, "msg_edge318.bin"), "wb") as f:
    f.write(msg_edge318)

# Edge case: 319 bytes (triggers Hybrid mode)
msg_edge319 = os.urandom(319)
with open(os.path.join(testdata_dir, "msg_edge319.bin"), "wb") as f:
    f.write(msg_edge319)

# 1 KiB message
msg_1KiB = os.urandom(1024)
with open(os.path.join(testdata_dir, "msg_1KiB.bin"), "wb") as f:
    f.write(msg_1KiB)

# 1 MiB message
msg_1MiB = os.urandom(1024 * 1024)
with open(os.path.join(testdata_dir, "msg_1MiB.bin"), "wb") as f:
    f.write(msg_1MiB)

# 100 MiB message (for benchmark, not unit tests)
msg_100MiB = os.urandom(100 * 1024 * 1024)
with open(os.path.join(testdata_dir, "msg_100MiB.bin"), "wb") as f:
    f.write(msg_100MiB)

# Note: Files are generated with os.urandom (Python CSPRNG), as permitted
# Makefile note: add testdata/ to .gitignore

print("Test data files created in", testdata_dir)
print("  msg_small.bin (100 B)")
print("  msg_edge318.bin (318 B)")
print("  msg_edge319.bin (319 B)")
print("  msg_1KiB.bin (1 KiB)")
print("  msg_1MiB.bin (1 MiB)")
print("  msg_100MiB.bin (100 MiB)")