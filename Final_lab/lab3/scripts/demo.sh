#!/usr/bin/env bash
# demo.sh — End-to-end demo: keygen -> encrypt (direct) -> decrypt -> diff
# Then: encrypt (hybrid) -> decrypt -> diff
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build/linux-release"
TOOL="$BUILD_DIR/rsatool"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rsatool_demo.XXXXXX")"

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

if [[ ! -x "$TOOL" ]]; then
    echo "ERROR: rsatool not found at $TOOL. Run build.sh first."
    exit 1
fi

echo "========================================================"
echo "  rsatool End-to-End Demo"
echo "  Temp directory: $WORK_DIR"
echo "========================================================"
echo ""

# ── Key generation ────────────────────────────────────────────────────────────
echo "--- Step 1: Key generation (RSA-3072) ---"
"$TOOL" keygen \
    --bits 3072 \
    --pub  "$WORK_DIR/pub.pem" \
    --priv "$WORK_DIR/priv.pem"
echo ""

# ── Direct OAEP (small message) ───────────────────────────────────────────────
echo "--- Step 2: Direct RSA-OAEP encrypt (small message, 32 bytes) ---"
echo -n "Hello RSA-OAEP World! This is 32b" > "$WORK_DIR/small.bin"
"$TOOL" encrypt \
    --in    "$WORK_DIR/small.bin" \
    --pub   "$WORK_DIR/pub.pem" \
    --out   "$WORK_DIR/small.enc" \
    --mode  direct \
    --encode base64
echo ""

echo "--- Step 3: Decrypt ---"
"$TOOL" decrypt \
    --in    "$WORK_DIR/small.enc" \
    --priv  "$WORK_DIR/priv.pem" \
    --out   "$WORK_DIR/small.dec" \
    --encode base64
echo ""

echo "--- Step 4: Verify (should produce no output = files identical) ---"
if cmp -s "$WORK_DIR/small.bin" "$WORK_DIR/small.dec"; then
    echo "PASS: Decrypted file is byte-identical to original."
else
    echo "FAIL: Files differ!"
    exit 1
fi
echo ""

# ── Hybrid (large message) ────────────────────────────────────────────────────
echo "--- Step 5: Hybrid encrypt (1 KiB random data) ---"
dd if=/dev/urandom of="$WORK_DIR/large.bin" bs=1024 count=1 2>/dev/null
"$TOOL" encrypt \
    --in    "$WORK_DIR/large.bin" \
    --pub   "$WORK_DIR/pub.pem" \
    --out   "$WORK_DIR/large.enc" \
    --mode  hybrid \
    --encode hex
echo ""

echo "--- Step 6: Decrypt hybrid ---"
"$TOOL" decrypt \
    --in    "$WORK_DIR/large.enc" \
    --priv  "$WORK_DIR/priv.pem" \
    --out   "$WORK_DIR/large.dec" \
    --encode hex
echo ""

echo "--- Step 7: Verify (cmp) ---"
if cmp -s "$WORK_DIR/large.bin" "$WORK_DIR/large.dec"; then
    echo "PASS: Hybrid decrypted file is byte-identical."
else
    echo "FAIL: Hybrid files differ!"
    exit 1
fi
echo ""

# ── Wrong label -> must fail ──────────────────────────────────────────────────
echo "--- Step 8: Wrong label test (must fail with exit code != 0) ---"
"$TOOL" encrypt \
    --in    "$WORK_DIR/small.bin" \
    --pub   "$WORK_DIR/pub.pem" \
    --out   "$WORK_DIR/labeled.enc" \
    --label "correct-label" \
    --mode  direct
set +e
"$TOOL" decrypt \
    --in    "$WORK_DIR/labeled.enc" \
    --priv  "$WORK_DIR/priv.pem" \
    --out   "$WORK_DIR/labeled.dec" \
    --label "wrong-label"
RC=$?
set -e
if [[ $RC -ne 0 ]]; then
    echo "PASS: Wrong label correctly rejected (exit code $RC)."
else
    echo "FAIL: Wrong label should have failed!"
    exit 1
fi
echo ""

echo "========================================================"
echo "  All demo steps PASSED"
echo "========================================================"

