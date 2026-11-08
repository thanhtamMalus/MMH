#!/usr/bin/env bash
# test.sh — Run all Catch2 unit tests on Linux
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build/linux-release"

if [[ ! -f "$BUILD_DIR/test_rsatool" ]]; then
    echo "ERROR: test_rsatool not found. Run build.sh first."
    exit 1
fi

echo "=== Running unit tests ==="
cd "$BUILD_DIR"
ctest --output-on-failure -C Release

echo ""
echo "=== All tests passed ==="

