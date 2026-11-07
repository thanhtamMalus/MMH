#!/usr/bin/env bash
# build.sh — Build rsatool on Linux
# Usage: ./scripts/build.sh [/path/to/openssl4]
# OPENSSL_ROOT_DIR can also be set as an environment variable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build/linux-release"

# Allow passing OPENSSL_ROOT_DIR as first arg
if [[ "${1:-}" != "" ]]; then
    export OPENSSL_ROOT_DIR="$1"
fi

if [[ -z "${OPENSSL_ROOT_DIR:-}" ]]; then
    echo "INFO: OPENSSL_ROOT_DIR not set — CMake will search the system path."
    echo "      If OpenSSL 3.x is found, the build will FAIL (requires >= 4.0)."
    echo "      Set OPENSSL_ROOT_DIR or pass it as the first argument."
fi

echo "=== Configuring (cmake --preset linux-release) ==="
cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" \
      -DCMAKE_BUILD_TYPE=Release \
      ${OPENSSL_ROOT_DIR:+-DOPENSSL_ROOT_DIR="$OPENSSL_ROOT_DIR"}

echo ""
echo "=== Building ==="
cmake --build "$BUILD_DIR" --config Release -j"$(nproc)"

echo ""
echo "=== Done ==="
echo "Executable : $BUILD_DIR/rsatool"
echo ""
echo "Run the demo:  bash scripts/demo.sh"
echo "Run tests  :   bash scripts/test.sh"

