#!/usr/bin/env bash
# ==============================================================================
# Linux/macOS Runner Script for Lab 2: AES-128 (CTR Mode)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
    exec python3 "${SCRIPT_DIR}/run.py" "$@"
fi

if command -v python >/dev/null 2>&1; then
    exec python "${SCRIPT_DIR}/run.py" "$@"
fi

echo "[INFO] Python 3 not detected in PATH. Using native shell fallback..."

case "$1" in
    build)
        mkdir -p "${SCRIPT_DIR}/build"
        cd "${SCRIPT_DIR}/build"
        cmake .. -DCMAKE_BUILD_TYPE=Release
        cmake --build . -j
        ;;
    test)
        cd "${SCRIPT_DIR}/build"
        ctest --output-on-failure
        ;;
    kat)
        "${SCRIPT_DIR}/build/bin/aestool" --kat "${SCRIPT_DIR}/vectors/vectors.json"
        ;;
    demo)
        TOOL="${SCRIPT_DIR}/build/bin/aestool"
        mkdir -p "${SCRIPT_DIR}/demo_workspace"
        "${TOOL}" keygen --out "${SCRIPT_DIR}/demo_workspace/key.bin"
        "${TOOL}" ivgen --out "${SCRIPT_DIR}/demo_workspace/iv.bin"
        echo "Linux plaintext test message" > "${SCRIPT_DIR}/demo_workspace/msg.txt"
        "${TOOL}" encrypt --mode ctr --key "${SCRIPT_DIR}/demo_workspace/key.bin" --iv "${SCRIPT_DIR}/demo_workspace/iv.bin" --in "${SCRIPT_DIR}/demo_workspace/msg.txt" --out "${SCRIPT_DIR}/demo_workspace/ct.bin"
        "${TOOL}" decrypt --mode ctr --key "${SCRIPT_DIR}/demo_workspace/key.bin" --iv "${SCRIPT_DIR}/demo_workspace/iv.bin" --in "${SCRIPT_DIR}/demo_workspace/ct.bin" --out "${SCRIPT_DIR}/demo_workspace/dec.txt"
        diff "${SCRIPT_DIR}/demo_workspace/msg.txt" "${SCRIPT_DIR}/demo_workspace/dec.txt" && echo "[SUCCESS] Integrity verified."
        ;;
    *)
        echo "Usage: ./run.sh [build | test | kat | demo]"
        echo "Install python3 for the full interactive suite and benchmarks."
        exit 0
        ;;
esac
