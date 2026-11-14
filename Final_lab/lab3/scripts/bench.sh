#!/usr/bin/env bash
# bench.sh — Run benchmarks and generate plots on Linux
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build/linux-release"
BENCH="$BUILD_DIR/bench_rsatool"

if [[ ! -x "$BENCH" ]]; then
    echo "ERROR: bench_rsatool not found. Run build.sh first."
    exit 1
fi

echo "=== Running benchmarks ==="
cd "$PROJECT_DIR"
"$BENCH"

echo ""
echo "=== Generating plots ==="
if command -v python3 &>/dev/null; then
    python3 bench/plot.py
else
    echo "WARNING: python3 not found. Skipping plots."
    echo "Install: pip install pandas numpy scipy matplotlib"
fi

echo ""
echo "=== Done. Results in bench/results/ ==="

