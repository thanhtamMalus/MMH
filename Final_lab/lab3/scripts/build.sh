#!/usr/bin/env bash
# build.sh — Build rsatool trên Linux/macOS, tự động tìm OpenSSL >= 4.0
#
# Dùng:
#   ./scripts/build.sh                       # tự dò OpenSSL (khuyến nghị)
#   ./scripts/build.sh /duong/dan/openssl4   # chỉ định thủ công
#   ./scripts/build.sh --auto-openssl        # không có OpenSSL 4 -> tự tải & build
#   ./scripts/build.sh --static              # liên kết tĩnh libcrypto
#   ./scripts/build.sh --clean               # xoá build cũ trước khi build
#
# OPENSSL_ROOT_DIR (biến môi trường) cũng được hỗ trợ nhưng KHÔNG bắt buộc.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build/linux-release"

CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release)
CLEAN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --auto-openssl) CMAKE_ARGS+=(-DRSATOOL_AUTO_BUILD_OPENSSL=ON) ;;
        --static)       CMAKE_ARGS+=(-DRSATOOL_OPENSSL_STATIC=ON) ;;
        --clean)        CLEAN=1 ;;
        --verbose)      CMAKE_ARGS+=(-DRSATOOL_OPENSSL_VERBOSE=ON) ;;
        -h|--help)      sed -n '2,12p' "${BASH_SOURCE[0]}"; exit 0 ;;
        -*)             echo "Tuỳ chọn không hợp lệ: $1 (xem --help)"; exit 2 ;;
        *)              CMAKE_ARGS+=(-DOPENSSL_ROOT_DIR="$1") ;;
    esac
    shift
done

command -v cmake >/dev/null 2>&1 || { echo "ERROR: chưa cài cmake (>= 3.20)."; exit 1; }

# Thư mục build copy từ máy khác (CMakeCache trỏ đường dẫn cũ) -> CMake sẽ báo lỗi
# "does not match the source". Tự phát hiện và xoá để configure lại sạch.
CACHE="$BUILD_DIR/CMakeCache.txt"
if [[ -f "$CACHE" ]]; then
    cached_src="$(sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' "$CACHE")"
    cached_bin="$(sed -n 's/^CMAKE_CACHEFILE_DIR:INTERNAL=//p' "$CACHE")"
    if [[ "$cached_src" != "$PROJECT_DIR" || "$cached_bin" != "$BUILD_DIR" ]]; then
        echo "INFO: build cũ được tạo ở đường dẫn khác ($cached_src) -> xoá và configure lại."
        CLEAN=1
    fi
elif [[ -d "$BUILD_DIR" ]]; then
    CLEAN=1   # thư mục build dở dang (không có CMakeCache.txt)
fi
if [[ "$CLEAN" == 1 ]]; then rm -rf "$BUILD_DIR"; fi

JOBS="$( (nproc || sysctl -n hw.ncpu || echo 2) 2>/dev/null | head -n1 )"

echo "=== Configuring (tự dò OpenSSL >= 4.0) ==="
cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" "${CMAKE_ARGS[@]}"

echo ""
echo "=== Building (-j$JOBS) ==="
cmake --build "$BUILD_DIR" --config Release -j"$JOBS"

echo ""
echo "=== Done ==="
echo "Executable : $BUILD_DIR/rsatool"
echo ""
echo "Run the demo:  bash scripts/demo.sh"
echo "Run tests  :   bash scripts/test.sh"
