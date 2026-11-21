#!/bin/bash
# run_all.sh - Lab 4: build -> KAT -> benchmark -> X.509 tests -> tables
# QUICK=1 ./scripts/run_all.sh   skips the 100 MiB / 1 GiB benchmarks (smoke test)
set -u
LAB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$LAB_DIR/build"; BIN="$LAB_DIR/bin/hashtool"
DATA="$LAB_DIR/data"; RES="$LAB_DIR/results"; LOGS="$LAB_DIR/logs"; CERTS="$LAB_DIR/certs"
mkdir -p "$BUILD_DIR" "$DATA" "$RES" "$LOGS" "$CERTS"

echo "=== LAB 4 RUN ALL ==="; echo "Working directory: $LAB_DIR"

echo; echo "--- Step 0: OpenSSL version ---"
openssl version -a 2>&1 | head -3
openssl version 2>&1 | grep -Eq "OpenSSL [34]\." && echo "OK (>= 3.0)" || echo "WARNING: need OpenSSL >= 3.0 (pass -DOPENSSL_ROOT_DIR=...)"

echo; echo "--- Step 1: Build ---"
cd "$BUILD_DIR" || exit 1
CMAKE_ARGS=(.. -DCMAKE_BUILD_TYPE=Release)
[ -n "${OPENSSL_ROOT_DIR:-}" ] && CMAKE_ARGS+=("-DOPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR")
cmake "${CMAKE_ARGS[@]}" && cmake --build . --config Release || { echo "Build failed"; exit 1; }
cd "$LAB_DIR"
[ -x "$BIN" ] || { echo "Binary not found: $BIN"; exit 1; }

echo; echo "--- Step 2: KAT ---"
"$BIN" --kat "$LAB_DIR/vectors/vectors.json" 2>&1 | tee "$LOGS/kat_run.log" | tail -3

echo; echo "--- Step 3: Benchmark ---"
mk() { [ -f "$1" ] || { echo "Creating $2 MiB file $(basename "$1")"; dd if=/dev/urandom of="$1" bs=1M count="$2" 2>/dev/null; }; }
mk "$DATA/test_1m.bin" 1
bench() { # name, then hashtool args
  local out="$RES/$1.csv"; shift
  echo "  bench -> $(basename "$out")"; "$BIN" "$@" > "$out" 2>&1
}
for a in sha256 sha512 sha3-256 sha3-512; do
  bench "${a}_1m" --algo "$a" --in "$DATA/test_1m.bin" --bench 30
done
if [ -z "${QUICK:-}" ]; then
  mk "$DATA/test_100m.iso" 100; mk "$DATA/test_1g.iso" 1024
  for a in sha256 sha512 sha3-256 sha3-512; do
    bench "${a}_100m_stream" --algo "$a" --in "$DATA/test_100m.iso" --stream --bench 30
    bench "${a}_100m_mmap"   --algo "$a" --in "$DATA/test_100m.iso" --mmap   --bench 30
  done
  bench sha256_1g_stream --algo sha256 --in "$DATA/test_1g.iso" --stream --bench 30
  bench sha256_1g_mmap   --algo sha256 --in "$DATA/test_1g.iso" --mmap   --bench 30
  bench sha512_1g_stream --algo sha512 --in "$DATA/test_1g.iso" --stream --bench 30
fi

echo; echo "--- Step 4: X.509 ---"
CERT="$CERTS/cert.pem"; [ -f "$CERT" ] || CERT="$CERTS/valid.crt"
if [ -f "$CERT" ]; then
  "$BIN" --algo x509 --in "$CERT" --out "$RES/valid_cert_info.txt" | tail -1
  # negative test: flip last byte of the DER (inside the signature value)
  python3 - "$CERT" "$CERTS/tampered.crt" << 'PY'
import base64, re, sys
b = bytearray(base64.b64decode(re.sub(r'-----.*?-----|\s', '', open(sys.argv[1]).read())))
b[-1] ^= 0xFF
body = re.sub(r'(.{64})', r'\1\n', base64.b64encode(bytes(b)).decode())
open(sys.argv[2], 'w').write("-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n")
PY
  "$BIN" --algo x509 --in "$CERTS/tampered.crt" --out "$RES/tampered_info.txt" | tail -1
  [ -f "$CERTS/expired.crt" ] && "$BIN" --algo x509 --in "$CERTS/expired.crt" --out "$RES/expired_info.txt" | tail -1
else
  echo "No certificate found in $CERTS"
fi

echo; echo "--- Step 5: Tables / plots ---"
python3 "$LAB_DIR/scripts/make_tables.py" 2>&1 | tail -5 || echo "(make_tables.py failed - needs matplotlib/numpy)"

echo; echo "=== SUMMARY ==="; echo "KAT log: logs/kat_run.log"; ls "$RES"
echo "=== END ==="
