# Lab 4 - changes (code aligned with the spec in Cryptography_Labs.md, Lab 4)

- src/hashtool.cpp: rewritten on the EVP API (no more `openssl` via `_popen`).
  SHA-224/256/384/512, SHA3-224/256/384/512, SHAKE128/256 (`--outlen`), `--stream` (1 MiB chunks),
  `--mmap`, hex console + hex/base64/raw `--out`, `--kat`, `--bench N` (mean/median/stddev/95% CI/CPU%),
  `--algo x509` (+ `--issuer`, `--no-time-check`). Fail closed: unknown algo/option, bad --outlen -> exit 2; I/O -> 3.
- src/x509_tool.cpp (new): Subject, Issuer, SPKI (alg + params), signature alg, validity, KeyUsage/EKU, SANs,
  signature verification (issuer key or self-signed), TBS-vs-outer algorithm consistency, MD5/SHA-1 rejection.
- common/common.hpp: fixed (from_hex used before declaration, missing <cmath>, wrong Student-t constant, bogus X509 API).
- vectors/vectors.json: regenerated, 72 vectors (old file had wrong digests/inputs).
- CMakeLists.txt: OpenSSL >= 3.0 (4.x also fine), MSVC flag typo fixed, binary always in bin/.
- scripts/run_all.ps1 / run_all.sh: new CLI, correct paths, tamper test flips a signature byte.
- scripts/make_tables.py: syntax error, wrong stats line, errorbar shape fixed.
Not covered by code (report/demo work): MD5 collision (hashclash), length-extension (hashpump or own), TLS deployment.
