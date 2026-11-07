# AGENTS.md — Lab 3: RSA-OAEP & Hybrid Encryption (`rsatool`)

You are a coding agent implementing `rsatool`, a C++ CLI for RSA-OAEP and hybrid (envelope) encryption.
Read this file fully before writing code. Follow it strictly. If something is ambiguous, pick the safer option and document it in README.md.

## 1. Hard constraints

- Language: C++17 or newer. Build system: CMake >= 3.20. Must build on Linux (GCC/Clang) and Windows (MSVC 2022).
- Crypto library: **OpenSSL >= 4.0 only** (libcrypto). Do NOT use Crypto++, libsodium, or any other crypto library.
- Use the high-level **EVP API only** (`EVP_PKEY`, `EVP_PKEY_CTX`, `EVP_CIPHER_CTX`, `EVP_MD`, `RAND_bytes`).
  Do NOT use deprecated low-level `RSA_*`, `AES_*`, `SHA256_*` functions. Do NOT use ENGINE (removed in 4.0). Do NOT use `ASN1_STRING` internals (opaque in 4.0).
- Enforce the version at build time:
  - CMake: `find_package(OpenSSL 4.0 REQUIRED)`
  - C++: `static_assert(OPENSSL_VERSION_MAJOR >= 4, "OpenSSL >= 4.0 required");`
- Third-party deps via CMake `FetchContent` (pin versions): CLI11 (args), nlohmann/json (JSON), Catch2 v3 (tests).
- No `using namespace std;` in headers. No raw `new/delete`; wrap OpenSSL objects in `std::unique_ptr` with custom deleters (RAII).

## 2. Cryptographic parameters (must match the lab spec)

| Item | Setting |
|---|---|
| RSA modulus | 3072 (required), 4096 (comparison). **Reject every other size**, including < 3072 |
| Padding | RSA-OAEP (`RSA_PKCS1_OAEP_PADDING`) |
| OAEP hash | SHA-256 (`EVP_PKEY_CTX_set_rsa_oaep_md`) |
| MGF1 hash | SHA-256 (`EVP_PKEY_CTX_set_rsa_mgf1_md`) |
| OAEP label | optional, `--label`, set with `EVP_PKEY_CTX_set0_rsa_oaep_label` (OpenSSL takes ownership: pass an `OPENSSL_malloc`'d copy) |
| Symmetric | AES-256-GCM, 32-byte key, **12-byte (96-bit) random IV**, 16-byte tag |
| Randomness | `RAND_bytes` only; check return value |

Max direct-OAEP plaintext: `mLen <= k - 2*hLen - 2`, with k = modulus bytes, hLen = 32.
- RSA-3072: 384 - 66 = **318 bytes**
- RSA-4096: 512 - 66 = **446 bytes**

Hybrid steps: random 32-byte AES key -> AES-256-GCM encrypt data -> wrap AES key with RSA-OAEP -> write envelope.
A fresh key and fresh IV for **every** encryption. Never reuse an IV with the same key.

## 3. Suggested layout

```
rsatool/
  CMakeLists.txt
  CMakePresets.json          (presets: linux-release, windows-release)
  .gitignore  .gitattributes
  README.md                  (quick start, both OS, Vietnamese)
  AGENTS.md
  docs/
    INSTALL_OPENSSL.md       (build/install OpenSSL >= 4.0 on Linux and Windows)
    USAGE.md                 (every command, every option, examples + expected output)
    DESIGN.md                (detailed code & crypto explanation)
    TESTING_AND_BENCH.md     (how to run tests/benchmarks, how to read results)
    TROUBLESHOOTING.md
  scripts/
    build.sh   build.ps1
    test.sh    test.ps1
    demo.sh    demo.ps1      (end-to-end demo: keygen -> encrypt -> decrypt -> diff)
    bench.sh   bench.ps1
  include/rsatool/   keys.hpp  oaep.hpp  hybrid.hpp  envelope.hpp  codec.hpp  errors.hpp  secure.hpp  platform.hpp
  src/               main.cpp  keys.cpp  oaep.cpp  hybrid.cpp  envelope.cpp  codec.cpp  platform.cpp
  src/bonus/         oaep_manual.cpp   (optional bonus A)
  tests/             test_oaep.cpp  test_hybrid.cpp  test_negative.cpp  test_codec.cpp
  bench/             bench.cpp  plot.py  results/
  report/            report.md
```

## 4. CLI

```
rsatool keygen  --bits 3072 --pub pub.pem --priv priv.pem
rsatool encrypt --in msg.bin --pub pub.pem --out ct.bin [--label TEXT] [--encode raw|hex|base64] [--mode auto|direct|hybrid]
rsatool decrypt --in ct.bin --priv priv.pem --out msg.bin [--label TEXT] [--encode raw|hex|base64]
```

- `keygen` writes: PEM pair, DER pair (`pub.der`, `priv.der`), and `meta.json`:
  `{"creation_time":"<ISO-8601 UTC>","modulus_bits":3072,"hash":"SHA-256"}`
- Private key file permissions 0600 on POSIX. Never print key material or plaintext to the terminal/logs.
- Key loading accepts PEM or DER (auto-detect by trying DER only if PEM header is absent). Reject non-RSA keys and unsupported sizes.
- `--mode auto` (default): direct OAEP if `len <= mLen`, otherwise hybrid automatically. `--mode hybrid` forces hybrid (needed for benchmarks on 1 KiB).
- Exit code 0 on success, non-zero on any failure. Never leave a partial output file on failure (write to temp file, rename on success).

## 5. Envelope format

Container (same for direct and hybrid so `decrypt` never has to guess):

```
[4 bytes big-endian: header_len][header JSON, UTF-8][payload bytes]
```

Header JSON:

```json
{
  "mode": "RSA-OAEP-AES-GCM",
  "rsa_modulus": 3072,
  "hash": "SHA-256",
  "wrapped_key": "<base64>",
  "iv": "<base64, 12 bytes>",
  "tag": "<base64, 16 bytes>"
}
```

- Direct mode uses `"mode": "RSA-OAEP"` with only `rsa_modulus`, `hash`, `wrapped_key` (= the OAEP ciphertext). Document this choice in README.
- **Bind the header to the ciphertext**: pass the canonical header bytes (header JSON without `tag`, serialized deterministically) as **AAD** to AES-GCM, so any header tampering makes tag verification fail.
- Parsing rules (fail closed): enforce max `header_len` (e.g. 64 KiB); require exact field set; strict base64 (no whitespace, correct padding); `iv` must decode to exactly 12 bytes, `tag` to exactly 16; `wrapped_key` length must equal modulus bytes; `rsa_modulus` must match the private key; `hash` must be `SHA-256`; reject unknown `mode`.
- Outer `--encode` applies to the whole output file (raw / hex / base64). Decoders must be strict and reject invalid characters or odd-length hex.

## 6. Secure-coding rules

1. **Decrypt, then release.** For AES-GCM, never write plaintext to the final output until `EVP_DecryptFinal_ex` succeeds (tag verified). Stream into a temp file or buffer, delete it on failure.
2. Set the expected tag with `EVP_CTRL_AEAD_SET_TAG` **before** `Final`. Tag comparison is done by OpenSSL (constant time).
3. **One generic error message** for every cryptographic failure, e.g. `error: decryption failed`. Do not distinguish bad padding / bad label / bad tag / wrong key in user-visible output (avoids Bleichenbacher/Manger-style oracles). Parse/format errors may be specific but must not leak secrets (e.g. `error: malformed envelope`).
4. Always drain the OpenSSL error queue (`ERR_clear_error()`); do not print `ERR_error_string` output in normal mode (allow it only behind a `--debug` flag).
5. Wipe secrets: AES key, plaintext buffers holding secrets, and private-key buffers with `OPENSSL_cleanse`. Prefer a small RAII `SecureBuffer`.
6. Check the return value of **every** OpenSSL call. Use a single `throw CryptoError` path; `main` catches and exits non-zero.
7. Chunk large files (e.g. 1 MiB chunks) with `EVP_EncryptUpdate` so 100 MiB does not need to be fully loaded (single GCM tag over the whole stream).
8. No timing-dependent early exits on secret-dependent data in your own code. Use `CRYPTO_memcmp` for any comparison of secret values.

## 6A. Cross-platform requirements (Linux AND Windows are both mandatory)

The tool must build and run on **Linux (GCC >= 11 or Clang >= 14)** and **Windows 10/11 x64 (MSVC 2022)**. Write portable code from the start; do not write for one OS and "port later".

OpenSSL location (never hardcode in CMakeLists.txt; always take it from `OPENSSL_ROOT_DIR` or CMake's normal discovery):
- Developer's Windows machine: `OPENSSL_ROOT_DIR=D:/cryptolibrary/openssl403` (OpenSSL 4.0.3, installed with `include/`, `lib/`, `bin/`).
- Linux example: `OPENSSL_ROOT_DIR=/opt/openssl4`.
- Do NOT use `D:/cryptolibrary/include`, `D:/cryptolibrary/libs`, or `cryptopp`; they may contain other versions and cause header/lib mismatch.
- After `find_package`, print the found version and path in the CMake output and fail if `OPENSSL_VERSION` < 4.0 (this catches a system OpenSSL 3.x being picked up by mistake).

Portability rules:
1. **Binary I/O everywhere.** Open every file with `std::ios::binary`. On Windows text mode corrupts data (`\r\n`, Ctrl-Z). Never write binary data to stdout/stderr.
2. Use `std::filesystem` for all paths. Accept UTF-8 paths (on Windows convert via `std::filesystem::u8path` / `char8_t` helpers in `platform.cpp`).
3. Do not pass `FILE*` to OpenSSL (avoids Windows `applink` problems). Read files yourself and pass buffers / `BIO_new_mem_buf`.
4. File permissions: on POSIX set 0600 on the private key (`chmod`/`std::filesystem::permissions`). On Windows `chmod` is meaningless: restrict inheritance/ACL if feasible, otherwise print a one-line warning and document it in README. Hide this behind `platform::restrict_private_file(path)`.
5. Time: ISO-8601 UTC for `creation_time`; use `std::chrono` plus `gmtime_s` (Windows) / `gmtime_r` (POSIX) inside `platform.cpp`. No plain `gmtime`.
6. Safe overwrite: write to a temp file in the same directory, then `std::filesystem::rename` to the target. Delete the temp file on every failure path.
7. Endianness and sizes: encode `header_len` explicitly as big-endian bytes; use `std::uint32_t/std::uint64_t/std::size_t`; never use `long` for sizes (it is 32-bit on Windows).
8. Compiler flags: GCC/Clang `-Wall -Wextra -Wpedantic -Wconversion`; MSVC `/W4 /permissive- /utf-8`. Warnings must be clean. Build in Release by default.
9. Linking: `OpenSSL::Crypto`. If statically linked on Windows also link `ws2_32 crypt32 advapi32 user32`. Prefer dynamic linking for simplicity.
10. **Windows DLLs:** add a post-build CMake step that copies the OpenSSL `libcrypto*.dll` from `${OPENSSL_ROOT_DIR}/bin` next to `rsatool.exe` and the test/bench executables (use `$<TARGET_FILE_DIR:...>`). On Linux set `RPATH`/`BUILD_RPATH` to the OpenSSL `lib` directory so a custom `/opt/openssl4` is found at runtime.
11. Line endings: `.gitattributes` with `* text=auto` and `*.bin *.der -text`. Shell scripts `*.sh text eol=lf`, PowerShell `*.ps1 text eol=crlf`.
12. Tests and benchmarks must create their own temp files via `std::filesystem::temp_directory_path()`; no hardcoded `/tmp` or `C:\`.
13. `CMakePresets.json` must provide `linux-release` and `windows-release` presets (Ninja or Visual Studio 17 2022 generator) so the build is one command per OS.
14. Provide script pairs (`.sh` and `.ps1`) with identical behavior for build, test, demo, and bench. Scripts must stop on first error (`set -euo pipefail` / `$ErrorActionPreference = "Stop"`) and accept the OpenSSL root as an argument or env var.
15. Optional but recommended: `.github/workflows/ci.yml` building and testing on `ubuntu-latest` and `windows-latest`.

**Honesty rule:** you can only claim a platform works if you actually built and ran the tests on it. If you can run only one OS, say so explicitly in your final summary and in README ("Verified on: ...", "Written to be portable but not verified on: ..."). Never state that an untested platform works.

## 6B. Documentation deliverables (required, written in Vietnamese; keep code, commands, and identifiers in English)

Documentation is graded (build & docs 5 pts, report 10 pts). Write real, step-by-step, copy-pasteable instructions. Every command must appear for **both** Linux (bash) and Windows (PowerShell), side by side, with expected output.

1. `README.md`: what the tool does; requirements table; quick start (clone -> build -> demo) for Linux and Windows; folder map; link to the other docs; "Verified on" line, main language is Vietnamese.
2. `docs/INSTALL_OPENSSL.md`: why OpenSSL >= 4.0; how to check the installed version; build from source on Linux (`./Configure --prefix=/opt/openssl4 --libdir=lib && make && make install`) and on Windows (VS x64 Native Tools prompt, Perl, NASM, `perl Configure VC-WIN64A --prefix=... --openssldir=...`, `nmake`, `nmake install`); how to point CMake at it with `OPENSSL_ROOT_DIR`; how to confirm the right DLL/so is loaded.
3. `docs/USAGE.md`: every subcommand and option (`keygen`, `encrypt`, `decrypt`, `--label`, `--encode`, `--mode`, `--bits`), exit codes, file formats produced (PEM, DER, meta.json, envelope), and 3 worked examples (small message -> direct RSA-OAEP; large file -> hybrid; wrong label -> failure) with real output.
4. `docs/DESIGN.md`: detailed explanation of the code, module by module (what each file does, key functions, data flow diagram for encrypt and decrypt in text/mermaid); why each parameter was chosen (SHA-256, MGF1, 96-bit IV, AAD-bound header); the mLen formula with the 3072/4096 numbers; why one generic error message; why decrypt-then-release; how the envelope bytes are laid out (offset table); how secrets are wiped.
5. `docs/TESTING_AND_BENCH.md`: how to run unit tests and benchmarks on each OS, what each test proves (map each negative test to the lab requirement), how to regenerate plots, how to read the CSV and the 95% CI.
6. `docs/TROUBLESHOOTING.md`: at least these cases with cause and fix: CMake finds OpenSSL 3.x instead of 4.x; `cannot find libcrypto` / missing DLL on Windows; `LNK2019`/lib mismatch; wrong `OPENSSL_ROOT_DIR` slashes on Windows (use `/`); Python plot dependencies missing; permission errors on key files; garbled output from text-mode file I/O.
7. `report/report.md`: the lab report (theory + benchmark analysis + bonus if done).
8. In-code documentation: short header comment per source file saying its purpose; comments only where the "why" is not obvious (especially security-relevant choices).

Doc quality bar: someone who has never seen the project must be able to go from an empty machine to a successful `scripts/demo` run by following README.md alone. Verify this by re-reading the commands you wrote against the real scripts.

## 7. Tests (Catch2) — all must pass in CI

Positive:
- RSA-3072 and RSA-4096 OAEP round trip (empty label and with label), at 0 bytes, 1 byte, and exactly `mLen` bytes.
- `mLen + 1` triggers hybrid automatically; hybrid round trip for 1 KiB, 1 MiB (100 MiB only in benchmark, not unit tests).
- raw / hex / base64 encode-decode round trips.
- Key generation produces valid PEM, DER, and metadata JSON.

Negative (each must fail closed with a generic error, and write no output file):
- Flip one bit in the RSA ciphertext.
- Flip one bit in AES-GCM ciphertext (tag failure).
- Wrong private key.
- Wrong OAEP label (and label present vs absent).
- Tampered header (change `rsa_modulus`, `iv`, `tag`, `wrapped_key`, `mode`, or any byte of the JSON).
- Truncated file, empty file, `header_len` larger than file, absurd `header_len`.
- Invalid base64 / hex, unsupported key size (2048, 1024), non-RSA key, plaintext too long in `--mode direct`.

## 8. Benchmarks (`bench/`)

- Measure with `std::chrono::steady_clock`; warm up first; **>= 30 repetitions** (fewer for 100 MiB, but >= 10), build in Release (`-O2`).
- RSA: keygen time (3072 vs 4096; keygen is slow and variable, use fewer reps and report that), encrypt time, decrypt time.
- AES-256-GCM throughput (MiB/s) and hybrid total time for 1 KiB, 1 MiB, 100 MiB.
- Output CSV into `bench/results/`. `plot.py` (pandas, numpy, scipy, matplotlib) computes mean and **95% CI** (Student t) and writes latency and throughput plots (PNG, log-scale axes where useful).
- Report analysis points: RSA decrypt vs encrypt cost (decrypt is much slower: private exponent), 3072 vs 4096 trade-off, why hybrid wins, why symmetric dominates throughput, memory/CPU notes (streaming chunks, AES-NI).

## 9. Bonus (only after everything above works)

**A. Manual OAEP (+5)** in `src/bonus/oaep_manual.cpp`: implement MGF1 (SHA-256) and the seed/DB masking yourself with `EVP_Digest`; do the raw RSA step via EVP with `RSA_NO_PADDING`. Decoding must be **constant-time** (no early return; combine checks with bitmask arithmetic; single failure path). Cross-test: manual encode -> OpenSSL decrypt and OpenSSL encrypt -> manual decode. In the report explain why non-constant-time decoding enables a padding oracle (Manger).

**B. Hybrid security analysis (+10)** in `report/`: envelope vs direct RSA; how TLS uses hybrid design; why static-RSA key exchange lacks forward secrecy; upgrade path to ECDHE / ML-KEM (OpenSSL 4.0 can be used for a preview). Optional: AES-CTR + HMAC vs AES-GCM and auth-failure timing variance.

## 10. Deliverables checklist

- [ ] Builds with CMake on Linux **and** Windows against OpenSSL >= 4.0 (`-DOPENSSL_ROOT_DIR=...` documented, presets + `.sh`/`.ps1` scripts provided)
- [ ] Build fails loudly if OpenSSL < 4.0 is found
- [ ] Windows DLL copy step and Linux RPATH work (run `rsatool` from a clean shell without editing PATH)
- [ ] End-to-end `scripts/demo.sh` and `scripts/demo.ps1` succeed (decrypted file is byte-identical, verified with `cmp` / `fc /b` or hash compare)
- [ ] `rsatool keygen/encrypt/decrypt` working, PEM + DER + metadata JSON
- [ ] Hybrid envelope with AAD-bound header
- [ ] Unit tests (positive + negative) green via `ctest`
- [ ] Benchmarks + plots with 95% CI
- [ ] Docs in section 6B all present (README, INSTALL_OPENSSL, USAGE, DESIGN, TESTING_AND_BENCH, TROUBLESHOOTING) with Linux + Windows commands
- [ ] "Verified on" statement is truthful
- [ ] Report (IND-CCA2, PKCS#1 v1.5 weakness, mLen formula, why RSA can't encrypt files, benchmark analysis)

## 11. Working style for the agent

- Work in small steps: CMake skeleton with OpenSSL >= 4 check (both OS) -> keys -> OAEP -> codec -> envelope/hybrid -> CLI -> tests -> scripts -> bench -> docs -> bonus. Build and run tests after each step.
- Do not add features not listed here. Do not weaken any security rule to make a test pass; fix the code instead.
- When you finish, summarize what was done, how to build, and any deviation from this file.