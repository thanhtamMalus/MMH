# Week 3 — ChaCha20-Poly1305 Cryptanalysis / Misuse Labs

These labs extend the earlier known-plaintext/keystream-reuse exercise. They are
organized around a crucial distinction:

> **ChaCha20-Poly1305 is not practically broken when used according to RFC 8439.**
> The most instructive failures are misuse conditions and unsafe implementations,
> especially nonce reuse.

## 1. `aead_controlled_tamper_rejection.py`

Shows why the controlled ciphertext patch that works against **bare ChaCha20** does
not work against correctly implemented ChaCha20-Poly1305.

```text
C' = C XOR Delta
```

still changes the underlying ChaCha20 plaintext predictably, but the Poly1305 tag no
longer verifies, so the receiver rejects the record before releasing plaintext.

Run:

```bash
python aead_controlled_tamper_rejection.py --demo
```

Teaching role: **AEAD fixes malleability when authentication is enforced.**

---

## 2. `poly1305_nonce_reuse_forgery_lab.py`

This is the central advanced cryptanalysis lab.

Reusing the same `(key, nonce)` repeats:

1. the ChaCha20 payload keystream; and
2. the Poly1305 one-time key `(r,s)` derived from ChaCha20 counter 0.

The program demonstrates actual **integrity forgery** in a deliberately restricted
case that keeps the mathematics transparent:

- empty AAD;
- two valid records under the same reused nonce;
- equal ciphertext lengths;
- ciphertext length 1..16 bytes.

For this case the RFC 8439 Poly1305 input has two blocks, and the equal length block
cancels between the two tag equations. The program recovers the clamped `r`, derives
`s`, modifies ciphertext, computes a fresh valid tag, and shows the victim accepting
the forged plaintext.

```bash
python poly1305_nonce_reuse_forgery_lab.py --demo
```

The attacker portion receives **no ChaCha20 key**.

An attacker-only mode is also provided:

```bash
python poly1305_nonce_reuse_forgery_lab.py \
  --c1 <HEX> --t1 <HEX> \
  --c2 <HEX> --t2 <HEX> \
  --target <TARGET_CIPHERTEXT_HEX>
```

The supplied records must satisfy the restricted lab assumptions above.

Teaching role:

```text
nonce reuse
   -> same ChaCha20 stream        -> confidentiality failure
   -> same Poly1305 one-time key  -> integrity/forgery failure
```

---

## 3. `tag_truncation_forgery_lab.py`

ChaCha20-Poly1305 in RFC 8439 uses a **128-bit tag**. This program demonstrates how
an application that improperly truncates the tag lowers random-forgery resistance.

```bash
python tag_truncation_forgery_lab.py --bits 16 --guesses 100000 --trials 20
```

It reports

```text
Pr[random success per guess] = 2^-t
Pr[success after q guesses]   = 1-(1-2^-t)^q
```

The brute-force simulation is intentionally limited to small classroom values. For
128 bits the program reports the analytical result only.

Teaching role: **tag truncation is an application-level security degradation, not a
break of the standard 128-bit AEAD.**

---

## 4. `nonce_collision_risk_lab.py`

Computes the birthday collision probability when nonces are selected randomly:

```text
Pr[collision] ≈ 1 - exp(-q(q-1)/(2*2^n))
```

and uses a smaller nonce space for a visible Monte Carlo demonstration.

```bash
python nonce_collision_risk_lab.py \
  --messages 1000000 \
  --bits 96 \
  --simulate-bits 16 \
  --simulate-messages 300 \
  --trials 200
```

Teaching role: the security requirement is **nonce uniqueness per key**, not merely
"a large nonce usually does not collide."

---

## 5. `unsafe_release_before_verify_lab.py`

Demonstrates a dangerous implementation anti-pattern:

```text
UNSAFE: decrypt/release plaintext -> verify tag
SAFE:   verify tag -> decrypt/release plaintext
```

A modified ciphertext is rejected in both cases eventually, but the unsafe version
lets attacker-influenced plaintext reach application logic before authentication is
known.

```bash
python unsafe_release_before_verify_lab.py
```

Teaching role: **AEAD security also depends on correct API/use semantics.**

---

## Recommended Week 3 order

```text
Bare ChaCha20 malleability
        ↓
ChaCha20-Poly1305 rejects the same patch
        ↓
Nonce reuse repeats payload keystream
        ↓
Nonce reuse also repeats Poly1305 (r,s)
        ↓
Restricted nonce-reuse tag forgery
        ↓
Tag-length and nonce-management security bounds
        ↓
Verify-before-release implementation discipline
```

## Self-test

```bash
python selftest.py
```

The core implementation is checked against the RFC 8439 ChaCha20-Poly1305 test
vector before running the labs.

Educational / authorized laboratory use only.
