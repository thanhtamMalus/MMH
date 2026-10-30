# Week 3 — ChaCha20 Cryptanalysis / Security-Boundary Labs

These programs separate three ideas that should not be conflated:

1. **Bare ChaCha20 malleability** — an active attack caused by using encryption without authentication.
2. **Round-by-round diffusion** — a teaching diagnostic showing how a one-bit difference spreads.
3. **Reduced-round differential bias** — a toy statistical experiment illustrating the style of modern ARX cryptanalysis.

The package does **not** claim a practical break of standardized 20-round IETF ChaCha20.
Published cryptanalysis discussed in the Week 3 lecture targets reduced-round variants at high complexity.

---

## 1. Controlled plaintext modification by ciphertext editing

File:

```text
chacha20_malleability_controlled_patch.py
```

For a stream cipher:

```text
C = P XOR Z
```

If an attacker changes ciphertext by a mask `Delta`:

```text
C' = C XOR Delta
```

then the receiver obtains:

```text
P' = P XOR Delta
```

If the attacker knows an original plaintext segment `OLD` and wants the same-length
segment `NEW`, then:

```text
Delta = OLD XOR NEW
```

and the attacker XORs `Delta` into the corresponding ciphertext bytes.

### Self-contained sender / attacker / receiver demo

```bash
python chacha20_malleability_controlled_patch.py --demo
```

Default demonstration:

```text
uid=1001;role=user;expires=2026-12-31
```

is changed to:

```text
uid=1001;role=root;expires=2026-12-31
```

The attacker-side patch function receives **no key**.

### Choose your own text

```bash
python chacha20_malleability_controlled_patch.py --demo \
  --demo-plaintext 'text:amount=1000;approved=no ' \
  --demo-old 'text:no ' \
  --demo-new 'text:yes'
```

`OLD` and `NEW` must contain the same number of bytes because XOR modification does
not insert or delete ciphertext bytes.

### Patch an existing ciphertext file without the key

Suppose the attacker knows that bytes at offset 14 decrypt to `user` and wants the
receiver to obtain `root`:

```bash
python chacha20_malleability_controlled_patch.py \
  --cipher file:message.enc \
  --offset 14 \
  --old text:user \
  --new text:root \
  --output forged.enc
```

This demonstrates why **standalone ChaCha20 should not be treated as authenticated
encryption**. ChaCha20-Poly1305 detects such modification when the tag is correctly
verified.

---

## 2. Reduced-round diffusion / avalanche laboratory

File:

```text
chacha20_diffusion_rounds_lab.py
```

The program flips one bit in a key, nonce, or counter and measures the Hamming
distance after different numbers of rounds.

Example:

```bash
python chacha20_diffusion_rounds_lab.py \
  --rounds 0,2,4,6,8,12,20 \
  --target nonce \
  --bit 0 \
  --csv diffusion.csv
```

It reports both:

- internal-state difference before feed-forward;
- final block-output difference after feed-forward.

Typical behavior is rapid movement toward roughly half of the 512 state/output bits
being different. This is a **diffusion diagnostic**, not a direct attack.

---

## 3. Toy reduced-round differential-bias experiment

File:

```text
chacha20_reduced_round_differential_lab.py
```

For many random keys, compare two reduced-round ChaCha blocks whose public inputs
differ in one bit:

```text
Y  = ChaCha_r(K, counter, nonce)
Y' = ChaCha_r(K, counter, nonce XOR Delta)
D  = Y XOR Y'
```

For each output bit, estimate:

```text
Pr[D_i = 1]
```

A random-difference reference suggests probability near `1/2`. A large stable
deviation indicates reduced-round structure.

Example:

```bash
python chacha20_reduced_round_differential_lab.py \
  --rounds 2,4,6,8 \
  --samples 5000 \
  --target nonce \
  --bit 0 \
  --top 10 \
  --csv reduced_round_bias.csv
```

### Important statistical caution

The script inspects 512 output bits. Therefore the largest observed bias can look
non-trivial merely because of **multiple testing** and finite-sample noise. Do not
interpret a 3-sigma-looking maximum from a few thousand samples as a published
cryptanalytic result. Increase the sample count, pre-register the tested relation, or
apply an appropriate multiple-comparison correction before making a statistical claim.

The intended teaching observation is:

```text
few rounds -> visible structured differential behavior
more rounds -> diffusion becomes much harder to distinguish from random behavior
```

This does **not** constitute a practical attack on full ChaCha20.

---

## 4. Core implementation

File:

```text
chacha20_core.py
```

It contains:

- IETF 256-bit key / 96-bit nonce state layout;
- correct ARX quarter round;
- column + diagonal round pair;
- selectable even round count;
- mandatory feed-forward for block output;
- little-endian serialization;
- stream XOR helper;
- RFC 8439 block-function self-test.

Run:

```bash
python chacha20_core.py
```

Expected:

```text
RFC 8439 block test: PASS
```

---

## Teaching sequence

Recommended order:

```text
ChaCha20 XOR model
       |
       v
Malleability without authentication
       |
       v
Why AEAD is necessary
       |
       v
Round-by-round diffusion
       |
       v
Reduced-round differential experiment
       |
       v
Security boundary: reduced-round research != full ChaCha20 break
```

Educational / authorized laboratory use only.
