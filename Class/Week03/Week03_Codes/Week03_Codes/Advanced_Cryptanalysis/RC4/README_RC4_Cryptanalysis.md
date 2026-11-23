# Week 3 — RC4 Cryptanalysis Labs: Why RC4 Is Obsolete

These programs are deliberately **statistical cryptanalysis demonstrations**. They
show weaknesses specific to RC4 that do not require brute-force key search.

The progression is:

1. **Measure the non-random keystream bias.**
2. **Turn that bias into a distinguisher.**
3. **Turn the same bias into repeated-plaintext recovery.**
4. **Show why discarding some early bytes is only a historical mitigation, not a
   reason to use RC4 today.**

RC4 was prohibited for TLS by RFC 7465. The RFC explicitly cites RC4's cryptographic
weaknesses and plaintext-recovery attacks based on keystream biases.

## Files

### `rc4_core.py`
Minimal RC4 KSA/PRGA used by the labs. Includes an RFC 6229 self-test.

### `rc4_bias_lab.py`
Empirically measures output-byte distributions over many independent random keys.
The main expected teaching result is the classic second-output-byte zero bias:

```text
Pr[Z2 = 00] approximately 1/128
```

rather than the uniform value:

```text
1/256
```

Example:

```bash
python rc4_bias_lab.py --samples 100000 --positions 16
```

Outputs a CSV and, when matplotlib is installed, a PNG plot.

### `rc4_distinguisher.py`
Uses the same second-byte bias as a hypothesis test.

```bash
python rc4_distinguisher.py --source rc4 --samples 50000
python rc4_distinguisher.py --source random --samples 50000
```

The RC4 source should normally produce a large positive z-score, while the random
source should fluctuate around zero.

This is cryptanalysis even though no plaintext or key is recovered: the cipher can
be distinguished from the ideal random-stream model.

### `rc4_repeated_plaintext_recovery.py`
A small simulation of the statistical principle behind RC4 plaintext-recovery
attacks against repeatedly encrypted data.

Because:

```text
C2 = P2 XOR Z2
```

and `Z2=0` occurs too often, the same plaintext byte encrypted many times under
independent RC4 keys makes the corresponding ciphertext byte equal to the plaintext
byte unusually often.

```bash
python rc4_repeated_plaintext_recovery.py \
  --plaintext "text:Secret-cookie" \
  --sessions 50000
```

The program estimates the **second plaintext byte without recovering any key**.
It can also save or analyze ciphertext hex-line datasets.

### `rc4_dropn_comparison.py`
Compares the visible second-byte zero bias after discarding different amounts of
RC4 output:

```bash
python rc4_dropn_comparison.py --samples 30000 --drops 0,256,768,1536
```

This is included to explain historical `RC4-dropN` proposals. It should **not** be
interpreted as making RC4 acceptable for modern protocol design.

## Suggested lab order

### Experiment A — Observe the bias

```bash
python rc4_bias_lab.py --samples 50000
```

Compare:

```text
uniform Pr[byte=00] = 1/256
observed RC4 Pr[Z2=00]
```

### Experiment B — Distinguisher

Run both:

```bash
python rc4_distinguisher.py --source random
python rc4_distinguisher.py --source rc4
```

Ask students why a secure stream cipher should be computationally indistinguishable
from random output.

### Experiment C — Plaintext recovery

```bash
python rc4_repeated_plaintext_recovery.py \
  --plaintext "text:Cookie=MASTER-CLASS" \
  --sessions 50000
```

Then repeat with 1,000, 5,000, 10,000, and 50,000 sessions and observe the
probabilistic nature of the attack.

### Experiment D — Why `drop-N` was not the final answer

```bash
python rc4_dropn_comparison.py
```

Discuss the difference between mitigating one visible bias and establishing a
modern security argument for an entire cipher/protocol construction.

## Interpretation

The important conclusion is **not** "RC4 has a small numerical imperfection." The
important conclusion is that RC4's output distribution is detectably non-random,
and sufficiently large collections of ciphertexts can turn those biases into
plaintext information. This violates the design expectation of a modern stream cipher.

## References

- A. Popov, *Prohibiting RC4 Cipher Suites*, RFC 7465, 2015.
- I. Mantin and A. Shamir, *A Practical Attack on Broadcast RC4*, FSE 2001.
- N. AlFardan, D. J. Bernstein, K. G. Paterson, B. Poettering, and J. C. N. Schuldt,
  *On the Security of RC4 in TLS*, USENIX Security 2013.
- M. Vanhoef and F. Piessens, *All Your Biases Belong to Us: Breaking RC4 in
  WPA-TKIP and TLS*, USENIX Security 2015.

Educational and authorized laboratory use only.
