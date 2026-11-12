# gcm-forbidden

Key-recovery + forgery on AES-128-GCM under **nonce reuse** (Joux's "forbidden
attack", 2006). GHASH is a polynomial hash evaluated at a secret point `H` in
GF(2^128); reusing a nonce cancels the tag mask and leaves a polynomial whose
root is `H`. Recover `H`, recover the mask `S`, and forge any message under that
nonce. Fully implemented, with a live demo and three test gates.

## Build & run

Needs a C++17 compiler (`unsigned __int128` → GCC/Clang) and OpenSSL headers (`libssl-dev`).

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

./build/tests          # GATE #1 — field + GCM vs. NIST/McGrew–Viega vectors
./build/poly_tests     # GATE #3 — GF(2^128) polynomials + root finding
./build/attack_tests   # GATE #4 — build f, recover H/S, forge
ctest --test-dir build # all gates at once

./build/forbidden        # live demo (random each run)
./build/forbidden 200    # ...with a chosen number of captured reports
```

All three gates print `GATE #N GREEN` when passing.

## The live demo (`main.cpp`)

A flaky fleet node streams telemetry to a collector over AES-128-GCM. Its
firmware randomly crashes, and on reboot the nonce counter winds back to a fixed
value (`BOOT_NONCE`), so the first report of each boot **reuses a nonce**. Every
run randomizes the key, the report contents, and *when* the node crashes.

The attacker is **passive and IV-blind** — it never inspects IVs to spot repeats.
It just grinds **every pair** of captured reports through the forbidden attack
and lets the math reveal the key:

- `H = E_K(0)` is a root of a pair's polynomial **iff that pair reused a nonce**
  (otherwise `f(H) = S_i ⊕ S_j ≠ 0`);
- `H` depends only on the key, not the nonce, so **every** nonce-reusing pair
  (across all reused nonces) votes for the **same** `H`, while spurious roots are
  random and never recur.

So tallying roots over all pairs makes `H` win by a landslide. The recovered `H`
is then confirmed the only way a real attacker can — by forging a report the
collector **accepts** (a fabricated "all healthy" status that hides a breach).
The nonce-reuse structure is even recovered from the mask `S`, still without
reading a single IV.

## The math

Tag: `T = GHASH_H(A,C) ⊕ E_K(J₀)`, mask `S = E_K(J₀)`, and for blocks
`X₁…Xₘ = AAD ‖ C ‖ (len(A)₆₄‖len(C)₆₄)`:

```
GHASH_H(X) = X₁·H^m ⊕ X₂·H^(m−1) ⊕ … ⊕ Xₘ·H¹
```

Two messages under the **same nonce** share `S`, so `T₁ ⊕ T₂` depends only on `H`:

```
f(Y) = (T₁ ⊕ T₂)  ⊕  Σᵢ (Xᵢ ⊕ X′ᵢ)·Y^(m−i+1)        with   f(H) = 0
```

Root-find `f` over GF(2^128):

1. make `f` monic;
2. `g = gcd(f, Y^(2^128) − Y)` keeps only in-field roots. Compute `Y^(2^128) mod f`
   by squaring `Y` modulo `f` **128 times**, then `gcd(f, that ⊕ Y)`;
3. split `g` (now a product of distinct linear factors) with char-2
   Cantor–Zassenhaus: for random `c`, `gcd(g, Σ_{i=0}^{127} (c·Y)^(2^i) mod g)`
   peels ~half the roots; recurse. Each `Y − r` gives a candidate `H`.

A single pair yields **several** candidate roots. Three ways to pin the real `H`:

- **disambiguate** — a second reused-nonce pair gives `f₂`; `poly_gcd(f₁, f₂)` is
  `(Y − H)` (oracle-free, needs a 3rd message);
- **vote** — over many pairs, the true `H` is the only root that recurs (what the
  live demo uses; oracle-free, no IVs);
- **oracle** — for each candidate derive `S` and forge a test message; the one the
  victim accepts reveals `H`.

Then `S = T₁ ⊕ GHASH_H(A₁,C₁)`, and forge `T* = GHASH_H(A*,C*) ⊕ S`.

## What the attack does and doesn't give you

- **Authenticity forgery (unbounded):** with `H` and `S` you can produce a valid
  tag for **any** ciphertext — the receiver accepts it.
- **Chosen-plaintext forgery (bounded):** to control the *decrypted* plaintext you
  need the CTR keystream `KS = P_known ⊕ C_known` for that nonce, so this is a
  **known-plaintext** capability, limited to the length you have. `forge()` throws
  if asked to exceed the recovered keystream.
- **Confidentiality** leaks only from the nonce reuse itself (keystream reuse /
  two-time-pad among messages at the same nonce), *not* from recovering `H`.
- **The AES key `K` is never recovered** — `H = E_K(0)` and `S = E_K(J₀)` are two
  input/output pairs of AES; inverting them is breaking AES (~2¹²⁸). So no
  fresh-nonce decryption and no unbounded chosen-plaintext.

## File map

| file                | role                                                            |
|---------------------|-----------------------------------------------------------------|
| `gf128.{h,cpp}`     | GF(2^128) field arithmetic                                      |
| `gcm.{h,cpp}`       | GHASH + AES-128-GCM (AES block via OpenSSL ECB)                 |
| `gf128poly.{h,cpp}` | polynomials over GF(2^128) + root finding — **the attack core** |
| `attack.{h,cpp}`    | build `f`, recover `H`/`S`, forge                               |
| `victim.{h,cpp}`    | broken GCM user: nonce counter resets to `BOOT_NONCE` on reboot |
| `main.cpp`          | live demo (IV-blind all-pairs break + forged injection)         |
| `tests.cpp`         | GATE #1 — McGrew–Viega / NIST vectors                           |
| `poly_tests.cpp`    | GATE #3 — polynomial ring + root finding                        |
| `attack_tests.cpp`  | GATE #4 — forbidden poly, H/S recovery, forgery                 |

## Pitfalls

- **Bit reflection** in `gf_mul` — handled in `gf_load_be` (big-endian, `R = 0xE1<<120`). Don't "fix" it.
- **Length block** is part of the polynomial; it **cancels** when both messages share lengths (lowers the degree).
- A single pair gives multiple candidate roots — disambiguate (2nd pair), vote (many pairs), or test against the victim oracle.
- Stick to **96-bit IVs** (`J₀ = IV‖0³¹‖1`); other lengths make `J₀` itself a GHASH.
- Cost is one GF(2^128) root-find per pair (~`O(m²)` in blocks, times a fixed
  128-squaring constant). Cheap per pair, but the IV-blind attacker's all-pairs
  sweep is `O(N²)` of them.

## References

- A. Joux, *Authentication Failures in NIST Version of GCM* (2006).
- Böck, Zauner, Devlin et al., *Nonce-Disrespecting Adversaries* (2016) — real TLS
  servers (Radware CVE-2016-10212, Citrix NetScaler CVE-2017-5933, IBM Domino
  CVE-2016-0270, A10).
- Cryptopals Set 8, Challenge 63 — closest existing exercise.
- NIST SP 800-38D — GCM spec; Algorithm 1 is `gf_mul`; Appendix B are the test vectors.
