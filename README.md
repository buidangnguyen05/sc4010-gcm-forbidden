# gcm-forbidden

Key-recovery + forgery on AES-128-GCM under **nonce reuse** (Joux's "forbidden
attack", 2006). GHASH is a polynomial hash evaluated at a secret point `H` in
GF(2^128); reusing a nonce cancels the tag mask and leaves a polynomial whose
root is `H`. Recover `H`, recover the mask `S`, forge any message under that nonce.

## Build & run

Needs a C++17 compiler (`unsigned __int128` → GCC/Clang) and OpenSSL headers
(`libssl-dev`).

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/tests        # GATE #1 — must print "GATE #1 GREEN"
./build/forbidden    # live demo driver (once the attack is implemented)
```

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

Several candidates are normal → build `f₂` from a **second** reused-nonce pair and
take `poly_gcd(f₁, f₂)` to pin a unique `H`. Then `S = T₁ ⊕ GHASH_H(A₁,C₁)`, and
forge `T* = GHASH_H(A*,C*) ⊕ S`.

## File map

Everything is a stub (`throw std::logic_error("TODO: ...")`); headers carry the
signatures. Fill in the `.cpp` bodies — the whole implementation is yours.

| file | what to implement |
|---|---|
| `gf128.{h,cpp}`     | GF(2^128) field arithmetic |
| `gcm.{h,cpp}`       | GHASH + AES-128-GCM (AES block via OpenSSL ECB) |
| `gf128poly.{h,cpp}` | polynomials over GF(2^128) + root finding — **the attack core** |
| `attack.{h,cpp}`    | build `f`, recover `H`/`S`, forge |
| `victim.{h,cpp}`    | broken GCM user: nonce counter resets on `reboot()` |
| `main.cpp`          | live demo driver |
| `tests.cpp`         | Gate #1 harness (McGrew–Viega / NIST vectors) — calls your code |

## Build order (don't skip a gate)

1. **Gate #1 — field + GCM vs. vectors.** Implement `gf128` + `gcm`; `./build/tests`
   must print `GATE #1 GREEN`. It starts **red** until you do.
2. **`gf128poly` ring ops** — `poly_mul`, `poly_divmod`, `poly_gcd`, `poly_make_monic`.
3. **Gate #3 — root finding.** Build `(Y−a)(Y−b)(Y−c)` with `poly_mul`; assert
   `find_roots` returns exactly `{a,b,c}`. (Add this test yourself in `tests.cpp`.)
4. **Attack end-to-end.** Two messages with a **known** reused nonce (you know the
   true `H`): assert it's among the candidates and disambiguation is unique.
5. **Gate #5 — forgery accepted.** Produce an `(iv, ct*, tag*)` the victim never
   saw and show `Victim::receive` returns `true`.

## Pitfalls
- **Bit reflection** in `gf_mul` — handled in `gf_load_be` (big-endian, `R = 0xE1<<120`). Don't "fix" it.
- **Length block** is part of the polynomial; it **cancels** when both messages share lengths (lowers the degree).
- Multiple candidate roots are expected — you need a second pair to disambiguate.
- Stick to **96-bit IVs** (`J₀ = IV‖0³¹‖1`); other lengths make `J₀` itself a GHASH.

## References
- A. Joux, *Authentication Failures in NIST Version of GCM* (2006).
- Böck, Zauner, Devlin et al., *Nonce-Disrespecting Adversaries* (2016) — real TLS servers.
- Cryptopals Set 8, Challenge 63 — closest existing exercise.
- NIST SP 800-38D — GCM spec; Algorithm 1 is `gf_mul`; Appendix B are the test vectors.
