// attack.h — the forbidden attack: recover H and the tag mask S from two
// messages that reused a nonce, then forge.
#pragma once
#include "gf128.h"
#include "gf128poly.h"
#include <cstdint>
#include <vector>

using Bytes = std::vector<uint8_t>;

// One captured GCM message under a (reused) nonce. The attacker sees exactly this.
struct Msg {
    Bytes aad;
    Bytes ct;
    Bytes tag;   // 16 bytes
};

// f(Y) = (T1^T2) + sum_i (Xi ^ Xi') Y^(m-i+1), with H as a root. See README §math.
poly build_forbidden_poly(const Msg& m1, const Msg& m2);

// Root-find f -> candidate H values (true H plus spurious field roots).
std::vector<gf> recover_H_candidates(const Msg& m1, const Msg& m2);

// Intersect candidates from a second reused-nonce pair to pin a unique H
// (poly_gcd of the two forbidden polynomials).
gf disambiguate(const Msg& m1, const Msg& m2, const Msg& m3);

// Once H is known: S = tag1 ^ GHASH_H(aad1, ct1).
gf recover_mask_S(gf H, const Msg& m1);

// Forge a valid (ct*, tag*) for chosen plaintext under the same nonce.
// Needs the keystream, recoverable from any known-plaintext message (CTR).
struct Forgery { Bytes aad, ct, tag; };
Forgery forge(gf H, gf S, const Bytes& keystream,
              const Bytes& chosen_aad, const Bytes& chosen_plaintext);

// TODO(you): implement in attack.cpp once gf128poly is green.
