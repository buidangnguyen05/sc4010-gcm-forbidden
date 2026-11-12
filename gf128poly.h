// gf128poly.h — polynomials over GF(2^128).  coeff[i] is the coefficient of Y^i.
// THIS IS WHERE THE ATTACK LIVES. Implement + unit-test (gate #3) before attack.cpp.
#pragma once
#include "gf128.h"
#include <vector>

using poly = std::vector<gf>; // little-endian in degree: coeff[0] + coeff[1]*Y + ...

// --- ring operations ---
poly poly_trim(poly a); // drop trailing zero (high) coeffs
poly poly_add(const poly &a, const poly &b); // coefficient-wise XOR
poly poly_mul(const poly &a, const poly &b);

poly poly_scalar_mul(const poly &a, gf c);

void poly_divmod(const poly &a, const poly &b, poly &q, poly &r);

poly poly_mod(const poly &a, const poly &b);

poly poly_gcd(poly a, poly b);

poly poly_make_monic(const poly &a); // divide through by leading coeff

// --- building blocks for root finding ---
poly poly_sqr_mod(const poly &p, const poly &mod); // p^2 mod `mod`
poly poly_Ypow_2_128_mod(const poly &f); // Y^(2^128) mod f (128 squarings of Y)

// --- root finding in GF(2^128) ---
poly distinct_roots_factor(const poly &f); // gcd(f, Y^(2^128) - Y): product of (Y - root)
std::vector<gf> find_roots(const poly &f); // all roots of f in the field
