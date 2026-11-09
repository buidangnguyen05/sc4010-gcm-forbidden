// gf128.h — arithmetic in GF(2^128), GCM's bit-reflected convention.
// Element stored in an `unsigned __int128`. Field poly x^128 + x^7 + x^2 + x + 1.
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

using gf = unsigned __int128;

inline constexpr gf GF_R   = 0;   // TODO: reduction constant
inline constexpr gf GF_ONE = 0;   // TODO: multiplicative identity in this representation

// byte <-> field
gf   gf_load_be(const uint8_t b[16]);
void gf_store_be(gf u, uint8_t b[16]);
gf   gf_load_partial_be(const uint8_t* p, size_t n);   // n < 16, zero-padded

// field ops
inline gf gf_add(gf a, gf b) { return a ^ b; }         // addition is XOR (given)
gf gf_mul(gf a, gf b);
gf gf_sqr(gf a);
gf gf_inv(gf a);                                        // a^(2^128 - 2)

std::string gf_to_hex(gf u);                            // 32 hex chars, MSB first
