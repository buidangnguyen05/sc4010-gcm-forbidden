#include "gf128.h"

gf gf_load_be(const uint8_t b[16]) {
    gf u = 0;
    for (int i = 0; i < 16; ++i) {
        u = (u << 8) | b[i];
    }
    return u;
}

void gf_store_be(gf u, uint8_t b[16]) {
    for (int i = 15; i >= 0; --i) {
        b[i] = u & 0xFF;
        u >>= 8;
    }
}

gf gf_load_partial_be(const uint8_t *p, size_t n) {
    gf u = 0;
    for (size_t i = 0; i < 16; ++i) {
        u <<= 8;
        if (i < n) u |= p[i];
    }
    return u;
}

gf gf_mul(gf a, gf b) {
    gf z = 0, v = a;
    for (int i = 127; i >= 0; --i) {
        z ^= v & -(gf) ((b >> i) & 1);
        v = (v >> 1) ^ (GF_R & -(gf) (v & 1));
    }
    return z;
}

gf gf_mul_x(gf a) {
    return (a >> 1) ^ (GF_R & -(gf) (a & 1));
}

gf gf_sqr(gf a) {
    gf hi = 0, lo = 0;
    for (int i = 0; i < 64; ++i) {
        hi |= ((a >> (i + 64)) & 1) << (2 * i + 1);
        lo |= ((a >> (i)) & 1) << (2 * i + 1);
    }
    gf x1 = gf_mul_x(lo), x2 = gf_mul_x(x1), x7 = x2;
    for (int k = 0; k < 5; ++k) x7 = gf_mul_x(x7);
    return hi ^ lo ^ x1 ^ x2 ^ x7;
}

gf gf_inv(gf a) {
    gf res = GF_ONE;
    for (int i = 127; i >= 0; --i) {
        res = gf_sqr(res);
        if (i) res = gf_mul(res, a);
    }
    return res;
}

std::string gf_to_hex(gf a) {
    std::string s(32, '0');
    static const auto digits = "0123456789abcdef";
    for (int i = 31; i >= 0; --i) {
        s[i] = digits[a & 0xF];
        a >>= 4;
    }
    return s;
}
