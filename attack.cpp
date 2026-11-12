#include "attack.h"
#include "gcm.h"
#include <stdexcept>
#include <vector>

static std::vector<gf> ghash_block(const Bytes& aad, const Bytes& ct) {
    std::vector<gf> X;
    auto push = [&](const uint8_t *in, size_t len) {
        size_t i = 0;
        for (; i + 16 <= len; i += 16) X.push_back(gf_load_be(in + i));
        if (i < len) X.push_back(gf_load_partial_be(in + i, len - i));
    };
    push(aad.data(), aad.size());
    push(ct.data(), ct.size());
    gf L = static_cast<gf>(aad.size()) * 8;
    L = (L << 64) | (static_cast<gf>(ct.size()) * 8);
    X.push_back(L);
    return X;
}
poly build_forbidden_poly(const Msg &m1, const Msg &m2) {
    std::vector<gf> A = ghash_block(m1.aad, m1.ct);
    std::vector<gf> B = ghash_block(m2.aad, m2.ct);
    poly f(std::max(A.size(), B.size()) + 1, static_cast<gf>(0));
    for (size_t i = 0; i < A.size(); ++i) f[A.size() - i] = gf_add(f[A.size() - i], A[i]);
    for (size_t i = 0; i < B.size(); ++i) f[B.size() - i] = gf_add(f[B.size() - i], B[i]);
    f[0] = gf_add(f[0], gf_load_be(m1.tag.data()) ^ gf_load_be(m2.tag.data()));
    return poly_trim(f);
}

std::vector<gf> recover_H_candidates(const Msg &m1, const Msg &m2) {
    return find_roots(build_forbidden_poly(m1, m2));
}

gf disambiguate(const Msg &m1, const Msg &m2, const Msg &m3) {
    poly f1 = build_forbidden_poly(m1, m2);
    poly f2 = build_forbidden_poly(m1, m3);
    poly g = poly_gcd(f1, f2);
    // chance of collision on random inputs is like what, deg / 2^128? if this actually has more than 1 root im going to tilt
    return find_roots(g)[0];
}

gf recover_mask_S(gf H, const Msg &m1) {
    return gf_load_be(m1.tag.data()) ^ ghash(H, m1.aad.data(), m1.aad.size(), m1.ct.data(), m1.ct.size());
}

Forgery forge(gf H, gf S, const Bytes &ks, const Bytes &aad, const Bytes &pt) {
    Bytes ct(pt.size());
    for (size_t i = 0; i < pt.size(); ++i) ct[i] = pt[i] ^ ks[i];
    gf T = ghash(H, aad.data(), aad.size(), ct.data(), ct.size()) ^ S;
    Bytes tag(16); gf_store_be(T, tag.data());
    return Forgery{aad, ct, tag};
}
