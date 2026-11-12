#include "gf128poly.h"
#include <stdexcept>
#include <algorithm>
#include <random>
#include <utility>

gf lead(const poly& a) {
    return a.back();
}

poly poly_trim(poly a) {
    while (a.size() > 1 && lead(a) == 0) a.pop_back();
    return a;
}
poly poly_add(const poly &a, const poly &b) {
    poly c(std::max<size_t>(a.size(), b.size()), static_cast<gf>(0));
    for (size_t i = 0; i < c.size(); ++i) {
        if (i < a.size()) c[i] = gf_add(c[i], a[i]);
        if (i < b.size()) c[i] = gf_add(c[i], b[i]);
    }
    return poly_trim(c);
}
poly poly_mul(const poly &a, const poly &b) {
    poly c(a.size() + b.size() - 1, static_cast<gf>(0));
    for (size_t i = 0; i < a.size(); ++i) {
        for (size_t j = 0; j < b.size(); ++j) {
            c[i + j] = gf_add(c[i + j], gf_mul(a[i], b[j]));
        }
    }
    return poly_trim(c);
}
poly poly_scalar_mul(const poly &a, gf c) {
    poly b = a;
    for (gf &i : b) {
        i = gf_mul(i, c);
    }
    return poly_trim(b);
}
static bool poly_is_zero(const poly &a) {
    return a.empty() || (a.size() == 1 && a[0] == static_cast<gf>(0));
}
void poly_divmod(const poly &a, const poly &b, poly &q, poly &r) {
    r = a;
    q = poly(a.size() + 1, static_cast<gf>(0));
    gf binv = gf_inv(lead(b));

    while (r.size() >= b.size() && !poly_is_zero(r)) {
        size_t shift = r.size() - b.size();
        gf coef = gf_mul(lead(r), binv);
        q[shift] = coef;
        for (size_t j = 0; j < b.size(); ++j) {
            r[shift + j] = gf_add(r[shift + j], gf_mul(b[j], coef));
        }
        r = poly_trim(r);
    }
    q = poly_trim(q);
}
poly poly_mod(const poly &a, const poly &b) {
    poly q, r;
    poly_divmod(a, b, q, r);
    return r;
}
poly poly_gcd(poly a, poly b) {
    while (!poly_is_zero(b)) {
        a = poly_mod(a, b);
        std::swap(a, b);
    }
    return a;
}
poly poly_make_monic(const poly &a) {
    return poly_scalar_mul(a, gf_inv(lead(a)));
}
poly poly_sqr_mod(const poly &a, const poly &mod) {
    return poly_mod(poly_mul(a, a), mod);
}
poly poly_Ypow_2_128_mod(const poly &f) {
    poly y = {0, GF_ONE};
    for (int i = 0; i < 128; ++i) y = poly_sqr_mod(y, f);
    return y;
}
poly distinct_roots_factor(const poly &f) {
    poly g = poly_Ypow_2_128_mod(f);
    g = poly_add(g, {0, GF_ONE});
    return poly_gcd(f, g);
}

static gf rand_gf() {
    static std::mt19937_64 rng(0xD15EA5EDBEEF0000); // hehe
    return (static_cast<gf>(rng()) << 64) | rng();
}
void split(poly g, std::vector<gf>& roots) {
    g = poly_make_monic(g);
    if (g.size() == 1) return;
    if (g.size() == 2) {
        roots.push_back(g[0]);
        return;
    }
    poly h;
    while (true) {
        gf c = rand_gf();
        poly t = {0}, cur = {0, c};
        for (int j = 0; j < 128; ++j) {
            t = poly_add(t, cur);
            cur = poly_sqr_mod(cur, g);
        }
        t = poly_mod(t, g);
        h = poly_gcd(g, t);
        if (h.size() <= 1 || h.size() == g.size()) continue;
        break;
    }
    split(h, roots);
    poly q, _;
    poly_divmod(g, h, q, _);
    split(q, roots);
}
std::vector<gf> find_roots(const poly &f) {
    poly g = distinct_roots_factor(f);
    std::vector<gf> roots;
    split(g, roots);
    return roots;
}
