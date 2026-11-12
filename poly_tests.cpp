// poly_tests.cpp — GATE #3.  Unit tests for gf128poly.{h,cpp}.
//
// Each test runs in a forked child with a timeout, so a stub (TODO), a crash,
// or an infinite loop is reported for that test alone and the rest still run.
//
//   ./build/poly_tests            run everything
//   ./build/poly_tests divmod     run only tests whose name contains "divmod"
//
// Conventions checked throughout:
//   * polys are trimmed: no trailing zero coeffs, and the zero poly is {0};
//   * the field's 1 is GF_ONE (1<<127), NOT the integer 1;
//   * "monic" means leading coeff == GF_ONE.
#include "gf128.h"
#include "gf128poly.h"
#include <algorithm>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <functional>
#include <random>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

// ---------------------------------------------------------------- helpers ---

static std::mt19937_64 rng(0xC0FFEE);
static gf rand_gf() { return ((gf) rng() << 64) | rng(); }
static gf rand_nonzero() { gf x; do x = rand_gf(); while (x == 0); return x; }

static const poly ZERO = {0};
static const poly ONE = {GF_ONE};
static const poly Y = {0, GF_ONE};

static poly lin(gf r) { return {r, GF_ONE}; } // (Y + r), root r  (char 2: -r = r)

static poly from_roots(const std::vector<gf> &rs) {
    poly f = ONE;
    for (gf r : rs) f = poly_mul(f, lin(r));
    return f;
}

static poly rand_poly(size_t deg) { // exact degree `deg`
    poly p(deg + 1);
    for (auto &c : p) c = rand_gf();
    p.back() = rand_nonzero();
    return p;
}

static bool is_zero(const poly &p) { return p.size() == 1 && p[0] == 0; }
static bool is_trimmed(const poly &p) { return !p.empty() && (p.size() == 1 || p.back() != 0); }

// absolute trace Tr(c) = sum_{i<128} c^(2^i); always 0 or GF_ONE.
static gf trace(gf c) {
    gf t = 0, x = c;
    for (int i = 0; i < 128; ++i) { t ^= x; x = gf_sqr(x); }
    return t;
}

// Y^2 + Y + c is irreducible over GF(2^128) iff Tr(c) = 1.  A poly with no roots
// in the field, so root-finding must ignore it.
static poly rand_irreducible_quadratic() {
    gf c;
    do c = rand_gf(); while (trace(c) != GF_ONE);
    return {c, GF_ONE, GF_ONE};
}

static std::string show(const poly &p) {
    if (p.empty()) return "<empty vector>";
    std::string s = "[deg " + std::to_string(p.size() - 1) + "]";
    size_t n = std::min<size_t>(p.size(), 4);
    for (size_t i = 0; i < n; ++i) s += " c" + std::to_string(i) + "=" + gf_to_hex(p[i]);
    if (p.size() > n) s += " ... lead=" + gf_to_hex(p.back());
    return s;
}

// --------------------------------------------------------- tiny framework ---

static int child_fails = 0;

#define EXPECT(cond, ...)                                                        \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::printf("        line %d: EXPECT(%s) failed\n", __LINE__, #cond); \
            std::printf("        " __VA_ARGS__);                                 \
            std::printf("\n");                                                   \
            ++child_fails;                                                       \
        }                                                                        \
    } while (0)

#define EXPECT_POLY(got, want)                                                   \
    do {                                                                         \
        poly g_ = (got), w_ = (want);                                            \
        if (g_ != w_) {                                                          \
            std::printf("        line %d: %s != %s\n", __LINE__, #got, #want);  \
            std::printf("          got  %s\n", show(g_).c_str());               \
            std::printf("          want %s\n", show(w_).c_str());               \
            ++child_fails;                                                       \
        }                                                                        \
    } while (0)

struct Test { const char *name; std::function<void()> fn; };
static std::vector<Test> &registry() { static std::vector<Test> r; return r; }
struct Reg { Reg(const char *n, std::function<void()> f) { registry().push_back({n, std::move(f)}); } };
#define TEST(name) static void name(); static Reg reg_##name(#name, name); static void name()

enum { R_PASS = 0, R_FAIL = 1, R_TODO = 2, R_EXC = 3 };

// Runs t in a child; child's printed details are captured into `out`.
static int run_one(const Test &t, int timeout_s, std::string &out) {
    std::fflush(stdout);
    int fds[2];
    if (pipe(fds) != 0) { std::perror("pipe"); return R_EXC; }
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);
        alarm(timeout_s);
        int code = R_PASS;
        try {
            t.fn();
            code = child_fails ? R_FAIL : R_PASS;
        } catch (const std::logic_error &e) {
            bool todo = std::strncmp(e.what(), "TODO", 4) == 0;
            std::printf("        %s: %s\n", todo ? "not implemented" : "exception", e.what());
            code = todo ? R_TODO : R_EXC;
        } catch (const std::exception &e) {
            std::printf("        exception: %s\n", e.what());
            code = R_EXC;
        }
        std::fflush(stdout);
        _exit(code);
    }
    close(fds[1]);
    char buf[4096];
    ssize_t n;
    while ((n = read(fds[0], buf, sizeof buf)) > 0) out.append(buf, (size_t) n);
    close(fds[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)) {
        int sig = WTERMSIG(st);
        if (sig == SIGALRM) out += "        TIMEOUT after " + std::to_string(timeout_s) + "s (infinite loop?)\n";
        else out += std::string("        CRASH: ") + strsignal(sig) + "\n";
        return R_EXC;
    }
    return WEXITSTATUS(st);
}

// ================================================================= tests ===
// Ordered like the suggested implementation order in gf128poly.cpp.

// ---- poly_trim ----
TEST(trim_drops_high_zeros) {
    EXPECT_POLY(poly_trim({5, 7, 0, 0}), (poly{5, 7}));
    EXPECT_POLY(poly_trim({5}), (poly{5}));
}
TEST(trim_zero_poly_is_single_zero) {
    EXPECT_POLY(poly_trim({0, 0, 0}), ZERO);
    EXPECT_POLY(poly_trim({0}), ZERO);
}
TEST(trim_keeps_inner_zeros) {
    EXPECT_POLY(poly_trim({0, 0, 9, 0}), (poly{0, 0, 9}));
}

// ---- poly_add ----
TEST(add_basic) {
    gf a = rand_gf(), b = rand_gf(), c = rand_gf();
    EXPECT_POLY(poly_add({a, b}, {c}), (poly{a ^ c, b}));
    EXPECT_POLY(poly_add({c}, {a, b}), (poly{a ^ c, b}));
}
TEST(add_self_is_zero) {
    poly p = rand_poly(5);
    EXPECT_POLY(poly_add(p, p), ZERO);
}
TEST(add_cancels_leading_term_and_trims) {
    // (Y + 1) + Y = 1  -> must come back as degree 0, not {1, 0}
    poly got = poly_add({GF_ONE, GF_ONE}, Y);
    EXPECT_POLY(got, ONE);
}
TEST(add_zero_identity) {
    poly p = rand_poly(4);
    EXPECT_POLY(poly_add(p, ZERO), p);
}

// ---- poly_scalar_mul ----
TEST(scalar_mul_by_one_is_identity) {
    poly p = rand_poly(6);
    EXPECT_POLY(poly_scalar_mul(p, GF_ONE), p);
}
TEST(scalar_mul_by_zero_is_zero) {
    EXPECT_POLY(poly_scalar_mul(rand_poly(6), 0), ZERO);
}
TEST(scalar_mul_coefficientwise) {
    poly p = rand_poly(3);
    gf c = rand_nonzero();
    poly want(p.size());
    for (size_t i = 0; i < p.size(); ++i) want[i] = gf_mul(p[i], c);
    EXPECT_POLY(poly_scalar_mul(p, c), want);
}

// ---- poly_mul ----
TEST(mul_two_linears) {
    // (Y+a)(Y+b) = Y^2 + (a+b)Y + ab
    gf a = rand_gf(), b = rand_gf();
    EXPECT_POLY(poly_mul(lin(a), lin(b)), (poly{gf_mul(a, b), a ^ b, GF_ONE}));
}
TEST(mul_identity_and_zero) {
    poly p = rand_poly(5);
    EXPECT_POLY(poly_mul(p, ONE), p);
    EXPECT_POLY(poly_mul(ONE, p), p);
    EXPECT_POLY(poly_mul(p, ZERO), ZERO);
}
TEST(mul_by_Y_shifts) {
    poly p = rand_poly(4);
    poly want = p;
    want.insert(want.begin(), 0);
    EXPECT_POLY(poly_mul(p, Y), want);
}
TEST(mul_commutative_and_degree) {
    poly a = rand_poly(7), b = rand_poly(4);
    poly ab = poly_mul(a, b);
    EXPECT_POLY(ab, poly_mul(b, a));
    EXPECT(ab.size() == 12, "deg(a*b) = %zu, want 11", ab.size() - 1);
}
TEST(mul_distributes_over_add) {
    poly a = rand_poly(3), b = rand_poly(5), c = rand_poly(2);
    EXPECT_POLY(poly_mul(a, poly_add(b, c)), poly_add(poly_mul(a, b), poly_mul(a, c)));
}

// ---- poly_divmod ----
static void check_divmod(const poly &a, const poly &b) {
    poly q, r;
    poly_divmod(a, b, q, r);
    EXPECT(is_trimmed(q), "q not trimmed: %s", show(q).c_str());
    EXPECT(is_trimmed(r), "r not trimmed: %s", show(r).c_str());
    EXPECT(is_zero(r) || r.size() < b.size(), "deg r (%zu) >= deg b (%zu)", r.size() - 1, b.size() - 1);
    EXPECT_POLY(poly_add(poly_mul(q, b), r), a); // a == q*b + r
}
TEST(divmod_random_identity) {
    for (int i = 0; i < 20; ++i) check_divmod(rand_poly(3 + rng() % 15), rand_poly(1 + rng() % 6));
}
TEST(divmod_exact_division) {
    poly b = rand_poly(3), q0 = rand_poly(5);
    poly q, r;
    poly_divmod(poly_mul(b, q0), b, q, r);
    EXPECT_POLY(q, q0);
    EXPECT_POLY(r, ZERO);
}
TEST(divmod_by_monic_linear) {
    gf a = rand_gf(), b = rand_gf(), c = rand_gf();
    poly q, r;
    poly_divmod(from_roots({a, b, c}), lin(a), q, r);
    EXPECT_POLY(q, from_roots({b, c}));
    EXPECT_POLY(r, ZERO);
}
TEST(divmod_dividend_smaller_than_divisor) {
    poly a = rand_poly(2), b = rand_poly(5);
    poly q, r;
    poly_divmod(a, b, q, r);
    EXPECT_POLY(q, ZERO);
    EXPECT_POLY(r, a);
}
TEST(divmod_by_constant) {
    // Euclid's gcd ends with exactly this when the inputs are coprime.
    poly a = rand_poly(6);
    gf c = rand_nonzero();
    poly q, r;
    poly_divmod(a, {c}, q, r);
    EXPECT_POLY(q, poly_scalar_mul(a, gf_inv(c)));
    EXPECT_POLY(r, ZERO);
}
TEST(divmod_zero_dividend) {
    poly q, r;
    poly_divmod(ZERO, rand_poly(3), q, r);
    EXPECT_POLY(q, ZERO);
    EXPECT_POLY(r, ZERO);
}

// ---- poly_mod ----
TEST(mod_matches_divmod) {
    for (int i = 0; i < 10; ++i) {
        poly a = rand_poly(2 + rng() % 12), b = rand_poly(1 + rng() % 5);
        poly q, r;
        poly_divmod(a, b, q, r);
        EXPECT_POLY(poly_mod(a, b), r);
    }
}

// ---- poly_make_monic ----
TEST(make_monic_leading_is_GF_ONE) {
    poly m = poly_make_monic(rand_poly(5));
    EXPECT(m.back() == GF_ONE, "lead = %s, want GF_ONE (1<<127, not the integer 1)",
           gf_to_hex(m.back()).c_str());
}
TEST(make_monic_is_scalar_multiple) {
    poly p = rand_poly(4);
    EXPECT_POLY(poly_make_monic(p), poly_scalar_mul(p, gf_inv(p.back())));
}
TEST(make_monic_already_monic_unchanged) {
    poly f = from_roots({rand_gf(), rand_gf()});
    EXPECT_POLY(poly_make_monic(f), f);
}

// ---- poly_gcd ----  (compared after make_monic, so either convention passes)
TEST(gcd_common_linear_factor) {
    gf a = rand_gf(), b = rand_gf(), c = rand_gf();
    poly g = poly_gcd(from_roots({a, b}), from_roots({a, c}));
    EXPECT_POLY(poly_make_monic(g), lin(a));
}
TEST(gcd_common_cubic_factor) {
    poly common = from_roots({rand_gf(), rand_gf(), rand_gf()});
    poly f = poly_mul(common, rand_poly(4)), g = poly_mul(common, rand_poly(6));
    // random cofactors are coprime with overwhelming probability
    EXPECT_POLY(poly_make_monic(poly_gcd(f, g)), common);
}
TEST(gcd_coprime_is_constant) {
    poly g = poly_gcd(from_roots({rand_gf(), rand_gf()}), from_roots({rand_gf()}));
    EXPECT(g.size() == 1 && g[0] != 0, "gcd of coprime polys should be a nonzero constant, got %s",
           show(g).c_str());
}
TEST(gcd_argument_order_irrelevant) {
    poly common = from_roots({rand_gf(), rand_gf()});
    poly f = poly_mul(common, rand_poly(2)), g = poly_mul(common, rand_poly(7));
    EXPECT_POLY(poly_make_monic(poly_gcd(f, g)), poly_make_monic(poly_gcd(g, f)));
}
TEST(gcd_with_zero) {
    poly f = rand_poly(3);
    EXPECT_POLY(poly_make_monic(poly_gcd(f, ZERO)), poly_make_monic(f));
    EXPECT_POLY(poly_make_monic(poly_gcd(ZERO, f)), poly_make_monic(f));
}

// ---- poly_sqr_mod ----
TEST(sqr_mod_matches_mul_then_mod) {
    for (int i = 0; i < 10; ++i) {
        poly m = rand_poly(2 + rng() % 8);
        poly p = poly_mod(rand_poly(1 + rng() % 10), m);
        EXPECT_POLY(poly_sqr_mod(p, m), poly_mod(poly_mul(p, p), m));
    }
}

// ---- poly_Ypow_2_128_mod ----
// Every field element is a root of Y^(2^128) - Y, so if f splits into linear
// factors over GF(2^128), Y^(2^128) == Y (mod f).
TEST(Ypow_on_split_poly_is_Y) {
    poly f = from_roots({rand_gf(), rand_gf(), rand_gf(), rand_gf()});
    EXPECT_POLY(poly_Ypow_2_128_mod(f), Y);
}
TEST(Ypow_reduces_to_Y_mod_split_factor) {
    // f = (Y+a)(Y+b) * random junk: the result needn't be Y, but must be Y mod (Y+a)(Y+b)
    poly split = from_roots({rand_gf(), rand_gf()});
    poly f = poly_mul(split, rand_poly(5));
    poly r = poly_Ypow_2_128_mod(f);
    EXPECT(r.size() < f.size(), "result not reduced mod f: %s", show(r).c_str());
    EXPECT_POLY(poly_mod(poly_add(r, Y), split), ZERO);
}
TEST(Ypow_on_irreducible_quadratic_is_not_Y) {
    // no roots in the field -> Y^(2^128) != Y mod f  (it's the conjugate root, Y + 1)
    poly q = rand_irreducible_quadratic();
    EXPECT_POLY(poly_Ypow_2_128_mod(q), (poly{GF_ONE, GF_ONE}));
}

// ---- distinct_roots_factor ----
TEST(drf_keeps_in_field_roots) {
    gf a = rand_gf(), b = rand_gf(), c = rand_gf();
    poly f = from_roots({a, b, c});
    EXPECT_POLY(poly_make_monic(distinct_roots_factor(f)), f);
}
TEST(drf_removes_irreducible_factor) {
    gf a = rand_gf(), b = rand_gf();
    poly f = poly_mul(from_roots({a, b}), rand_irreducible_quadratic());
    EXPECT_POLY(poly_make_monic(distinct_roots_factor(f)), from_roots({a, b}));
}
TEST(drf_collapses_repeated_roots) {
    gf a = rand_gf(), b = rand_gf();
    poly f = from_roots({a, a, a, b});
    EXPECT_POLY(poly_make_monic(distinct_roots_factor(f)), from_roots({a, b}));
}
TEST(drf_non_monic_input) {
    gf a = rand_gf(), b = rand_gf();
    poly f = poly_scalar_mul(from_roots({a, b}), rand_nonzero());
    EXPECT_POLY(poly_make_monic(distinct_roots_factor(f)), from_roots({a, b}));
}

// ---- find_roots ----
static void check_roots(const poly &f, std::vector<gf> want) {
    std::vector<gf> got = find_roots(f);
    std::sort(got.begin(), got.end());
    std::sort(want.begin(), want.end());
    EXPECT(got == want, "found %zu roots, want %zu", got.size(), want.size());
    if (got != want) {
        for (gf g : got) std::printf("          got  %s\n", gf_to_hex(g).c_str());
        for (gf w : want) std::printf("          want %s\n", gf_to_hex(w).c_str());
    }
}
TEST(roots_single_linear) {
    gf a = rand_gf();
    check_roots(lin(a), {a});
}
TEST(roots_three_linears) { // the gate-#3 test suggested in gf128poly.h
    gf a = rand_gf(), b = rand_gf(), c = rand_gf();
    check_roots(from_roots({a, b, c}), {a, b, c});
}
TEST(roots_zero_is_a_root) {
    gf b = rand_gf();
    check_roots(from_roots({0, b}), {0, b});
}
TEST(roots_constant_has_none) {
    check_roots({rand_nonzero()}, {});
}
TEST(roots_ignores_irreducible_factor) {
    gf a = rand_gf(), b = rand_gf();
    check_roots(poly_mul(from_roots({a, b}), rand_irreducible_quadratic()), {a, b});
}
TEST(roots_irreducible_alone_has_none) {
    check_roots(rand_irreducible_quadratic(), {});
}
TEST(roots_repeated_reported_once) {
    gf a = rand_gf(), b = rand_gf();
    check_roots(from_roots({a, a, b}), {a, b});
}
TEST(roots_non_monic) {
    gf a = rand_gf(), b = rand_gf(), c = rand_gf();
    check_roots(poly_scalar_mul(from_roots({a, b, c}), rand_nonzero()), {a, b, c});
}
TEST(roots_many) {
    // attack-sized: a few-block message gives f of degree ~ 5-20
    std::vector<gf> rs;
    for (int i = 0; i < 20; ++i) rs.push_back(rand_gf());
    check_roots(from_roots(rs), rs);
}
TEST(roots_mixed_realistic) {
    // what the attack actually sees: a couple of in-field roots buried in junk
    gf a = rand_gf(), b = rand_gf();
    poly f = poly_mul(from_roots({a, b}), poly_mul(rand_irreducible_quadratic(), rand_irreducible_quadratic()));
    check_roots(poly_scalar_mul(f, rand_nonzero()), {a, b});
}

// ================================================================== main ===

int main(int argc, char **argv) {
    const char *filter = argc > 1 ? argv[1] : nullptr;
    int counts[4] = {0, 0, 0, 0};
    const char *label[4] = {"PASS", "FAIL", "TODO", "ERR "};

    for (const Test &t : registry()) {
        if (filter && !std::strstr(t.name, filter)) continue;
        // Re-seed per test so each test sees the same randoms regardless of filter.
        rng.seed(std::hash<std::string>{}(t.name));
        std::string details;
        int r = run_one(t, 10, details);
        std::printf("  [%s] %s\n%s", label[r], t.name, details.c_str());
        ++counts[r];
    }

    int bad = counts[R_FAIL] + counts[R_EXC];
    std::printf("\n%d passed, %d failed, %d errors, %d not implemented\n",
                counts[R_PASS], counts[R_FAIL], counts[R_EXC], counts[R_TODO]);
    std::printf("%s\n", bad == 0 && counts[R_TODO] == 0 ? "GATE #3 GREEN" : "GATE #3 NOT GREEN");
    return bad || counts[R_TODO] ? 1 : 0;
}
