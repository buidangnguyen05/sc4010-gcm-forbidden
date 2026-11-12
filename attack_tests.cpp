// attack_tests.cpp — GATE #4.  Unit tests for attack.{h,cpp}: build the
// forbidden polynomial, recover H (candidates + unique disambiguation),
// recover the tag mask S, and forge an accepted message.
//
//   ./build/attack_tests           run everything
//   ./build/attack_tests forge     run only tests whose name contains "forge"
//
// Same forked-child harness as poly_tests.cpp: a stub (TODO), crash, or
// infinite loop is reported for that test alone and the rest still run.
//
// Each test builds a *real* nonce-reuse scenario with a known key, so the true
// H and the true mask S are known independently and asserted against.
#include "attack.h"
#include "gcm.h"
#include "gf128.h"
#include "gf128poly.h"
#include "victim.h"
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

static Bytes rand_bytes(size_t n) {
    Bytes b(n);
    for (auto &x : b) x = static_cast<uint8_t>(rng());
    return b;
}

// Evaluate f at x by Horner over GF(2^128):  f[0] + x*(f[1] + x*(...)).
static gf poly_eval(const poly &f, gf x) {
    gf acc = 0;
    for (size_t i = f.size(); i-- > 0;) acc = gf_add(gf_mul(acc, x), f[i]);
    return acc;
}

// Encrypt one message and package it the way the attacker captures it.
static Msg make_msg(const uint8_t key[16], const uint8_t iv[12],
                    const Bytes &aad, const Bytes &pt) {
    Msg m;
    m.aad = aad;
    m.ct.resize(pt.size());
    m.tag.resize(16);
    gcm_encrypt(key, iv, aad.data(), aad.size(), pt.data(), pt.size(), m.ct.data(), m.tag.data());
    return m;
}

// The true tag mask S = E_K(J0), J0 = iv || 0^31 || 1 (96-bit IV).  Mirrors
// gcm.cpp exactly but is computed from the key directly, so it's an independent
// oracle for recover_mask_S.
static gf true_mask(const uint8_t key[16], const uint8_t iv[12]) {
    gf J0 = gf_load_partial_be(iv, 12) | 1;
    uint8_t cb[16], ks[16];
    gf_store_be(J0, cb);
    aes128_encrypt_block(key, cb, ks);
    return gf_load_be(ks);
}

// A ready-made nonce-reuse scenario: one key, one reused IV, three captured
// messages under it, and the known-plaintext keystream from msg #1.
struct Scenario {
    uint8_t key[16];
    uint8_t iv[12];
    gf H;              // ground-truth hash subkey
    Bytes pt1;         // known plaintext of m1 (gives the keystream)
    Msg m1, m2, m3;
    Bytes keystream() const {                 // ks = pt1 ^ ct1  (CTR)
        Bytes ks(m1.ct.size());
        for (size_t i = 0; i < ks.size(); ++i) ks[i] = pt1[i] ^ m1.ct[i];
        return ks;
    }
};

// Default: multi-block, equal-length messages (len block cancels -> a few
// in-field roots, the realistic attack shape).  aad_len / pt_len let a test
// force unequal lengths.
static Scenario make_scenario(size_t pt_len = 32, size_t aad_len = 16) {
    Scenario s;
    for (auto &b : s.key) b = static_cast<uint8_t>(rng());
    for (auto &b : s.iv) b = static_cast<uint8_t>(rng());
    s.H = gcm_H(s.key);

    Bytes aad = rand_bytes(aad_len);
    s.pt1 = rand_bytes(pt_len);
    Bytes pt2 = rand_bytes(pt_len);
    Bytes pt3 = rand_bytes(pt_len);
    // same (key, iv) for all three — THE bug
    s.m1 = make_msg(s.key, s.iv, aad, s.pt1);
    s.m2 = make_msg(s.key, s.iv, aad, pt2);
    s.m3 = make_msg(s.key, s.iv, aad, pt3);
    return s;
}

static bool contains(const std::vector<gf> &v, gf x) {
    return std::find(v.begin(), v.end(), x) != v.end();
}

// --------------------------------------------------------- tiny framework ---
// (identical mechanism to poly_tests.cpp)

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

struct Test { const char *name; std::function<void()> fn; };
static std::vector<Test> &registry() { static std::vector<Test> r; return r; }
struct Reg { Reg(const char *n, std::function<void()> f) { registry().push_back({n, std::move(f)}); } };
#define TEST(name) static void name(); static Reg reg_##name(#name, name); static void name()

enum { R_PASS = 0, R_FAIL = 1, R_TODO = 2, R_EXC = 3 };

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

// ---- build_forbidden_poly ----
// The one invariant that makes the whole attack work: the true H is a root.
TEST(forbidden_poly_vanishes_at_true_H) {
    Scenario s = make_scenario();
    poly f = build_forbidden_poly(s.m1, s.m2);
    EXPECT(f.size() > 1, "f collapsed to a constant (size %zu) — messages too similar?", f.size());
    EXPECT(poly_eval(f, s.H) == 0, "f(H) = %s, want 0", gf_to_hex(poly_eval(f, s.H)).c_str());
}
TEST(forbidden_poly_nonzero_off_H) {
    Scenario s = make_scenario();
    poly f = build_forbidden_poly(s.m1, s.m2);
    gf r = rand_nonzero();
    while (r == s.H) r = rand_nonzero();
    EXPECT(poly_eval(f, r) != 0, "f vanished at a random non-H point — f is degenerate");
}
// Different-length messages: the len block no longer cancels, higher degree,
// and the max(size)+1 sizing must still land every coefficient in bounds.
TEST(forbidden_poly_vanishes_unequal_lengths) {
    Scenario s;
    for (auto &b : s.key) b = static_cast<uint8_t>(rng());
    for (auto &b : s.iv) b = static_cast<uint8_t>(rng());
    s.H = gcm_H(s.key);
    Msg a = make_msg(s.key, s.iv, rand_bytes(16), rand_bytes(48)); // 3 ct blocks
    Msg b = make_msg(s.key, s.iv, rand_bytes(0), rand_bytes(13));  // 1 partial ct block, no aad
    poly f = build_forbidden_poly(a, b);
    EXPECT(poly_eval(f, s.H) == 0, "f(H) = %s, want 0 (unequal lengths)",
           gf_to_hex(poly_eval(f, s.H)).c_str());
}
// Argument order only flips nothing (add == XOR): same polynomial either way.
TEST(forbidden_poly_symmetric) {
    Scenario s = make_scenario();
    EXPECT(build_forbidden_poly(s.m1, s.m2) == build_forbidden_poly(s.m2, s.m1),
           "build_forbidden_poly is not symmetric in its arguments");
}

// ---- recover_H_candidates ----
TEST(candidates_contain_true_H) {
    Scenario s = make_scenario();
    std::vector<gf> c = recover_H_candidates(s.m1, s.m2);
    EXPECT(!c.empty(), "no candidates returned");
    EXPECT(contains(c, s.H), "true H not among %zu candidates", c.size());
}
TEST(every_candidate_is_a_real_root) {
    Scenario s = make_scenario();
    poly f = build_forbidden_poly(s.m1, s.m2);
    for (gf c : recover_H_candidates(s.m1, s.m2))
        EXPECT(poly_eval(f, c) == 0, "candidate %s is not a root of f", gf_to_hex(c).c_str());
}

// ---- disambiguate ----
// A second reused-nonce pair pins H uniquely (no oracle needed).
TEST(disambiguate_returns_true_H) {
    Scenario s = make_scenario();
    gf H = disambiguate(s.m1, s.m2, s.m3);
    EXPECT(H == s.H, "disambiguate = %s, want %s", gf_to_hex(H).c_str(), gf_to_hex(s.H).c_str());
}

// ---- recover_mask_S ----
// Checked against E_K(J0) computed straight from the key — independent of the
// tag ^ ghash formula recover_mask_S uses.
TEST(mask_matches_aes_on_J0) {
    Scenario s = make_scenario();
    gf S = recover_mask_S(s.H, s.m1);
    EXPECT(S == true_mask(s.key, s.iv), "S = %s, want E_K(J0) = %s",
           gf_to_hex(S).c_str(), gf_to_hex(true_mask(s.key, s.iv)).c_str());
}
TEST(mask_same_for_both_messages) {
    Scenario s = make_scenario();
    EXPECT(recover_mask_S(s.H, s.m1) == recover_mask_S(s.H, s.m2),
           "mask differs between two messages that share a nonce");
}

// ---- forge ----  (end to end, verified by the real victim)

// 3-message path: disambiguate -> unique H -> one forgery, accepted.
TEST(forge_accepted_three_message) {
    Scenario s = make_scenario(48, 16);
    Victim victim(s.key);

    gf H = disambiguate(s.m1, s.m2, s.m3);
    gf S = recover_mask_S(H, s.m1);

    Bytes chosen_aad = rand_bytes(16);
    Bytes chosen_pt = rand_bytes(32); // <= keystream length (48)
    Forgery fg = forge(H, S, s.keystream(), chosen_aad, chosen_pt);

    Captured c{Bytes(s.iv, s.iv + 12), fg.ct, fg.tag}; // reuse the nonce
    Bytes out;
    EXPECT(victim.receive(c, fg.aad, out), "victim rejected the forged tag");
    EXPECT(out == chosen_pt, "forged message decrypted to the wrong plaintext");
}

// 2-message path: no third message — test each candidate against the victim's
// accept/reject oracle; exactly one (the real H) must produce an accepted forgery.
TEST(forge_accepted_two_message_oracle) {
    Scenario s = make_scenario(48, 16);
    Victim victim(s.key);

    Bytes chosen_aad = rand_bytes(16);
    Bytes chosen_pt = rand_bytes(32);
    Bytes ks = s.keystream();

    int accepted = 0;
    gf winning_H = 0;
    for (gf cand : recover_H_candidates(s.m1, s.m2)) {
        gf S = recover_mask_S(cand, s.m1);
        Forgery fg = forge(cand, S, ks, chosen_aad, chosen_pt);
        Captured c{Bytes(s.iv, s.iv + 12), fg.ct, fg.tag};
        Bytes out;
        if (victim.receive(c, fg.aad, out)) {
            ++accepted;
            winning_H = cand;
            EXPECT(out == chosen_pt, "accepted forgery decrypted to the wrong plaintext");
        }
    }
    EXPECT(accepted >= 1, "no candidate produced an accepted forgery");
    EXPECT(winning_H == s.H, "the accepted candidate was not the true H");
}

// A forgery under the WRONG mask must be rejected — proves the victim is a real
// oracle and the acceptance above isn't vacuous.
TEST(forge_with_wrong_mask_rejected) {
    Scenario s = make_scenario(48, 16);
    Victim victim(s.key);

    gf H = s.H;
    gf S_bad = recover_mask_S(H, s.m1) ^ GF_ONE; // corrupt the mask
    Forgery fg = forge(H, S_bad, s.keystream(), rand_bytes(16), rand_bytes(32));
    Captured c{Bytes(s.iv, s.iv + 12), fg.ct, fg.tag};
    Bytes out;
    EXPECT(!victim.receive(c, fg.aad, out), "victim accepted a forgery built on a wrong mask");
}

// ================================================================== main ===

int main(int argc, char **argv) {
    const char *filter = argc > 1 ? argv[1] : nullptr;
    int counts[4] = {0, 0, 0, 0};
    const char *label[4] = {"PASS", "FAIL", "TODO", "ERR "};

    for (const Test &t : registry()) {
        if (filter && !std::strstr(t.name, filter)) continue;
        rng.seed(std::hash<std::string>{}(t.name)); // stable per-test randoms
        std::string details;
        int r = run_one(t, 10, details);
        std::printf("  [%s] %s\n%s", label[r], t.name, details.c_str());
        ++counts[r];
    }

    int bad = counts[R_FAIL] + counts[R_EXC];
    std::printf("\n%d passed, %d failed, %d errors, %d not implemented\n",
                counts[R_PASS], counts[R_FAIL], counts[R_EXC], counts[R_TODO]);
    std::printf("%s\n", bad == 0 && counts[R_TODO] == 0 ? "GATE #4 GREEN" : "GATE #4 NOT GREEN");
    return bad || counts[R_TODO] ? 1 : 0;
}
