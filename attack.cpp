#include "attack.h"
#include "gcm.h"
#include <stdexcept>

// ============================================================================
// STUBS — implement once gf128poly's find_roots passes gate #3.
// ============================================================================
[[noreturn]] static void todo(const char *w) { throw std::logic_error(std::string("TODO: ") + w); }

poly build_forbidden_poly(const Msg &m1, const Msg &m2) {
    (void) m1;
    (void) m2;
    todo("build_forbidden_poly");
}

std::vector<gf> recover_H_candidates(const Msg &m1, const Msg &m2) {
    (void) m1;
    (void) m2;
    todo("recover_H_candidates");
}

gf disambiguate(const Msg &m1, const Msg &m2, const Msg &m3) {
    (void) m1;
    (void) m2;
    (void) m3;
    todo("disambiguate");
}

gf recover_mask_S(gf H, const Msg &m1) {
    (void) H;
    (void) m1;
    todo("recover_mask_S");
}

Forgery forge(gf H, gf S, const Bytes &ks, const Bytes &a, const Bytes &p) {
    (void) H;
    (void) S;
    (void) ks;
    (void) a;
    (void) p;
    todo("forge");
}
