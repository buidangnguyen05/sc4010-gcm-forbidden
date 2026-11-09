#include "gf128poly.h"
#include <stdexcept>

// STUBS — the attack core. Implement + unit-test (gate #3) before attack.cpp.
// Suggested order: poly_trim, poly_add, poly_scalar_mul, poly_mul, poly_divmod,
// poly_gcd, poly_make_monic, poly_sqr_mod, poly_Ypow_2_128_mod,
// distinct_roots_factor, find_roots.
[[noreturn]] static void todo(const char* w) { throw std::logic_error(std::string("TODO: ") + w); }

poly poly_trim(poly)                                 { todo("poly_trim"); }
poly poly_add(const poly&, const poly&)              { todo("poly_add"); }
poly poly_mul(const poly&, const poly&)              { todo("poly_mul"); }
poly poly_scalar_mul(const poly&, gf)                { todo("poly_scalar_mul"); }
void poly_divmod(const poly&, const poly&, poly&, poly&) { todo("poly_divmod"); }
poly poly_mod(const poly&, const poly&)              { todo("poly_mod"); }
poly poly_gcd(poly, poly)                            { todo("poly_gcd"); }
poly poly_make_monic(const poly&)                    { todo("poly_make_monic"); }
poly poly_sqr_mod(const poly&, const poly&)          { todo("poly_sqr_mod"); }
poly poly_Ypow_2_128_mod(const poly&)                { todo("poly_Ypow_2_128_mod"); }
poly distinct_roots_factor(const poly&)              { todo("distinct_roots_factor"); }
std::vector<gf> find_roots(const poly&)              { todo("find_roots"); }
