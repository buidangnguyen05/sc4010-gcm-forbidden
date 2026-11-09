#include "gf128.h"
#include <stdexcept>

// STUBS — implement these. See README §math and NIST SP 800-38D Algorithm 1.
[[noreturn]] static void todo(const char* w) { throw std::logic_error(std::string("TODO: ") + w); }

gf   gf_load_be(const uint8_t[16])            { todo("gf_load_be"); }
void gf_store_be(gf, uint8_t[16])             { todo("gf_store_be"); }
gf   gf_load_partial_be(const uint8_t*, size_t) { todo("gf_load_partial_be"); }
gf   gf_mul(gf, gf)                           { todo("gf_mul"); }
gf   gf_sqr(gf)                               { todo("gf_sqr"); }
gf   gf_inv(gf)                               { todo("gf_inv"); }
std::string gf_to_hex(gf)                     { todo("gf_to_hex"); }
