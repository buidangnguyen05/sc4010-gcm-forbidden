#include "gcm.h"
#include <stdexcept>
// You'll want OpenSSL here for the AES block: #include <openssl/evp.h>
// (gcmcore already links OpenSSL::Crypto — see CMakeLists.txt.)

// STUBS — implement these. AES block via OpenSSL EVP_aes_128_ecb; build GHASH,
// CTR, J0 and the tag yourself. 96-bit IV only.
[[noreturn]] static void todo(const char* w) { throw std::logic_error(std::string("TODO: ") + w); }

void aes128_encrypt_block(const uint8_t[16], const uint8_t[16], uint8_t[16]) { todo("aes128_encrypt_block"); }
gf   gcm_H(const uint8_t[16])                                                { todo("gcm_H"); }
gf   ghash(gf, const uint8_t*, size_t, const uint8_t*, size_t)              { todo("ghash"); }

void gcm_encrypt(const uint8_t[16], const uint8_t[12],
                 const uint8_t*, size_t, const uint8_t*, size_t,
                 uint8_t*, uint8_t[16])                                      { todo("gcm_encrypt"); }

bool gcm_decrypt(const uint8_t[16], const uint8_t[12],
                 const uint8_t*, size_t, const uint8_t*, size_t,
                 const uint8_t[16], uint8_t*)                                { todo("gcm_decrypt"); }
