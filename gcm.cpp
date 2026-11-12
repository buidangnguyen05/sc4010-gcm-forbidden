#include "gcm.h"
#include <stdexcept>
#include <openssl/evp.h>
#include <algorithm>

void aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int len = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) == 1
              && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1
              && EVP_EncryptUpdate(ctx, out, &len, in, 16) == 1 && len == 16
              && EVP_EncryptFinal(ctx, out + len, &len) == 1;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) throw std::runtime_error("AES-128 block encryption failed");
}

gf gcm_H(const uint8_t key[16]) {
    using Block16 = uint8_t[16];
    Block16 out;
    aes128_encrypt_block(key, Block16{}, out);
    return gf_load_be(out);
}

static gf absorb(gf Y, gf H, const uint8_t *in, size_t len) {
    size_t i = 0;
    for (; i + 16 <= len; i += 16) Y = gf_mul(Y ^ gf_load_be(in + i), H);
    if (i < len) Y = gf_mul(Y ^ gf_load_partial_be(in + i, len - i), H);
    return Y;
}

gf ghash(gf H, const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len) {
    gf Y = 0;
    Y = absorb(Y, H, aad, aad_len);
    Y = absorb(Y, H, ct, ct_len);
    gf L = static_cast<gf>(aad_len) * 8;
    L = (L << 64) | (static_cast<gf>(ct_len) * 8);
    Y = gf_mul(Y ^ L, H);
    return Y;
}

static gf inc32(gf x) {
    const gf hi_mask = ~(gf)0xFFFFFFFF;
    uint32_t c = (uint32_t)x + 1;
    return (x & hi_mask) | c;
}
void gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *pt, size_t pt_len,
                 uint8_t *ct, uint8_t tag[16]) {
    gf H = gcm_H(key);
    gf J0 = gf_load_partial_be(iv, 12) | 1;
    gf ctr = J0;
    uint8_t cb[16], ks[16];
    for (size_t i = 0; i < pt_len; i += 16) {
        ctr = inc32(ctr);
        gf_store_be(ctr, cb);
        aes128_encrypt_block(key, cb, ks);
        size_t n = std::min<size_t>(16, pt_len - i);
        for (size_t j = 0; j < n; ++j) ct[i + j] = pt[i + j] ^ ks[j];
    }
    gf S = ghash(H, aad, aad_len, ct, pt_len);
    gf_store_be(J0, cb);
    aes128_encrypt_block(key, cb, ks);
    gf_store_be(S ^ gf_load_be(ks), tag);
}

bool gcm_decrypt(const uint8_t key[16], const uint8_t iv[12],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ct, size_t ct_len,
                 const uint8_t tag[16], uint8_t *pt) {
    gf H = gcm_H(key);
    gf S = ghash(H, aad, aad_len, ct, ct_len);
    gf J0 = gf_load_partial_be(iv, 12) | 1;
    uint8_t cb[16], ks[16];
    gf_store_be(J0, cb);
    aes128_encrypt_block(key, cb, ks);
    uint8_t Tp[16];
    gf_store_be(S ^ gf_load_be(ks), Tp);
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= Tp[i] ^ tag[i];
    if (diff != 0) return false;

    gf ctr = J0;
    for (size_t i = 0; i < ct_len; i += 16) {
        ctr = inc32(ctr);
        gf_store_be(ctr, cb);
        aes128_encrypt_block(key, cb, ks);
        size_t n = std::min<size_t>(16, ct_len - i);
        for (size_t j = 0; j < n; ++j) pt[i + j] = ct[i + j] ^ ks[j];
    }

    return true;
}
