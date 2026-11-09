// gcm.h — GHASH and AES-128-GCM.
//
// AES itself is borrowed from OpenSSL (EVP_aes_128_ecb) purely as the block
// permutation E_K(.); CTR mode, GHASH, J0 and the tag are built here so the
// whole authentication path is ours to attack.  96-bit IV only.
#pragma once
#include "gf128.h"
#include <cstdint>
#include <cstddef>

void aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

// Hash subkey H = E_K(0^128).
gf gcm_H(const uint8_t key[16]);

// GHASH_H over AAD || ciphertext || len-block.  Returns the field element.
gf ghash(gf H, const uint8_t* aad, size_t aad_len,
                const uint8_t* ct,  size_t ct_len);

// Encrypt: writes ct (pt_len bytes) and tag (16 bytes).
void gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
                 const uint8_t* aad, size_t aad_len,
                 const uint8_t* pt,  size_t pt_len,
                 uint8_t* ct, uint8_t tag[16]);

// Decrypt + verify. Returns false (and leaves pt untouched) on tag mismatch.
bool gcm_decrypt(const uint8_t key[16], const uint8_t iv[12],
                 const uint8_t* aad, size_t aad_len,
                 const uint8_t* ct,  size_t ct_len,
                 const uint8_t tag[16], uint8_t* pt);
