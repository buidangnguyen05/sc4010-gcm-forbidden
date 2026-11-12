#include "victim.h"
#include "gcm.h"
#include <cstring>

// A deliberately broken AES-128-GCM user.  The nonce is a fixed-field || counter
// construction (NIST SP 800-38D §8.2.1, the deterministic method TLS also uses).
// That is fine on its own — but reboot() winds the counter back to 0, so the
// first message after every reboot reuses nonce 0 under the same key.  GCM under
// a repeated (key, nonce) is fatal: the tag mask cancels and H is recoverable
// (the "forbidden attack").  The attacker only ever sees the (iv, ct, tag)
// triples returned by send().
//
// ===== THE FIX =============================================================
// The invocation counter must be strictly monotonic across the key's whole
// life — it must NEVER go backwards.  Concretely:
//   (1) persist `counter_` in non-volatile storage and reload it on boot
//       instead of resetting (and refuse to send if it can't be persisted); or
//   (2) make the nonce (per-boot random salt) || counter — draw a fresh random
//       salt at each boot (RAND_bytes), so even a counter restart gives a new
//       nonce.  This is exactly what TLS 1.3 does.
//   (3) if you can't guarantee a monotonic counter, switch to a nonce-misuse-
//       resistant mode (AES-GCM-SIV), which tolerates accidental reuse.
// Rotating the key on every reboot also works, since (key, nonce) is what must
// stay unique.  See reboot() below for where the bug lives.

Victim::Victim(const uint8_t key[16]) { std::memcpy(key_, key, 16); }

// THE BUG: wind the nonce counter back to 0, so the next send() repeats nonce 0.
// A correct device would reload a persisted counter here, or reseed a per-boot
// nonce salt — see "THE FIX" at the top of this file.
void Victim::reboot() { counter_ = 0; }

// Turn the 64-bit counter into a 96-bit IV: 4 zero bytes || counter (big-endian).
// GCM here is 96-bit-IV only, so the IV must be exactly 12 bytes.
void Victim::make_iv(uint8_t iv[12]) {
    std::memset(iv, 0, 12);
    for (int i = 0; i < 8; ++i)
        iv[11 - i] = static_cast<uint8_t>(counter_ >> (8 * i));
}

Captured Victim::send(const Bytes &aad, const Bytes &plaintext) {
    uint8_t iv[12];
    make_iv(iv);

    Captured c;
    c.iv.assign(iv, iv + 12);
    c.ct.resize(plaintext.size());
    c.tag.resize(16);

    gcm_encrypt(key_, iv,
                aad.data(), aad.size(),
                plaintext.data(), plaintext.size(),
                c.ct.data(), c.tag.data());

    ++counter_; // next message gets a fresh nonce — until the next reboot()
    return c;
}

// Verify + decrypt a triple.  Returns false (and leaves plaintext_out empty) on
// a bad tag; never releases unverified plaintext.
bool Victim::receive(const Captured &c, const Bytes &aad, Bytes &plaintext_out) {
    if (c.iv.size() != 12 || c.tag.size() != 16) return false;

    Bytes pt(c.ct.size());
    bool ok = gcm_decrypt(key_, c.iv.data(),
                          aad.data(), aad.size(),
                          c.ct.data(), c.ct.size(),
                          c.tag.data(), pt.data());
    if (!ok) { plaintext_out.clear(); return false; }

    plaintext_out = std::move(pt);
    return true;
}
