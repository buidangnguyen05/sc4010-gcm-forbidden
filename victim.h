// victim.h — a deliberately broken AES-128-GCM user: its nonce counter RESETS
// on construction (the classic VM-snapshot / embedded-reboot bug), so the first
// message after every "reboot" reuses nonce 0. The attacker only ever sees the
// (iv, ct, tag) triples returned here.
#pragma once
#include <cstdint>
#include <vector>
#include <string>

using Bytes = std::vector<uint8_t>;

struct Captured {
    Bytes iv;
    Bytes ct;
    Bytes tag;
};

// The nonce counter the firmware (re)boots to. A nonzero *fixed* value is still
// the bug: every boot reuses the same nonce. (It's a joke value — any constant,
// including 0, triggers the reuse.)
inline constexpr uint64_t BOOT_NONCE = 0xBADC0FFEE0DDF00DULL; // "bad coffee, odd food"

class Victim {
public:
    explicit Victim(const uint8_t key[16]);

    void reboot(); // winds the nonce counter back to its boot value (the bug)
    Captured send(const Bytes &aad, const Bytes &plaintext);

    bool receive(const Captured &c, const Bytes &aad, Bytes &plaintext_out);

private:
    uint8_t key_[16];
    uint64_t counter_ = BOOT_NONCE; // becomes the IV; reset by reboot()
    void make_iv(uint8_t iv[12]);
};

// TODO(you): implement in victim.cpp (thin wrapper over gcm_encrypt/decrypt).
