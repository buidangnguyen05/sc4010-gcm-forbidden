#include "victim.h"
#include <cstring>
#include <stdexcept>
// Implement over gcm_encrypt/gcm_decrypt: #include "gcm.h"

// STUBS — a deliberately broken GCM user whose nonce counter resets on reboot().
[[noreturn]] static void todo(const char* w) { throw std::logic_error(std::string("TODO: ") + w); }

Victim::Victim(const uint8_t key[16])            { std::memcpy(key_, key, 16); }
void Victim::reboot()                            { todo("Victim::reboot"); }
void Victim::make_iv(uint8_t[12])                { todo("Victim::make_iv"); }
Captured Victim::send(const Bytes&, const Bytes&) { todo("Victim::send"); }
bool Victim::receive(const Captured&, const Bytes&, Bytes&) { todo("Victim::receive"); }
