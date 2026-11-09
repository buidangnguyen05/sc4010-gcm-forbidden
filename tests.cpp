// tests.cpp — GATE #1.  Reproduce canonical AES-128-GCM test vectors
// (McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)", Appendix B;
// also NIST SP 800-38D). If any of these fail, gf_mul / ghash / gcm are wrong
// and nothing downstream can work — fix this before building the attack.
#include "gf128.h"
#include "gcm.h"
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

static std::vector<uint8_t> unhex(const std::string& h) {
    std::vector<uint8_t> v;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back((uint8_t)std::stoul(h.substr(i, 2), nullptr, 16));
    return v;
}
static std::string tohex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 0xf]; }
    return s;
}

static int failures = 0;
static void check(const std::string& name, const std::string& got, const std::string& want) {
    bool ok = (got == want);
    std::printf("  [%s] %-18s got=%s\n", ok ? "PASS" : "FAIL", name.c_str(), got.c_str());
    if (!ok) { std::printf("        %-18s want=%s\n", "", want.c_str()); ++failures; }
}

struct Vec {
    const char* name;
    std::string K, IV, A, P, Hexp, Cexp, Texp;
};

static void run(const Vec& v) {
    std::printf("%s\n", v.name);
    auto K = unhex(v.K), IV = unhex(v.IV), A = unhex(v.A), P = unhex(v.P);

    // H = E_K(0^128)
    check("H", gf_to_hex(gcm_H(K.data())), v.Hexp);

    std::vector<uint8_t> C(P.size());
    uint8_t T[16];
    gcm_encrypt(K.data(), IV.data(), A.data(), A.size(), P.data(), P.size(), C.data(), T);
    check("ciphertext", tohex(C.data(), C.size()), v.Cexp);
    check("tag", tohex(T, 16), v.Texp);

    // round-trip: decrypt must accept and recover P
    std::vector<uint8_t> P2(C.size());
    bool ok = gcm_decrypt(K.data(), IV.data(), A.data(), A.size(),
                          C.data(), C.size(), T, P2.data());
    check("decrypt-accept", ok ? "ok" : "REJECTED", "ok");
    check("decrypt-plain", tohex(P2.data(), P2.size()), v.P);
}

int main() {
    // field sanity: 1 * x == x
    gf one = GF_ONE, x = ((gf)0x0123456789abcdefULL << 64) | 0xfedcba9876543210ULL;
    std::printf("field sanity\n");
    check("1*x==x", gf_to_hex(gf_mul(one, x)), gf_to_hex(x));

    // McGrew-Viega Test Case 2: all-zero key/iv, one zero plaintext block.
    run({ "GCM Test Case 2",
        "00000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "00000000000000000000000000000000",
        "66e94bd4ef8a2c3b884cfa59ca342b2e",
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf" });

    // Test Case 4: real key, AAD + 60-byte plaintext (exercises AAD, partial
    // blocks, and the length block — the full GHASH path).
    run({ "GCM Test Case 4",
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "b83b533708bf535d0aa6e52980d53b78",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        "5bc94fbc3221a5db94fae95ae7121a47" });

    std::printf("\n%s (%d failure%s)\n",
                failures ? "GATE #1 FAILED" : "GATE #1 GREEN",
                failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
