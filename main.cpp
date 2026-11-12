// main.cpp — live forbidden-attack demo driver (run: ./build/forbidden).
//
// Scenario: a fleet node streams telemetry/status reports to a central
// collector (think SIEM / monitoring) over AES-128-GCM, one directional key.
// The node's firmware is buggy: it randomly crashes, and on reboot its nonce
// counter winds back to a fixed value (victim.cpp's bug), so the first report
// of each boot reuses a nonce. Forging reports here is genuinely harmful: an
// attacker can fabricate an "all healthy" status that hides a real incident.
//
// Everything below is RANDOM each run: the key, the number of reports, their
// contents, and WHEN the node crashes. Nothing is hard-coded or pre-marked.
//
// The attacker is PASSIVE and IV-BLIND: it never inspects IVs to spot repeats.
// It just grinds EVERY pair of captured reports through Joux's forbidden attack
// and lets the math reveal the key:
//   * H = E_K(0) is a root of a pair's forbidden polynomial  iff  that pair
//     reused a nonce (else f(H) = S_i ^ S_j != 0);
//   * H depends only on the key, not the nonce, so every nonce-reusing pair
//     votes for the SAME H while spurious roots are random and never recur.
//   => tally the roots over all pairs; the most-voted value is H.
// The recovered H is then confirmed the only way a real attacker can: by
// forging a report and seeing the collector accept it.
#include "attack.h"
#include "gcm.h"
#include "gf128.h"
#include "victim.h"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <random>
#include <string>
#include <thread>
#include <vector>

using Bytes = std::vector<uint8_t>;

static Bytes str_bytes(const std::string &s) { return {s.begin(), s.end()}; }
static std::string show(const Bytes &b) { return {b.begin(), b.end()}; }

// One record the attacker sniffed. `iv` is kept only because it was on the wire;
// the cryptanalysis never reads it. `pt` is the plaintext the attacker knows or
// guesses (telemetry is highly structured) — needed only to forge, not to break.
struct Cap {
    Bytes iv, ct, tag, pt, aad;
};
static Msg as_msg(const Cap &c) { return Msg{c.aad, c.ct, c.tag}; }

static void hr(const char *t) { std::printf("\n\033[1m== %s ==\033[0m\n", t); }

int main(int argc, char **argv) {
    std::random_device rd;
    uint64_t seed = (static_cast<uint64_t>(rd()) << 32) | rd();
    std::mt19937_64 rng(seed);

    uint8_t key[16];
    for (uint8_t &b : key) b = static_cast<uint8_t>(rng());
    Victim node(key);      // the flaky telemetry source
    Victim collector(key); // verifies reports with the shared directional key

    std::printf("random key this run: (hidden from attacker)   seed=%016llx\n",
                static_cast<unsigned long long>(seed));

    // ---- 1. a long, random, crash-prone telemetry stream -------------------
    hr("1. node streams telemetry to the collector (and randomly crashes)");

    static const char *nodes[] = {"web-01", "web-07", "db-02", "db-05", "auth-1",
                                  "cache-3", "edge-9", "worker-4", "gw-0", "lb-2"};
    static const char *stat[] = {"OK", "OK", "OK", "OK", "WARN", "HEALTHY"};
    auto gen_report = [&]() -> Bytes {
        char buf[96];
        const char *n = nodes[rng() % (sizeof(nodes) / sizeof(*nodes))];
        const char *s = stat[rng() % (sizeof(stat) / sizeof(*stat))];
        int len = std::snprintf(buf, sizeof buf, "node=%s cpu=%d%% mem=%d%% disk=%d%% req=%d %s",
                                n, (int) (rng() % 100), (int) (rng() % 100),
                                (int) (rng() % 100), (int) (rng() % 5000), s);
        return Bytes(buf, buf + len);
    };

    // Number of reports: optional CLI arg (./build/forbidden 200), else random.
    const int N = argc > 1 ? std::max(2, std::atoi(argv[1]))
                           : 45 + static_cast<int>(rng() % 45); // default 45..89
    std::vector<Cap> wire;
    std::uniform_int_distribution<int> gap_ms(200, 500); // random inter-report delay
    int crashes = 0;
    // Stream at least N reports, but keep listening past N until the node has
    // glitched at least once — crash timing stays fully random, we just wait for
    // the bug to fire (hard cap so a pathological run still terminates).
    for (int i = 0; i < N || (crashes == 0 && i < N + 400); ++i) {
        if (i > 0 && (rng() % 100) < 5) { // ~5% chance to crash before this report
            node.reboot();
            ++crashes;
            std::printf("\033[31m  *** node crashed (watchdog reset) — rebooting ***\033[0m\n");
            std::fflush(stdout);
        }
        Bytes aad = str_bytes("feed=telemetry;v1");
        Bytes pt = gen_report();
        Captured c = node.send(aad, pt);
        Bytes got;
        collector.receive(c, aad, got); // normal operation: collector ingests it
        wire.push_back(Cap{c.iv, c.ct, c.tag, pt, aad});
        std::printf("  [node -> collector] %s\n", show(pt).c_str()); // stream it live
        std::fflush(stdout);
        if (i + 1 < N) std::this_thread::sleep_for(std::chrono::milliseconds(gap_ms(rng)));
    }
    std::printf("  node crashed %d time(s); attacker captured %zu reports\n",
                crashes, wire.size());

    // ---- 2. IV-blind break: try EVERY pair, tally roots --------------------
    hr("2. grinding all pairs of captured data");
    std::map<gf, int> votes;
    size_t pairs = 0;
    const size_t total_pairs = wire.size() * (wire.size() - 1) / 2;
    std::printf("  grinding %zu pairs", total_pairs);
    std::fflush(stdout);
    auto t0 = std::chrono::steady_clock::now();
    for (size_t i = 0; i < wire.size(); ++i)
        for (size_t j = i + 1; j < wire.size(); ++j) {
            poly f = build_forbidden_poly(as_msg(wire[i]), as_msg(wire[j]));
            for (gf r : find_roots(f)) votes[r]++;
            if (++pairs % 500 == 0) { std::printf("."); std::fflush(stdout); }
        }
    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::printf(" done\n");

    // candidates, most-voted first
    std::vector<std::pair<gf, int>> ranked(votes.begin(), votes.end());
    std::sort(ranked.begin(), ranked.end(), [](auto &a, auto &b) { return a.second > b.second; });

    std::printf("  tried %zu pairs in \033[1m%.0f ms\033[0m  (%.1f ms/pair)\n", pairs, ms,
                pairs ? ms / pairs : 0.0);
    std::printf("  %zu distinct candidate roots; top vote counts:", votes.size());
    for (size_t i = 0; i < std::min<size_t>(ranked.size(), 4); ++i) std::printf(" %d", ranked[i].second);
    std::printf("\n");

    // ---- 3. confirm H the only way a real attacker can: forge + inject -----
    hr("3. recover the key by forging");
    // Pick the longest known report for the most keystream to forge with.
    size_t tgt = 0;
    for (size_t i = 1; i < wire.size(); ++i)
        if (wire[i].pt.size() > wire[tgt].pt.size()) tgt = i;
    Bytes ks(wire[tgt].pt.size());
    for (size_t i = 0; i < ks.size(); ++i) ks[i] = wire[tgt].pt[i] ^ wire[tgt].ct[i];

    // The forged "all healthy" report — a fabricated status that hides a breach.
    Bytes forged_aad = str_bytes("feed=telemetry;v1");
    Bytes forged_pt = str_bytes("node=core-db cpu=1% mem=1% disk=1% req=0 OK");
    if (forged_pt.size() > ks.size()) forged_pt.resize(ks.size());

    // Walk candidates by vote rank; the real H forges a report the collector
    // accepts. (In practice the top-voted candidate is H on the first try.)
    gf H = 0;
    bool won = false;
    int tried = 0;
    Bytes out;
    for (auto &[cand, n] : ranked) {
        ++tried;
        gf S = recover_mask_S(cand, as_msg(wire[tgt]));
        Forgery fg = forge(cand, S, ks, forged_aad, forged_pt);
        Captured pkt{wire[tgt].iv, fg.ct, fg.tag}; // reuse a captured nonce as transport
        if (collector.receive(pkt, forged_aad, out)) {
            H = cand;
            won = true;
            break;
        }
        (void) n;
    }

    if (!won) {
        std::printf("  no candidate forged an accepted report — this capture had no "
                    "nonce reuse (try again; crashes are random).\n");
        return 1;
    }

    std::printf("  recovered H in %d forgery attempt(s): \033[1m%s\033[0m\n", tried, gf_to_hex(H).c_str());
    std::printf("  (ground-truth E_K(0) = %s -> %s)\n", gf_to_hex(gcm_H(key)).c_str(),
                H == gcm_H(key) ? "\033[1;32mMATCH\033[0m" : "\033[1;31mMISMATCH\033[0m");

    // How many nonces were actually reused — recovered from the mask S, no IVs.
    std::map<gf, int> by_nonce;
    for (auto &c : wire) by_nonce[recover_mask_S(H, as_msg(c))]++;
    size_t reused = 0, biggest = 0;
    for (auto &[s, k] : by_nonce) {
        if (k > 1) ++reused;
        biggest = std::max<size_t>(biggest, k);
    }
    std::printf("  nonce map (from S, still no IVs): %zu distinct, %zu reused, largest group %zu\n",
                by_nonce.size(), reused, biggest);

    // ---- 4. the harm -------------------------------------------------------
    hr("4. report forging");
    std::printf("  collector.receive() -> \033[1;32mACCEPTED\033[0m\n");
    std::printf("  logged a healthy node:  \033[1m\"%s\"\033[0m\n", show(out).c_str());
    std::printf("  ...breached.\n");

    return H == gcm_H(key) ? 0 : 1;
}
