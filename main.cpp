// main.cpp — demo driver. Fill this in as the attack modules come online;
// this is the thing you run live during the presentation.
//
// Intended flow (see README §demo):
//   1. Victim boots, sends message A under nonce 0.
//   2. Victim "reboots" (reboot()), sends message B — nonce 0 again.  <- the bug
//   3. recover_H_candidates(A, B)  ->  disambiguate with a 3rd message.
//   4. recover_mask_S(H, A); forge a modified transfer; victim.receive() ACCEPTS.
#include "victim.h"
#include "attack.h"
#include "gf128.h"
#include <cstdio>

int main() {
    std::printf("gcm-forbidden demo driver — attack modules not implemented yet.\n");
    std::printf("Run ./tests first: it must print 'GATE #1 GREEN' before you build the attack.\n");
    return 0;
}
