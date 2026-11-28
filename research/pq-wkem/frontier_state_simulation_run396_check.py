#!/usr/bin/env python3
"""Run 396: exact finite checks of a witness-free local-frontier sampler attack.

No actual obfuscation, KEM, signature security, RIO or quantum algorithm is tested.
All assertions concern elementary finite distributions and a source-interface bypass.
"""
from itertools import permutations
import json

checks = 0

def chk(ok, why):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(f"{checks}: {why}")

# Three distinct valid ORIGINAL witness labels. A private/local reversible
# scrambling is represented by any permutation pi of all possible states.
# For every fixed valid witness w and uniform random r, pi(r) XOR w is uniform.
W = (1, 3, 5)
N = 8
K = 17  # toy protected capability, symbolic; not an actual signing key
GOOD = {0, 1, 2, 3, 5, 6, 7}

def release(s):
    return K if s in GOOD else None

permutation_count = 0
state_count = 0
for pi in permutations(range(N)):
    permutation_count += 1
    for w in W:
        state_hist = [0] * N
        honest_success = 0
        for r in range(N):
            s = pi[r] ^ w
            state_hist[s] += 1
            honest_success += (release(s) == K)
            state_count += 1
        chk(state_hist == [1] * N, "bijective mixing yields perfectly uniform states")
        chk(honest_success == len(GOOD), "all valid witnesses have same success probability")

chk(permutation_count == 40320, "all reversible 3-bit functions visited")
unauthorized_success = sum(release(s) == K for s in range(N))
chk(unauthorized_success == len(GOOD), "uniform witness-free sampler succeeds equally")

# Contrasting two *marginally uniform* seam shares with a correlated joint law.
# Valid states are (u,u XOR k); random independent shares are both uniform,
# but the pair's distributions are far apart. The theorem requires JOINT
# indistinguishability, never separate marginals.
pair_checks = 0
joint_tvs = []
for k in range(N):
    real = {(a,b): (1/N if b == (a ^ k) else 0)
            for a in range(N) for b in range(N)}
    sim = {(a,b): 1/(N*N)
           for a in range(N) for b in range(N)}
    for bit in (0,1):
        for v in range(N):
            marginal_r = sum(prob for (a,b),prob in real.items()
                             if (a if bit == 0 else b) == v)
            marginal_q = sum(prob for (a,b),prob in sim.items()
                             if (a if bit == 0 else b) == v)
            chk(marginal_r == 1/N == marginal_q, "individual marginal uniforms")
            pair_checks += 1
    tv = sum(abs(real[key]-sim[key]) for key in real)/2
    chk(abs(tv - (1 - 1/N)) < 1e-12, "joint TV is 1-1/N")
    # The two-share decoder is jointly source/capability correlated. Without a
    # valid joint sample, independent sampling guesses k with chance 1/N.
    real_auth = sum(p for (a,b),p in real.items() if (a ^ b) == k)
    sim_auth = sum(p for (a,b),p in sim.items() if (a ^ b) == k)
    chk(real_auth == 1, "real two-share relationship is exact")
    chk(abs(sim_auth-1/N) < 1e-12, "simulated two-share chance is 1/N")
    joint_tvs.append(tv)

# A public acceptance flag is not an authenticated proof of the ORIGINAL
# source relation, if the protected release region accepts the flag directly.
for r in range(N):
    chk(release(r) == (K if r in GOOD else None), "direct chosen frontier state")

print(json.dumps({
    "run": 396, "status": "PASS", "assertions": checks,
    "reversible_three_bit_permutations": permutation_count,
    "valid_original_witness_labels": list(W),
    "exact_honest_frontier_states_tested": state_count,
    "state_space_size": N,
    "honest_release_success": len(GOOD)/N,
    "witness_free_release_success": unauthorized_success/N,
    "two_share_joint_tv": joint_tvs[0],
    "two_share_real_authorization": 1,
    "two_share_independent_authorization": 1/N,
    "individual_marginal_checks": pair_checks,
    "requires_frontier_independent_callability": True,
    "real_kem": False, "secure_signature": False,
    "qpt_security_proven": False,
}, sort_keys=True, indent=2))
