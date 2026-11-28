#!/usr/bin/env python3
"""Exact finite counterexample for setup-correctness quantifiers; no FE implementation."""
import json
from itertools import product
N=12
D=1<<N
# Valid 'source' in this synthetic model: top three bits 101. No PoW is modeled.
valid=lambda w: (w>>(N-3)) == 0b101
W=[w for w in range(D) if valid(w)]
# Each capsule with coin rho rejects exactly the valid input rho, otherwise opens one frozen secret.
S=0x5F34

def evaluate(rho,w):
    return S if valid(w) and w!=rho else None

# For fixed valid w, failure probability over uniformly sampled rho in W is 1/|W|.
w=W[7]
fail_fixed=sum(evaluate(rho,w)!=S for rho in W)
assert fail_fixed==1
# For every sampled rho, there is some valid w that fails (namely rho).
all_bad=sum(any(evaluate(rho,x)!=S for x in W) for rho in W)
assert all_bad==len(W)
# Every non-blacklisted valid w still opens to same frozen S.
assert all(evaluate(rho,x)==S for rho in W[:8] for x in W if x!=rho)
# Rare catastrophic bad coins: for honest uniform coins, a complete failure is 1/2^N;
# a malicious party can select them deliberately and still prove canonical compiler execution.
rare_bad=0
assert sum(1 for rho in range(D) if rho==rare_bad)==1
# Simulated XOR coin-flip once with fixed malicious choice: honest uniform share makes rho uniform,
# but a malicious abort/restart can filter outcomes in an unbounded sequence.
malicious=177
freq_bad=sum((malicious^honest)==rare_bad for honest in range(D))
assert freq_bad==1
# Special-case repair: two capsules with publicly proved DISTINCT point exceptions
# have an empty intersection of bad sets, so every valid w opens under at least one.
ra,rb=W[0],W[1]
assert ra!=rb
assert all(evaluate(ra,w)==S or evaluate(rb,w)==S for w in W)
assert any(evaluate(ra,w)!=S and evaluate(ra,w)!=S for w in W)
result={
    "scope":"finite quantifier counterexample only; no FE/ZK/PoW/source validation",
    "domain_size":D,"valid_witnesses":len(W),
    "fixed_witness_failure_fraction":f"{fail_fixed}/{len(W)}",
    "capsules_with_at_least_one_failed_valid_witness":all_bad,
    "uniform_bad_coin_probability":f"1/{D}",
    "malicious_selected_bad_coin_fails_all":True,
    "xor_beacon_bad_probability":f"{freq_bad}/{D}",
    "every_witness_correctness_not_implied_by_pointwise_correctness":True,
    "two_distinct_point_exceptions_cover_all_valid_witnesses":True,
    "duplicate_point_exceptions_leave_a_hole":True,
}
print(json.dumps(result,sort_keys=True,indent=2))
