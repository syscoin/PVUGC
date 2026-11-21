#!/usr/bin/env python3
"""Deterministic finite exact checks for Run 575 public-unary-orbit lemma.
Algebraic/interface checks only; this is NOT a cryptographic implementation.
"""
import itertools
import json
import hashlib

counter = dict(assertions=0, exhaustive_unary_models=0,
               choices_tested=0, positive_models=0,
               fixed_orbit_successes=0, branching_path_checks=0)

def check(expr):
    counter['assertions'] += 1
    assert expr

def orbit(phi, start, T):
    o=[start]
    for _ in range(T): o.append(phi[o[-1]])
    return o

# Exhaustive unary state mappings and credential-output masks.
# Every legitimate witness is allowed to select any t for which a candidate
# credential is usable. Enumerating all t always finds that same credential.
for n,T in [(2,2),(3,3),(4,4)]:
    for phi in itertools.product(range(n), repeat=n):
        for start in range(n):
            traj=orbit(phi,start,T)
            for mask in range(1<<n):
                counter['exhaustive_unary_models']+=1
                legal=[t for t,s in enumerate(traj) if (mask>>s)&1]
                # Simulated public test accepts precisely candidate values in mask.
                attacker=[s for s in traj if (mask>>s)&1]
                check(bool(legal)==bool(attacker))
                if legal:
                    counter['positive_models']+=1
                for t in range(T+1):
                    counter['choices_tested']+=1
                    if t in legal:
                        check(traj[t] in attacker)
                        counter['fixed_orbit_successes']+=1
                    else:
                        check(not ((mask>>traj[t])&1))
                # Incremental enumeration should be T function calls, not O(T^2).
                k=start
                states=[k]
                for _ in range(T):
                    k=phi[k];states.append(k)
                check(states==traj)

# Boundary check: two operations can expose exponentially many syntactically
# different source paths; this DOES NOT prove any cryptographic security.
for depth in range(1,11):
    observed=set()
    for bits in itertools.product((0,1),repeat=depth):
        state=(0,0)
        for bit in bits:
            d,prefix=state
            state=(d+1,(prefix<<1)|bit)
        observed.add(state)
    check(len(observed)==2**depth)
    counter['branching_path_checks']+=1

# A public, nonunique native verifier suffices: several candidates may pass.
# Enumeration finds *some* acceptable signing credential, not necessarily
# the same seed. This is a different claim from Run 574's unique-check WE compiler.
phi=[1,2,3,0]; traj=orbit(phi,0,8)
for accepted in [{2},{1,3},{0,2,3}]:
    check(any(s in accepted for s in traj))
    check(len(accepted)>=1)

out={"run":575,"result":"PASS","model":"finite-public-orbit-exhaustive",
     "parameter_grids":[[2,2],[3,3],[4,4]],"counters":counter,
     "security_claim":"none; finite combinatorial verification only"}
print(json.dumps(out,sort_keys=True,indent=2))
