#!/usr/bin/env python3
"""Run 358: exact finite PRG-boundary-mask falsification.
Toy G is intentionally distinguishable. NO cryptographic/QPT security is inferred.
The checks validate the tight tester/sampler reduction in finite spaces.
"""
import hashlib
import json

assertions = 0
def check(x, message=""):
    global assertions
    assertions += 1
    if not x:
        raise AssertionError((assertions, message))

def g(seed, k):
    # Injective expansion, NON-CRYPTOGRAPHIC: top k bits contain seed.
    mask=(1 << k)-1
    return (seed << k) | ((seed*seed*3 + seed*7 + 1) & mask)

records=[]
for k in range(2, 6):
    d=2*k
    n=1 << d
    source=1 << k
    vals={g(seed,k) for seed in range(source)}
    check(len(vals)==source, "injective")
    sample_offsets=range(n) if k <= 4 else range(0,n,7)
    cases=0
    for a in sample_offsets:
        accepted={a ^ v for v in vals}
        check(len(accepted)==source)
        # T(P,s) is a public native-key-success predicate (abstract toy table).
        # The PRG case is exactly correct, the uniform case succeeds on a fraction.
        true_cases=sum(int((a ^ g(seed,k)) in accepted) for seed in range(source))
        uniform_cases=sum(int(s in accepted) for s in range(n))
        check(true_cases==source)
        check(uniform_cases==source)
        # Exact statistical distance of uniform-on-image from uniform.
        tv_num=sum(abs((n if s in accepted else 0)-source) for s in range(n))
        check(tv_num == 2*source*(n-source))
        # Distinguisher advantage = 1 - uniform release success.
        check(n*true_cases-source*uniform_cases == source*(n-source))
        cases+=1
    records.append({
       "seed_bits":k,"output_bits":d,"offsets":cases,
       "prg_case_success":{"num":1,"den":1},
       "uniform_case_success":{"num":source,"den":n},
       "tester_advantage":{"num":n-source,"den":n}
    })

# Multi-witness correctness with witness-dependent, noncanonical states.
# A single public release table usable for all three offsets necessarily
# accepts the union. Thus public uniform sampling succeeds with union density.
multi=[]
for k in range(2,7):
    n=1<<(2*k); seeds=range(1<<k)
    offsets=[0, (n//3), (2*n//3)]
    images=[{a ^ g(seed,k) for seed in seeds} for a in offsets]
    union=set().union(*images)
    for image in images:
        check(image.issubset(union))
        check(len(image)==1<<k)
    check(len(union)>=1<<k)
    check(len(union)<=3*(1<<k))
    check(sum(int(y in union) for y in range(n))==len(union))
    multi.append({"seed_bits":k,"output_bits":2*k,
                  "witness_branches":3,"accepted_states":len(union),
                  "public_uniform_success_num":len(union),
                  "public_uniform_success_den":n})

# Exact triangle/testing inequality for arbitrary distributions on 4 outcomes.
# For ANY test, |P[test]-Q[test]| <= TV(P,Q).
tv_checked=0
m=4
def comps(t,dim):
    if dim==1:
        yield (t,)
    else:
        for j in range(t+1):
            for r in comps(t-j,dim-1):
                yield (j,)+r
probvec=list(comps(4,m))
for p in probvec:
    for q in probvec:
        l1=sum(abs(x-y) for x,y in zip(p,q))
        for b in range(1<<m):
            diff=abs(sum(p[j] for j in range(m) if (b>>j)&1)
                     -sum(q[j] for j in range(m) if (b>>j)&1))
            check(2*diff<=l1)
            tv_checked+=1

# A concrete failure fixture under a useful public checking key:
# success on valid PRG-masked states and success on uniform public states
# cannot both be (1) near-perfect and (2) negligible if G is QPT-secure.
output={
 "run":358,
 "status":"PASS",
 "assertions":assertions,
 "toy_noncryptographic":True,
 "single_branch":records,
 "multi_witness":multi,
 "tv_test_cases":tv_checked,
 "scope":"finite combinatorics only; no PRG/WE/LWE/SIS hardness or source extraction"
}
print(json.dumps(output,sort_keys=True,indent=2))
