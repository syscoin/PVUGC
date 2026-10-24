#!/usr/bin/env python3
"""Run 687: finite-distribution verification, NOT a signature-security test.

Exact arithmetic using Python standard library. Tests conditioning on a correlated
public verification key, joint smoothness, mask reuse, and leaked auxiliaries.
"""
from collections import Counter
from fractions import Fraction
from itertools import product
import json

N=8
K_VALUES=range(N)
MASKS=range(N)

def pubkey(k):
    return (5*k+1)%N  # a visibly invertible toy checking key

def inv_pubkey(pk):
    return (5*(pk-1))%N

def tv(a,b):
    assert sum(a.values())==sum(b.values())
    total=sum(a.values())
    return Fraction(sum(abs(a[x]-b[x]) for x in set(a)|set(b)),2*total)

def fresh(k):
    return Counter((pubkey(k),k^u,k^v) for u,v in product(MASKS,repeat=2))

def simulated(k):
    return Counter((pubkey(k),c,d) for c,d in product(range(N),repeat=2))

def reused(k):
    # Each pair is repeated N times to match the 64-outcome fresh distribution.
    return Counter((pubkey(k),k^u,k^u) for u in MASKS for _ in range(N))

def leaked_aux(k):
    # Pub auxiliary data includes the supposedly erased pad u. Exact 64 samples.
    return Counter((pubkey(k),k^u,u) for u in MASKS for _ in range(N))

assertions=0
fresh_tv=[]
reuse_tv=[]
aux_tv=[]
for k in K_VALUES:
    assert inv_pubkey(pubkey(k))==k
    assertions+=1
    fresh_tv.append(tv(fresh(k),simulated(k)))
    assertions+=1
    reuse_tv.append(tv(reused(k),simulated(k)))
    assertions+=1
    aux_tv.append(tv(leaked_aux(k),simulated(k)))
    assertions+=1
    assert set(v[1] for v in fresh(k))==set(range(N))
    assertions+=1
    assert set(v[2] for v in fresh(k))==set(range(N))
    assertions+=1

assert all(t==0 for t in fresh_tv)
assert all(t==Fraction(7,8) for t in reuse_tv)
assert all(t==Fraction(7,8) for t in aux_tv)
assertions+=3

# The public-key map alone identifies the toy key, despite perfect masking.
assert len(set(pubkey(k) for k in K_VALUES))==8
assertions+=1

# For any two fixed k values, the *masked pair* conditional on k is uniform.
for k0,k1 in product(K_VALUES,repeat=2):
    a=Counter((k0^u,k0^v) for u,v in product(MASKS,repeat=2))
    b=Counter((k1^u,k1^v) for u,v in product(MASKS,repeat=2))
    assert a==b
    assertions+=1

result={
 "fixture":"8 possible secrets; 8 fresh mask values per capsule; public injective affine checking-key map",
 "per_key_fresh_capsule_total_variation":sorted(set(map(str,fresh_tv))),
 "per_key_reused_mask_total_variation":sorted(set(map(str,reuse_tv))),
 "per_key_exposed_pad_aux_total_variation":sorted(set(map(str,aux_tv))),
 "public_key_exact_secret_recovery": "8/8",
 "uniform_pair_distribution_identical_for_all_secrets":True,
 "assertions":assertions,
 "interpretation":"Toy exact-distribution verification only; no QPT signature security or full WKEM is implemented."
}
print(json.dumps(result,sort_keys=True,indent=2))
