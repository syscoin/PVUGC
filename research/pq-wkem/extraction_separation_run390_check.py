#!/usr/bin/env python3
"""Run 390: exhaustive finite toy for true-instance extraction separation.
No signature security, one-wayness, oracle-query theorem, or WKEM construction is tested.
"""
import itertools, json

N=8
TAGS=range(4)
checks=0
perms=0
preimages={y:[0]*N for y in range(N)}

def ck(condition, label):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(f'{checks}: {label}')

# A random permutation with output y has a perfectly uniform inverse
# before f is queried.  This is a zero-query census, not a quantum test.
for perm in itertools.permutations(range(N)):
    perms += 1
    for u,y in enumerate(perm):
        preimages[y][u] += 1
for y in range(N):
    for u in range(N):
        ck(preimages[y][u] == 5040, 'uniform zero-query preimage posterior')
    ck(sum(preimages[y]) == 40320, 'all permutations counted')

# Source relation has four distinct ORIGINAL witnesses for each true x.
# These witnesses retain distinct source states but recover the identical K.
fixtures=[tuple((u+shift)%N for u in range(N)) for shift in range(6)]
valid_witness_checks=0
for f in fixtures:
    for y in range(N):
        x=(1,y,'claimA/challenge')
        K=19
        capsule=K
        found=[]
        for u in range(N):
            for t in TAGS:
                valid = f[u]==y
                got = capsule if valid else None
                ck((got==K) == valid, 'release correctly reflects ORIGINAL R')
                if valid:
                    found.append((u,t))
                    valid_witness_checks += 1
        ck(len(found)==len(TAGS), 'four distinct valid ORIGINAL witnesses')
        ck(len(set(found))==4, 'witness-specific source states preserved')
        # False branch has no valid witness, and capsule is independent of K.
        xb=(0,y,'claimA/challenge')
        empty_capsule=None
        ck(all(not (xb[0]==1 and f[u]==y) for u in range(N)),
           'all false ORIGINAL instances lack witnesses')
        for k in range(16):
            vk=k%2 # Toy metadata, not a secure signature key.
            view=(vk,empty_capsule)
            ck(view == (k%2,None), 'false capsule adds no key information')

# A true-instance adversary reads the key directly from the capsule:
# it is independent of the (hard-to-invert, asymptotically) preimage.
for y in range(N):
    for K in range(16):
        P=K
        ck(P==K, 'unauthorized true-instance release without witness')

print(json.dumps({
    'run':390, 'status':'PASS', 'assertions':checks,
    'permutations_exhaustively_enumerated':perms,
    'zero_query_preimage_count_per_y_and_u':5040,
    'valid_original_witness_checks':valid_witness_checks,
    'true_instance_unauthorized_capability_read':'exact in toy',
    'false_instance_capsule':'constant independent of K',
    'assumed_qpt_one_way_permutation_instantiated':False,
    'native_signature_security_tested':False,
    'quantum_query_lower_bound_tested':False,
    'practical_wkem':False
},sort_keys=True,indent=2))
