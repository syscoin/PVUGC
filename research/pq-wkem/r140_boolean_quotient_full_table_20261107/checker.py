#!/usr/bin/env python3
"""R140 finite comparison: globally Boolean quotient masking on K4 parity CNF.
No crypto security or QPT hardness is tested.
"""
import hashlib, itertools, json, random
Q=7
EDGES=tuple(itertools.combinations(range(4),2))
STARS=tuple(tuple(i for i,(a,b) in enumerate(EDGES) if a==v or b==v) for v in range(4))
NUM=1<<len(EDGES)
FALSE_B=(1,0,0,0)
TRUE_B=(0,0,0,0)
RNG=random.Random(1401107)
checks=0

def check(z,label):
    global checks
    checks+=1
    if not z: raise AssertionError(label)

def witness(w,b):
    return all(sum((w>>e)&1 for e in s)%2 == b[v] for v,s in enumerate(STARS))

def violations(w,b):
    return tuple(int(sum((w>>e)&1 for e in s)%2 != b[v]) for v,s in enumerate(STARS))

def code(b,k,masks):
    return tuple((k+sum(violations(w,b)[j]*masks[j][w] for j in range(4)))%Q for w in range(NUM))

# For every false statement coordinate and every fixed mask on all but a nonzero constraint,
# randomizing the selected mask yields uniform K-independent output.
for w in range(NUM):
    check(not witness(w,FALSE_B),'K4 charged instance is false')
    v=violations(w,FALSE_B)
    j=next(j for j,c in enumerate(v) if c)
    for k in range(Q):
        for anchor in range(Q):
            outcomes=[(k+anchor+v[j]*a)%Q for a in range(Q)]
            check(set(outcomes)==set(range(Q)),'uniform coordinate conditional law')

true_ws=[w for w in range(NUM) if witness(w,TRUE_B)]
check(len(true_ws)==8,'eight uncharged K4 assignments')
for run in range(48):
    masks=tuple(tuple(RNG.randrange(Q) for w in range(NUM)) for _ in range(4))
    k=RNG.randrange(Q)
    ptrue=code(TRUE_B,k,masks)
    pfalse=code(FALSE_B,k,masks)
    for w in true_ws:
        check(ptrue[w]==k,'every valid ORIGINAL witness gets same value')
    # A FALSE-coordinate public fake cannot be a homomorphism B_n -> F_q
    # unless it is an actual Boolean evaluation; all those are nonsolutions.
    for w in range(NUM):
        check(violations(w,FALSE_B)!=(0,0,0,0),'no false-satisfying Boolean point')
    check(len(pfalse)==NUM,'output table length')

# Algebraic field-homomorphism soundness: if z^2=z in F_q, then z is 0 or 1.
for z in range(Q):
    check((z*z-z)%Q==0 if z in (0,1) else (z*z-z)%Q!=0,'Boolean idempotents')

# Full table is exponential: bytes for 7856-byte signature directly in per-assignment table.
sizes={str(n):7856*(1<<n) for n in (6,16,20,24,32)}
check(sizes['20']==8237613056,'exponential size')
report={
 'run':'R140-BOOLEAN-QUOTIENT-FULL-TABLE-20261107',
 'status':'NON_PRACTICAL_INFORMATION_THEORETIC_REFERENCE_ONLY',
 'field':Q,'variables':len(EDGES),'assignments':NUM,
 'true_witness_count':len(true_ws),'false_witness_count':0,
 'checks':checks,'random_full_table_trials':48,
 'signature_table_bytes':sizes,
 'security_statement':'perfect marginal/joint fixed-FALSE full-table hiding under independent uniform mask values; NOT PPT setup and NOT a generic WKEM',
 'assumptions':'independent uniform full-table masks; no secret checking/auxiliary leakage; sampled classic exact law',
 'checker_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest(),
}
print(json.dumps(report,sort_keys=True,separators=(',',':')))
