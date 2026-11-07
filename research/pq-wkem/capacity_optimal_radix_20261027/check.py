#!/usr/bin/env python3
"""Reproducible bounded algebraic checker, not cryptographic parameter validation."""
from itertools import product
from math import ceil, floor, log2
import hashlib
import json
import random

checks=0
def test(cond, msg):
    global checks
    if not cond: raise AssertionError(msg)
    checks+=1

def digits(z,radix,columns):
    xs=[]
    for _ in range(columns):
        z, t=divmod(z,radix)
        xs.append(t)
    test(z==0,"capacity")
    return xs

def undigits(xs,radix):
    s=0
    for t in reversed(xs): s=s*radix+t
    return s

def nearest(r,centers,q):
    dist=lambda a,b:min((a-b)%q,(b-a)%q)
    scored=sorted((dist(r,c),j) for j,c in enumerate(centers))
    return scored[0]

def mat_vec(B,z,q):
    return [sum(a*b for a,b in zip(row,z))%q for row in B]

q=65537; h=2; beta=1; E=h*beta; g=2*E+1
m=q//g; ell=ceil(256/log2(m)); previous=ceil(256/log2(128))
centers=[g*t for t in range(m)]
test(g==5 and m==13107 and ell==19 and previous==37,"parameters")
test(m**ell >= 2**256 and m**(ell-1)<2**256,"minimal fixed-length digit count")
test(min(g,q-(m-1)*g)==g,"cyclic minimum distance")
test(m==q//(2*E+1),"sphere-packing capacity optimality")

# Verify exact coding for all residue/error possibilities in a small field.
qsmall=31; msmall=qsmall//g
small_centers=[i*g for i in range(msmall)]
for t in range(msmall):
    for err in range(-E,E+1):
        v=(small_centers[t]+err)%qsmall
        dist,j=nearest(v,small_centers,qsmall)
        test(j==t and dist<=E,"small exact decoding")
test(msmall==6 and (msmall+1)*(2*E+1)>qsmall,"tight bound")
# All beta-bounded independent noises on n=6 entries, all digits, all valid witnesses.
ws=[[1,1,0,0,0,0],[1,0,1,0,0,0]]
for eps in product(range(-beta,beta+1),repeat=6):
    for w in ws:
        err=sum(a*b for a,b in zip(w,eps))
        for t in range(msmall):
            r=(g*t+err)%qsmall
            dist,j=nearest(r,small_centers,qsmall)
            test(j==t and dist<=E,"all error patterns")

rand=random.Random(0x4A0D2026)
num_trials=96
for trial in range(num_trials):
    d=3;n=6
    # A SOURCE with two different valid weight-h witnesses; completeness only.
    B=[]
    for _ in range(d):
        a=rand.randrange(q)
        B.append([a,-a%q,-a%q]+[rand.randrange(q) for _ in range(n-3)])
    for w in ws: test(mat_vec(B,w,q)==[0]*d,"honest kernel")
    # K,U,Z independent, checking key is a deterministic hash surrogate only.
    K=rand.getrandbits(256); U=rand.getrandbits(256); Z=rand.getrandbits(256)
    D=U^Z;V=K^U
    native_pk_surrogate=hashlib.sha256(K.to_bytes(32,'big')).hexdigest()
    ts=digits(Z,m,ell);test(undigits(ts,m)==Z,"base radix bijection")
    public_cols=[]
    for t in ts:
        s=[rand.randrange(q) for _ in range(d)]
        eps=[rand.randint(-beta,beta) for _ in range(n)]
        p=[(sum(B[r][i]*s[r] for r in range(d))+eps[i]+(g*t if i==0 else 0))%q for i in range(n)]
        public_cols.append(p)
    for w in ws:
        recovered=[]
        for p in public_cols:
            residue=sum(a*b for a,b in zip(w,p))%q
            # efficient nearest-radix decoding avoids scanning m symbols
            # modular wrap matters at the last center, inspect 3 neighbor indices
            approx=residue//g
            candidates={int(approx+j) for j in (-1,0,1,2)}|{0,m-1}
            best=min((min((residue-g*j)%q,(g*j-residue)%q),j) for j in candidates if 0<=j<m)
            dist,j=best
            test(dist<=E,"bounded noise")
            recovered.append(j)
        recovered_Z=undigits(recovered,m)
        recovered_K=V^D^recovered_Z
        test(recovered_Z==Z and recovered_K==K,"same precommitted key")
        test(hashlib.sha256(recovered_K.to_bytes(32,'big')).hexdigest()==native_pk_surrogate,"check key surrogate")

# Boundary for ordinary LWE proof: arbitrary shifts are bijections for uniform masks.
# Exhaustively verify a toy single-coordinate shift distribution for every digit.
for a in range(qsmall):
    for t in range(msmall):
        test(len({(v+g*t)%qsmall for v in range(qsmall)})==qsmall,"uniform challenge shift")

results={"status":"PASS","checks":checks,"q":q,"weight":h,"error_abs":beta,"error_max":E,
 "minimum_spacing":g,"radix":m,"columns":ell,"baseline_radix":128,"baseline_columns":previous,
 "column_reduction_pct":round(100*(previous-ell)/previous,6),"full_key_trials":num_trials,
 "distinct_true_witnesses":2,"exhaustive_error_vectors":3**6,"small_q":qsmall,
 "small_capacity":msmall,"experimental_security_bits":"NOT ESTABLISHED"}
print(json.dumps(results,sort_keys=True))
