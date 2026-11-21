#!/usr/bin/env python3
# Exact offline checker for projected-source spectral LWE component.
# Arithmetic only; NO QPT/native-signature security claim.
from itertools import product
from collections import Counter
from fractions import Fraction
from random import Random
import json
q=257
checks=0
def ck(v):
    global checks
    assert v
    checks+=1
def counts(q):
    c=[0]*q;c[0]=1
    for j in range(1,q):
        c=[c[(r-j)%q]+c[r]+c[(r+j)%q] for r in range(q)]
    return c
for p in (5,7,11,17,257):
    c=counts(p);N=3**(p-1)
    ck(sum(c)==N)
    ck(c[0]==(N+p-1)//p)
    for r in range(1,p):ck(c[r]==(N-1)//p)
    for d in range(1,p):
        ck(sum(abs(c[r]-c[(r-d)%p]) for r in range(p))==2)
# Full p-vector distribution: q=5, C rows (-2,1,0,0), etc.
p=5
rows=[tuple((-j if i==0 else (1 if i==j-1 else 0))%p
            for i in range(p-1)) for j in range(2,p)]
P=[Counter(),Counter()]
for y in product(range(p),repeat=p-2):
    b=[sum(y[k]*rows[k][i] for k in range(p-2))%p
       for i in range(p-1)]
    for eps in product((-1,0,1),repeat=p-1):
        v=tuple((b[i]+eps[i])%p for i in range(p-1))
        P[0][v]+=1
        P[1][((v[0]+1)%p,)+v[1:]]+=1
        ck(sum((i+1)*v[i] for i in range(p-1))%p==
           sum((i+1)*eps[i] for i in range(p-1))%p)
TV=Fraction(sum(abs(P[0][v]-P[1][v]) for v in set(P[0])|set(P[1])),
            2*5**3*3**4)
ck(TV==Fraction(1,81))
# True source C row (1,-1,-1), identity at j>=3, one zero row.
# Two ORIGINAL w: (1,1,0,...) and (1,0,1,...).
rng=Random(28)
g=5;base=q//g;ell=46
ck(base==51 and base**ell>=2**256 and base**(ell-1)<2**256)
for trial in range(8):
    K=bytes(rng.randrange(256) for _ in range(32))
    U=bytes(rng.randrange(256) for _ in range(32))
    Z=bytes(rng.randrange(256) for _ in range(32))
    D=bytes(a^b for a,b in zip(U,Z))
    V=bytes(a^b for a,b in zip(K,U))
    z=int.from_bytes(Z,'big');digs=[]
    for _ in range(ell):
        digs.append(z%base);z//=base
    ck(z==0)
    for a in digs:
        y0=rng.randrange(q)
        eps=[rng.choice((-1,0,1)) for _ in range(3)]
        p0=(y0+eps[0]+g*a)%q
        p1=(-y0+eps[1])%q
        p2=(-y0+eps[2])%q
        for ph in ((p0+p1)%q,(p0+p2)%q):
            valid=[d for d in range(base) if
                   min((ph-g*d)%q,(g*d-ph)%q)<=2]
            ck(valid==[a])
    rec=bytes(a^b^c for a,b,c in zip(D,V,Z))
    ck(rec==K)
print(json.dumps({"result":"PASS","assertions":checks,
                  "false_shift_tv":"1/3^256",
                  "toy_full_p_tv":"1/81",
                  "true_witnesses":2,"seed_bits":256,"columns":ell},
                 sort_keys=True))
