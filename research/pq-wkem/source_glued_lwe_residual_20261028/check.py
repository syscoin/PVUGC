#!/usr/bin/env python3
"""Offline exact checks for the source-glued LWE release candidate.
Proves finite-field identities only. Does not claim QPT security."""
from itertools import product
from random import Random
import json

q=257
g=9
rng=Random(20261028)
A=[[rng.randrange(q) for j in range(3)] for i in range(2)]
R=[[rng.randrange(q) for j in range(3)] for i in range(3)]
C=[[1,-1,0],[0,0,0]]
w=[1,1,0]
e=[1,0,0]
assert all(sum(row[j]*w[j] for j in range(3))%q==0 for row in C)
assert sum(w[j]*e[j] for j in range(3))%q==1
checks=2

def tr_matvec(M,x):
    return [sum(M[i][j]*x[i] for i in range(len(M)))%q for j in range(len(M[0]))]

def plus(*vectors):
    return [sum(v[i] for v in vectors)%q for i in range(len(vectors[0]))]

def dot(x,y):
    return sum(a*b for a,b in zip(x,y))%q

for trial in range(5000):
    s=[rng.randrange(q) for _ in range(2)]
    t=[rng.randrange(q) for _ in range(2)]
    epsL=[rng.choice((-1,0,1)) for _ in range(3)]
    epsR=[rng.choice((-1,0,1)) for _ in range(3)]
    a=rng.randrange(16)
    pL=plus(tr_matvec(A,s),epsL)
    residual=plus(tr_matvec(C,t),epsR,[g*a,0,0])
    pR=plus(tr_matvec(R,pL),residual)
    recovered_res=[(pR[j]-tr_matvec(R,pL)[j])%q for j in range(3)]
    assert recovered_res==residual
    checks+=1
    r=dot(w,recovered_res)
    assert (r-g*a)%q == dot(w,epsR)
    checks+=1
    centered=((r-g*a+q//2)%q)-q//2
    assert abs(centered)<=2 and abs(centered)<g//2
    checks+=1

# Distributional test of uniform y left block: conditioning on its value
# leaves the publicly computable source residual completely unchanged.
for y in product(range(3),repeat=3):
    for t in product(range(3),repeat=2):
        pR=plus(tr_matvec(R,y),tr_matvec(C,t),[g*2,0,0])
        assert plus(pR,[(-x)%q for x in tr_matvec(R,y)]) == plus(tr_matvec(C,t),[g*2,0,0])
        checks+=1

# False affine-source exact shift: if e=C_false^T lambda, then
# shifting uniformly random t absorbs every protected digit.
C_false=[[1,0,0],[0,1,0]]
for t in product(range(q),repeat=2):
    for a in range(2):
        real=plus(tr_matvec(C_false,t),[g*a,0,0])
        shifted=tr_matvec(C_false,[(t[0]+g*a)%q,t[1]])
        assert real == shifted
        checks+=1

print(json.dumps({"candidate":"source-glued-LWE","q":q,"checks":checks,
                  "full_original_witness_reduction":False,
                  "ordinary_LWE_source_residual_hiding":False,
                  "verified":"exact identities, bounded-noise toy release, public residual"}))
