#!/usr/bin/env python3
"""Half-orbit projected SOURCE exact checker, standard library only.
No quantum-security or native-signature implementation claims.
"""
import json
from math import ceil, log2
from random import Random
from itertools import product
from collections import Counter
from fractions import Fraction

checks=0
def ck(ok):
    global checks
    assert ok
    checks+=1

def distribution(q):
    m=(q-1)//2
    c=[0]*q;c[0]=1
    for j in range(1,m+1):
        c=[c[(i-j)%q]+c[i]+c[(i+j)%q] for i in range(q)]
    return c

for q in (5,7,11,13,17,257):
    m=(q-1)//2; N=3**m
    sigma=1 if pow(3,m,q)==1 else -1
    c=distribution(q)
    ck(sum(c)==N)
    ck(c[0]==(N+(q-1)*sigma)//q)
    for k in range(1,q): ck(c[k]==(N-sigma)//q)
    for d in range(1,q):
        ck(sum(abs(c[k]-c[(k-d)%q]) for k in range(q))==2)

# Independently enumerate COMPLETE p-vector (not just quotient).
for q in (5,7):
    m=(q-1)//2
    C=[]
    for j in range(2,m+1):
        row=[0]*m;row[0]=-j;row[j-1]=1
        C.append(row)
    P=[Counter(),Counter()]
    for y in product(range(q),repeat=m-1):
        b=[sum(C[k][i]*y[k] for k in range(m-1))%q for i in range(m)]
        for eps in product((-1,0,1),repeat=m):
            p=tuple((b[i]+eps[i])%q for i in range(m))
            P[0][p]+=1
            P[1][((p[0]+1)%q,)+p[1:]]+=1
            ck(sum((i+1)*p[i] for i in range(m))%q==
               sum((i+1)*eps[i] for i in range(m))%q)
    tv=Fraction(sum(abs(P[0][k]-P[1][k]) for k in set(P[0])|set(P[1])),
                2*(q**(m-1))*(3**m))
    ck(tv==Fraction(1,3**m))

# SOURCE true: distinct ORIGINAL w1,w2, both binary anchored weight two.
q=257; m=128; g=5; b=q//g; ell=ceil(256/log2(b))
ck(b==51 and ell==46 and b**45<2**256<=b**46)
rng=Random(20261028)
for trial in range(12):
    K=bytes(rng.randrange(256) for _ in range(32))
    U=bytes(rng.randrange(256) for _ in range(32))
    Z=bytes(rng.randrange(256) for _ in range(32))
    D=bytes(x^y for x,y in zip(U,Z))
    V=bytes(x^y for x,y in zip(K,U))
    zint=int.from_bytes(Z,'big');digits=[]
    for _ in range(ell):digits.append(zint%b);zint//=b
    ck(zint==0)
    for a in digits:
        y0=rng.randrange(q)
        e0,e1,e2=(rng.choice((-1,0,1)) for _ in range(3))
        p0=(y0+e0+g*a)%q
        p1=(-y0+e1)%q
        p2=(-y0+e2)%q
        for phase in ((p0+p1)%q,(p0+p2)%q):
            v=[d for d in range(b) if min((phase-g*d)%q,(g*d-phase)%q)<=2]
            ck(v==[a])
    ck(bytes(x^y^z for x,y,z in zip(D,V,Z))==K)

print(json.dumps({"status":"PASS","assertions":checks,"q":257,
    "m":128,"r":127,"columns":46,"false_full_vector_tv":"1/3^128",
    "seed_bits":256,"true_original_witnesses":2,
    "hard_true_extraction":False,"concrete_128_bit_qpt":False},sort_keys=True))
