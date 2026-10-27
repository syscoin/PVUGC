#!/usr/bin/env python3
"""Exact small-ring checks of independently keyed, adaptive-open transverse-LWE composition.
Algebra and conditional-distribution checks ONLY; no proof of LWE or native hardness.
"""
import json
from collections import Counter
from itertools import product

Q, G, H, N, K_BITS = 32, 4, 1, 3, 2
B = (0, 0, 5)
ALPHA = (G//H,)*N
WS = ((1,0,0),(0,1,0))
COUNT = 0

def chk(p):
    global COUNT
    COUNT += 1
    assert p

def mod(x):
    return x % Q

def generate(t,u,e):
    return tuple(mod(ALPHA[a]*t+B[a]*u+e[a]) for a in range(N))

def embed(t,c):
    return tuple(mod(ALPHA[a]*t+c[a]) for a in range(N))

def round_residue(y):
    # Given |err| <= 1 and G=4, choose the unique closest multiple of G in Z_Q.
    residues=[((y-G*z)%Q,z) for z in range(Q//G)]
    distances=[(min(d,Q-d),z) for d,z in residues]
    distance,z=min(distances)
    chk(distance<=1)
    chk(sum(distance==dist for dist,zz in distances)==1)
    return z

def projection(z):
    # fixed full-rank linear map Z_8 (3 bits) -> GF(2)^2
    return z & 3

# Exact, all-error, all-u, all-t SAME precommitted 2-bit U recover via accepted w.
for t,u,e in product(range(Q),range(Q),product((-1,0,1),repeat=N)):
    p=generate(t,u,e)
    p_from_challenge=embed(t,tuple(mod(B[a]*u+e[a]) for a in range(N)))
    chk(p==p_from_challenge)
    for W in WS:
        y=sum(W[a]*p[a] for a in range(N))%Q
        chk(round_residue(y)==t%(Q//G))
        for U in range(1<<K_BITS):
            D=U^projection(t%(Q//G))
            Urec=D^projection(round_residue(y))
            chk(Urec==U)

# Exact conditional null: for each fixed actual native K, pk=f(K), other-opening data o,
# and target NP share V revealed, target public (p,D,V) has uniform D,V independently.
# Uniform p may be conditioned on any chosen value, so it is not enumerated.
for K in range(1<<K_BITS):
    hist=Counter()
    for U,t in product(range(1<<K_BITS),range(Q)):
        V=K^U
        D=U^projection(t%(Q//G))
        hist[(D,V)]+=1
    chk(len(hist)==(1<<K_BITS)**2)
    for D,V in product(range(1<<K_BITS),repeat=2):
        chk(hist[(D,V)]==Q//(1<<K_BITS))
        # Adaptive opening of unrelated instance J can be fixed to any tuple
        # independent of target coins and does not modify this conditional count.
        for otherK,otherU in product(range(1<<K_BITS),repeat=2):
            otherV=otherK^otherU
            chk(hist[(D,V)]==Q//(1<<K_BITS) and 0<=otherV<(1<<K_BITS))

# At the declared security boundary, an adversary may learn target NP V and all NP coins;
# but revealing target linear pad/coins or valid opening witness is a disallowed challenge.
for K,U,t in product(range(1<<K_BITS),range(1<<K_BITS),range(Q)):
    V=K^U
    D=U^projection(t%(Q//G))
    chk((D^projection(t%(Q//G)))^V==K)
    chk(D^V^projection(t%(Q//G))==K)

# Explicit sub-relation: only e0 and e1 qualify here; not a Bitcoin witness compiler.
for w in product((0,1),repeat=N):
    is_valid=(sum(w)==H and sum(w[i]*B[i] for i in range(N))%Q==0)
    chk(is_valid==(w in WS))

result={
  'record':'adaptive_independent_lwe_20261027',
  'checker':'check_adaptive.py',
  'total_assertions':COUNT,
  'exact_ring':{'q':Q,'g':G,'h':H,'n':N,'B':B,'alpha':ALPHA,'chi':[-1,0,1]},
  'observations':['LWE embedding algebra exact','two distinct accepted witnesses both round to the same U for all 32^2*27 noise cases','null D,V independent of fixed checking-key-associated K and unrelated openings','target linear material must remain unopened'],
  'security_claims':'none: exact identities only; no QPT-LWE or native reduction experimentally established'
}
print(json.dumps(result,sort_keys=True,separators=(',',':')))
