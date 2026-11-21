#!/usr/bin/env python3
"""Bounded exact integer/rational and simulated-phase adversarial test for R156.
No external dependencies. This is a functional counterexample, not a QPT test.
"""
from fractions import Fraction as F
from itertools import product
from random import Random
from hashlib import sha256
import json

Q=65521
DELTA=4096
ERR=3
SEED=15620261108
rng=Random(SEED)
checks=0

def ck(v, label):
    global checks
    checks+=1
    if not v:
        raise AssertionError(f'{checks}: {label}')

def build(n, parity):
    # Ring of n two-bit XOR gates: x_i XOR x_(i+1) = parity[i].
    # Two permitted local tuples per gate, parameterized by the first bit a=0,1.
    # Variables: lambda_(gate,a) at offsets 2*gate+a, then y_i at 2*n+i.
    N=3*n
    A=[]; rhs=[]
    def row(items, v):
        z=[0]*N
        for idx, coef in items:
            z[idx]+=coef
        A.append(z); rhs.append(v)
    for e,p in enumerate(parity):
        u=e; v=(e+1)%n
        row([(2*e,1),(2*e+1,1)],1)
        # First endpoint is 0/1 for a=0/1.
        row([(2*e+1,1),(2*n+u,-1)],0)
        # Second endpoint = a XOR parity, row coefficients are those bits.
        row([(2*e, p),(2*e+1,1-p),(2*n+v,-1)],0)
    return A,rhs

def prod(A,z):
    return [sum(a*b for a,b in zip(row,z)) for row in A]

def legal(n,parity):
    return [bits for bits in product(range(2),repeat=n)
            if all((bits[e]^bits[(e+1)%n])==parity[e] for e in range(n))]

def witness_vec(n,parity,bits):
    z=[0]*(3*n)
    for e in range(n):
        z[2*e+bits[e]]=1
    z[2*n:]=list(bits)
    return z

def center(x):
    return (x+Q//2)%Q-Q//2

def phase_attack(A,rhs,twice_z,key):
    # Public SAMPLE of (c,t). An adversary does not see r, errors, or key.
    r=[rng.randrange(Q) for _ in A]
    e=[rng.randrange(-ERR,ERR+1) for _ in twice_z]
    e0=rng.randrange(-ERR,ERR+1)
    c=[(sum(A[j][i]*r[j] for j in range(len(A)))+e[i])%Q
       for i in range(len(twice_z))]
    t=(sum(b*a for b,a in zip(rhs,r))+DELTA*key+e0)%Q
    observed=(2*t-sum(a*b for a,b in zip(c,twice_z)))%Q
    distance=[abs(center(observed-(2*DELTA)*k)) for k in (0,1)]
    guess=min(range(2),key=lambda i:distance[i])
    error=center(observed-2*DELTA*key)
    expected=2*e0-sum(ee*z for ee,z in zip(e,twice_z))
    ck(error==expected, "noise identity, no modular wrapping")
    ck(abs(error)<=ERR*(2+sum(abs(t) for t in twice_z)),"exact worst-case bound")
    ck(distance[key]<distance[1-key], "unambiguous decode")
    ck(guess==key,"false-source key recovered")
    return abs(error)

results=[]
for n in (3,5,7,9):
    for false in (False,True):
        parity=[0]*n
        if false: parity[-1]=1
        A,rhs=build(n,parity)
        w=legal(n,parity)
        ck((len(w)==0)==false,"sat / unsat parity invariant")
        zk=[1]*(3*n) # 2 * fractional local-marginal one-half solution.
        ck(prod(A,zk)==[2*b for b in rhs],"universal fractional mask solves 2b")
        zhalf=[F(1,2)]*(3*n)
        ck(prod(A,zhalf)==[F(b,1) for b in rhs],"fractional correct syndrome")
        ck(sum(x*x for x in zhalf)==F(3*n,4),"fractional l2 norm")
        for bits in w:
            z=witness_vec(n,parity,bits)
            ck(prod(A,z)==rhs,"every honest witness gets same syndrome")
            ck(sum(x*x for x in z)==n+sum(bits),"honest onehot bit norm")
        maximum=0
        for i in range(256):
            k=i%2
            maximum=max(maximum,phase_attack(A,rhs,zk,k))
        results.append({"n":n,"unsatisfiable":false,"valid_witness_count":len(w),
                        "fractional_norm2":f'{sum(x*x for x in zhalf)}',
                        "scaled_vector_nonzero":sum(z!=0 for z in zk),
                        "phase_trials":256,"max_abs_noise":maximum,
                        "phase_bound":ERR*(2+3*n)})
# Exhaustive assignment counts plus real exact phases are finite adversarial checks.
summary={"run":"R156","seed":SEED,"q":Q,"delta":DELTA,"noise_abs_max":ERR,
         "assertions":checks,"results":results,
         "conclusion":"All 1024 tested FALSE phase decryptions succeed, so this candidate is rejected."}
print(json.dumps(summary,indent=2,sort_keys=True))
