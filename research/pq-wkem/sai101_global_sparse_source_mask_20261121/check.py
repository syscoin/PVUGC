#!/usr/bin/env python3
"""Ruling out a concrete *serialized* sparse high-degree Boolean-ideal candidate.
All inputs are synthetic Boolean gate traces, no real Bitcoin or bridge evidence.
Fully public P (expanded polynomial), no private evaluator.
"""
from collections import defaultdict
from hashlib import sha256
import json, random

RNG = random.Random(21112026)
N = 32
FULL = (1<<N)-1

def xor_terms(xs):
    c=set()
    for x in xs:
        if x in c: c.remove(x)
        else: c.add(x)
    return tuple(sorted(c))

def poly_mul(f, mons):
    return xor_terms(a|b for a in f for b in mons)

def ch_constraint(x,y,z,t):
    # f = t XOR z XOR xy XOR xz (exact Boolean Ch relation)
    return xor_terms([1<<t,1<<z,(1<<x)|(1<<y),(1<<x)|(1<<z)])

def evaluate(p, w):
    # vector-valued coefficients
    v=0
    for mon,coef in p.items():
        if mon & w == mon: v ^= coef
    return v

def popcount(a):return a.bit_count()

def build_case(num_gates, n_masks, rng):
    constraints=[xor_terms([0,1])] # f0=1 XOR x0; must set first bit 1
    for j in range(num_gates):
        x,y,z,t=4*j,4*j+1,4*j+2,4*j+3
        constraints.append(ch_constraint(x,y,z,t))
    # N=32 for 8 gates. valid source assignment
    w=1
    for j in range(num_gates):
        x,y,z,t=4*j,4*j+1,4*j+2,4*j+3
        xb=1 if j==0 else rng.randrange(2)
        yb,zb=rng.randrange(2),rng.randrange(2)
        tb=(xb&yb)^((1-xb)&zb)
        for i,b in ((x,xb),(y,yb),(z,zb),(t,tb)):
            if b:w|=1<<i
            else:w &=~(1<<i)
    assert all(sum(1 for mon in f if mon&w==mon)%2==0 for f in constraints)
    K=int.from_bytes(rng.randbytes(32),'big'); S=int.from_bytes(rng.randbytes(32),'big')
    P={0:K}; true_masks=[]
    for j,f in enumerate(constraints):
        masks={0:rng.getrandbits(256)} if j==0 else {}
        for _ in range(n_masks):
            m=0
            used=0
            for a in f:used |= a
            available=[i for i in range(4*num_gates) if not ((1<<i)&used)]
            for i in rng.sample(available, rng.randrange(10,min(24,len(available)))):m |= 1<<i
            masks[m]=rng.getrandbits(256)
        true_masks.append(masks)
        for qmon,b in masks.items():
            for fmon in f:
                target=qmon|fmon
                P[target]=P.get(target,0)^b
                if not P[target]:del P[target]
    assert evaluate(P,w)==K
    return constraints,w,K,S,P,true_masks

def candidate_monoms_from_p(P, constraints):
    # In Boolean quotient, monomial A in f_j*q_{j,C} requires B subset A,
    # and A\\B subset C subset A for some support monomial B in f_j.
    candidates=set()
    for A in P:
        for j,f in enumerate(constraints):
            for B in f:
                if B & A != B: continue
                forced=A&~B
                sub=B
                while True:
                    candidates.add((j,forced|sub))
                    if sub == 0:break
                    sub=(sub-1)&B
    return sorted(candidates)

def extract_key(P, constraints, candidates):
    # equations over vector-valued GF(2)^256: P = K*1 + sum b_(j,C)*f_j*C.
    # Use columns unknown b's as high bits and K as bit zero,
    # eliminate from highest pivot; K becomes an isolated public combination.
    qcols=[]
    for j,C in candidates:
        qcols.append(poly_mul(constraints[j],(C,)))
    all_rows=set(P)
    for col in qcols:all_rows.update(col)
    rowidx={r:i for i,r in enumerate(sorted(all_rows))}
    rows=[0]*len(rowidx);rhs=[0]*len(rowidx)
    for A,v in P.items():rhs[rowidx[A]]=v
    assert 0 in rowidx
    rows[rowidx[0]]=1
    for i,col in enumerate(qcols):
        bit=1<<(i+1)
        for A in col:rows[rowidx[A]]^=bit
    basis={}; isolated=None
    for row,val in zip(rows,rhs):
        while row:
            high=row.bit_length()-1
            if high not in basis:
                basis[high]=(row,val)
                if high==0:isolated=val
                break
            r,v=basis[high];row^=r;val^=v
        if row==0 and val != 0: raise AssertionError('no decomposition: candidate basis incomplete')
    return isolated, len(rowidx),len(qcols),len(basis)

def main():
    out=[]
    for seed in range(8):
        rng=random.Random(44200+seed)
        num_gates=8
        constraints,w,K,S,P,truemasks=build_case(num_gates,3,rng)
        C=candidate_monoms_from_p(P,constraints)
        got,rows,cols,rank=extract_key(P,constraints,C)
        assert got==K
        assert all((j,m) in C for j,mm in enumerate(truemasks) for m in mm)
        assert S==S^K^got
        raw=[(mon,coef) for mon,coef in sorted(P.items())]
        out.append({'seed':seed,'variables':32,'constraints':len(constraints),
            'degree_max':max(x.bit_count() for x in P),
            'capsule_expanded_terms':len(P),'candidate_masks':len(C),
            'linear_equations':rows,'elimination_rank':rank,
            'unobserved_q_supports':sum((j,m) not in C for j,mm in enumerate(truemasks) for m in mm),
            'key_recovers_from_public_coefficients':got==K,
            'naive_constant_coefficient_equals_K':P.get(0,0)==K,
            'public_polynomial_sha256':sha256(json.dumps(raw).encode()).hexdigest()})
    print(json.dumps({'scope':'synthetic Boolean Ch gate constraints; arbitrary-degree sparse expanded Boolean-ideal compiler, NOT authentic source or QPT','results':out},sort_keys=True,indent=2))
if __name__=='__main__':main()
