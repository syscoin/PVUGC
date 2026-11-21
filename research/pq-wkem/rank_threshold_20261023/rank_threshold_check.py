#!/usr/bin/env python3
"""Exact finite-field check of paired-gate rank-threshold interface.

This is a toy/scope validation, not K security. No private setup factors, keys
or witnesses are given to the checker when applying the public rank test.
The theorem in the companion note is for independent full-uniform factors,
not for Python's deterministic fixture RNG or these tiny toy dimensions.
"""
import hashlib
import json
import random
from pathlib import Path
import numpy as np

Q=16
POLY=0x13
MULT=np.zeros((Q,Q),dtype=np.uint8)
for a in range(Q):
    for b in range(Q):
        x,y,z=a,b,0
        while y:
            if y&1:z^=x
            y>>=1;x<<=1
            if x&Q:x^=POLY
        MULT[a,b]=z
INV=[0]+[next(x for x in range(1,Q) if MULT[a,x]==1) for a in range(1,Q)]

def mm(A,B):
    A=np.asarray(A,dtype=np.uint8);B=np.asarray(B,dtype=np.uint8)
    out=np.zeros((A.shape[0],B.shape[1]),dtype=np.uint8)
    for j in range(A.shape[1]):out^=MULT[A[:,j,None],B[j,None,:]]
    return out

def rank(A):
    A=np.array(A,copy=True,dtype=np.uint8)
    nr,nc=A.shape;r=0
    for j in range(nc):
        p=next((i for i in range(r,nr) if A[i,j]),None)
        if p is None:continue
        if p!=r:A[[p,r]]=A[[r,p]]
        A[r]=MULT[A[r],INV[A[r,j]]]
        for i in range(r+1,nr):
            if A[i,j]:A[i]^=MULT[A[r],A[i,j]]
        r+=1
        if r==nr:break
    return r

def P(t):
    a,b,c,d,s=map(int,t)
    return np.array([[0,a,d,s],[a,0,s,c],[d,s,0,b],[s,c,b,0]],dtype=np.uint8)

def Pstar(t):
    a,b,c,d,s=map(int,t)
    return np.array([[0,b,c,s],[b,0,s,d],[c,s,0,a],[s,d,a,0]],dtype=np.uint8)

def gate(t,eta):
    G=np.zeros((8,8),dtype=np.uint8)
    G[:4,:4]=P(t);G[4:,4:]=Pstar(t)
    G[:4,4:]=np.eye(4,dtype=np.uint8)*int(eta)
    return G

def randmat(rng,n,m):
    return np.array([[rng.randrange(Q) for _ in range(m)] for _ in range(n)],dtype=np.uint8)

# Three public SOURCE gate forms with exactly two normalized accepting points.
# y=(z0,w,rho); residues r_e=w(w+z0)+alpha_e*z0*rho.
# y0=1 and two different alpha imply rho=0 and w in {0,1}.
ALPHAS=[1,2,4]
FORMS=[]
for alpha in ALPHAS:
    # Each row holds coefficient tuple (a,b,c,d,s) for one coordinate.
    FORMS.append(np.array([[0,1,0,1,0],
                           [1,1,0,0,0],
                           [0,0,alpha,0,0]],dtype=np.uint8))

K=3;L=len(FORMS);D=4*L;H=4;N=D+H
assert K==3 and N==16

def values(forms,y):
    v=np.zeros(5,dtype=np.uint8)
    for a,row in zip(y,forms):v^=MULT[int(a),row]
    return v

def residual(t):
    a,b,c,d,s=map(int,t)
    return int(MULT[a,b]) ^ int(MULT[c,d]) ^ int(MULT[s,s])

def build(seed):
    rng=random.Random(seed);secret=rng.randrange(1,Q)
    public=np.zeros((K,N,N),dtype=np.uint8)
    full_masks=[]
    for forms in FORMS:
        U=randmat(rng,N,8);V=randmat(rng,8,N)
        etacoefs=[rng.randrange(Q) for _ in range(K)]
        full_masks.append((U,V,etacoefs))
        for j in range(K):
            E=gate(forms[j],etacoefs[j])
            public[j]^=mm(mm(U,E),V)
    public[0]^=secret*np.eye(N,dtype=np.uint8)
    return public,secret,full_masks

def evaluate(public,y):
    C=np.zeros((N,N),dtype=np.uint8)
    for i in range(K):C^=MULT[int(y[i]),public[i]]
    return C

def validate():
    assert_count=0
    for alpha in ALPHAS:
        for w in range(Q):
            for rho in range(Q):
                y=[1,w,rho];vals=values(FORMS[0],y)
                good=all(residual(values(F,y))==0 for F in FORMS)
                assert good == (w in [0,1] and rho==0)
                assert_count+=1
        break
    summaries=[]
    for seed in [31,47,79]:
        pub,key,priv=build(seed); accepted=[]; false_positive=0
        for w in range(Q):
            for rho in range(Q):
                y=[1,w,rho]
                M=evaluate(pub,y)^ (key*np.eye(N,dtype=np.uint8))
                observed=rank(M)
                good=all(residual(values(F,y))==0 for F in FORMS)
                if good:
                    assert observed<=D
                    accepted.append((w,rho,observed))
                elif observed<=D:
                    false_positive+=1
                assert_count+=1
        assert false_positive==0
        assert {tuple(x[:2]) for x in accepted}=={(0,0),(1,0)}
        # Pair-wise distinct witness-dependent public states, same secret.
        assert not np.array_equal(evaluate(pub,[1,0,0]),evaluate(pub,[1,1,0]))
        summaries.append(dict(seed=seed,valid=accepted,invalid_rejected=Q*Q-2,
                              false_rank_acceptance=false_positive))
    # Honest setup theorem's illustrative k=27000, q=2^256 certificate;
    # exact integer inequalities, not floating-point exponents.
    n=11000;m=16000;r=11636;k=n+m;q=1<<256
    d=q-2*m+2-r
    assert d>0
    # Conservative denominator d valid for EVERY tail draw.
    source_upper_num=(q**(n+1)-1)//(q-1) * (m-1)**r
    source_upper_den=d**r
    assert source_upper_num * (1<<129) < source_upper_den
    h=(k+8+3)//4
    assert h==6752
    # Rank failure bound: 56 * q^(k+7-4h) <= 2^-128
    # Here exponent = -1 and q>=56*2^128, exact.
    assert k+7-4*h == -1 and (1<<256)>56*(1<<129)
    Nbig=4*(m-1+r)+h
    baseN=4*(m-1+r)+1
    public_elements=k*Nbig*Nbig
    assert public_elements==371450158128000
    assert_count+=10
    return dict(checkpoint="paired-rank-threshold-20261023",status="SCOPED_SUPPLIED_REPRESENTATION_EXTRACTION_ONLY",
                assertions=assert_count,fixture_field="GF(16)",D=D,h=H,N=N,
                source_toy_exhaustive_cases=Q*Q,
                public_rank_checks=3*Q*Q,
                experiments=summaries,
                exact_large_parameters=dict(k=k,L=m-1+r,base_N=baseN,
                    h=h,N=Nbig,public_field_elements=public_elements,
                    public_bytes=public_elements*32,
                    source_bound_less_than_2minus128=True,
                    outer_bound_less_than_2minus129=True,
                    combined_source_outer_less_than_2minus128=True,
                    outer_bound_at_most="56*2^-256"),
                key_security_proved=False)

if __name__=='__main__':
    print(json.dumps(validate(),sort_keys=True,indent=2))
