#!/usr/bin/env python3
"""Offline check: ORIGINAL NAND kernel compiler and its false-SOURCE bypass.
Algebra only; NOT a QPT security or native signature test.
"""
from itertools import product
from fractions import Fraction
from random import Random
from math import ceil, log2
from collections import Counter
import json
q=257;checks=0

def ck(b):
    global checks
    assert b
    checks+=1

def build(gates,inputs,public=()):
    v=inputs+len(gates);m=1+2*v+4*len(gates)
    rows=[]
    def row(terms):
        t=[0]*m
        for i,a in terms:t[i]+=a
        rows.append(t)
    u=lambda i,b:1+2*i+b
    t=lambda g,k:1+2*v+4*g+k
    for i in range(v):row([(u(i,0),1),(u(i,1),1),(0,-1)])
    for j,(a,b) in enumerate(gates):
        out=inputs+j
        row([(t(j,k),1) for k in range(4)]+[(0,-1)])
        row([(t(j,2),1),(t(j,3),1),(u(a,1),-1)])
        row([(t(j,1),1),(t(j,3),1),(u(b,1),-1)])
        row([(t(j,0),1),(t(j,1),1),(t(j,2),1),(u(out,1),-1)])
    for i,b in enumerate(public):row([(u(i,1),1),(0,-b)])
    row([(u(v-1,1),1),(0,-1)])
    return v,m,rows

def eval_bits(gates,bits):
    bits=list(bits)
    for a,b in gates:bits.append(1-bits[a]*bits[b])
    return bits

def lift(gates,inputs,bits):
    wire=eval_bits(gates,bits)
    if wire[-1]!=1:return None
    v=len(wire);w=[0]*(1+2*v+4*len(gates));w[0]=1
    for i,b in enumerate(wire):w[1+2*i+b]=1
    for j,(a,b) in enumerate(gates):w[1+2*v+4*j+2*wire[a]+wire[b]]=1
    return w

def accepted(rows,w,h):
    return w[0]==1 and all(a in (0,1) for a in w) and sum(w)==h and all(
        sum(a*b for a,b in zip(row,w))%q==0 for row in rows)

true_g=((0,1),);false_g=((0,0),(0,1),(2,2))
result={}
for name,gates,n in [('true',true_g,2),('false',false_g,1)]:
    v,m,rows=build(gates,n);h=1+v+len(gates)
    intended=[lift(gates,n,bits) for bits in product((0,1),repeat=n)]
    intended=[w for w in intended if w is not None]
    for w in intended:ck(accepted(rows,w,h))
    all_accepted=[]
    for wire in product((0,1),repeat=v):
        for ts in product(range(4),repeat=len(gates)):
            w=[0]*m;w[0]=1
            for i,b in enumerate(wire):w[1+2*i+b]=1
            for j,k in enumerate(ts):w[1+2*v+4*j+k]=1
            if accepted(rows,w,h):all_accepted.append(w)
            checks+=1
    ck(sorted(all_accepted)==sorted(intended))
    result[name]={'accepted_original_witnesses':len(intended),'m':m,'r':len(rows),'h':h}

# False circuit: force last output to 1; use signed truth-table interpolation.
v,m,rows=build(false_g,1);wire=eval_bits(false_g,(0,));ck(wire[-1]==0)
wire[-1]=1;z=[0]*m;z[0]=1
for i,b in enumerate(wire):z[1+2*i+b]=1
for j,(a,b) in enumerate(false_g):
    A,B,Y=wire[a],wire[b],wire[1+j]
    for k,val in enumerate((2-A-B-Y,B+Y-1,A+Y-1,1-Y)):
        z[1+2*v+4*j+k]=val
ck(sum(abs(a) for a in z)==10)
ck(all(sum(a*b for a,b in zip(row,z))%q==0 for row in rows))
ck(not accepted(rows,z,8))
noise=Counter({0:1})
for _ in range(10):
    nxt=Counter()
    for v,n in noise.items():
        for a in (-1,0,1):nxt[v+a]+=n
    noise=nxt
ck(sum(noise.values())==59049)
ck(sum(n for v,n in noise.items() if abs(v)<=8)==59027)
chance=Fraction(59027,59049)**66
ck(Fraction(97,100)<chance<Fraction(98,100))

rng=Random(20261028)
v,m,rows=build(true_g,2);h=5;g0=2*h+1;base=q//g0;ell=ceil(256/log2(base))
ws=[lift(true_g,2,b) for b in product((0,1),repeat=2)]
ws=[w for w in ws if w is not None]
ck(len(ws)==3 and ell==57)
for _ in range(16):
    K=rng.randbytes(32);U=rng.randbytes(32);Z=rng.randbytes(32)
    D=bytes(a^b for a,b in zip(U,Z));V=bytes(a^b for a,b in zip(K,U))
    zint=int.from_bytes(Z,'big');cols=[]
    for _ in range(ell):
        a=zint%base;zint//=base
        y=[rng.randrange(q) for _ in rows]
        eps=[rng.choice((-1,0,1)) for _ in range(m)]
        cols.append([(sum(row[i]*y[j] for j,row in enumerate(rows))+eps[i]+(g0*a if i==0 else 0))%q for i in range(m)])
    ck(zint==0)
    for w in ws:
        digits=[]
        for p in cols:
            ph=sum(a*b for a,b in zip(w,p))%q
            options=[d for d in range(base) if min((ph-g0*d)%q,(g0*d-ph)%q)<=h]
            ck(len(options)==1)
            digits+=options
        zrec=sum(a*base**i for i,a in enumerate(digits)).to_bytes(32,'big')
        Krec=bytes(a^b^c for a,b,c in zip(D,V,zrec))
        ck(Krec==K)
print(json.dumps({'status':'PASS','checks':checks,'original_cases':result,
 'same_K_full_seed_trials':16,'different_valid_witnesses':3,
 'false_attack_probability':round(float(chance),12),
 'false_source_insecure':True,'QPT_security_claim':False},sort_keys=True))
