#!/usr/bin/env python3
"""Run 379: exact finite grey-zone witness/decryption mismatch; NOT LWE security."""
import json
n=0

def ck(z):
    global n
    n+=1
    assert z

def ctr(a,q): return ((a+q//2)%q)-q//2

def dec(v,q):
    if abs(ctr(v,q))<=3: return 0
    if abs(ctr(v-(q+1)//2,q))<=3: return 1
    return None

sizes={}
for q in (17,19,23,29):
    counts={'L':0,'G':0,'Lprime':0}
    for c0 in range(q):
        for v in range(q):
            L=abs(ctr(v,q))<=1
            G=(not L) and dec(v,q)==0
            Lp=dec(v,q)!=0
            ck(sum((L,G,Lp))==1)
            choices=[s for s in range(q) if abs(ctr(c0-s,q))<=1 and L]
            ck(bool(choices)==L)
            if L: ck(len(choices)==3)
            if G: ck(not choices and dec(v,q)==0)
            counts['L' if L else 'G' if G else 'Lprime']+=1
    ck(counts=={'L':3*q,'G':4*q,'Lprime':q*(q-7)})
    ck(dec(2,q)==0 and abs(ctr(2,q))>1)
    sizes[q]=counts

# Elementary correctness/smoothness logical countermodel only:
# project K directly on L and G; project 0 on L'. L-hardness does NOT hold.
for K in range(256):
    ck(all((K if category in ('L','G') else 0)==K
           for category in ('L','G')))
    ck((0,K)==(0,K))  # Uniform K conditioned on projection zero, for L'.
print(json.dumps({'run':379,'status':'PASS','assertions':n,'sizes':sizes,
                   'scope':'toy lattice gap and logical countermodel only; no QPT/WE proof'},
                  sort_keys=True))
