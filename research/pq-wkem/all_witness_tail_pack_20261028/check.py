#!/usr/bin/env python3
"""Exact offline arithmetic checks; no cryptographic security claims."""
import itertools
import json
from math import comb
q,d,n,h,E,bits=65537,256,4240,2120,727,256
g=2*E+1
m=q//g
ell=47
N=comb(n-1,h-1)
assert m==45 and m**46<2**bits<=m**47
assert q-(m-1)*g>=g
assert N>q**d*2**136
num=2*ell*N*31**h*4**(E+1)
den=q**d*28**h*7**(E+1)
assert num*2**133<den
assert num*2**(132+136)<den*(2**136-1)
# Exhaustive small-source check of the pairwise-independence premise.
qt,nt,ht=3,6,3
subs=list(itertools.combinations(range(1,nt),ht-1))
counts=[0]*len(subs)
pairs=[[0]*len(subs) for _ in subs]
for row in itertools.product(range(qt),repeat=nt):
    valid=[(row[0]+sum(row[i] for i in s))%qt==0 for s in subs]
    for i,vi in enumerate(valid):
        counts[i]+=vi
        for j,vj in enumerate(valid):
            pairs[i][j]+=vi and vj
assert all(x==qt**(nt-1) for x in counts)
assert all(pairs[i][j]==qt**(nt-2) for i in range(len(subs)) for j in range(i+1,len(subs)))
# Deterministic correctness on the all-witness good event.
B=(1,100,100,7,9)
ws=((1,1,0,0,0),(1,0,1,0,0))
for w in ws:
    assert sum(x*y for x,y in zip(B,w))%101==0
for eps in itertools.product((-1,0,1),repeat=5):
    if any(abs(sum(x*y for x,y in zip(w,eps)))>1 for w in ws):
        continue
    for digit in range(3):
        p=[(7*b+e+(3*digit if i==0 else 0))%101 for i,(b,e) in enumerate(zip(B,eps))]
        for w in ws:
            observed=sum(x*y for x,y in zip(w,p))%101
            assert min((observed-3*digit)%101,(3*digit-observed)%101)<=1
print(json.dumps({"status":"PASS","q":q,"n":n,"h":h,"radix":m,"columns":ell,"false_lt_2^-136":True,"all_witness_bad_lt_2^-133":True,"conditional_true_bad_lt_2^-132":True,"toy_pairwise_events":len(subs)*(len(subs)-1)//2},sort_keys=True))
