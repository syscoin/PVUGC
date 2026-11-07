#!/usr/bin/env python3
"""Exact finite-field Run 610 checker; toy, NOT a PQ security proof."""
import json
from itertools import product
q=17
A=((2,3,5,7),(5,7,12,4))
W=list(product((-1,0,1),repeat=4))
def dot(a,b): return sum(x*y for x,y in zip(a,b))%q
def aw(w): return tuple(dot(row,w) for row in A)
def proj(s): return tuple(dot((A[0][j],A[1][j]),s) for j in range(4))
def cap(s,y,k): return proj(s),(k+dot(s,y))%q
def recover(C,w): return (C[1]-dot(C[0],w))%q
def solve(y):
    # First two columns form an invertible square minor with det=-1 mod 17.
    a,b=A[0][:2]; c,d=A[1][:2]
    det=(a*d-b*c)%q
    z=((d*y[0]-b*y[1])*pow(det,-1,q)%q,
       (-c*y[0]+a*y[1])*pow(det,-1,q)%q,0,0)
    assert aw(z)==y
    return z
Y={aw(w) for w in W}
assert len(Y)==57
true_y=(5,12)
true_ws=[w for w in W if aw(w)==true_y]
assert len(true_ws)==2
checks=0
for s in product(range(q),repeat=2):
    for w in true_ws:
        assert recover(cap(s,true_y,6),w)==6
        checks+=1
false_ys=[y for y in product(range(q),repeat=2) if y not in Y]
assert len(false_ys)==232
for y in false_ys:
    z=solve(y)
    assert z not in W
    for s in product(range(q),repeat=2):
        assert recover(cap(s,y,6),z)==6
        checks+=1
fy=false_ys[0]
assert fy==(0,1)
assert solve(fy)==(3,15,0,0)
for s in product(range(q),repeat=2):
    assert cap(s,fy,6)!=cap(s,fy,12)
    checks+=1
w0,w1=true_ws
agreements=sum(dot(e,w0)==dot(e,w1)
               for e in product((-1,0,1),repeat=4))
assert agreements==21
print(json.dumps({"run":610,"q":q,"short_images":len(Y),
 "false_source_statements":len(false_ys),
 "true_original_witnesses":len(true_ws),
 "all_valid_witness_checks":289*len(true_ws),
 "false_source_recovery_checks":len(false_ys)*289,
 "keyed_transcripts_distinguished":289,
 "raw_noise_agreement":"21/81",
 "verified_assertions":checks,
 "scope":"exact toy falsifier only; not PQ/native Bitcoin"},
 indent=2,sort_keys=True))
