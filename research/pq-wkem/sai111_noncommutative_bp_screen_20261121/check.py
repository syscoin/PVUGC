#!/usr/bin/env python3
"""Noncommuting contradictory-literal screen; not FE/source proof."""
import json
def compose(p,q): return tuple(p[q[i]] for i in range(5))
def inv(p): return tuple(p.index(i) for i in range(5))
I=tuple(range(5))
def cyc(a,b,c):
 p=list(I); p[a],p[b],p[c]=b,c,a; return tuple(p)
a=cyc(0,1,2); b=cyc(0,1,3)
def word(first,second):
 A=a if first==0 else I
 B=b if second==1 else I
 return compose(compose(compose(A,B),inv(A)),inv(B))
assert word(0,0)==I and word(1,1)==I
assert word(0,1)!=I
print(json.dumps({"all_consistent_values_false":[word(0,0)==I,word(1,1)==I],"mixed_occurrences_accept":word(0,1)!=I,"commutator":word(0,1)},sort_keys=True))
