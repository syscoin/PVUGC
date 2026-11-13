# Run 441 exact S3 overlay/refresh test. Stdlib only; not a WKEM.
from itertools import permutations, product
from collections import Counter
from hashlib import sha256
import json
P=list(permutations(range(3)))
I=(0,1,2); C=(1,2,0)
def mul(a,b): return tuple(a[b[i]] for i in range(3))
def inv(a): return tuple(a.index(i) for i in range(3))
def gate(u,v,t): return mul(v,mul(t,inv(u)))
def table(bit,mode):
    out=Counter(); t=C if bit else I
    for u,v in product(P,repeat=2):
        if mode=='shared': out[(gate(u,v,I),gate(u,v,t))]+=1
        if mode=='input':
            for v1 in P: out[(gate(u,v,I),gate(u,v1,t))]+=1
        if mode=='output':
            for u1 in P: out[(gate(u,v,I),gate(u1,v,t))]+=1
        if mode=='fresh':
            for u1,v1 in product(P,repeat=2): out[(gate(u,v,I),gate(u1,v1,t))]+=1
    return out
R={}; checks=0
for mode in ['shared','input','output','fresh']:
    a,b=table(0,mode),table(1,mode)
    for bit,x in [(0,a),(1,b)]:
        total=sum(x.values()); assert total=={'shared':36,'input':216,'output':216,'fresh':1296}[mode];checks+=1
        for j in [0,1]:
            h=Counter()
            for pair,n in x.items(): h[pair[j]]+=n
            assert len(h)==6 and set(h.values())=={total//6};checks+=1
    if mode=='shared':
        assert a.keys().isdisjoint(b.keys());checks+=1
        assert (len(a),set(a.values()),len(b),set(b.values()))==(6,{6},12,{3});checks+=1
    else:
        assert a==b and len(a)==36;checks+=1
    R[mode]={'bit0_support':len(a),'bit1_support':len(b)}
# This subgroup has faithful genuinely nonlinear three-bit reversible gates.
g=[1,2,0,3,4,5,6,7]
assert any(g[x^y]!=(g[x]^g[y]^g[0]) for x in range(8) for y in range(8));checks+=1
key=sha256(b'run441/min/no-real-key').digest(); recovered=[]
for bit in [(z>>j)&1 for z in key for j in range(8)]:
    u,v=P[(len(recovered)*7+1)%6],P[(len(recovered)*5+3)%6]
    g0,g1=gate(u,v,I),gate(u,v,C if bit else I)
    d=mul(inv(g0),g1)
    recovered.append(0 if d==I else 1)
assert recovered==[(z>>j)&1 for z in key for j in range(8)];checks+=1
print(json.dumps({'run':441,'assertions':checks,'supports':R,'recovered_diagnostic_bits':len(recovered),'scope':'finite algebra, no WE, no QPT hiding'},sort_keys=True))
