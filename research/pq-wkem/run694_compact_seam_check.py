"""Run 694: exact finite affine-seam attack, not a PQ proof."""
import json
from itertools import product, permutations
I=tuple(range(8))
def cp(p,q): return tuple(p[q[i]] for i in I)
def iv(p):
 v=[0]*8
 for i,j in enumerate(p): v[j]=i
 return tuple(v)
def af(rows,b): return tuple(sum((((x&r).bit_count()&1)<<i) for i,r in enumerate(rows))^b for x in I)
H=[af(r,b) for r in product(range(8),repeat=3) if len(set(af(r,0)))==8 for b in I]
def der(p,u,v): return p[0]^p[u]^p[v]^p[u^v]
def affine(p): return all(der(p,u,v)==0 for u in I for v in I)
TA=tuple(x^(4 if x&3==3 else 0) for x in I)
TB=tuple(x^(2 if x&5==5 else 0) for x in I)
S=tuple((x&1)|((x&2)<<1)|((x&4)>>1) for x in I)
checks=0
def ck(v):
 global checks
 assert v
 checks+=1
ck(len(H)==1344)
ck(cp(S,cp(TA,S))==TB)
ck(cp(TA,TA)==I and cp(TB,TB)==I)
W0=(TA,TA,TB,TB)
W1=(TA,TB,TB,TA)
for W in (W0,W1):
 f=I
 for gate in W: f=cp(gate,f)
 ck(f==I)
 ck(all(not affine(gate) for gate in W))
P0=cp(W0[1],W0[0]); P1=cp(W1[1],W1[0])
ck(affine(P0) and not affine(P1))
ck(sum(der(P0,u,v)!=0 for u in I for v in I)==0)
ck(sum(der(P1,u,v)!=0 for u in I for v in I)==36)
for A in H:
 ck(affine(cp(A,P0)))
 ck(not affine(cp(A,P1)))
# The two hidden sequences have the same total public function but
# opposite exposed two-gate affine-class membership, for every H-frame.
print(json.dumps({"run":694,"affine_frames":len(H),"single_gate_class":"quadratic Toffoli in both worlds","whole_unmixed_function":"identity","seam_derivative_counts":[0,36],"detection_probability":"9/16","miss_probability_t":"(7/16)^t","checks":checks},sort_keys=True,indent=2))
