#!/usr/bin/env python3
"""R218 public source-constraint polynomial-pad attack; abstract Boolean gate, not SHA/AuxPoW."""
import itertools, json, random
q=257
mons=[e for e in itertools.product(range(4),repeat=3) if sum(e)<=3]
mons.sort(key=lambda e:(sum(e),e))
z=(0,0,0)
units=[tuple(int(i==j) for i in range(3)) for j in range(3)]

def add(*xs):
    d={}
    for p in xs:
        for m,v in p.items():d[m]=(d.get(m,0)+v)%q
    return {k:v for k,v in d.items() if v}
def scl(a,c):return {k:v*c%q for k,v in a.items() if v*c%q}
def mul(a,b):
    d={}
    for x,v in a.items():
        for y,w in b.items():
            m=tuple(i+j for i,j in zip(x,y));assert sum(m)<=3
            d[m]=(d.get(m,0)+v*w)%q
    return {k:v for k,v in d.items() if v}
def V(a):return [a.get(m,0) for m in mons]
def dot(a,b):return sum(x*y for x,y in zip(a,b))%q

one={z:1};a,b,t=[{e:1} for e in units]
C=[add(mul(x,x),scl(x,-1)) for x in (a,b,t)]
C+=[add(t,scl(a,-1),scl(b,-1),mul(a,b)),add(t,scl(one,-1))]
B=[mul(c,m) for c in C for m in (one,a,b,t)]
# Solve lambda(B)=0 and lambda(1)=1 using only PUBLIC constraints.
mat=[V(c)+[0] for c in B]+[V(one)+[1]]
rank=0;pivots=[]
for col in range(len(mons)):
    j=next((k for k in range(rank,len(mat)) if mat[k][col]),None)
    if j is None:continue
    mat[rank],mat[j]=mat[j],mat[rank]
    inv=pow(mat[rank][col],-1,q)
    mat[rank]=[x*inv%q for x in mat[rank]]
    for k in range(len(mat)):
        if k!=rank and mat[k][col]:
            f=mat[k][col];mat[k]=[(x-f*y)%q for x,y in zip(mat[k],mat[rank])]
    pivots.append(col);rank+=1
    if rank==len(mat):break
assert all(any(row[:-1]) or row[-1]==0 for row in mat)
L=[0]*len(mons)
for i,col in enumerate(pivots):L[col]=mat[i][-1]
assert dot(L,V(one))==1 and all(dot(L,V(c))==0 for c in B)
valid=[(x,y,int(x or y)) for x,y in itertools.product((0,1),repeat=2) if x or y]
assert len(valid)==3
rng=random.Random(218)
for _ in range(100):
    K=rng.randrange(q);p=scl(one,K)
    for c in C:
        mask=add(*(scl(m,rng.randrange(q)) for m in (one,a,b,t)))
        p=add(p,mul(c,mask))
    assert dot(L,V(p))==K    # NO original witness provided to this attacker
    for w in valid:
        assert sum(v*__import__('math').prod(w[i]**m[i] for i in range(3)) for m,v in p.items())%q==K
print(json.dumps({'run':'R218-repro','field':q,'dimension':len(mons),
 'public_mask_generators':len(B),'projection_rank':rank,'valid_witnesses':3,
 'trials':100,'correct_openings':300,'unauthorized_public_recoveries':100,
 'scope':'toy Boolean OR gate; no real SHA/AuxPoW or QPT experiment'},sort_keys=True,indent=2))
