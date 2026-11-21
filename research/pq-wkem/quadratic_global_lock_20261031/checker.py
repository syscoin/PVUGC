"""QGL exact finite-field regression; deterministic toy, no PQ claim."""
import json, random, hashlib
from itertools import combinations_with_replacement
q=65537; rng=random.Random(0x51474C20261031)
def f(w):
 x,y,u,v,z=w
 return [a*(a-1)%q for a in w]+[(u-1+x*y)%q,(v-1+u*x)%q,(z-1+v*y)%q,z]
def feat(w,degree):
 a=f(w)
 return a if degree==1 else a+[a[i]*a[j]%q for i,j in combinations_with_replacement(range(9),2)]
def solve(rows,target):
 n=len(rows); m=len(target)
 a=[[rows[j][i] for j in range(n)]+[target[i]] for i in range(m)]
 piv=[]; k=0
 for j in range(n):
  h=next((r for r in range(k,m) if a[r][j]%q),None)
  if h is None: continue
  a[k],a[h]=a[h],a[k]; z=pow(a[k][j],-1,q)
  a[k]=[v*z%q for v in a[k]]
  for r in range(m):
   if r!=k:
    t=a[r][j]; a[r]=[(v-t*b)%q for v,b in zip(a[r],a[k])]
  piv.append(j); k+=1
  if k==m: break
 if any(a[r][-1] for r in range(k,m)): return None
 lam=[0]*n
 for r,j in enumerate(piv):lam[j]=a[r][-1]
 return lam
W=[(0,1,1,1,0),(1,1,0,1,0)]
assert all(f(w)==[0]*9 for w in W)
P=[tuple(rng.randrange(q) for _ in range(5)) for _ in range(180)]
assert all(any(f(w)) for w in P)
K=bytes(rng.randrange(256) for _ in range(32)); results={}
for deg in (1,2):
 rows=[(1,*feat(w,deg)) for w in P]
 lam=solve(rows,[1]+[0]*(len(rows[0])-1)); assert lam is not None
 assert all(sum(lam[j]*rows[j][i] for j in range(180))%q==(i==0) for i in range(len(rows[0])))
 used=sum(bool(a) for a in lam)
 for capsule in range(2):
  for byte in K:
   masks=[rng.randrange(q) for _ in range(len(rows[0])-1)]; noise=rng.randint(-10,10)
   raw=[(100*byte+noise+sum(m*a for m,a in zip(masks,row[1:])))%q for row in rows]
   recovered=sum(lam[i]*raw[i] for i in range(180))%q
   assert recovered==100*byte+noise and (recovered+50)//100==byte
   assert all((100*byte+noise+sum(m*a for m,a in zip(masks,feat(w,deg))))%q==recovered for w in W)
 results[str(deg)]={'feature_count':len(rows[0])-1,'nonzero_coefficients':used,'recovered_bytes':64,'valid_witness_queries':0}
print(json.dumps({'result':'negative; unauthorized TRUE capability recovery','q':q,'original_witness_count':len(W),'key_sha256':hashlib.sha256(K).hexdigest(),'capsules':2,'results':results},sort_keys=True))
