#!/usr/bin/env python3
import itertools,json,math
from fractions import Fraction
A=0
def ck(x,m='fail'):
 global A; A+=1
 if not x: raise AssertionError(m)
def mv(M,v,q): return [sum(a*b for a,b in zip(r,v))%q for r in M]
def mats(q,t,m):
 for f in itertools.product(range(q),repeat=t*m): yield [list(f[i*m:(i+1)*m]) for i in range(t)]
def rk(M,q):
 M=[[x%q for x in r] for r in M]; R=len(M); C=len(M[0]) if R else 0; k=0
 for c in range(C):
  p=next((i for i in range(k,R) if M[i][c]),None)
  if p is None: continue
  M[k],M[p]=M[p],M[k]; z=pow(M[k][c],-1,q); M[k]=[(x*z)%q for x in M[k]]
  for i in range(R):
   if i!=k and M[i][c]:
    z=M[i][c]; M[i]=[(x-z*y)%q for x,y in zip(M[i],M[k])]
  k+=1
 return k
def fullprob(q,t,d):
 if t<d:return Fraction(0,1)
 p=Fraction(1,1)
 for i in range(d):p*=Fraction(q**t-q**i,q**t)
 return p
# fixed-vector annihilation q^-t
for q,m,t in [(2,3,1),(2,3,2),(3,2,1),(3,2,2)]:
 v=(1,)+(0,)*(m-1); X=list(mats(q,t,m)); b=sum(not any(mv(S,v,q)) for S in X); ck(Fraction(b,len(X))==Fraction(1,q**t))
# exact subspace/full-column-rank law and deterministic t<d obstruction
cases=[(2,1,1),(2,2,1),(2,2,2),(2,2,3),(2,3,2),(2,3,3),(2,3,4),(3,1,1),(3,2,1),(3,2,2),(3,2,3)]
for q,d,t in cases:
 X=list(mats(q,t,d)); f=sum(rk(S,q)==d for S in X); ck(Fraction(f,len(X))==fullprob(q,t,d))
 if t<d:
  V=[v for v in itertools.product(range(q),repeat=d) if any(v)]
  for S in X: ck(any(not any(mv(S,v,q)) for v in V))
# Run-258 false CSP: x0=0,x1=1,x0=x1 over F5
q=5; R=[]
for x0,x1 in itertools.product([0,1],repeat=2):
 r=(x0%q,(x1-1)%q,(x0-x1)%q); ck(any(r)); R.append(r)
fold=[]
for t in [1,2,3]:
 X=mats(q,t,3); total=bad=0
 for S in X:
  total+=1; bad+=any(not any(mv(S,r,q)) for r in R)
 p=Fraction(bad,total); ub=Fraction(4,q**t); ck(p<=ub); fold.append([t,bad,total,ub.numerator,ub.denominator])
# Ajtai/SIS collision identity toy: any binary collision gives short kernel difference
q=3; M=[[1,1,1,1]]; E=list(itertools.product([0,1],repeat=4)); target=pair=0
for c in E:
 if c!=(0,0,0,0) and mv(M,c,q)==[0]:
  target+=1; ck(any(c)); ck(not any(mv(M,c,q))); ck(sum(x*x for x in c)<=4)
for i,c in enumerate(E):
 for d in E[i+1:]:
  if mv(M,c,q)==mv(M,d,q):
   pair+=1; e=tuple(x-y for x,y in zip(c,d)); ck(any(e)); ck(not any(mv(M,e,q))); ck(sum(x*x for x in e)<=4)
ck(target==4);ck(pair==35)
# residual-only valid path is public constant
P=37; q=257; ev=lambda r:(P*sum((i+1)*x for i,x in enumerate(r))+123)%q
for _ in range(32):ck(ev((0,0,0,0))==123)
# finite parameter arithmetic for 2^N q^-t <= 2^-128 at q=12289
q=12289; lg=math.log2(q); ts={}
for N in [64,256,1024,4096,16384]:
 t=math.ceil((N+128)/lg); ck(t*lg-N>=128-1e-12); ts[str(N)]=t
print(json.dumps({'status':'PASS','assertions':A,'fixed_vector_cases':4,'rank_cases':len(cases),'largest_exhaustive_matrix_count':1953125,'run258_folding':fold,'sis_target_collisions':target,'sis_pair_collisions':pair,'q12289_k128_fold_rows':ts},sort_keys=True,indent=2))
