#!/usr/bin/env python3
from collections import Counter
from fractions import Fraction
from itertools import product
import json, random
SEED=510051002; R=random.Random(SEED)
def inv(a,q):return pow(a%q,q-2,q)
def add(a,b,q):return tuple((x+y)%q for x,y in zip(a,b))
def dot(a,b,q):return sum(x*y for x,y in zip(a,b))%q
def basis(rows,q):
 A=[list(x%q for x in r) for r in rows if any(x%q for x in r)]
 if not A:return []
 m,n=len(A),len(A[0]); rr=0
 for c in range(n):
  p=next((i for i in range(rr,m) if A[i][c]),None)
  if p is None:continue
  A[rr],A[p]=A[p],A[rr]; z=inv(A[rr][c],q); A[rr]=[z*x%q for x in A[rr]]
  for i in range(m):
   if i!=rr and A[i][c]:z=A[i][c]; A[i]=[(x-z*y)%q for x,y in zip(A[i],A[rr])]
  rr+=1
  if rr==m:break
 return [tuple(x) for x in A[:rr]]
def insp(v,V,q):
 B=basis(V,q); return len(basis(B+[v],q))==len(B)
def span(V,q,d):
 B=basis(V,q)
 if not B:return [(0,)*d]
 out=[]
 for cs in product(range(q),repeat=len(B)):
  v=[0]*d
  for c,b in zip(cs,B):
   for i,x in enumerate(b):v[i]=(v[i]+c*x)%q
  out.append(tuple(v))
 return out
def solve(M,y,q):
 A=[list(r)+[b] for r,b in zip(M,y)]; m=len(A); n=len(A[0])-1; rr=0; piv=[]
 for c in range(n):
  p=next((i for i in range(rr,m) if A[i][c]%q),None)
  if p is None:continue
  A[rr],A[p]=A[p],A[rr]; z=inv(A[rr][c],q); A[rr]=[z*x%q for x in A[rr]]
  for i in range(m):
   if i!=rr and A[i][c]%q:z=A[i][c]%q; A[i]=[(x-z*v)%q for x,v in zip(A[i],A[rr])]
  piv.append(c); rr+=1
 for i in range(rr,m):
  if all(A[i][j]%q==0 for j in range(n)) and A[i][n]%q:return None
 x=[0]*n
 for i,c in enumerate(piv):x[c]=A[i][n]%q
 return tuple(x)
def sep(W,d,q):
 l=solve(list(W)+[d],[0]*len(W)+[1],q)
 if l is not None:assert all(dot(l,w,q)==0 for w in W) and dot(l,d,q)==1
 return l
def mv(T,v,q):return tuple(sum(a*b for a,b in zip(row,v))%q for row in T)
def tv(a,b):
 na,nb=sum(a.values()),sum(b.values()); return sum(abs(Fraction(a[k],na)-Fraction(b[k],nb)) for k in set(a)|set(b))/2
def run():
 q,pdim,m=5,5,3; ex=hid=pts=0
 for z in range(400):
  T=[tuple(R.randrange(q) for _ in range(m)) for __ in range(pdim)]
  V=basis([tuple(R.randrange(q) for _ in range(pdim)) for __ in range(R.randrange(3))],q)
  if z%2==0:b=(0,0,1); G=[(1,0,-1),(0,1,-1)]
  else:b=(1,1,1); G=[(1,2,3)]
  D=mv(T,b,q); TG=[mv(T,g,q) for g in G]; W=basis(V+TG,q); hidden=insp(D,W,q)
  masks=span(V,q,pdim); ds=[]
  for K in (0,1):
   c=Counter()
   for rho in product(range(q),repeat=len(G)):
    s=[K*b[j]%q for j in range(m)]
    for a,g in zip(rho,G):
     for j in range(m):s[j]=(s[j]+a*g[j])%q
    base=mv(T,s,q)
    for r in masks:c[add(base,r,q)]+=1
   ds.append(c); pts+=sum(c.values())
  assert tv(ds[0],ds[1])==Fraction(0 if hidden else 1,1)
  l=sep(W,D,q)
  if hidden:hid+=1; assert l is None
  else:
   ex+=1; assert l is not None
   for c in list(ds[1])[:8]:assert dot(l,c,q)==1
 return {'run':51,'seed':SEED,'fixtures':400,'exposed':ex,'hidden':hid,'enumerated_transcripts_with_multiplicity':pts,'scope':'correlated public linear-mask validation only; not a security proof'}
print(json.dumps(run(),sort_keys=True,indent=2))
