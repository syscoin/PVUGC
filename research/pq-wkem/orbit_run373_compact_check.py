#!/usr/bin/env python3
"""Exact modular orbit/source parsing; NOT an LWE/PQ/release instantiation."""
import json
Q,D,K,W=257,128,2,3
checks=0
def ok(b):
 global checks
 checks+=1
 assert b
def inj(base,w):
 return base[:K]+tuple((base[K+j][0],(base[K+j][1]+D*w[j])%Q) for j in range(W))
def extract(base,c):
 if len(c)!=K+W or c[:K]!=base[:K]:return None
 out=[]
 for j in range(W):
  a,b=base[K+j];u,v=c[K+j];d=(v-b)%Q
  if u!=a or d not in (0,D):return None
  out.append(int(d==D))
 return tuple(out)
def original(x,w):
 flag,target=x;v=w[0]+2*w[1]
 return flag==1 and v*v%7==target
for seed in (19,47,133):
 base=tuple(((seed+5*j)%Q,(seed*3+7*j)%Q) for j in range(K+W))
 for b in range(1<<W):
  w=tuple((b>>j)&1 for j in range(W));c=inj(base,w)
  ok(extract(base,c)==w)
  ok((extract(base,c) is not None and original((1,1),extract(base,c)))==original((1,1),w))
  for i in range(K):
   for delta in range(1,Q):
    t=list(c);t[i]=(t[i][0],(t[i][1]+delta)%Q)
    ok(extract(base,tuple(t)) is None)
  for i in range(K,K+W):
   for delta in range(Q):
    t=list(c);t[i]=(base[i][0],(base[i][1]+delta)%Q)
    ok((extract(base,tuple(t)) is not None)==(delta in (0,D)))
   t=list(c);t[i]=((t[i][0]+1)%Q,t[i][1]);ok(extract(base,tuple(t)) is None)
  for i in range(K):
   t=list(c);t[i]=((t[i][0]+1)%Q,t[i][1]);ok(extract(base,tuple(t)) is None)
 ok(sum(original((1,1),tuple((b>>j)&1 for j in range(W))) for b in range(1<<W))==2)
 ok(not any(original((0,1),tuple((b>>j)&1 for j in range(W))) for b in range(1<<W)))
print(json.dumps({'run':373,'status':'PASS','checks':checks,'toy_q':Q,'delta':D,'witness_bits':W,'capsule_seeds':3,'claim':'public orbit parser extracts the unique original witness from every accepted admission object; not from a signature','practical_qpt_security':False},sort_keys=True))
