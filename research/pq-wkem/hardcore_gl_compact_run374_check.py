#!/usr/bin/env python3
"""Exact finite parity-pad/Fourier checks, NOT cryptographic hardness."""
import json
checks=0
def ck(v):
 global checks
 checks+=1
 assert v
for n in range(3,11):
 N=1<<n
 for k in (0,1,N-1):
  parity=lambda x:x.bit_count()&1
  noisy=lambda r:parity(k&r)^int((r&3)==0)
  ck(sum(noisy(r)==parity(k&r) for r in range(N))*4==3*N)
  for b in (0,1):
   for r in range(N):ck((b^parity(k&r))^parity(k&r)==b)
  a=[1 if noisy(r)==0 else -1 for r in range(N)]
  size=1
  while size<N:
   for j in range(0,N,2*size):
    for i in range(j,j+size):
     x,y=a[i],a[i+size]
     a[i],a[i+size]=x+y,x-y
   size*=2
  ck(a[k]*2==N)
  ck({i for i,c in enumerate(a) if abs(c)*2>=N}=={k^d for d in range(4)})
  ck(sum(c*c for c in a)==N*N)
  R=lambda flag,w:flag and w in (3,5)
  release=lambda flag,w:k if R(flag,w) else None
  ck(release(True,3)==release(True,5)==k)
  ck(all(release(False,w) is None for w in range(8)))
print(json.dumps({'run':374,'status':'PASS','assertions':checks,'cases':24,'widths':'3-10','scope':'finite parity-pad and Fourier algebra only; no QPT hardness, real release, or practical WE'},sort_keys=True))
