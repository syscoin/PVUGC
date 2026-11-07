#!/usr/bin/env python3
"""Finite exact reversible-marker seam attack; NOT a WKEM security proof."""
import json,hashlib,random
checks=0
def ck(flag):
 global checks
 checks+=1
 assert flag

def gate(v,g):
 op,a,b,c=g
 if op==0:return v^(1<<a)
 if op==1:return v^(((v>>a)&1)<<b)
 return v^(((((v>>a)&1)&((v>>b)&1)))<<c)

def f(v,G):
 for g in G:v=gate(v,g)
 return v

def inv(v,G):return f(v,reversed(G))

out=[]
for d in (4,6,8):
 for seed in (7,19,37):
  rng=random.Random(d*100+seed)
  G=[]
  for j in range(40):
   a,b,c=rng.sample(range(d),3)
   G.append((j%3,a,b,c))
  mark=rng.randrange(1<<d)
  z=inv(mark,G)
  success=[v for v in range(1<<d) if f(v,G)==mark]
  ck(success==[z])
  for v in range(1<<d):ck(inv(f(v,G),G)==v)
  key=hashlib.sha256(f'run368:{d}:{seed}'.encode()).digest()
  pk=hashlib.sha256(b'public-check|'+key).digest()
  # Ideal sealed gate returns key only on a known public marker.
  release=lambda v: key if f(v,G)==mark else None
  ck(release(z)==key)
  ck(hashlib.sha256(b'public-check|'+release(z)).digest()==pk)
  roots_true=[u for u in range(17) if u*u%17==4]
  roots_false=[u for u in range(17) if u*u%17==3]
  ck(roots_true==[2,15]);ck(roots_false==[])
  # The source verifier refuses false x, but raw release accepts z anyway.
  ck(release(z)==key)
  out.append({'d':d,'seed':seed,'density':f'1/{1<<d}',
              'public_inverse_gates':40,'released_on_false_source':True})
print(json.dumps({'run':368,'status':'PASS','assertions':checks,
 'cases':out,'scope':'finite seam attack only; sealed gate is an ideal attacked abstraction'},
 indent=2,sort_keys=True))
