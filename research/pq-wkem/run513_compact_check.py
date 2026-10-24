#!/usr/bin/env python3
"""Run 513 compact exact finite-field/opaque-permutation attack checker."""
import json,random
H=3; N=1<<H; POLY=0b1011

def mul(a,b):
    c=0
    for _ in range(H):
        if b&1:c^=a
        b>>=1;a<<=1
        if a&N:a^=POLY
        a&=N-1
    return c

def div(a,b):
    assert b
    v=1
    for _ in range(N-2):v=mul(v,b)
    return mul(a,v)

def unpack(y):return y>>2,(y>>1)&1,y&1

def pack(u,z,t):return (u<<2)|(z<<1)|t

cases=0;bij=0;uniform=0
for ax in range(1,N):
 for ar in range(1,N):
  if ar==ax:continue
  for ass in range(1,N):
   if ass in (ax,ar):continue
   pairs=set()
   for k in range(N):
    left=set();right=set()
    for s in range(N):
     dx=mul(ax,s)^1;dr=mul(ar,s)^2;ds=mul(ass,s)^3
     d1=k^dx^dr;d2=k^dx^ds
     s2=div(d1^d2^2^3,ar^ass)
     k2=d1^mul(ax^ar,s2)^1^2
     assert (k2,s2)==(k,s)
     assert (d1,d2) not in pairs
     pairs.add((d1,d2));left.add(d1);right.add(d2)
     cases+=1
    assert len(left)==len(right)==N
    uniform+=2
   assert len(pairs)==N*N
   bij+=1

rng=random.Random(513)
P=list(range(N*4));rng.shuffle(P)
Q=[0]*(N*4)
for i,v in enumerate(P):Q[v]=i
xcoef,rcoef,scoef=2,3,5
oracle=0
for k in range(N):
 for seed in range(N):
  masks=[mul(v,seed)^b for v,b in ((xcoef,1),(rcoef,2),(scoef,3))]
  ax=P[pack(k^masks[0],0,0)]
  u,z,t=unpack(Q[ax]);assert (z,t)==(0,0)
  loaded=P[pack(u,1,0)] # public witness-flip loader X, not direct inverse
  def query(d,i):
   w,z,t=unpack(Q[loaded]);assert z==1
   return P[pack(w,z,t^(((w>>i)^(d>>i))&1))]
  words=[]
  for d in masks[1:]:
   word=0
   for i in range(H):
    word|=(query(d,i)!=loaded)<<i;oracle+=1
   words.append(word)
  s2=div(words[0]^words[1]^2^3,rcoef^scoef)
  k2=words[0]^mul(xcoef^rcoef,s2)^1^2
  assert (s2,k2)==(seed,k)
print(json.dumps({'algebra_cases':cases,'joint_bijections':bij,'uniform_one_view_checks':uniform,'opaque_frame_recoveries':N*N,'terminal_oracle_queries':oracle},sort_keys=True))
