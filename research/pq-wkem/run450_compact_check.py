#!/usr/bin/env python3
"""Run450 exact finite source-fold occupancy and one coherent phase-oracle diagnostic."""
import json
from fractions import Fraction
from math import comb,asin,sqrt,sin
assertions=0
cases=[]
for d in (1,2,3):
 for t in (1,2,3):
  N=1<<d
  p=Fraction(1,1<<t)
  weights=[Fraction(0)]*(N+1)
  for mask in range(1<<N):
   k=mask.bit_count();weights[k]+=p**k*(1-p)**(N-k)
  for k in range(N+1):
   assert weights[k]==comb(N,k)*p**k*(1-p)**(N-k);assertions+=1
  assert sum(weights)==1;assertions+=1
  assert 1-weights[0]==1-(1-p)**N;assertions+=1
  cases.append({'d':d,'t':t,'Pr_any':str(1-weights[0])})
# Coherent Grover phase marking for z=0, then diffusion (not classical oracle enumeration).
N=8;marked={0};v=[1/sqrt(N)]*N;theta=asin(sqrt(1/N));success=[]
for j in range(3):
 val=sum(v[k]*v[k] for k in marked)
 assert abs(val-sin((2*j+1)*theta)**2)<1e-12;assertions+=1
 success.append(round(val,12))
 if j<2:
  phase=[-a if k in marked else a for k,a in enumerate(v)]
  mean=sum(phase)/N
  v=[2*mean-a for a in phase]
print(json.dumps({'run':450,'assertions':assertions,'cases':cases,'coherent_grover_success':success,'security':'finite algebra only'},indent=2,sort_keys=True))
