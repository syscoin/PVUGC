#!/usr/bin/env python3
"""Run367 compact independent finite Grover oracle check; NOT WKEM security."""
from fractions import Fraction as F
import json
checks=0
for n in range(2,6):
 N=1<<n
 for m in range(1,min(5,N)+1):
  for steps in range(6):
   for mode in range(2):
    marked=set(range(m)) if mode==0 else set(range(N-m,N))
    a=[F(1)]*N
    for _ in range(steps):
     a=[-v if i in marked else v for i,v in enumerate(a)]
     avg=sum(a,F(0))/N
     a=[2*avg-v for v in a]
    q=sum((a[i]*a[i] for i in marked),F(0))/N
    p=F(m,N)
    prev=F(1);cur=3-4*p
    if steps==0:pred=p
    elif steps==1:pred=p*cur*cur
    else:
     for _ in range(2,steps+1):prev,cur=cur,2*(1-2*p)*cur-prev
     pred=p*cur*cur
    assert q==pred and 0<=q<=1
    checks+=1
for d,w in ((256,1),(257,2),(260,16),(276,1<<20)):
 assert (1<<d)//w==1<<256
 checks+=1
print(json.dumps({'run':367,'status':'PASS','assertions':checks,'scope':'exact finite Grover identities only'},sort_keys=True))
