#!/usr/bin/env python3
"""Run 382 exact finite noisy-projector falsifier. NOT LWE/WKEM security."""
import itertools,json
q=257; D=128; E=(-1,0,1); W=list(itertools.product(E,repeat=2)); checks=0
def ck(b):
 global checks
 checks+=1
 assert b

def dist(x,y):
 a=(x-y)%q
 return min(a,q-a)
def dec(x): return int(dist(x,D)<dist(x,0))
def cap(x,h,e,k): return ((h+e[0])%q,(h+e[1])%q),(D*k+h*x)%q
def rec(p,c,w): return dec((c-p[0]*w[0]-p[1]*w[1])%q)
V={x:[w for w in W if sum(w)==x] for x in range(4)}
ck([len(V[i]) for i in range(4)]==[3,2,1,0])
honest=attack=0
for h in range(q):
 for e in itertools.product(E,repeat=2):
  for k in (0,1):
   for x in (0,1,2):
    p,c=cap(x,h,e,k)
    for w in V[x]:
     ck(rec(p,c,w)==k)
     ck(dist((c-p[0]*w[0]-p[1]*w[1])%q,D*k)<=2)
     honest+=1
   p,c=cap(3,h,e,k); z=(3,0)
   ck(z not in W and sum(z)==3 and not V[3])
   ck(rec(p,c,z)==k)
   ck(dist((c-3*p[0])%q,D*k)<=3)
   attack+=1
ck(honest==27756 and attack==4626)
print(json.dumps({'run':382,'status':'PASS','assertions':checks,'q':q,'delta':D,
 'honest_witness_checks':honest,'false_unauthorized_recoveries':attack,
 'all_valid_witnesses_same_key':True,'false_original_x':3,
 'public_invalid_opening':[3,0],'attack_probability':1,
 'scope':'algebraic toy only, no practical LWE/QPT/WKEM security'},sort_keys=True))
