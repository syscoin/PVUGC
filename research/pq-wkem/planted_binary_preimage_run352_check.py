#!/usr/bin/env python3
"""Exact finite-field census for planted binary HPS targets. NOT a security proof."""
from itertools import product, islice
from fractions import Fraction
import json, hashlib
C=0

def check(test,label=''):
 global C
 C+=1
 if not test: raise AssertionError((C,label))

def target(A,u,q,n,m):
 return tuple(sum(A[i*m+j]*u[j] for j in range(m))%q for i in range(n))

def stats(q,n,m):
 N=2**m; p=Fraction(1,q**n)
 mean=1+(N-1)*p
 variance=(N-1)*p*(1-p)
 u0=(0,)*m
 binaries=list(product((0,1),repeat=m))
 zero=(0,)*n
 sumX=sumX2=0
 sample=0
 total_tv=Fraction(0)
 for A in product(range(q),repeat=n*m):
  counts={}
  for u in binaries:
   t=target(A,u,q,n,m)
   counts[t]=counts.get(t,0)+1
  x=counts.get(zero,0)
  check(x>=1,'planted u0')
  sumX+=x; sumX2+=x*x
  sample+=1
  total_tv+=sum(abs(Fraction(counts.get(t,0),N)-p) for t in product(range(q), repeat=n))/2
 assert sample==q**(n*m)
 observed_mean=Fraction(sumX,sample)
 observed_variance=Fraction(sumX2,sample)-observed_mean**2
 check(observed_mean==mean,'expected planted count')
 check(observed_variance==variance,'pairwise-independent variance')
 tv=total_tv/sample
 bound_sq=Fraction(q**n,4*N)
 check(tv*tv<=bound_sq,'LHL upper bound')
 return {'q':q,'n':n,'m':m,'number_matrices':sample,'mean':[mean.numerator,mean.denominator],
         'variance':[variance.numerator,variance.denominator],
         'average_tv':[tv.numerator,tv.denominator],
         'lhl_upper_bound_squared':[bound_sq.numerator,bound_sq.denominator]}

rows=[]
for q,n,m in [(3,1,3),(3,1,5),(3,1,7),(3,2,3),(3,2,4),(5,1,3),(5,1,5),(5,2,3)]:
 rows.append(stats(q,n,m))

# Conditional collision probability: for fixed planted u0 and distinct binary
# v,w, their difference vectors are independent over odd prime fields.
checks=0
for q in (3,5,7):
 for m in range(2,7):
  for u0 in product((0,1),repeat=m):
   diffs=[tuple((v[j]-u0[j])%q for j in range(m)) for v in product((0,1),repeat=m) if v!=u0]
   for i in range(len(diffs)):
    for j in range(i+1,len(diffs)):
     a,b=diffs[i],diffs[j]
     collinear=any(tuple((c*v)%q for v in a)==b for c in range(q))
     check(not collinear,'distinct planted differences are independent')
     checks+=1

# Decode all binary preimages (whether or not they are ORIGINAL source-valid)
# from a single publicly known t=Au, given public noisy projection h and d.
def decode(v,q):
 center=(q-1)//2
 dist=lambda a,b:min((a-b)%q,(b-a)%q)
 return int(dist(v,center)<dist(v,0))

HPS=0
for q,m,n in [(17,3,1),(19,4,2),(29,5,2)]:
 for A in islice(product(range(q),repeat=n*m),37):
  for u in product((0,1),repeat=m):
   t=target(A,u,q,n,m)
   for K in (0,1):
    for s in islice(product(range(q),repeat=n),19):
     # fixed bounded noise e_j=+1 (every binary preimage has error sum<=m<q/4)
     # require q>4*m for guaranteed nearest-center correctness.
     if q<=4*m+1: continue
     h=[(sum(A[i*m+j]*s[i] for i in range(n))+1)%q for j in range(m)]
     z=sum(t[i]*s[i] for i in range(n))%q
     d=((q-1)//2*K-z)%q
     recovered=decode((sum(h[j]*u[j] for j in range(m))+d)%q,q)
     check(recovered==K,'planted preimage recovers final bit')
     HPS+=1
result={'run':352,'status':'PASS','checks':C,'pair_independence_cases':checks,
        'planted_hps_decryptions':HPS,'exact_censuses':rows,
        'scope':'exact small-field algebra and moments; no SIS/LWE or QPT hardness established'}
print(json.dumps(result,indent=2,sort_keys=True))
