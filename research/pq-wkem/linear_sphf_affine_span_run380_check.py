#!/usr/bin/env python3
"""Run 380 finite linear SPHF and reuse checks: toy algebra, not a secure WKEM."""
import itertools,json
checks=0
def ck(b,info):
 global checks
 checks+=1
 if not b: raise AssertionError(f'check={checks}: {info}')
stats=[]
for q in (5,7,11):
 # Hash secret h=(a,b), public projection key hp=(a,a), x=(s,t).
 # Hash(h,x)=a*s+b*t, L={(s,0)}, witness z=(u,v), u+v=s.
 for a in range(q):
  for K in range(q):
   for s in range(q):
    C=(K+a*s)%q
    vals=set()
    for u in range(q):
     v=(s-u)%q
     vals.add((C-a*(u+v))%q)
    ck(vals=={K},'all q original witnesses recover identical K')
 for a in range(q):
  for K in range(q):
   for s in range(q):
    for t in range(1,q):
     ciphertexts=[(K+a*s+b*t)%q for b in range(q)]
     ck(set(ciphertexts)==set(range(q)),'false capsule uniform in b')
 count=0
 for a,b,K,s1,s2 in itertools.product(range(q),repeat=5):
  t1,t2=1,2
  C1=(K+a*s1+b*t1)%q
  C2=(K+a*s2+b*t2)%q
  b_rec=((C2-C1-a*(s2-s1))*pow(t2-t1,-1,q))%q
  K_rec=(C1-a*s1-b_rec*t1)%q
  ck(b_rec==b and K_rec==K,'two false same-mask capsules recover b,K')
  count+=1
 a,K,s1,s2,t1,t2=1,2,3,4,1,2
 pairs={((K+a*s1+b1*t1)%q,(K+a*s2+b2*t2)%q) for b1,b2 in itertools.product(range(q),repeat=2)}
 ck(len(pairs)==q*q,'independent masks give full joint uniform support')
 for a,b,K,s,t in itertools.product(range(q),repeat=5):
  if t==0:continue
  C=(K+a*s+b*t)%q
  ck((C-a*s-b*t)%q==K,'retained b breaks false confidentiality')
 stats.append({'q':q,'honest_openings_per_true_word':q,'reused_false_pairs_checked':count,'fresh_joint_support':q*q,'false_single_pad':'exactly uniform','same_mask_two_distinct_false_words':'key disclosed'})

# General d-dimensional hidden mask with shared use across k capsules:
# y_i=K+dot(b,t_i). Exactly one invariant decides leakage:
# 1_k in image(T) iff all K induce identical joint distributions.
from collections import Counter

def rank(mat,q):
 if not mat:return 0
 m=[list(row) for row in mat]
 rows,cols=len(m),len(m[0]); r=0
 for col in range(cols):
  pivot=next((j for j in range(r,rows) if m[j][col]%q),None)
  if pivot is None: continue
  m[r],m[pivot]=m[pivot],m[r]
  inv=pow(m[r][col]%q,-1,q)
  m[r]=[(v*inv)%q for v in m[r]]
  for j in range(rows):
   if j==r:continue
   f=m[j][col]%q
   if f:m[j]=[(v-f*w)%q for v,w in zip(m[j],m[r])]
  r+=1
  if r==rows:break
 return r

def lin(t,b,q):return sum(x*y for x,y in zip(t,b))%q

rank_checks=[]
for q,d,max_k in ((3,2,3),(5,2,2)):
 vectors=list(itertools.product(range(q),repeat=d))
 vectors=[v for v in vectors if any(v)]
 count_hiding=count_leaking=0
 for k in range(1,max_k+1):
  for T in itertools.product(vectors,repeat=k):
   r=rank(T,q)
   augmented=[list(t)+[1] for t in T]
   leak=(rank(augmented,q)>r)
   bvalues=list(itertools.product(range(q),repeat=d))
   dist0=Counter(tuple(lin(t,b,q) for t in T) for b in bvalues)
   dist1=Counter(tuple((1+lin(t,b,q))%q for t in T) for b in bvalues)
   ck((dist0==dist1)==(not leak),'complete joint distribution iff 1 in image(T)')
   if leak:
    count_leaking+=1
    witnesses=[v for v in itertools.product(range(q),repeat=k)
               if sum(v)%q==1 and all(sum(v[i]*T[i][j] for i in range(k))%q==0 for j in range(d))]
    ck(bool(witnesses),'exists linear key-extraction functional')
    lam=witnesses[0]
    for K in range(q):
     for b in bvalues:
      y=[(K+lin(t,b,q))%q for t in T]
      ck(sum(lam[i]*y[i] for i in range(k))%q==K,'extracts K from joint view')
   else:
    count_hiding+=1
 rank_checks.append({'q':q,'mask_dimension':d,'max_capsules':max_k,
                     'hiding_families':count_hiding,'leaking_families':count_leaking})
# Concrete pure three-way leakage over two hidden mask coordinates.
for q in (3,5,7,11):
 T=((1,0),(0,1),(1,1))
 for a,b1,b2,K in itertools.product(range(q),repeat=4):
  # This is after subtracting public a*s_i (choose all s_i=0 here).
  Y=[(K+b1)%q,(K+b2)%q,(K+b1+b2)%q]
  ck((Y[0]+Y[1]-Y[2])%q==K,'three-way only mask reuse extraction')
 for I in itertools.combinations(range(3),2):
  subset=[T[i] for i in I]
  D0=Counter(tuple(lin(t,b,q) for t in subset) for b in itertools.product(range(q),repeat=2))
  D1=Counter(tuple((1+lin(t,b,q))%q for t in subset) for b in itertools.product(range(q),repeat=2))
  ck(D0==D1,'every pair perfectly hides K although triple reveals')

print(json.dumps({'run':380,'status':'PASS','assertions':checks,'models':stats,'affine_span_rank_checks':rank_checks,'triple_only_attack':'C1+C2-C3 equals K after subtracting public a*s_i','concrete_QPT_security':False,'hard_NP_source_relation':False},sort_keys=True,indent=2))
