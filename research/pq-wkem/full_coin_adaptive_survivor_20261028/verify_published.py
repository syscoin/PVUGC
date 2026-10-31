#!/usr/bin/env python3
"""Finite algebra checker only; not cryptanalysis or native signature testing."""
import itertools, json, math, random
from collections import Counter
r=random.Random(20261028); checks=0
def ok(p):
 global checks
 checks+=1
 assert p

def count_sphere(m,h):
 return sum(2**k*math.comb(m,k)*math.comb(h-1,k-1) for k in range(1,min(m,h)+1))

# All proper subsets of t=3 shares, full (D,V,opened shares) transcript
# distribution independent of a 2-bit signing seed K.
t=3
for hidden in range(t):
 others=[i for i in range(t) if i!=hidden]
 for mask in range(1<<len(others)):
  opened=[i for j,i in enumerate(others) if mask>>j&1]
  hists=[]
  for K in range(4):
   hist=Counter()
   for U,*Z in itertools.product(range(4),repeat=4):
    D=U^Z[0]^Z[1]^Z[2]; V=K^U
    hist[(D,V)+tuple(Z[i] for i in opened)]+=1
   ok(len(hist)==4**(2+len(opened)))
   ok(all(v==4**(2-len(opened)) for v in hist.values()))
   hists.append(hist)
  ok(all(hist==hists[0] for hist in hists))

# A deliberately simple LWE SOURCE with two distinct ORIGINAL witnesses:
# A column is +/-1, b=A*3; s=3/e=0 and s=4/e=-A are both valid.
q,h,m,g=257,4,8,9; B=q//g; ell=math.ceil(256/math.log2(B))
A=[r.choice([-1,1]) for _ in range(m)];b=[3*a%q for a in A]
def sphere():
 weights=[2**k*math.comb(m,k)*math.comb(h-1,k-1) for k in range(1,h+1)]
 k=r.choices(range(1,h+1),weights=weights)[0]
 positions=r.sample(range(m),k); cuts=sorted(r.sample(range(1,h),k-1))
 parts=[y-x for x,y in zip([0]+cuts,cuts+[h])]; v=[0]*m
 for i,size in zip(positions,parts):v[i]=size*r.choice([-1,1])
 ok(sum(map(abs,v))==h);return v

def digits(v):
 a=[]
 for _ in range(ell):a.append(v%B);v//=B
 ok(v==0);return a

def decode(cipher,s):
 c,d=cipher;z=(d-s*c)%q
 distances=[min((z-g*a)%q,(g*a-z)%q) for a in range(B)]
 ok(min(distances)<=h and distances.count(min(distances))==1)
 return distances.index(min(distances))

for _ in range(4):
 K,U=r.getrandbits(256),r.getrandbits(256)
 Z=[r.getrandbits(256) for _ in range(t)];D=U^Z[0]^Z[1]^Z[2];V=K^U
 all_caps=[]
 for z in Z:
  cap=[]
  for a in digits(z):
   v=sphere();c=sum(A[i]*v[i] for i in range(m))%q
   d=(sum(b[i]*v[i] for i in range(m))+g*a)%q
   ok((c,d)==(sum(A[i]*v[i] for i in range(m))%q,(sum(b[i]*v[i] for i in range(m))+g*a)%q))
   cap.append(((c,d),v))
  all_caps.append(cap)
 for s in (3,4):
  values=[]
  for cap in all_caps:
   x=0
   for j,(c,v) in enumerate(cap):x+=decode(c,s)*B**j
   values.append(x)
  ok(values==Z)
  ok(K==V^D^values[0]^values[1]^values[2])

n_big,m_big,h_big,q_big=128,1600,696,65537
N=count_sphere(m_big,h_big);Q=q_big**(n_big+1)
g_big=2*h_big+1;B_big=q_big//g_big
ell_big=math.ceil(256/math.log2(B_big))
ok(B_big==47 and ell_big==47)
ok((t*ell_big)**2*(Q-1)*2**256 < 4*N)
print(json.dumps({'result':'PASS','assertions':checks,'full_coin_open_limit':2,
 'two_valid_original_witnesses':True,'complete_256bit_sameK_trials':4,
 'sphere_log2_N':round(math.log2(N),9),'B':B_big,'ell':ell_big,
 'bound_log2_t_ell_delta':round(math.log2(t*ell_big)-1+0.5*(math.log2(Q-1)-math.log2(N)),9),
 'scope':'restricted LWE; no QPT hardness or arbitrary-NP security proven'},sort_keys=True,indent=2))
