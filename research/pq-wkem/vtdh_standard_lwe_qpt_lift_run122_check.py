#!/usr/bin/env python3
from __future__ import annotations
import json, math
from collections import Counter

checks = 0
def ok(x, msg=''):
    global checks
    checks += 1
    if not x:
        raise AssertionError(msg)

def bits(x,w): return [(x>>i)&1 for i in range(w)]

def gval(v,q): return sum((1<<i)*b for i,b in enumerate(v)) % q

# Tiny exact controls for the formal Lemma-8 gadget identity and embedding.
gadget=[]; embedding=[]
for q in (4,8,16):
    w=q.bit_length()-1
    for A in range(q): ok(gval(bits(A,w),q)==A,(q,A))
    gadget.append({'q':q,'elements':q})
for q in (4,8):
    w=q.bit_length()-1; n=0
    for A in range(q):
        W=bits(A,w)
        for s in range(q):
            for e in range(q):
                z=(s*A+e)%q
                for um in range(q):
                    u=bits(um,w)
                    lhs=(z+sum(a*b for a,b in zip(u,W)))%q
                    sGpu=[(s*(1<<i)+u[i])%q for i in range(w)]
                    rhs=(sum(a*b for a,b in zip(sGpu,W))+e)%q
                    ok(lhs==rhs,(q,A,s,e,um,lhs,rhs)); n+=1
    embedding.append({'q':q,'tuples':n})

# Uniform challenge remains uniform under fixed additive translation.
for q in range(2,17):
    for c in range(q):
        f=Counter((z+c)%q for z in range(q))
        ok(len(f)==q and all(v==1 for v in f.values()),(q,c))

# Run-121 pad is exactly key-independent if r is uniform.
pads=[]
for k in range(1,13):
    mask=(1<<k)-1; ds=[]
    for K in (0,1):
        km=mask if K else 0
        ds.append(Counter(r^km for r in range(1<<k)))
    ok(ds[0]==ds[1],k); pads.append({'k':k,'states':1<<k})

# Printed Lemma-9 entropy inequality under the Section-5.5 sample scaling.
params=[]
for lam in (64,128,256,512):
    ell=lam**2; m=lam**3
    for c in (2,3,4):
        rhs=(m-c*math.log2(lam)-2*lam)/math.log2(m)
        ok(ell<=rhs,(lam,c,ell,rhs))
        params.append({'lambda':lam,'q_form':f'lambda^{c}','holds':True})

print(json.dumps({
  'run':122,'status':'PASS','assertions':checks,
  'scope':'finite algebra/distribution/parameter-bookkeeping only; not a QPT-hardness experiment',
  'gadget_identity':gadget,'hyb1_hyb2_embedding':embedding,
  'pad_uniformity':pads,'parameter_samples':params,
  'non_conclusions':['does not prove QPT-LWE','does not solve fixed-digest source opening','does not imply ORIGINAL-witness extraction from final-key recovery']
},sort_keys=True,indent=2))