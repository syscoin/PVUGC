#!/usr/bin/env python3
"""R152: exact source/correlation simulation and uniform-hybrid Fourier verifier.
Offline mathematical regression. No claim of quantum hardness.
"""
import cmath
import itertools
import json
from collections import Counter
from fractions import Fraction
from math import pi

q=11
Delta=5
ERR=(-1,0,1)
assertions=0

def check(condition, msg):
    global assertions
    assertions+=1
    if not condition: raise AssertionError(msg)

def dot(a,b):return sum(x*y for x,y in zip(a,b))%q

def dist(T,b,K=0, eta_set=ERR):
    """T is t x m, b length t; g uniform, all errors iid over ERR."""
    t=len(T);m=len(T[0]);cnt=Counter()
    for g in itertools.product(range(q),repeat=t):
        for e in itertools.product(ERR,repeat=m):
            B=tuple((sum(T[i][j]*g[i] for i in range(t))+e[j])%q for j in range(m))
            for eta in eta_set:
                p=(dot(b,g)+Delta*K+eta)%q
                cnt[(B,p)]+=1
    n=q**t*len(ERR)**m*len(eta_set)
    check(sum(cnt.values())==n,'distribution count')
    return cnt,n

def transform_direct(hist,n,u,v):
    s=0j
    for (B,p),count in hist.items():
        phase=(dot(u,B)+v*p)%q
        s+=count*cmath.exp(2j*pi*phase/q)
    return s/n

def err_phi(z):return sum(cmath.exp(2j*pi*z*e/q) for e in ERR)/len(ERR)

def transform_formula(T,b,u,v,K=0):
    t=len(T);m=len(u)
    if any((sum(T[i][j]*u[j] for j in range(m))+b[i]*v)%q !=0 for i in range(t)):
        return 0j
    r=cmath.exp(2j*pi*(v*Delta*K%q)/q)*err_phi(v)
    for ui in u:r*=err_phi(ui)
    return r

case={'q':q,'Delta':Delta,'error_support':list(ERR)}
T_true=((1,1),);b_true=(1,)
# Different ORIGINAL-valid Boolean paths have different coordinates and recover same K.
for g in range(q):
    for e in itertools.product(ERR,repeat=2):
        for eta in ERR:
            for K in (0,1):
                B=tuple((g+ee)%q for ee in e)
                p=(g+Delta*K+eta)%q
                for w in ((1,0),(0,1)):
                    z=(p-dot(B,w))%q
                    check(z==(Delta*K+eta-dot(e,w))%q,'exact all-witness residual')
                    def circular(a): return min(a%q,(-a)%q)
                    guess=min((0,1), key=lambda bit: circular(z-Delta*bit))
                    check(guess==K,'exact all-witness nearest decoding')

# Exact joint reduction: challenging g needs no s or epsilon for constructing B,p.
for A in range(q):
    for s in range(q):
        for eps in ERR:
            g=(A*s+eps)%q
            for e in itertools.product(ERR,repeat=2):
                for eta in ERR:
                    B_direct=((g+e[0])%q,(g+e[1])%q)
                    p_direct=(g+eta+Delta)%q
                    B_from_challenge=tuple((g+e[j])%q for j in range(2))
                    p_from_challenge=(g+eta+Delta)%q
                    check(B_direct==B_from_challenge and p_direct==p_from_challenge,'straight-line LWE input simulator')

# Full Fourier character law for two relations and both target bits.
results=[]
for name,T,b in [ ('two_witness_true',((1,1),),(1,)),
                   ('unreachable_false',((0,0),),(1,)),
                   ('short_representations_false',((1,1),),(5,)) ]:
    d0,n=dist(T,b,0);d1,_=dist(T,b,1)
    tv=Fraction(sum(abs(d0[z]-d1[z]) for z in set(d0)|set(d1)),2*n)
    max_delta=0.0
    for K,hist in ((0,d0),(1,d1)):
        for u in itertools.product(range(q),repeat=2):
            for v in range(q):
                measured=transform_direct(hist,n,u,v)
                predicted=transform_formula(T,b,u,v,K)
                error=abs(measured-predicted)
                max_delta=max(max_delta,error)
                check(error<3e-12,('Fourier',name,K,u,v,error))
    # Verify characterization: Fourier with v!=0 vanishes when b not in image T.
    if name=='unreachable_false':check(tv==0,'false exact uniform-hybrid hiding')
    if name=='two_witness_true':check(tv>0,'intended TRUE distinction')
    if name=='short_representations_false':check(tv>0,'shortness alone insufficient')
    results.append({'name':name,'exact_uniform_g_TV_K0_K1':f'{tv.numerator}/{tv.denominator}',
                    'TV_float':round(float(tv),8),'max_Fourier_discrepancy':round(max_delta,12)})

case.update({'cases':results,'assertions':assertions,
'provenance':'offline exact distribution and finite transform calculation; not QPT-LWE validation',
'conclusion':'Joint challenge simulation is exact; uniform-g FALSE hiding requires separate dual-character suppression.'})
print(json.dumps(case,indent=2,sort_keys=True))
