#!/usr/bin/env python3
"""Run 348: finite exact weak-view leakage and quantum phase-estimation controls.

Standard library only. These are probability/interface checks, not concrete LWE or
QPT security tests.
"""
import itertools
import json
import math
from collections import Counter
from fractions import Fraction
from math import comb

ASSERTS=0

def check(pred, label):
    global ASSERTS
    ASSERTS += 1
    if not pred:
        raise AssertionError(f"check {ASSERTS}: {label}")

# I. Uniform K + a BSC-biased noisy view is EXACTLY uniform marginally.
# Two views are correlated despite completely independent noise/mixer coins.
stats={}
for p in (Fraction(11,20),Fraction(3,5),Fraction(7,10),Fraction(3,4)):
    eps=p-Fraction(1,2)
    pair={}
    for b1,b2 in itertools.product((0,1),repeat=2):
        v=Fraction(0)
        for k in (0,1):
            prob=lambda b: p if b==k else 1-p
            v += Fraction(1,2)*prob(b1)*prob(b2)
        pair[(b1,b2)]=v
    for b in (0,1):
        check(sum(pair[(b,c)] for c in (0,1))==Fraction(1,2),"one-view uniform")
        check(sum(pair[(c,b)] for c in (0,1))==Fraction(1,2),"other-view uniform")
    for b1,b2 in itertools.product((0,1), repeat=2):
        expect=Fraction(1,4)+(eps*eps if b1==b2 else -eps*eps)
        check(pair[(b1,b2)]==expect,"pairwise correlation")
    agreement=pair[(0,0)]+pair[(1,1)]
    tv=sum(abs(v-Fraction(1,4)) for v in pair.values())/2
    check(agreement==Fraction(1,2)+2*eps*eps,"agreement fingerprint")
    check(tv==2*eps*eps,"pairwise TV")
    stats[str(p)]={"epsilon":str(eps),"pair_TV":str(tv),"pair_agreement":str(agreement)}

# II. Every individual full-vector view may be WRONG yet the per-bit bias is
# recoverable by majority of multiple views. Exhaustive Hamming sphere model.
hamming_cases=0
for n in range(3,9):
    for h in range(1,(n-1)//2+1):
        errors=list(itertools.combinations(range(n),h))
        for k in range(2**n):
            correct=[0]*n
            for error in errors:
                v=k
                for j in error:
                    v ^= (1<<j)
                check(v != k,"no whole-key-correct sample")
                for j in range(n):
                    correct[j]+=int(((v>>j)&1)==((k>>j)&1))
                hamming_cases+=1
            for j in range(n):
                check(correct[j]*n==len(errors)*(n-h),"coordinate correct fraction")
                check(correct[j]*2>len(errors),"strict coordinate bias")

# III. Independently noisy views: full-key coincidence is exponentially rare
# even when coordinate-wise majority succeeds with polynomial query count.
majority={}
for p in (Fraction(11,20),Fraction(3,5),Fraction(7,10)):
    eps=p-Fraction(1,2)
    for m in (3,5,11,21,51,101):
        # exact majority wrong probability, odd m
        failure=sum(Fraction(comb(m,j),1)*p**j*(1-p)**(m-j)
                    for j in range((m+1)//2))
        bound=math.exp(-2*m*float(eps*eps))
        check(float(failure)<=bound+1e-14,"Hoeffding upper bound")
        majority[f"p={p},m={m}"]=float(failure)
    for kappa in (128,256):
        full=p**kappa
        check(full<1,"whole-key coincidence bound")
        majority[f"single_full_view_p={p},kappa={kappa},log2prob"]=round(kappa*math.log2(float(p)),6)

# IV. Explicit idealized phase-estimation distribution for coherent quantum
# probability estimation. No claim of a quantum executable implementation.
# If amplitude is a=Pr[B=1], Grover operator eigenphases are +/-theta/pi
# with theta=asin(sqrt(a)). Standard phase estimation with M bins gives a
# Dirichlet-kernel distribution for the two phases.
def phase_probs(phi,M):
    out=[]
    for y in range(M):
        d=phi-y/M
        den=math.sin(math.pi*d)
        if abs(den)<1e-13:
            val=1.0
        else:
            val=(math.sin(math.pi*M*d)/(M*den))**2
        out.append(val)
    return out

def qae_success(a,M):
    ph=math.asin(math.sqrt(a))/math.pi
    first=phase_probs(ph,M)
    second=phase_probs(1-ph,M)
    check(abs(sum(first)-1)<1e-10,"qpe phase distribution normalization")
    check(abs(sum(second)-1)<1e-10,"negative phase normalization")
    want=a>0.5
    total=0.0
    for y in range(M):
        candidate=math.sin(math.pi*y/M)**2
        if (candidate>0.5)==want:
            total += (first[y]+second[y])/2
    return total

qae={}
for a in (0.3,0.4,0.45,0.55,0.6,0.7):
    for M in (32,64,128,256):
        success=qae_success(a,M)
        check(0<=success<=1+1e-9,"qae success probability")
        qae[f"p={a},M={M}"]=round(success,9)
for a in (0.45,0.55):
    check(qae_success(a,64)>0.99,"coherent test with 64 bins")

# V. Marginal uniformity does NOT imply multi-view indistinguishability, even
# with independently generated per-view noise. Check exact total variation
# of M=2/3 toy distributions from uniform independent bits.
TV={}
for p in (Fraction(11,20),Fraction(3,5)):
    for m in (2,3,4):
        tv=Fraction(0)
        for obs in itertools.product((0,1),repeat=m):
            pr=sum(Fraction(1,2)*math.prod(p if b==k else 1-p for b in obs)
                   for k in (0,1))
            tv += abs(pr-Fraction(1,2**m))
        tv/=2
        check(tv>0,"joint leakage despite uniform marginals")
        if m==2:
            eps=p-Fraction(1,2)
            check(tv==2*eps*eps,"pairwise TV exact repeated")
        TV[f"p={p},m={m}"]=str(tv)

result={"status":"PASS","assertions":ASSERTS,
        "hamming_sphere_nontrivial_wrong_views":hamming_cases,
        "bsc_pairs":stats,"majority":majority,"phase_estimation":qae,
        "joint_tv":TV,
        "scope":"Exact finite channel/interface checks only; no claim any actual PQ mixer yields bias."}
print(json.dumps(result,sort_keys=True,indent=2))
