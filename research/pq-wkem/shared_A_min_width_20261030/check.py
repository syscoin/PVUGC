#!/usr/bin/env python3
"""Exact integer parameter/minimality checks and exhaustive LWE projection regression."""
from math import comb, log2
from collections import Counter
import random, json

q=16_777_213
n=256
m_old=6800
w=2000
B=128
ell=5
L=52
C=100
N=4
J=2
K=C*L
checks=0

def check(v,why):
    global checks
    assert v,why
    checks+=1

def source_cardinality(m):
    return comb(m,w)<<w

# A conservative two-bit slack beyond 128-bit statistical bound:
# (K/2)*sqrt((q**n-1)/|T|) <= 2**-130.
# Sufficient exact-integer predicate |T| >= K^2 * 2^258 * q^n.
threshold=(K*K)*(1<<258)*pow(q,n)
m_new=next(m for m in range(w,m_old+1) if source_cardinality(m)>=threshold)
check(m_new==4469,'minimum m mismatch')
check(source_cardinality(m_new)>=threshold,'statistical predicate fails')
check(source_cardinality(m_new-1)<threshold,'m-1 unexpectedly sufficient')
check(2*B*(w+1) < q//(1<<ell),'decoding safety inequality fails')
check(q-((1<<ell)-1)*(q//(1<<ell))>2*B*(w+1),'circular endpoint gap fails')
check(m_new<m_old,'no width decrease')
check(source_cardinality(m_new)>pow(q,n),'no public target preimage entropy')

# Exact upper bound WITHOUT floating roundoff: K/2 * sqrt((q^n-1)/T) <= 2^-130
check(K*K*(pow(q,n)-1)*(1<<258) <= source_cardinality(m_new),'precise TV inequality fails')
# Union-bound on failure of any independently uniform target having zero T-preimages.
# K*q^n/|T| <= 2^-256 (the actual bound is much better).
check(K*pow(q,n)*(1<<256) <= source_cardinality(m_new),'preimage existence union bound fails')

A_old=N*n*m_old*3
A_new=N*n*m_new*3
U=N*C*n*L*3
ct_old=N*C*J*(m_old+L)*3
ct_new=N*C*J*(m_new+L)*3
check(A_old+U==36_864_000,'baseline SOURCE bytes')
check(A_new+U==29_703_168,'new SOURCE bytes')
check(ct_old==16_444_800,'baseline ciphertext bytes')
check(ct_new==10_850_400,'new ciphertext bytes')
check((A_old+U+ct_old)==53_308_800,'baseline aggregate')
check((A_new+U+ct_new)==40_553_568,'new aggregate')

# Exhaustively check the linear, exact QPT-safe projection of ordinary LWE:
# discard extra independently noisy A-coordinate samples, retain U coordinate.
# q_toy=5, n_toy=1, m_old=3, m_new=2, L=1, error {-1,0,1}.
qt=5
longM=[1,2,3,4]    # A_old length 3 and U last
shortM=[1,2,4]     # A_new length 2 and U last
long=Counter()
short=Counter()
for r in range(qt):
    for e0 in (-1,0,1):
        for e1 in (-1,0,1):
            for e2 in (-1,0,1):
                for e3 in (-1,0,1):
                    v=tuple((longM[i]*r+e)%qt for i,e in enumerate((e0,e1,e2,e3)))
                    long[(v[0],v[1],v[3])]+=1
            for e3 in (-1,0,1):
                v=tuple((shortM[i]*r+e)%qt for i,e in enumerate((e0,e1,e3)))
                short[v]+=1
check(len(long)>0 and len(short)>0,'empty distributions')
check(set(long)==set(short),'distribution support mismatch')
for sample,count in short.items():
    check(long[sample]==3*count,('projection measure mismatch',sample))

# Existing SOURCE release law: distinct legal openings get SAME precommitted bit.
# Toy modulus supports deterministic signed-short decoding with w=2, B=1.
qt=97; g=qt//2; A=[1,1,2,2,0,0]
z1=(1,-1,0,0,0,0)
z2=(0,0,1,-1,0,0)
check(sum(a*z for a,z in zip(A,z1))%qt==0,'first source opening')
check(sum(a*z for a,z in zip(A,z2))%qt==0,'second source opening')
check(z1!=z2 and sum(abs(v) for v in z1)==2 and sum(abs(v) for v in z2)==2,'distinct constant-weight')
check(g>2*(2+1),'toy correctness gap')
random.seed(20261030)
for bit in (0,1):
  for j in range(100):
    r=random.randrange(qt)
    eta=[random.randint(-1,1) for i in A]
    etd=random.randint(-1,1)
    c=[(a*r+e)%qt for a,e in zip(A,eta)]
    d=(etd+g*bit)%qt
    for z in (z1,z2):
        phase=(d-sum(zi*ci for zi,ci in zip(z,c)))%qt
        dist=lambda val,ctr:min((val-ctr)%qt,(ctr-val)%qt)
        decoded=min((0,1),key=lambda b:dist(phase,g*b))
        check(decoded==bit,'incorrect release')

# Check target independent U cannot be shared cross-claim: if a SOURCE z for same A,U
# is disclosed, it decrypts another capsule even if that capsule uses different secret.
for bit in (0,1):
  r=random.randrange(qt)
  eta=[random.randint(-1,1) for _ in A]
  etd=random.randint(-1,1)
  c=[(a*r+e)%qt for a,e in zip(A,eta)]
  d=(etd+g*bit)%qt
  phase=(d-sum(zi*ci for zi,ci in zip(z1,c)))%qt
  dist=lambda val,ctr:min((val-ctr)%qt,(ctr-val)%qt)
  check(min((0,1),key=lambda b:dist(phase,g*b))==bit,'cross-claim leakage regression')

result={
 'record':'shared_A_min_width_20261030',
 'status':'positive efficiency of restricted SOURCE-only construction, no ORIGINAL WKEM',
 'parameters':{'q':q,'n':n,'m_old':m_old,'m_new':m_new,'w':w,'B':B,'ell':ell,'L':L,'N':N,'C':C,'J':J,'K':K},
 'entropy_excess_bits':{'old':round(log2(source_cardinality(m_old))-n*log2(q),9),'new':round(log2(source_cardinality(m_new))-n*log2(q),9),'previous_width':round(log2(source_cardinality(m_new-1))-n*log2(q),9)},
 'tv_log2_upper_approx':round(log2(K)-1 - (log2(source_cardinality(m_new))-n*log2(q))/2,9),
 'zero_preimage_log2_union_upper_approx':round(log2(K) -(log2(source_cardinality(m_new))-n*log2(q)),9),
 'decoding':{'g':q//(1<<ell),'bound_twice':2*B*(w+1),'last_center_gap':q-((1<<ell)-1)*(q//(1<<ell))},
 'bytes':{'SOURCE_old':A_old+U,'SOURCE_new':A_new+U,'capsules_old':ct_old,'capsules_new':ct_new,'combined_old':A_old+U+ct_old,'combined_new':A_new+U+ct_new,'combined_saving_percent':round(100*(1-(A_new+U+ct_new)/(A_old+U+ct_old)),7),'matrix_width_reduction_percent':round(100*(1-m_new/m_old),7)},
 'exact_checks':checks,
 'toy_projection_long_outcomes':sum(long.values()),
 'toy_projection_short_outcomes':sum(short.values()),
 'toy_projection_support_size':len(short),
}
print(json.dumps(result,indent=2,sort_keys=True))
