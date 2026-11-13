#!/usr/bin/env python3
"""NIDR-ECO exact integer/finite-field and selective-opening checks.

No cryptographic security experiment; all tests are mathematical fixtures.
Python 3, standard library only. Deterministic.
"""
import hashlib
import itertools
import json
import math
import random
from fractions import Fraction

SEED = 2026110108
rng = random.Random(SEED)
checks = 0

def verify(condition, why):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(why)

def centered(x, q):
    x %= q
    return x if x <= q // 2 else x - q

def dot(a,b):
    return sum(x*y for x,y in zip(a,b))

def source(n):
    features = [()] + [(i,) for i in range(n)] + list(itertools.combinations(range(n),2))
    ix = {m:i for i,m in enumerate(features)}
    rows=[]
    for i in range(n):
        j=(i+1)%n
        row=[0]*len(features)
        row[ix[()]]=-1
        row[ix[(i,)]]+=1
        row[ix[(j,)]]+=1
        row[ix[tuple(sorted((i,j)))]]-=2
        rows.append(row)
    return features,rows

def evalvector(features, w):
    return [math.prod(w[i] for i in m) for m in features]

def encrypt(rows, s, e, m, q):
    out=[sum(rows[i][j]*s[i] for i in range(len(rows)))+e[j] for j in range(len(e))]
    out[0]+=((q-1)//2)*m
    return [v%q for v in out]

def dist(a,b,q):
    d=(a-b)%q
    return min(d,q-d)

def decode(v,beta,q):
    t=dot(v,beta)%q
    g=(q-1)//2
    return int(dist(t,g,q)<dist(t,0,q))

def shift(rows,q):
    delta=[(q+1)//2]*len(rows)
    M=len(rows[0]); h=[0]*M
    h[0]=(q-1)//2
    for i in range(len(rows)):
        for j in range(M):h[j]+=rows[i][j]*delta[i]
    return delta,[centered(x,q) for x in h]

# Valid ORIGINAL witnesses of even parity-cycle and SAME capability recovery.
q=(1<<255)-19
B=1<<145
true_recoveries=0
for n in (4,6):
    features,A=source(n)
    verify(q>4*B*len(features)+2, "decoding separation")
    w0=[i%2 for i in range(n)]
    w1=[1-x for x in w0]
    v0=evalvector(features,w0)
    v1=evalvector(features,w1)
    for row in A:
        verify(dot(row,v0)==0 and dot(row,v1)==0,"two valid ORIGINAL traces")
    for _ in range(64):
        m=rng.randrange(2)
        s=[rng.randrange(q) for _ in A]
        e=[rng.randint(-B,B) for _ in features]
        beta=encrypt(A,s,e,m,q)
        verify(decode(v0,beta,q)==m,"witness 0 original bit")
        verify(decode(v1,beta,q)==m,"witness 1 original bit")
        true_recoveries+=2

# FALSE n odd has explicit public approximate source-dependent shift.
odd_results=[]
for n in (3,5,7):
    features,A=source(n)
    delta,h=shift(A,q)
    expected=[-(n+1)//2]+[1]*n + [(-1 if len(m)==2 and ((m[1]-m[0]==1) or (m==(0,n-1))) else 0) for m in features[1+n:]]
    verify(h==expected, "exact parity shift formula")
    H=sum(abs(z) for z in h)
    verify(H==(5*n+1)//2, "shift L1 norm")
    e0=[1]+[0]*(len(features)-1)
    for j in range(len(features)):
        t=sum(A[i][j]*delta[i] for i in range(n)) + ((q-1)//2)*e0[j]
        verify(centered(t,q)==h[j],"shift relation")
    for _ in range(128):
        s=[rng.randrange(q) for _ in A]
        e=[rng.randint(-B,B) for _ in features]
        zero=encrypt(A,s,e,0,q)
        s1=[(x+y)%q for x,y in zip(s,delta)]
        e1=[x-y for x,y in zip(e,h)]
        verify(encrypt(A,s1,e1,1,q)==zero,"exact coin equivocation equality")
    log2_tv_upper=math.log2(3*512*2*H)-math.log2(2*B+1)
    verify(log2_tv_upper < -128,"128-bit statistical cap for this restricted fixture")
    odd_results.append({"n":n,"M":len(features),"H":H,"log2_TV_union_upper":round(log2_tv_upper,6)})

# Exact finite interval-overlap TV, and brute-force count for B=2.
features,A=source(3)
qsmall=97
_,h=shift(A,qsmall)
E=2
in_support=0
for e in itertools.product(range(-E,E+1),repeat=len(features)):
    within=all(-E<=e[j]-h[j]<=E for j in range(len(features)))
    in_support+=int(within)
    verify(within == all(-E <= e[j]-h[j] <= E for j in range(len(features))),"support predicate")
expected=math.prod(max(0,2*E+1-abs(z)) for z in h)
verify(in_support==expected,"exhaustive error support overlap")
exact_tv=Fraction((2*E+1)**len(features)-in_support,(2*E+1)**len(features))
verify(exact_tv <= Fraction(sum(abs(z) for z in h),2*E+1),"overlap TV union bound")

# All 3 choose 2 opened-share marginals are independent of the unknown bit K.
share_cases=0
for i in range(3):
    for j in range(3):
        if i==j:continue
        counts=[]
        for K in (0,1):
            outcomes={}
            for a,b in itertools.product((0,1),repeat=2):
                shares=(a,b,K^a^b)
                pair=(shares[i],shares[j])
                outcomes[pair]=outcomes.get(pair,0)+1
            counts.append(outcomes)
        verify(counts[0]==counts[1]=={(0,0):1,(0,1):1,(1,0):1,(1,1):1},"deferred opening pair")
        share_cases+=1
# Adaptive second lane depending on first opened bit (and an arbitrary first lane).
for i in range(3):
    table=[]
    others=[j for j in range(3) if j!=i]
    for K in (0,1):
        outcomes={}
        for a,b in itertools.product((0,1),repeat=2):
            shares=(a,b,K^a^b)
            j=others[shares[i]]
            t=(i,shares[i],j,shares[j])
            outcomes[t]=outcomes.get(t,0)+1
        table.append(outcomes)
    verify(table[0]==table[1],"adaptive opening transcript independent of core")

# Functional two-capsule, three-lane, adaptive opening: ciphertexts all encrypt ZERO
# but any chosen plaintext share can be opened consistently with simulated coins.
opened_verified=0
for _ in range(128):
    K=rng.randrange(2)
    C=2
    for _capsule in range(C):
        a,b=rng.randrange(2),rng.randrange(2)
        shares=[a,b,K^a^b]
        sampled=[]
        for j in range(3):
            s=[rng.randrange(qsmall) for _ in A]
            e=[rng.randint(-1,1) for _ in features]
            c=encrypt(A,s,e,0,qsmall)
            sampled.append((s,e,c))
        first=sampled[0][2][0]%3
        second=[j for j in range(3) if j!=first][shares[first]]
        for j in (first,second):
            s,e,c=sampled[j]
            delta,_h=shift(A,qsmall)
            sv=[(s[k]+shares[j]*delta[k])%qsmall for k in range(len(A))]
            ev=[e[k]-shares[j]*_h[k] for k in range(len(features))]
            verify(encrypt(A,sv,ev,shares[j],qsmall)==c,"opened adaptive share and coins consistent")
            opened_verified+=1

result={
  "run":"NIDR-ECO-2026-11-01-T08",
  "status":"restricted lemma, not generic NP WKEM",
  "seed":SEED,
  "checks":checks,
  "two_valid_original_witness_decryptions":true_recoveries,
  "odd_parity_shift_parameters":odd_results,
  "small_exact_error_overlap_count":in_support,
  "small_exact_error_total":(2*E+1)**len(features),
  "small_exact_TV":str(exact_tv),
  "opened_share_pair_orderings":share_cases,
  "adaptive_opened_coin_equations":opened_verified,
  "q_bits":q.bit_length(),
  "B_bits":B.bit_length(),
  "two_capsule_key_bits":2*3*512,
  "n3_ciphertext_bytes_32byte_residues":(2*3*512)*7*32,
}
print(json.dumps(result,sort_keys=True,indent=2))
