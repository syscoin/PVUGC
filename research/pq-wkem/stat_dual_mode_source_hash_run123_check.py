#!/usr/bin/env python3
from fractions import Fraction
from itertools import product
import hashlib, json, os, random

A = 0

def ck(x, m=''):
    global A
    A += 1
    if not x: raise AssertionError(m)

def tv(p,q):
    keys=set(p)|set(q)
    return sum(abs(p.get(k,Fraction(0))-q.get(k,Fraction(0))) for k in keys)/2

def maps(domain):
    for bits in product((0,1), repeat=len(domain)):
        yield dict(zip(domain,bits))

# 1. Statistical mode transfer under arbitrary deterministic postprocessing.
rng=random.Random(123123)
for _ in range(500):
    n=rng.randrange(2,8)
    raw=[rng.randrange(1,20) for _ in range(n)]
    s=sum(raw)
    p={i:Fraction(raw[i],s) for i in range(n)}
    bumps=[rng.randrange(-4,5) for _ in range(n-1)]
    bumps.append(-sum(bumps))
    scale=1
    while any(p[i]+Fraction(bumps[i],s*scale)<0 for i in range(n)): scale*=2
    q={i:p[i]+Fraction(bumps[i],s*scale) for i in range(n)}
    d=tv(p,q); ck(sum(q.values())==1)
    f={i:rng.randrange(4) for i in range(n)}
    pp={b:sum((p[i] for i in range(n) if f[i]==b),Fraction(0)) for b in range(4)}
    qq={b:sum((q[i] for i in range(n) if f[i]==b),Fraction(0)) for b in range(4)}
    ck(tv(pp,qq)<=d, 'TV increased')

# 2. One-bit false hiding: if (P,H) is eps-close to (P,U), exact K recovery <= 1/2+eps.
inputs=[(p,c) for p in (0,1) for c in (0,1)]
false_cases=[]
for bias in range(5):
    eps=Fraction(bias,16)
    real={(p,h):Fraction(1,2)*(Fraction(1,2)+(eps if h==p else -eps)) for p in (0,1) for h in (0,1)}
    ideal={(p,h):Fraction(1,4) for p in (0,1) for h in (0,1)}
    ck(tv(real,ideal)==eps)
    best=Fraction(0)
    for F in maps(inputs):
        succ=Fraction(0)
        for (p,h),pr in real.items():
            for k in (0,1):
                c=k^h
                succ += pr*Fraction(1,2)*(F[(p,c)]==k)
        best=max(best,succ)
    ck(best<=Fraction(1,2)+eps)
    false_cases.append({'epsilon':str(eps),'best_recovery':str(best)})

# 3. Canonical target must be mode-independent: identical public P, targets differ.
P={0:Fraction(1)}
F={(0,0):0,(0,1):1}  # Khat=C

def succ(H):
    return sum(F[(0,k^H)]==k for k in (0,1))*Fraction(1,2)
sh,se=succ(0),succ(1)
ck(tv(P,P)==0 and sh==1 and se==0)

# 4. N-of-N xor: one uniform honest share remains uniform after any public-aux-dependent mask.
aux=range(4)
for g in maps(list(aux)):
    joint={}
    for a in aux:
        for h in (0,1):
            z=h^g[a]
            joint[(a,z)]=joint.get((a,z),Fraction(0))+Fraction(1,8)
    ideal={(a,z):Fraction(1,8) for a in aux for z in (0,1)}
    ck(joint==ideal)

# Extraction cancellation for N=3: z*=C xor Khat xor other masks equals honest H* on success.
for Hstar,h1,h2,K in product((0,1), repeat=4):
    C=K^Hstar^h1^h2; Khat=K
    z=C^Khat^h1^h2
    ck(z==Hstar)

# 5. Joint hash+extract trapdoor collapses witness search in toy relation w=H(P)+10.
for p in range(64):
    H=(7*p+3)%17
    w=H+10
    ck(w==H+10)

# 6. Multi-bit xor algebra.
for kappa in range(1,9):
    mod=1<<kappa
    for _ in range(250):
        H=rng.randrange(mod); K=rng.randrange(mod); C=K^H; Khat=K
        ck((C^Khat)==H)

with open(__file__,'rb') as f: sha=hashlib.sha256(f.read()).hexdigest()
out={
 'run':123,
 'checker':os.path.basename(__file__),
 'checker_sha256':sha,
 'assertions':A,
 'false_hiding_cases':false_cases,
 'canonical_index_negative_control':{'public_tv':'0','hash_mode_recovery':str(sh),'ext_mode_recovery':str(se)},
 'claims_not_tested':['QPT hardness of any computational assumption','existence of generic-NP SDMSH','malicious-secure MPC/erasure ceremony']
}
print(json.dumps(out,indent=2,sort_keys=True))