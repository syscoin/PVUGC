#!/usr/bin/env python3
"""Bounded offline checks for a shared-CRS ternary 3COL SOURCE certificate
and an adversarial-co-verifier/honest-last challenge. NOT a QPT experiment.
"""
import hashlib, random, json, math
from collections import Counter
from itertools import product, combinations
rng = random.Random(20261029)
checks = 0

def test(flag, why):
    global checks
    checks += 1
    if not flag:
        raise AssertionError(why)

kappa,t=4,14
mask=(1<<t)-1

def G(seed):
    return int.from_bytes(hashlib.shake_256(b'PVUGC late-share toy G v1'+bytes([seed])).digest(2),'big')&mask

vals=[G(r) for r in range(1<<kappa)]
diffs={a^b for a in vals for b in vals}
# Sample one pair of *globally shared* offsets, not one pair per vertex.
while True:
    s1,s2=rng.randrange(1<<t),rng.randrange(1<<t)
    if not (s1 in diffs or s2 in diffs or (s1^s2) in diffs):
        break
Delta=(0,s1,s2)
for r in range(1<<kappa):
    for color in range(3):
        C=G(r)^Delta[color]
        openings=[(alt,sp) for alt in range(3) for sp in range(1<<kappa) if (G(sp)^Delta[alt])==C]
        test(all(alt==color for alt,sp in openings), 'cross-color double-opened globally shared CRS')
        test((color,r) in openings,'honest opening absent')
# All 81 assignments of K4, all corrupt co-verifier shares, all fresh honest shares.
E=list(combinations(range(4),2)); ne=len(E)
max_good=0
for colors in product(range(3), repeat=4):
    good=[int(colors[a]!=colors[b]) for a,b in E]
    max_good=max(max_good,sum(good))
    for c in range(ne):
        cnt=0
        for h in range(ne):
            e=(c+h)%ne
            test(e in range(ne),'edge index outside range')
            cnt+=good[e]
        test(cnt<=ne-1,'false K4 passed all possible honest shares')
test(max_good==5,'wrong K4 best fixed coloring')
# Independent of commitments, any adaptive corrupt c(C) has identical
# (h,e) distribution under honest-last real and e*-first simulator when
# commitments are ideally perfectly hiding (the actual transition is via PRG).
policies=[lambda C:0,lambda C:C%ne,lambda C:(C*C+3)%ne,
          lambda C:(17*C+7)%ne,lambda C:((C^(C>>2))*5+1)%ne]
for idx,policy in enumerate(policies):
    for C in range(64):
        c=policy(C)
        real=Counter((h,(c+h)%ne) for h in range(ne))
        sim=Counter((((e-c)%ne),e) for e in range(ne))
        test(real==sim,'ideal single-round programming failed')
# A second adaptive challenge share can depend on the entire first transcript.
for C in range(12):
    c1=policies[C%len(policies)](C)
    for C2 in range(12):
        real=Counter()
        sim=Counter()
        for h1,h2 in product(range(ne),repeat=2):
            e1=(c1+h1)%ne
            c2=(C2*7+e1*3+h1*h1)%ne
            e2=(c2+h2)%ne
            real[(h1,e1,h2,e2)]+=1
        for e1,e2 in product(range(ne),repeat=2):
            h1=(e1-c1)%ne
            c2=(C2*7+e1*3+h1*h1)%ne
            h2=(e2-c2)%ne
            sim[(h1,e1,h2,e2)]+=1
        test(real==sim,'ideal adaptive two-round programming failed')
# One shared CRS: global opposite-color opening bound has NO factor M.
M=2048; K=256; T=898
per_position=3*M*T
shared=(M+2)*T
logbad=math.log2(3)+2*K-T
logbad_old=math.log2(3*M)+2*K-T
target_bits=128
kround=math.ceil(target_bits*math.log(2)/(-math.log(5/6)))
test(shared<per_position/2, 'shared CRS compression weaker than expected')
test(logbad<logbad_old,'no global statistical binding improvement')
test((5/6)**kround<=2**(-target_bits),'K4 soundness rounds insufficient')
print(json.dumps({
    'status':'PASS','assertions':checks,'seed':20261029,
    'toy':{'kappa':kappa,'t':t,'seed_space':2**kappa,
           'difference_set_size':len(diffs),'shared_sigma_offsets':[s1,s2],
           'color_assignments_K4':81,'corrupt_share_values':ne,
           'ideal_commitment_values':64,'adaptive_two_round_pairs':12**2},
    'illustrative':{'M':M,'kappa':K,'t':T,
        'prior_per_position_sigma_plus_commit_bits':per_position,
        'new_global_sigma_plus_commit_bits':shared,
        'relative_reduction':round(1-shared/per_position,8),
        'shared_CRS_bad_event_log2_bound':round(logbad,5),
        'prior_per_position_bad_event_log2_bound':round(logbad_old,5),
        'K4_rounds_for_at_least_128_bit_soundness_if_uniform_independent':kround},
    'scope':'algebraic enumerations and an IDEAL-HIDING transcript coupling; no QPT proof from tests, no ORIGINAL release, no concrete native PQ'
},indent=2,sort_keys=True))
