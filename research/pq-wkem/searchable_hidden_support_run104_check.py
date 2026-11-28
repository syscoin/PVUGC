#!/usr/bin/env python3
from __future__ import annotations

from itertools import product
from fractions import Fraction
from collections import defaultdict
import json, math

def span(vs):
    out={0}
    for v in vs:
        out |= {x^v for x in list(out)}
    return frozenset(out)

def all_subspaces_dim(n,d):
    subs=set()
    vecs=list(range(1,1<<n))
    def rec(gens):
        if len(gens)==d:
            subs.add(span(gens))
            return
        sg=span(gens)
        for v in vecs:
            if v not in sg:
                rec(gens+[v])
    rec([])
    return sorted(subs,key=lambda s:tuple(sorted(s)))

def orth(U,n):
    return frozenset(
        x for x in range(1<<n)
        if all(((x&u).bit_count()&1)==0 for u in U)
    )

def mat(cols,n):
    x=0
    for j,v in enumerate(cols):
        x |= v << (j*n)
    return x

def cols(M,n,c):
    mask=(1<<n)-1
    return tuple((M>>(j*n))&mask for j in range(c))

def rank_cols(M,n,c):
    vs=list(cols(M,n,c))
    rows=[0]*n
    for j,v in enumerate(vs):
        for i in range(n):
            if (v>>i)&1:
                rows[i] |= 1<<j
    r=0
    for col in range(c):
        p=next((i for i in range(r,n) if (rows[i]>>col)&1),None)
        if p is None:
            continue
        rows[r],rows[p]=rows[p],rows[r]
        for i in range(n):
            if i!=r and ((rows[i]>>col)&1):
                rows[i]^=rows[r]
        r+=1
    return r

def perp_code(C,bits):
    return frozenset(
        x for x in range(1<<bits)
        if all(((x&y).bit_count()&1)==0 for y in C)
    )

def WU(U,n,c):
    return frozenset(mat(cs,n) for cs in product(U,repeat=c))

def sumsp(A,B):
    return frozenset(a^b for a in A for b in B)

def KU(C,U,n,c):
    Up=orth(U,n)
    return frozenset(
        y for y in C
        if all(col in Up for col in cols(y,n,c))
    )

checks=[]
def ok(name, cond, detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    checks.append({"name":name,"detail":detail})

# ------------------------------------------------------------------
# Run-103 exact tiny fixture: 3x2 binary matrices, D=2, dim(U)=2.
# ------------------------------------------------------------------
n=3; c=2; D=2; m=n-D+1
Us=all_subspaces_dim(n,m)
ok("seven_hidden_subspaces",len(Us)==7,len(Us))

e0=1
T1=mat((e0,0),n)
T2=mat((0,e0),n)
Ctrue=span([T1,T2])

F1=mat((1,2),n)
F2=mat((2,3),n)
Cfalse=span([F1,F2])

ok("true_all_nonzero_rank1",
   all(rank_cols(y,n,c)==1 for y in Ctrue if y))
ok("false_all_nonzero_rank2",
   all(rank_cols(y,n,c)==2 for y in Cfalse if y))

# Searchable-support probability p_x = Pr_U[K_U != 0].
def searchable_profile(C):
    rec=[]
    for i,U in enumerate(Us):
        K=KU(C,U,n,c)
        for y in K:
            if y:
                ok(f"ku_low_rank_{len(checks)}",rank_cols(y,n,c)<D,
                   (i,y,rank_cols(y,n,c)))
        rec.append((i,len(K),K))
    p=Fraction(sum(1 for _,sz,_ in rec if sz>1),len(rec))
    return p,rec

p_true, prof_true = searchable_profile(Ctrue)
p_false, prof_false = searchable_profile(Cfalse)
ok("true_search_probability",p_true==Fraction(1,7),p_true)
ok("false_search_probability_zero",p_false==0,p_false)

# ------------------------------------------------------------------
# Exact public bundle distributions for the true fixture.
# Bundle: hidden U, public uniform H, T independent D_t uniform on
# S_U=C^perp+W_U, C_t=D_t+bH.
# Check T=1 and T=2. TV is <= p_x exactly.
# ------------------------------------------------------------------
ambient=list(range(1<<(n*c)))
Cperp=perp_code(Ctrue,n*c)

def bundle_dist(bit,T):
    out=defaultdict(Fraction)
    for U in Us:
        S=sumsp(Cperp,WU(U,n,c))
        pU=Fraction(1,len(Us))
        pH=Fraction(1,len(ambient))
        pD=Fraction(1,len(S)**T)
        for H in ambient:
            for Ds in product(S,repeat=T):
                Cs=tuple(d ^ (H if bit else 0) for d in Ds)
                out[(H,)+Cs] += pU*pH*pD
    return out

tv_records=[]
for T in (1,2):
    P0=bundle_dist(0,T)
    P1=bundle_dist(1,T)
    keys=set(P0)|set(P1)
    tv=sum(abs(P0.get(k,0)-P1.get(k,0)) for k in keys)/2
    ok(f"bundle_tv_le_search_T{T}",tv<=p_true,(tv,p_true))
    ok(f"bundle_tv_exact_T{T}",tv==Fraction(3,28),(T,tv))
    tv_records.append({"T":T,"TV":str(tv),"search_probability":str(p_true)})

# False fixture: every S_U is full ambient, hence exact identity.
Cfalse_perp=perp_code(Cfalse,n*c)
for i,U in enumerate(Us):
    S=sumsp(Cfalse_perp,WU(U,n,c))
    ok(f"false_full_mask_{i}",len(S)==len(ambient),len(S))

# ------------------------------------------------------------------
# Correctness -> searchable-support lower bound.
# If L independent bundles have decoding success >= 1/2+eta, then
# 2 eta <= TV(P0^L,P1^L) <= 1-(1-p)^L.
# Thus p >= 1-(1-2eta)^(1/L).
# Check numerical and Bernoulli lower bound p >= 2eta/L.
# ------------------------------------------------------------------
corr_rows=[]
for L in (1,2,4,8,16,64):
    for eta in (Fraction(1,10),Fraction(1,4),Fraction(49,100)):
        if 2*eta>=1:
            continue
        exact=1-float(1-2*eta)**(1.0/L)
        simple=float(2*eta)/L
        ok(f"correctness_bound_{L}_{eta}",exact+1e-15>=simple,(exact,simple))
        corr_rows.append({
            "L":L,"eta":str(eta),
            "p_search_exact_lower":exact,
            "p_search_simple_lower":simple,
            "expected_trials_upper_from_simple":1.0/simple
        })

# Apply to tiny fixture: with p=1/7 and L=4, any decoder success is
# at most 1/2*(1+1-(6/7)^4).
for L in (1,2,4,8):
    tv_upper=1-(1-float(p_true))**L
    success_upper=(1+tv_upper)/2
    corr_rows.append({
        "fixture_L":L,
        "fixture_success_upper":success_upper,
        "fixture_tv_upper":tv_upper
    })

# ------------------------------------------------------------------
# Hair-Sahai binary scalar-descent ledger from published interface.
# If practical hidden-subspace correctness made L polynomial, the public
# randomized witness search has comparable expected trial count.
# ------------------------------------------------------------------
hs=[]
for N in (8,16,32,64):
    R=int(math.floor(math.log2(N)))
    alpha=(2**R-1)/(2**(N+1)-1)
    expected=1/alpha
    # Lower bound L for merely 2/3 bit-success from TV<=1-(1-p)^L,
    # using p>=alpha only as the honest rank-one good-event benchmark.
    # This is a benchmark, not the generic p_x theorem.
    L23=math.log(1/3)/math.log1p(-alpha)
    hs.append({
        "N":N,"R":R,"alpha_rank1":alpha,
        "public_search_expected_trials_if_p_equals_alpha":expected,
        "bundles_needed_for_2_over_3_if_only_alpha_events_carry_signal":L23
    })
ok("hs_expected_trials_increasing",
   all(hs[i]["public_search_expected_trials_if_p_equals_alpha"]
       < hs[i+1]["public_search_expected_trials_if_p_equals_alpha"]
       for i in range(len(hs)-1)))

# ------------------------------------------------------------------
# Generic one-sided decision implication sanity:
# NO: p=0. YES with success advantage eta and polynomial L:
# p >= 2eta/L, so O(L/eta) public samples give constant witness-search
# success. Verify repetition success >= 1-exp(-2) for R=ceil(L/eta)
# under p=2eta/L when feasible.
# ------------------------------------------------------------------
rp_rows=[]
for L in (10,100,1000):
    eta=0.25
    p=2*eta/L
    R=math.ceil(L/eta)
    succ=1-(1-p)**R
    ok(f"rp_constant_success_{L}",succ>1-math.exp(-1.9),succ)
    rp_rows.append({"L":L,"eta":eta,"p_lower":p,
                    "trials":R,"success_from_lower_bound":succ})

out={
    "run":104,
    "status":"PASS",
    "total_assertions":len(checks),
    "fixture":{
        "q":2,"n":n,"c":c,"D":D,"hidden_subspace_dim":m,
        "true_search_probability":str(p_true),
        "false_search_probability":str(p_false),
        "bundle_tv":tv_records
    },
    "correctness_search_rows":corr_rows,
    "hair_sahai_benchmark":hs,
    "rp_rows":rp_rows,
    "scope":[
        "Finite controls for the searchable-support theorem and exact tiny bundle distributions.",
        "The theorem itself is linear-algebraic and proved in the accompanying note.",
        "NP subset RP is a conditional complexity consequence of a generic polynomial-time instantiation, not a claimed established collapse.",
        "This run does not retry previously safety-blocked Run 100-103 publication payloads."
    ]
}
print(json.dumps(out,indent=2,sort_keys=True))
