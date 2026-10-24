#!/usr/bin/env python3
from __future__ import annotations
from fractions import Fraction
import hashlib, json, random
from collections import defaultdict

SEED = 0x41A5517E
rng = random.Random(SEED)


def parity(x: int) -> int:
    return x.bit_count() & 1


def rref_basis(vecs, n):
    rows = [v & ((1<<n)-1) for v in vecs if v]
    piv = 0
    for col in range(n-1, -1, -1):
        j = next((j for j in range(piv, len(rows)) if (rows[j]>>col)&1), None)
        if j is None:
            continue
        rows[piv], rows[j] = rows[j], rows[piv]
        for k in range(len(rows)):
            if k != piv and ((rows[k]>>col)&1):
                rows[k] ^= rows[piv]
        piv += 1
        if piv == len(rows):
            break
    rows = [r for r in rows if r]
    # deterministic sort by highest bit descending
    rows.sort(key=lambda x: x.bit_length(), reverse=True)
    return rows


def rank(vecs, n):
    return len(rref_basis(vecs,n))


def in_span(x, basis, n):
    return rank(list(basis)+[x], n) == rank(basis,n)


def enum_span(basis):
    basis = list(basis)
    out = [0]
    for b in basis:
        out += [x ^ b for x in out]
    return out


def random_basis(n, d):
    basis=[]
    while len(basis)<d:
        v=rng.randrange(1,1<<n)
        nb=rref_basis(basis+[v],n)
        if len(nb)>len(basis):
            basis=nb
    return basis


def sum_basis(a,b,n):
    return rref_basis(list(a)+list(b),n)


def exact_single_distribution(n,R,S,a,delta,k):
    # direct enumeration of U_R + (a+U_S) + k delta
    RR=enum_span(R); SS=enum_span(S)
    den=len(RR)*len(SS)
    d=defaultdict(Fraction)
    for r in RR:
        for s in SS:
            d[r^a^s^(delta if k else 0)] += Fraction(1,den)
    return dict(d)


def formula_single_distribution(n,R,S,a,delta,k):
    T=sum_basis(R,S,n); TT=enum_span(T)
    off=a^(delta if k else 0)
    p=Fraction(1,len(TT))
    return {off^t:p for t in TT}


def tv(P,Q):
    keys=set(P)|set(Q)
    return sum(abs(P.get(x,Fraction(0))-Q.get(x,Fraction(0))) for x in keys)/2


def normalize_weights(ints):
    s=sum(ints)
    return [Fraction(x,s) for x in ints]


def direct_mixture_distribution(n,R,components,delta,k):
    # component = (weight, a, S_basis)
    out=defaultdict(Fraction)
    RR=enum_span(R)
    for weight,a,S in components:
        SS=enum_span(S)
        den=len(RR)*len(SS)
        for r in RR:
            for s in SS:
                out[r^a^s^(delta if k else 0)] += weight*Fraction(1,den)
    return dict(out)


def public_likelihood(x,k,n,R,components,delta):
    z=x^(delta if k else 0)
    ans=Fraction(0)
    for weight,a,S in components:
        T=sum_basis(R,S,n)
        if in_span(z^a,T,n):
            ans += weight*Fraction(1,1<<len(T))
    return ans


def formula_mixture_distribution(n,R,components,delta,k):
    return {x:public_likelihood(x,k,n,R,components,delta)
            for x in range(1<<n)
            if public_likelihood(x,k,n,R,components,delta)}


def map_success(P0,P1):
    keys=set(P0)|set(P1)
    # uniform prior
    return sum(max(P0.get(x,Fraction(0)),P1.get(x,Fraction(0))) for x in keys)/2


def decoder_success(P0,P1,dec):
    # uniform prior K
    s=Fraction(0)
    for x,p in P0.items():
        if dec(x)==0: s += p/2
    for x,p in P1.items():
        if dec(x)==1: s += p/2
    return s


def apply_linear(cols,x):
    y=0; i=0
    while x:
        if x&1: y ^= cols[i]
        x >>= 1; i += 1
    return y


def random_invertible_cols(n):
    while True:
        cols=[rng.randrange(1,1<<n) for _ in range(n)]
        if rank(cols,n)==n:
            return cols


def inverse_map_table(cols,n):
    tab={apply_linear(cols,x):x for x in range(1<<n)}
    assert len(tab)==1<<n
    return tab

single_cases=0
single_equal=0
single_disjoint=0
single_membership_decoder_checks=0
for n in range(4,10):
    for _ in range(70):
        dr=rng.randrange(0,min(n,4)+1)
        ds=rng.randrange(0,min(n,5)+1)
        R=random_basis(n,dr); S=random_basis(n,ds)
        a=rng.randrange(1<<n); delta=rng.randrange(1,1<<n)
        P0=exact_single_distribution(n,R,S,a,delta,0)
        P1=exact_single_distribution(n,R,S,a,delta,1)
        F0=formula_single_distribution(n,R,S,a,delta,0)
        F1=formula_single_distribution(n,R,S,a,delta,1)
        assert P0==F0 and P1==F1
        T=sum_basis(R,S,n)
        v=tv(P0,P1)
        if in_span(delta,T,n):
            assert v==0
            single_equal += 1
        else:
            assert v==1
            single_disjoint += 1
            # Public decoder: membership in a+T versus a+delta+T
            for x in P0:
                assert in_span(x^a,T,n)
                assert not in_span(x^a^delta,T,n)
                single_membership_decoder_checks += 1
            for x in P1:
                assert not in_span(x^a,T,n)
                assert in_span(x^a^delta,T,n)
                single_membership_decoder_checks += 1
        single_cases += 1

mixture_cases=0
mixture_likelihood_points=0
mixture_decoder_comparisons=0
mixture_strict_map=0
scramble_cases=0
examples=[]
for n in range(5,9):
    for _ in range(45):
        R=random_basis(n,rng.randrange(0,min(n,3)+1))
        M=rng.randrange(2,7)
        weights=normalize_weights([rng.randrange(1,10) for _ in range(M)])
        components=[]
        for i in range(M):
            S=random_basis(n,rng.randrange(0,min(n,4)+1))
            a=rng.randrange(1<<n)
            components.append((weights[i],a,S))
        delta=rng.randrange(1,1<<n)
        P0=direct_mixture_distribution(n,R,components,delta,0)
        P1=direct_mixture_distribution(n,R,components,delta,1)
        F0=formula_mixture_distribution(n,R,components,delta,0)
        F1=formula_mixture_distribution(n,R,components,delta,1)
        assert P0==F0 and P1==F1
        for x in range(1<<n):
            assert public_likelihood(x,0,n,R,components,delta)==P0.get(x,Fraction(0))
            assert public_likelihood(x,1,n,R,components,delta)==P1.get(x,Fraction(0))
            mixture_likelihood_points += 2
        ms=map_success(P0,P1)
        # Compare to random public/witness-like deterministic decoders.
        decs=[]
        for __ in range(12):
            table=[rng.randrange(2) for _ in range(1<<n)]
            decs.append(lambda x,t=table:t[x])
        for __ in range(12):
            w=rng.randrange(1,1<<n); c=rng.randrange(2)
            decs.append(lambda x,w=w,c=c:parity(w & x)^c)
        for dec in decs:
            ds=decoder_success(P0,P1,dec)
            assert ds <= ms
            mixture_decoder_comparisons += 1
            if ds < ms: mixture_strict_map += 1
        # public invertible scramble preserves exact TV and MAP
        cols=random_invertible_cols(n); inv=inverse_map_table(cols,n)
        Q0={apply_linear(cols,x):p for x,p in P0.items()}
        Q1={apply_linear(cols,x):p for x,p in P1.items()}
        assert tv(Q0,Q1)==tv(P0,P1)
        assert map_success(Q0,Q1)==ms
        # exact likelihood after inverse agrees
        for y in set(Q0)|set(Q1):
            x=inv[y]
            assert Q0.get(y,Fraction(0))==public_likelihood(x,0,n,R,components,delta)
            assert Q1.get(y,Fraction(0))==public_likelihood(x,1,n,R,components,delta)
        scramble_cases += 1
        if len(examples)<6:
            examples.append({
                'n':n,'components':M,'rank_R':len(R),
                'tv':str(tv(P0,P1)), 'map_success':str(ms),
                'support0':len(P0),'support1':len(P1)})
        mixture_cases += 1

# A deterministic dense example: n=16, R dim 4, S dim 10, so each key law has 2^rank(T)
# support. We don't enumerate pair representation; enumerate T only.
n=16
R=random_basis(n,4); S=random_basis(n,10); a=rng.randrange(1<<n)
T=sum_basis(R,S,n)
# choose delta outside T to ensure the all-or-nothing public break
while True:
    delta=rng.randrange(1,1<<n)
    if not in_span(delta,T,n): break
P0=formula_single_distribution(n,R,S,a,delta,0)
P1=formula_single_distribution(n,R,S,a,delta,1)
assert tv(P0,P1)==1
large_dense={
    'n':n,'rank_R':len(R),'rank_S':len(S),'rank_R_plus_S':len(T),
    'support_per_key':len(P0),'tv':'1','public_membership_decoder':'perfect'
}

result={
 'seed':SEED,
 'single_subspace':{
   'cases':single_cases,'equal_cases':single_equal,'disjoint_cases':single_disjoint,
   'membership_decoder_point_checks':single_membership_decoder_checks,
   'claim':'TV is exactly 0 iff delta in R+S, else exactly 1'
 },
 'polynomial_affine_mixtures':{
   'cases':mixture_cases,'exact_likelihood_coordinates_checked':mixture_likelihood_points,
   'decoder_comparisons':mixture_decoder_comparisons,
   'strict_map_improvements':mixture_strict_map,
   'scramble_cases':scramble_cases,
   'claim':'public exact MAP from affine-subspace membership dominates every tested decoder; public invertible scrambles preserve likelihood after inversion',
   'examples':examples
 },
 'large_dense_control':large_dense,
 'scope_note':'Finite tests validate algebra/implementation only. They are not a cryptographic security claim.'
}
blob=json.dumps(result,sort_keys=True,indent=2).encode()
result['json_payload_sha256_before_self_field']=hashlib.sha256(blob).hexdigest()
print(json.dumps(result,sort_keys=True,indent=2))
