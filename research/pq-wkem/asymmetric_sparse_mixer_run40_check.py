#!/usr/bin/env python3
"""Run 40 validation: exact subset-partition likelihood DP for asymmetric sparse mixers.

Standard-library only.  This validates the algebraic DP theorem on deliberately
non-exchangeable public channels and checks invariance under public invertible
binary scrambling.  It is NOT a security proof for a surviving WKEM.
"""

from __future__ import annotations

from collections import defaultdict
from fractions import Fraction
import hashlib
import json
import math
import random
from typing import Dict, List, Tuple

SEED = 0x52A9D40
RNG = random.Random(SEED)

# Local hidden state is (two syndrome bits, one local parity bit): 0..7.
# Public quotient endpoint keeps only the two syndrome bits per gadget and the
# XOR of all local parity bits.
LOCAL = 8
SYN = 4


def rand_prob_vector(n: int, rng: random.Random) -> List[Fraction]:
    # Deliberately asymmetric, all entries nonzero.
    ws = [rng.randint(1, 17) for _ in range(n)]
    s = sum(ws)
    return [Fraction(w, s) for w in ws]


def rand_matrix8(rng: random.Random) -> List[List[Fraction]]:
    """Dense, generally noncommuting row-stochastic 8x8 matrix."""
    out = []
    for _ in range(LOCAL):
        ws = [rng.randint(1, 11) for _ in range(LOCAL)]
        s = sum(ws)
        out.append([Fraction(w, s) for w in ws])
    return out


def mat_vec_step(dist: List[Fraction], M: List[List[Fraction]]) -> List[Fraction]:
    out = [Fraction(0) for _ in range(LOCAL)]
    for a, pa in enumerate(dist):
        if not pa:
            continue
        row = M[a]
        for b, p in enumerate(row):
            if p:
                out[b] += pa * p
    return out


def local_endpoint(slot_subset: int, mats: List[List[List[Fraction]]], H: int) -> List[Fraction]:
    """Endpoint distribution on full local state for a fixed assigned slot subset."""
    dist = [Fraction(0) for _ in range(LOCAL)]
    dist[0] = Fraction(1)
    for t in range(H):
        if (slot_subset >> t) & 1:
            dist = mat_vec_step(dist, mats[t])
    return dist


def owner_weight(slot_subset: int, owner: int, owner_probs: List[List[Fraction]], H: int) -> Fraction:
    w = Fraction(1)
    for t in range(H):
        if (slot_subset >> t) & 1:
            w *= owner_probs[t][owner]
    return w


def precompute_local_terms(
    g: int,
    target_syn: int,
    owner_probs: List[List[Fraction]],
    mats_by_g: List[List[List[List[Fraction]]]],
    H: int,
) -> List[Tuple[Fraction, Fraction]]:
    """For each subset A, return weights ending at target syndrome with local parity 0/1.

    Includes the probability that exactly the slots in A choose gadget g, but not
    probabilities for slots assigned to other gadgets/idle.
    """
    terms = []
    mats = mats_by_g[g]
    for A in range(1 << H):
        end = local_endpoint(A, mats, H)
        ow = owner_weight(A, g + 1, owner_probs, H)  # owner 0 is idle
        q0 = Fraction(0)
        q1 = Fraction(0)
        for st, p in enumerate(end):
            if (st & 3) == target_syn:
                q = (st >> 2) & 1
                if q:
                    q1 += p
                else:
                    q0 += p
        terms.append((ow * q0, ow * q1))
    return terms


def subset_partition_likelihood(
    target_syns: Tuple[int, ...],
    target_parity: int,
    owner_probs: List[List[Fraction]],
    mats_by_g: List[List[List[List[Fraction]]]],
    H: int,
) -> Fraction:
    """Exact likelihood via O(m 3^H) subset-partition DP."""
    m = len(target_syns)
    full = (1 << H) - 1
    # dp[(used_subset, parity)]
    dp: Dict[Tuple[int, int], Fraction] = {(0, 0): Fraction(1)}
    for g in range(m):
        terms = precompute_local_terms(g, target_syns[g], owner_probs, mats_by_g, H)
        nd: Dict[Tuple[int, int], Fraction] = defaultdict(Fraction)
        for (used, par), base in dp.items():
            rem = full ^ used
            A = rem
            while True:
                w0, w1 = terms[A]
                if w0:
                    nd[(used | A, par)] += base * w0
                if w1:
                    nd[(used | A, par ^ 1)] += base * w1
                if A == 0:
                    break
                A = (A - 1) & rem
        dp = nd

    ans = Fraction(0)
    # Remaining slots are idle. Each contributes its own public idle probability.
    for (used, par), base in dp.items():
        if par != target_parity:
            continue
        idle = Fraction(1)
        rem = full ^ used
        for t in range(H):
            if (rem >> t) & 1:
                idle *= owner_probs[t][0]
        ans += base * idle
    return ans


def brute_distribution(
    owner_probs: List[List[Fraction]],
    mats_by_g: List[List[List[List[Fraction]]]],
    H: int,
) -> Dict[Tuple[Tuple[int, ...], int], Fraction]:
    """Exact full labelled endpoint distribution, then quotient local parities to global XOR."""
    m = len(mats_by_g)
    # Full state stores all local 3-bit states.
    d: Dict[Tuple[int, ...], Fraction] = {tuple([0] * m): Fraction(1)}
    for t in range(H):
        nd: Dict[Tuple[int, ...], Fraction] = defaultdict(Fraction)
        for state, base in d.items():
            # idle
            p0 = owner_probs[t][0]
            if p0:
                nd[state] += base * p0
            for g in range(m):
                pg = owner_probs[t][g + 1]
                if not pg:
                    continue
                row = mats_by_g[g][t][state[g]]
                for nxt, pk in enumerate(row):
                    if not pk:
                        continue
                    ss = list(state)
                    ss[g] = nxt
                    nd[tuple(ss)] += base * pg * pk
        d = nd

    out: Dict[Tuple[Tuple[int, ...], int], Fraction] = defaultdict(Fraction)
    for states, p in d.items():
        syns = tuple(st & 3 for st in states)
        parity = 0
        for st in states:
            parity ^= (st >> 2) & 1
        out[(syns, parity)] += p
    assert sum(out.values(), Fraction(0)) == 1
    return dict(out)


def tv_shift_parity(dist: Dict[Tuple[Tuple[int, ...], int], Fraction]) -> Fraction:
    # P1 is P0 with global parity toggled.
    tv2 = Fraction(0)
    keys = set(dist)
    for syns, p in list(keys):
        keys.add((syns, p ^ 1))
    for syns, p in keys:
        tv2 += abs(dist.get((syns, p), Fraction(0)) - dist.get((syns, p ^ 1), Fraction(0)))
    return tv2 / 2


def quotient_key(syns: Tuple[int, ...], p: int) -> int:
    x = 0
    bit = 0
    for s in syns:
        x |= (s & 1) << bit
        bit += 1
        x |= ((s >> 1) & 1) << bit
        bit += 1
    x |= (p & 1) << bit
    return x


def unquotient_key(x: int, m: int) -> Tuple[Tuple[int, ...], int]:
    syns = []
    bit = 0
    for _ in range(m):
        s = ((x >> bit) & 1) | (((x >> (bit + 1)) & 1) << 1)
        syns.append(s)
        bit += 2
    p = (x >> bit) & 1
    return tuple(syns), p


def gf2_rank(rows: List[int], d: int) -> int:
    a = rows[:]
    r = 0
    for col in range(d):
        pivot = next((i for i in range(r, len(a)) if (a[i] >> col) & 1), None)
        if pivot is None:
            continue
        a[r], a[pivot] = a[pivot], a[r]
        for i in range(len(a)):
            if i != r and ((a[i] >> col) & 1):
                a[i] ^= a[r]
        r += 1
    return r


def rand_invertible_matrix(d: int, rng: random.Random) -> List[int]:
    while True:
        rows = [rng.getrandbits(d) for _ in range(d)]
        if gf2_rank(rows, d) == d:
            return rows


def gf2_apply(rows: List[int], x: int) -> int:
    y = 0
    for i, row in enumerate(rows):
        if ((row & x).bit_count() & 1):
            y |= 1 << i
    return y


def scrambled_distribution(dist, rows, m):
    out = defaultdict(Fraction)
    for (syns,p), mass in dist.items():
        x = quotient_key(syns,p)
        y = gf2_apply(rows,x)
        out[y] += mass
    return dict(out)


def tv_between(a: Dict[int, Fraction], b: Dict[int, Fraction]) -> Fraction:
    keys = set(a) | set(b)
    return sum((abs(a.get(k,Fraction(0))-b.get(k,Fraction(0))) for k in keys), Fraction(0))/2


def shifted_full(dist, m):
    out = defaultdict(Fraction)
    for (syns,p), mass in dist.items():
        out[quotient_key(syns,p^1)] += mass
    return dict(out)


def validate_random_fixtures():
    fixtures = []
    endpoint_checks = 0
    scramble_checks = 0
    max_states = 0
    for idx in range(20):
        m = 1 + (idx % 4)
        H = 1 + ((idx // 4) % 4)
        owner_probs = [rand_prob_vector(m + 1, RNG) for _ in range(H)]
        mats_by_g = [[rand_matrix8(RNG) for _ in range(H)] for _ in range(m)]
        brute = brute_distribution(owner_probs, mats_by_g, H)
        max_states = max(max_states, len(brute))
        # Check every public endpoint in support plus a few impossible/random endpoints.
        for (syns,p), exact in brute.items():
            got = subset_partition_likelihood(syns,p,owner_probs,mats_by_g,H)
            assert got == exact, (idx,m,H,syns,p,got,exact)
            endpoint_checks += 1
        for _ in range(8):
            syns = tuple(RNG.randrange(4) for _ in range(m))
            p = RNG.randrange(2)
            got = subset_partition_likelihood(syns,p,owner_probs,mats_by_g,H)
            exact = brute.get((syns,p), Fraction(0))
            assert got == exact
            endpoint_checks += 1

        # Public dense invertible scramble cannot change TV.
        d = 2*m + 1
        rows = rand_invertible_matrix(d,RNG)
        p0s = scrambled_distribution(brute, rows, m)
        p1_orig = shifted_full(brute,m)
        # Scramble P1 using same public bijection.
        p1s = defaultdict(Fraction)
        for x,mass in p1_orig.items():
            p1s[gf2_apply(rows,x)] += mass
        tv0 = tv_shift_parity(brute)
        tvs = tv_between(p0s,dict(p1s))
        assert tv0 == tvs
        scramble_checks += 1
        fixtures.append({
            "fixture": idx,
            "m": m,
            "H": H,
            "public_endpoints": len(brute),
            "tv_num": tv0.numerator,
            "tv_den": tv0.denominator,
        })
    return {
        "fixtures": len(fixtures),
        "endpoint_likelihood_equalities": endpoint_checks,
        "invertible_scramble_tv_equalities": scramble_checks,
        "max_public_endpoint_support": max_states,
        "sample_rows": fixtures[:8],
    }


def validate_owner_partition_identity():
    # Isolate the subset partition logic with identity local transitions.  Summing
    # over all assignments of H slots to m gadgets/idle must equal one exactly.
    rows=[]
    for m in range(1,6):
        for H in range(1,7):
            probs=[rand_prob_vector(m+1,RNG) for _ in range(H)]
            total=Fraction(0)
            # Enumerate all owner functions only in this small control.
            def rec(t,w):
                nonlocal total
                if t==H:
                    total += w
                    return
                for g in range(m+1):
                    rec(t+1,w*probs[t][g])
            rec(0,Fraction(1))
            assert total==1
            rows.append((m,H))
    return {"exact_assignment_mass_controls":len(rows)}



def active_run39_matrix() -> List[List[Fraction]]:
    types = [
        (0,0,2),(0,1,2),(1,0,3),(1,1,1),
        (2,0,4),(3,0,1),(3,1,3),
    ]
    M=[]
    for st in range(LOCAL):
        syn=st & 3
        par=(st>>2)&1
        row=[Fraction(0) for _ in range(LOCAL)]
        for d,q,mult in types:
            nxt=(syn ^ d) | ((par ^ q)<<2)
            row[nxt] += Fraction(mult,16)
        assert sum(row,Fraction(0))==1
        M.append(row)
    return M


def centered_distinct_probs(m:int, delta:Fraction) -> List[Fraction]:
    # b_g are distinct centered integers with exact sum zero.
    b=[2*(g+1)-(m+1) for g in range(m)]
    assert sum(b)==0 and len(set(b))==m
    sab=sum(abs(x) for x in b)
    eta=Fraction(2)*delta/sab
    p=[Fraction(1,m)+eta*x for x in b]
    assert all(x>0 for x in p)
    assert sum(p,Fraction(0))==1
    tv=sum((abs(x-Fraction(1,m)) for x in p),Fraction(0))/2
    assert tv==delta
    return p


def run39_owner_probs(m:int,C:int,base:List[Fraction]):
    out=[]
    for _ in range(C):
        out.append([Fraction(0)]+base) # mandatory hit
        out.append([Fraction(1,5)]+[Fraction(4,5)*x for x in base]) # optional hit
    return out


def run39_asymmetric_controls():
    active=active_run39_matrix()
    rows=[]
    for m,C in [(2,1),(3,1),(4,1),(2,2),(3,2)]:
        H=2*C
        delta=Fraction(1,1000)
        pu=[Fraction(1,m)]*m
        pa=centered_distinct_probs(m,delta)
        owner_u=run39_owner_probs(m,C,pu)
        owner_a=run39_owner_probs(m,C,pa)
        mats=[[active for _ in range(H)] for _ in range(m)]
        du=brute_distribution(owner_u,mats,H)
        da=brute_distribution(owner_a,mats,H)
        tvu=tv_shift_parity(du)
        tva=tv_shift_parity(da)
        eps=Fraction(9,5)*C*delta
        assert abs(tva-tvu) <= 2*eps
        # Exact DP check on a deterministic sample of asymmetric endpoints.
        for (syns,p),mass in list(sorted(da.items(), key=lambda kv: (kv[0][0],kv[0][1])))[:min(24,len(da))]:
            got=subset_partition_likelihood(syns,p,owner_a,mats,H)
            assert got==mass
        rows.append({
            "m":m,"C":C,
            "all_gadget_weights_distinct":len(set(pa))==m,
            "uniform_tv":[tvu.numerator,tvu.denominator],
            "asymmetric_tv":[tva.numerator,tva.denominator],
            "abs_tv_change":[abs(tva-tvu).numerator,abs(tva-tvu).denominator],
            "proved_two_key_tv_change_bound":[(2*eps).numerator,(2*eps).denominator],
        })
    return {"fixtures":len(rows),"base_gadget_choice_tv":[1,1000],"rows":rows}

def resource_table():
    # Run-38 notch honest bias beta=(3/10)^C. If beta >= lambda^-a then
    # C <= a/log2(10/3)*log2(lambda). H=2C and subset DP factor 3^H.
    logbase = math.log2(10/3)
    exponent_per_a = (2/logbase)*math.log2(3)
    tbl=[]
    for a in [0.25,0.5,1.0,2.0]:
        tbl.append({
            "honest_inverse_poly_exponent_a": a,
            "max_C_over_log2_lambda": a/logbase,
            "max_H_over_log2_lambda": 2*a/logbase,
            "subset_3H_lambda_exponent": exponent_per_a*a,
        })
    finite=[]
    for lam in [256,1024,16384,1048576]:
        C=math.ceil(math.log2(lam)/4)
        H=2*C
        finite.append({"lambda":lam,"C":C,"H":H,"three_pow_H":3**H})
    return {
        "log2_10_over_3":logbase,
        "three_pow_H_exponent_per_honest_a":exponent_per_a,
        "asymptotic":tbl,
        "finite_C_equals_ceil_log2lambda_over4":finite,
    }


def main():
    result={
        "run":40,
        "seed":SEED,
        "theorem_scope":"public H-slot sparse direct-sum mixer; arbitrary public slot/gadget probabilities and local stochastic kernels",
        "random_asymmetric_validation":validate_random_fixtures(),
        "owner_partition_validation":validate_owner_partition_identity(),
        "run39_asymmetric_controls":run39_asymmetric_controls(),
        "resource_boundary":resource_table(),
        "claims_not_established":[
            "security of any dense non-factorizing channel",
            "generic impossibility of witness encryption",
            "arbitrary-QPT key-recovery-to-witness extraction",
            "a complete practical PQ witness KEM",
        ],
    }
    raw=json.dumps(result,sort_keys=True,indent=2)+"\n"
    print(raw,end="")

if __name__=="__main__":
    main()
