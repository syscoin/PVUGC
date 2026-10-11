#!/usr/bin/env python3
import itertools, random, json, hashlib, os, sys
from collections import Counter
from fractions import Fraction

SEED = 26092201
rng = random.Random(SEED)


def inv_mod(a, q):
    return pow(a % q, -1, q)


def rref(rows, q):
    if not rows:
        return [], []
    A = [[x % q for x in row] for row in rows]
    m, n = len(A), len(A[0])
    pivots = []
    r = 0
    for c in range(n):
        p = next((i for i in range(r, m) if A[i][c] % q), None)
        if p is None:
            continue
        A[r], A[p] = A[p], A[r]
        z = inv_mod(A[r][c], q)
        A[r] = [(z*x) % q for x in A[r]]
        for i in range(m):
            if i == r:
                continue
            f = A[i][c] % q
            if f:
                A[i] = [(A[i][j] - f*A[r][j]) % q for j in range(n)]
        pivots.append(c)
        r += 1
        if r == m:
            break
    return A, pivots


def rank(rows, q):
    if not rows:
        return 0
    return len(rref(rows, q)[1])


def in_span(v, rows, q):
    if not rows:
        return all((x % q) == 0 for x in v)
    return rank(rows, q) == rank(rows + [list(v)], q)


def affine_hull_contains(S, x, q):
    S = list(S)
    if not S:
        return False
    r = S[0]
    D = [[(s[i]-r[i]) % q for i in range(len(r))] for s in S[1:]]
    diff = [(x[i]-r[i]) % q for i in range(len(r))]
    return in_span(diff, D, q)


def affine_hull_points(S, q, d):
    return {x for x in itertools.product(range(q), repeat=d) if affine_hull_contains(S, x, q)}


def hull_intersection_nonempty(sets, q, d):
    pts = itertools.product(range(q), repeat=d)
    return any(all(affine_hull_contains(S, x, q) for S in sets) for x in pts)


def actual_intersection_nonempty(sets):
    it = iter(sets)
    try:
        z = set(next(it))
    except StopIteration:
        return False
    for S in it:
        z.intersection_update(S)
    return bool(z)


def obs_and_constraints(sets, q, d):
    T = len(sets)
    n = T + T*d
    rows = []
    for j, S in enumerate(sets):
        for x in S:
            row = [0]*n
            row[j] = 1
            off = T + j*d
            for t in range(d):
                row[off+t] = x[t] % q
            rows.append(row)
    # public setup relation sum_j a_j = 0
    for t in range(d):
        row = [0]*n
        for j in range(T):
            row[T+j*d+t] = 1
        rows.append(row)
    H = [1]*T + [0]*(T*d)
    return rows, H


def key_recoverable_by_linear_view(sets, q, d):
    rows, H = obs_and_constraints(sets, q, d)
    return in_span(H, rows, q)


def affine_eval(k, a, x, q):
    return (k + sum(ai*xi for ai,xi in zip(a,x))) % q


def setup_tables(sets, q, d, K, rng):
    T = len(sets)
    avec = [[rng.randrange(q) for _ in range(d)] for _ in range(T-1)]
    lasta = [(-sum(avec[j][t] for j in range(T-1))) % q for t in range(d)]
    avec.append(lasta)
    ks = [rng.randrange(q) for _ in range(T-1)]
    ks.append((K - sum(ks)) % q)
    tabs = []
    for j,S in enumerate(sets):
        tabs.append({tuple(x): affine_eval(ks[j], avec[j], x, q) for x in S})
    return ks, avec, tabs


def transcript_tuple(sets, tabs):
    out=[]
    for j,S in enumerate(sets):
        for x in sorted(S):
            out.append(tabs[j][tuple(x)])
    return tuple(out)


def enumerate_transcripts(sets, q, d, K):
    T = len(sets)
    count = Counter()
    for flat_a in itertools.product(range(q), repeat=(T-1)*d):
        avec=[]
        for j in range(T-1):
            avec.append(list(flat_a[j*d:(j+1)*d]))
        lasta=[(-sum(avec[j][t] for j in range(T-1)))%q for t in range(d)]
        avec.append(lasta)
        for kprefix in itertools.product(range(q), repeat=T-1):
            ks=list(kprefix)+[(K-sum(kprefix))%q]
            tabs=[]
            for j,S in enumerate(sets):
                tabs.append({tuple(x): affine_eval(ks[j],avec[j],x,q) for x in S})
            count[transcript_tuple(sets,tabs)] += 1
    return count


def random_nonempty_set(q,d,rng):
    pts=list(itertools.product(range(q), repeat=d))
    while True:
        S=[x for x in pts if rng.getrandbits(1)]
        if S:
            return tuple(S)



def rank2_f2(M):
    # exact rank of a 2x2 matrix over F2
    rows=[[x&1 for x in row] for row in M]
    return rank(rows,2)

def majority_success(n, h):
    # odd n, per-copy bit correctness h, independent repetitions
    from math import comb
    lo=n//2+1
    return sum(Fraction(comb(n,i))*h**i*(1-h)**(n-i) for i in range(lo,n+1))

def run():
    res={"seed":SEED,"tests":{}}

    # Explicit false affine-hull splice over F2^2.
    S1=((0,0),(0,1),(1,0)); S2=((1,1),)
    sets=(S1,S2)
    assert not actual_intersection_nonempty(sets)
    assert hull_intersection_nonempty(sets,2,2)
    for _ in range(500):
        K=rng.randrange(2)
        ks,av,tabs=setup_tables(sets,2,2,K,rng)
        got=(tabs[0][(0,0)] + tabs[0][(0,1)] + tabs[0][(1,0)] + tabs[1][(1,1)])%2
        assert got==K
    res["tests"]["explicit_F2_false_splice"]={"trials":500,"recovered":500}

    # Same affine certificate over a large odd field: x*=e1+e2 = -0+e1+e2.
    q=101; sets101=(((0,0),(1,0),(0,1)),((1,1),))
    for _ in range(500):
        K=rng.randrange(q)
        ks,av,tabs=setup_tables(sets101,q,2,K,rng)
        got=(-tabs[0][(0,0)] + tabs[0][(1,0)] + tabs[0][(0,1)] + tabs[1][(1,1)])%q
        assert got==K
    res["tests"]["explicit_F101_false_splice"]={"trials":500,"recovered":500}

    # Direct rank-condenser-style false fixture over F2^2.  Block 1 has
    # rank<2 exactly at {00,01,10}; block 2 has rank<2 exactly at {11}.
    rank_sets=[[],[]]
    for x,y in itertools.product(range(2), repeat=2):
        M1=((x,0),(0,y))
        M2=((1,x),(y,1))
        if rank2_f2(M1)<2: rank_sets[0].append((x,y))
        if rank2_f2(M2)<2: rank_sets[1].append((x,y))
    assert tuple(rank_sets[0])==S1
    assert tuple(rank_sets[1])==S2
    assert not set(rank_sets[0]) & set(rank_sets[1])
    # At 00 block 1 has rank 0; the other three certificate evaluations have rank 1.
    cert_ranks=[rank2_f2(((0,0),(0,0))), rank2_f2(((0,0),(0,1))), rank2_f2(((1,0),(0,0))), rank2_f2(((1,1),(1,1)))]
    assert cert_ranks==[0,1,1,1]
    h63=majority_success(63,Fraction(2,3))
    independent_attack=(1+(2*h63-1)**3)/2
    union_attack=1-3*(1-h63)
    res["tests"]["rank_condensor_false_fixture"]={
        "block1_rank_lt_2": [list(x) for x in rank_sets[0]],
        "block2_rank_lt_2": [list(x) for x in rank_sets[1]],
        "actual_common_candidate": False,
        "certificate_local_ranks": cert_ranks,
        "rank1_raw_success": "2/3",
        "rank1_63_repeat_success": f"{float(h63):.16f}",
        "three_rank1_union_bound_attack_success": f"{float(union_attack):.16f}",
        "three_independent_rank1_attack_success": f"{float(independent_attack):.16f}"
    }

    # Exhaustive set-pair census.
    census={}
    for q,d in [(2,2),(3,1),(3,2)]:
        pts=list(itertools.product(range(q), repeat=d))
        subsets=[tuple(pts[i] for i in range(len(pts)) if (mask>>i)&1) for mask in range(1,1<<len(pts))]
        total=disjoint=false_leak=0
        rowspace_checked=0
        # full rowspace equivalence for the two smaller spaces, sampled for F3^2
        check_all = (q,d)!=(3,2)
        for idx,S1x in enumerate(subsets):
            h1=affine_hull_points(S1x,q,d)
            for S2x in subsets:
                total += 1
                disj = set(S1x).isdisjoint(S2x)
                h2=affine_hull_points(S2x,q,d)
                hint = bool(h1 & h2)
                if disj:
                    disjoint += 1
                    if hint:
                        false_leak += 1
                do_check = check_all or (rng.randrange(257)==0)
                if do_check:
                    rec=key_recoverable_by_linear_view((S1x,S2x),q,d)
                    assert rec==hint
                    rowspace_checked += 1
        census[f"F{q}^{d}"]={"pairs":total,"disjoint_actual":disjoint,"disjoint_but_affine_hulls_intersect":false_leak,"rowspace_equivalence_checked":rowspace_checked}
    res["tests"]["set_pair_census"]=census

    # Random theorem checks for T=2..4.
    nchecks=0
    for q,d in [(2,3),(3,2),(5,2)]:
        for T in [2,3,4]:
            for _ in range(120):
                setsr=tuple(random_nonempty_set(q,d,rng) for __ in range(T))
                hint=hull_intersection_nonempty(setsr,q,d)
                rec=key_recoverable_by_linear_view(setsr,q,d)
                assert hint==rec
                nchecks += 1
    res["tests"]["random_rowspace_iff_hull_intersection"]={"checks":nchecks}

    # Exact complete-distribution controls over F2^2.
    hidden_sets=(((0,0),(1,1)),((0,1),(1,0)))
    assert not hull_intersection_nonempty(hidden_sets,2,2)
    d0=enumerate_transcripts(hidden_sets,2,2,0)
    d1=enumerate_transcripts(hidden_sets,2,2,1)
    assert d0==d1
    leak0=enumerate_transcripts(sets,2,2,0)
    leak1=enumerate_transcripts(sets,2,2,1)
    assert set(leak0).isdisjoint(set(leak1))
    res["tests"]["exact_distribution_dichotomy"]={
        "hidden_fixture_support":len(d0),"hidden_total_per_key":sum(d0.values()),"hidden_distributions_equal":True,
        "leak_fixture_support_key0":len(leak0),"leak_fixture_support_key1":len(leak1),"leak_support_intersection":0
    }

    # Tight noisy lower bound for the four-decoder F2 certificate.
    # Four error bits each have marginal error eps. Distribution: all-zero 1-4eps,
    # each singleton error eps. Then XOR error is 1 on every singleton.
    eps=Fraction(1,10)
    probs={(0,0,0,0):1-4*eps}
    for i in range(4):
        e=[0]*4; e[i]=1; probs[tuple(e)]=eps
    for i in range(4):
        err=sum(p for e,p in probs.items() if e[i])
        assert err==eps
    parity_success=sum(p for e,p in probs.items() if sum(e)%2==0)
    assert parity_success==1-4*eps==Fraction(3,5)
    res["tests"]["noisy_bound_tight_control"]={"per_decoder_success":"9/10","guaranteed_combined_success":"3/5","constructed_joint_distribution_combined_success":"3/5"}

    # General finite-field fiber check: if hulls are disjoint, all key-conditioned
    # transcript distributions must coincide. Exhaust a collection of random F3,d=1,T=3 systems.
    fiber_checks=0
    equal_checks=0
    leak_checks=0
    pts3=list(itertools.product(range(3), repeat=1))
    subs3=[tuple(pts3[i] for i in range(3) if (mask>>i)&1) for mask in range(1,8)]
    for _ in range(80):
        setsr=tuple(rng.choice(subs3) for __ in range(3))
        hint=hull_intersection_nonempty(setsr,3,1)
        dists=[enumerate_transcripts(setsr,3,1,K) for K in range(3)]
        if not hint:
            assert dists[0]==dists[1]==dists[2]
            equal_checks+=1
        else:
            # H is determined, so supports of different keys are disjoint.
            supp=[set(x) for x in dists]
            assert not (supp[0]&supp[1] or supp[0]&supp[2] or supp[1]&supp[2])
            leak_checks+=1
        fiber_checks+=1
    res["tests"]["F3_complete_fiber_checks"]={"systems":fiber_checks,"hiding_cases":equal_checks,"recoverable_cases":leak_checks}

    res["summary"]={
        "proved_identity":"K recoverable from complete affine-evaluation tables iff intersection of affine hulls is nonempty",
        "explicit_false_fixture":"S1={00,01,10}, S2={11} over F2^2 has empty actual intersection but recovers K exactly",
        "stopping_condition_met":False
    }
    return res

if __name__=='__main__':
    out=run()
    print(json.dumps(out, indent=2, sort_keys=True))
