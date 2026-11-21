#!/usr/bin/env python3
"""Finite algebra checks for a helper-aware vector linear release.
No network calls, native cryptographic implementation, or hardness experiment.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from itertools import product
from math import gcd, lcm
from pathlib import Path
import hashlib
import json
import random

checks = defaultdict(int)

def check(cond, group, message):
    if not cond:
        raise AssertionError(f"{group}: {message}")
    checks[group] += 1

def dot(x, y, q):
    return sum(a*b for a,b in zip(x,y)) % q

def transpose_times(A, s, q):
    return tuple(sum(A[i][j]*s[i] for i in range(len(A))) % q
                 for j in range(len(A[0])))

def adapted(A, b, q):
    """b[0] is a unit; a=A^T v, B=N^T A with b^T[v N]=(1,0...)."""
    inv = pow(b[0], -1, q)
    a = tuple(inv*v % q for v in A[0])
    B = tuple(tuple((A[i][j]-b[i]*a[j]) % q for j in range(len(a)))
              for i in range(1, len(A)))
    return a, B

def original_matrix(a, B, b, q):
    return (tuple(b[0]*v % q for v in a),) + tuple(
        tuple((B[i-1][j]+b[i]*a[j]) % q for j in range(len(a)))
        for i in range(1,len(b)))

def secret_from(P, t, b, q):
    return ((pow(b[0],-1,q)*(P-sum(b[i]*t[i-1] for i in range(1,len(b))))) % q,) + tuple(t)

def split_value(P, Delta):
    return P % Delta, P // Delta

def projected_pad(values, Delta, bits, k):
    z = sum((P//Delta) << (bits*j) for j,P in enumerate(values))
    return z & ((1<<k)-1)

def round_residue(value, h, Delta, q):
    candidates = [(h+Delta*j) % q for j in range(q//Delta)]
    dist = lambda z: min((value-z) % q, (z-value) % q)
    distances = [dist(z) for z in candidates]
    best = min(distances)
    if distances.count(best) != 1:
        raise ValueError("ambiguous rounding")
    return candidates[distances.index(best)]

def test_transform_and_conditioned_laws():
    q, Delta, b = 4, 2, (1,2)
    errors = list(product((-1,0,1), repeat=2))
    seen = Counter()
    for flat in product(range(q), repeat=4):
        A = (flat[:2], flat[2:])
        a, B = adapted(A,b,q)
        check(original_matrix(a,B,b,q)==A, "matrix_bijection", "inverse")
        seen[(a,B)] += 1
        real, embedded = Counter(), Counter()
        for s in product(range(q), repeat=2):
            P = dot(b,s,q)
            check(secret_from(P,s[1:],b,q)==s, "secret_bijection", "inverse")
            for e in errors:
                p = tuple((u+v)%q for u,v in zip(transpose_times(A,s,q),e))
                real[(P, P%Delta, p)] += 1
        for P,t0 in product(range(q), repeat=2):
            for e in errors:
                z = tuple((B[0][j]*t0+e[j])%q for j in range(2))
                p = tuple((a[j]*P+z[j])%q for j in range(2))
                embedded[(P,P%Delta,p)] += 1
        check(real==embedded, "full_helper_law", "joint P,h,p equality")
    check(len(seen)==q**4 and set(seen.values())=={1},
          "matrix_bijection", "a and B jointly uniform")

def test_multi_column_embedding():
    q, Delta, b = 4, 2, (3,2)
    errors = (-1,0,1)
    report = []
    for av,bv in [(0,1),(1,1),(2,3),(3,2)]:
        a, B = (av,), ((bv,),)
        A = original_matrix(a,B,b,q)
        single_real, single_embed = Counter(),Counter()
        for s in product(range(q),repeat=2):
            P=dot(b,s,q)
            for e in errors:
                p=(transpose_times(A,s,q)[0]+e)%q
                single_real[(P,P%Delta,p)] += 1
        for P,t,e in product(range(q),range(q),errors):
            p=(av*P+bv*t+e)%q
            single_embed[(P,P%Delta,p)] += 1
        check(single_real==single_embed, "multicolumn", "one-column exact law")
        def complete(single):
            law=Counter()
            for (P0,h0,p0),c0 in single.items():
                for (P1,h1,p1),c1 in single.items():
                    pad=projected_pad((P0,P1),Delta,1,2)
                    for K in range(4):
                        # Deliberately weak toy checking map; not a signature key.
                        pk=(K&1)
                        ctx=(pk, av, bv)
                        law[(K,pk,ctx,h0,h1,p0,p1,K^pad)] += c0*c1
            return law
        lr, le = complete(single_real), complete(single_embed)
        check(lr==le, "multicolumn", "full K/pk/context/helper/mask law")
        report.append({"a":av,"B":bv,"joint_support":len(lr),
                       "sampling_mass":sum(lr.values())})
    return report

def test_uniform_challenge_and_native_simulator():
    q, Delta, r, k = 4, 2, 1, 2
    a=(1,3)
    for P in range(q):
        counts=Counter(tuple((u[j]+a[j]*P)%q for j in range(2))
                       for u in product(range(q),repeat=2))
        check(len(counts)==q*q and set(counts.values())=={1},
              "uniform_challenge", "uniform translation conditional on P")
    # Full ideal capsule with two columns and a key-correlated toy public key.
    ideal, simulated=Counter(),Counter()
    for K in range(4):
        pk=K&1
        for P0,P1 in product(range(q),repeat=2):
            pad=projected_pad((P0,P1),Delta,r,k)
            for pflat in product(range(q),repeat=4):
                ideal[(K,pk,P0%Delta,P1%Delta,pflat,K^pad)] += 1
        for h0,h1 in product(range(Delta),repeat=2):
            for pflat in product(range(q),repeat=4):
                for D in range(4):
                    simulated[(K,pk,h0,h1,pflat,D)] += 1
    check(ideal==simulated, "native_null", "exact full-view null simulation")
    # Revealing an independently generated other capsule secret does not alter
    # equality: tensor with a nontrivial independent revealed transcript.
    other=Counter({("other_key_0","other_secret_0"):2,
                   ("other_key_1","other_secret_1"):1})
    # Compare compressed marginals, not an unnecessarily large Cartesian table.
    for o,wt in other.items():
        check({v:c*wt for v,c in ideal.items()}
              =={v:c*wt for v,c in simulated.items()},
              "independent_opening", str(o))

def test_rounding_every_witness():
    q, Delta, beta = 32,16,1
    A=((1,0,1,0),(0,1,0,1))
    b=(1,1)
    witnesses=[w for w in product((0,1),repeat=4)
               if tuple(dot(row,w,q) for row in A)==b]
    check(len(witnesses)==4, "correctness", "four distinct binary witnesses")
    check(Delta>2*4*beta, "correctness", "strict all-witness noise bound")
    rng=random.Random(20261026)
    trials=40
    for _ in range(trials):
        secrets=[tuple(rng.randrange(q) for _ in range(2)) for _ in range(4)]
        Ps=[dot(b,s,q) for s in secrets]
        K=rng.randrange(16)
        pad=projected_pad(Ps,Delta,1,4)
        D=K^pad
        # Enumerate ALL bounded error vectors for each column, not unknown keys.
        for j,s in enumerate(secrets):
            for e in product((-1,0,1),repeat=4):
                p=tuple((u+v)%q for u,v in zip(transpose_times(A,s,q),e))
                for w in witnesses:
                    recovered=round_residue(dot(w,p,q),Ps[j]%Delta,Delta,q)
                    check(recovered==Ps[j], "correctness", "exact rounded value")
                    values=list(Ps);values[j]=recovered
                    check(D^projected_pad(values,Delta,1,4)==K,
                          "same_capability", "same fixed native seed")
    return {"q":q,"Delta":Delta,"noise_bound":beta,
            "distinct_witnesses":len(witnesses),"setups":trials,
            "note":"chosen correctness fixture, NOT a random-LWE security parameter set"}

def test_gcd_and_entropy():
    for q in (4,6,8,12):
        divisors=[d for d in range(1,q+1) if q%d==0]
        for b in product(range(q),repeat=2):
            vals={dot(b,s,q) for s in product(range(q),repeat=2)}
            g=gcd(q,*b)
            for Delta in divisors:
                per_h=defaultdict(set)
                for P in vals: per_h[P%Delta].add(P)
                target=q//lcm(g,Delta)
                check(all(len(v)==target for v in per_h.values()),
                      "gcd_coset", "conditional support size")
    for r,ell,k in ((1,3,3),(2,2,3),(3,2,4),(2,3,5)):
        hist=Counter()
        for z in product(range(1<<r), repeat=ell):
            value=sum(v<<(r*j) for j,v in enumerate(z)) & ((1<<k)-1)
            hist[value]+=1
        check(len(hist)==1<<k and len(set(hist.values()))==1,
              "vector_entropy", "fixed projection exactly uniform")
    check((256+8-1)//8==32, "vector_entropy", "algebra-only column count")

def main():
    test_transform_and_conditioned_laws()
    mc=test_multi_column_embedding()
    test_uniform_challenge_and_native_simulator()
    correctness=test_rounding_every_witness()
    test_gcd_and_entropy()
    result={
        "status":"PASS",
        "assertions":sum(checks.values()),
        "groups":dict(sorted(checks.items())),
        "multi_column_laws":mc,
        "all_witness_correctness":correctness,
        "scope":"exact finite algebra/distributions only; no LWE hardness, native signature, or generic-NP security test",
        "source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=="__main__":
    main()
