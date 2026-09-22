#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter
from fractions import Fraction
from itertools import product
import hashlib, json, random, sys


def inv(x: int, q: int) -> int:
    x %= q
    if x == 0:
        raise ZeroDivisionError
    return pow(x, q - 2, q)


def prodmod(xs, q):
    z = 1
    for x in xs:
        z = (z * (x % q)) % q
    return z


def carrier(r: int, a: tuple[int, ...], x: tuple[int, ...], q: int) -> int:
    return (r * prodmod(((ai + xi) % q for ai, xi in zip(a, x)), q)) % q


def local_value(block: int, K: int, k0: int, r: int, a: tuple[int, ...], x: tuple[int, ...], q: int) -> int:
    p = carrier(r, a, x, q)
    if block == 0:
        return (k0 + p) % q
    k1 = (K - k0) % q
    return (k1 - p) % q


def face_point(block: int, s: int, t: int, n: int) -> tuple[int, ...]:
    assert n >= 3
    return (block, s, t) + (0,) * (n - 3)


def face_tables(K: int, k0: int, r: int, a: tuple[int, ...], q: int):
    n = len(a)
    t0 = {}
    t1 = {}
    for s, t in product((0, 1), repeat=2):
        t0[(s, t)] = local_value(0, K, k0, r, a, face_point(0, s, t, n), q)
        t1[(s, t)] = local_value(1, K, k0, r, a, face_point(1, s, t, n), q)
    return t0, t1


def attack_from_tables(t0, t1, q: int):
    def secdiff(t):
        return (t[(1,1)] - t[(1,0)] - t[(0,1)] + t[(0,0)]) % q
    D0 = secdiff(t0)
    D1 = secdiff(t1)
    R = (-(D0 + D1)) % q
    B = (t0[(0,0)] + t1[(0,0)]) % q
    if R == 0:
        return B, {"R": 0, "D0": D0, "D1": D1, "branch": "R=0"}
    E0 = (t0[(1,0)] - t0[(0,0)]) % q
    E1 = (t1[(1,0)] - t1[(0,0)]) % q
    F0 = (t0[(0,1)] - t0[(0,0)]) % q
    F1 = (t1[(0,1)] - t1[(0,0)]) % q
    a3 = (-(E0 + E1) * inv(R, q)) % q
    a2 = (-(F0 + F1) * inv(R, q)) % q
    Khat = (B + R * a2 * a3) % q
    return Khat, {"R": R, "D0": D0, "D1": D1, "a2": a2, "a3": a3, "branch": "R!=0"}


def singleton_transcript(K, k0, r, a, u, v, q):
    return (
        local_value(0, K, k0, r, a, u, q),
        local_value(1, K, k0, r, a, v, q),
    )


def tv_counts(c0: Counter, c1: Counter) -> Fraction:
    n0 = sum(c0.values()); n1 = sum(c1.values())
    assert n0 == n1
    keys = set(c0) | set(c1)
    return Fraction(sum(abs(c0[k] - c1[k]) for k in keys), 2*n0)


def singleton_zero_prob(q: int, u, v) -> Fraction:
    z = 0
    total = q ** len(u)
    for a in product(range(q), repeat=len(u)):
        du = prodmod(((ai + ui) % q for ai, ui in zip(a,u)), q)
        dv = prodmod(((ai + vi) % q for ai, vi in zip(a,v)), q)
        if (du - dv) % q == 0:
            z += 1
    return Fraction(z, total)


def test_common_correctness(rng):
    q=101; n=8; trials=2000
    for _ in range(trials):
        K=rng.randrange(q); k0=rng.randrange(q); r=rng.randrange(q)
        a=tuple(rng.randrange(q) for _ in range(n))
        x=tuple(rng.randrange(2) for _ in range(n))
        y=(local_value(0,K,k0,r,a,x,q)+local_value(1,K,k0,r,a,x,q))%q
        assert y==K
    return {"q":q,"n":n,"trials":trials,"passed":trials}


def test_random_false_attack(rng):
    cases=[]
    for q,n,trials in [(101,3,1000),(101,8,2000),(101,16,1000),(1009,12,1000)]:
        passed=0; zero_branch=0
        for _ in range(trials):
            K=rng.randrange(q); k0=rng.randrange(q); r=rng.randrange(q)
            a=tuple(rng.randrange(q) for _ in range(n))
            t0,t1=face_tables(K,k0,r,a,q)
            kh,info=attack_from_tables(t0,t1,q)
            assert kh==K
            passed+=1
            zero_branch += info["R"]==0
        cases.append({"q":q,"n":n,"trials":trials,"passed":passed,"R_zero_cases":zero_branch})
    return cases


def test_exhaustive_false_attack():
    q=5; n=3
    checked=0; branch0=0
    supports={0:set(),1:set()}
    for K in (0,1):
        for r in range(q):
            for a in product(range(q), repeat=n):
                for k0 in range(q):
                    t0,t1=face_tables(K,k0,r,a,q)
                    kh,info=attack_from_tables(t0,t1,q)
                    assert kh==K
                    checked += 1
                    branch0 += info["R"]==0
                    transcript=tuple(t0[(s,t)] for s,t in product((0,1), repeat=2))+tuple(t1[(s,t)] for s,t in product((0,1), repeat=2))
                    supports[K].add(transcript)
    inter=len(supports[0]&supports[1])
    assert inter==0
    return {"q":q,"n":n,"keys_checked":[0,1],"setups_checked":checked,"R_zero_cases":branch0,"support_sizes":{str(k):len(v) for k,v in supports.items()},"cross_key_support_intersection":inter,"tv":"1"}


def test_singleton_distribution():
    q=5; n=3; u=(0,0,0); v=(1,0,0)
    counts={0:Counter(),1:Counter()}
    for K in (0,1):
        for r in range(q):
            for a in product(range(q), repeat=n):
                for k0 in range(q):
                    counts[K][singleton_transcript(K,k0,r,a,u,v,q)] += 1
    tv=tv_counts(counts[0],counts[1])
    pz=singleton_zero_prob(q,u,v)
    bound=Fraction(n-1,q)
    assert tv==pz
    assert tv<=bound
    return {"q":q,"n":n,"u":u,"v":v,"setups_per_key":sum(counts[0].values()),"exact_tv":str(tv),"exact_delta_zero_probability":str(pz),"schwartz_zippel_bound":str(bound),"support_sizes":{str(k):len(c) for k,c in counts.items()}}


def test_delta_nonzero_and_bound():
    cases=[]
    for q,n in [(5,3),(7,4),(11,5)]:
        us=[(0,)*n, tuple([1]+[0]*(n-1)), tuple(i%2 for i in range(n))]
        vs=[(1,)*n, tuple([0,1]+[0]*(n-2)), tuple(1-(i%2) for i in range(n))]
        for u,v in zip(us,vs):
            if u==v: continue
            pz=singleton_zero_prob(q,u,v)
            bound=Fraction(n-1,q)
            assert pz<=bound
            cases.append({"q":q,"n":n,"u":"".join(map(str,u)),"v":"".join(map(str,v)),"p_zero":str(pz),"bound":str(bound)})
    return cases


def test_identity_direct(rng):
    q=101; trials=1000
    for n in [3,4,8,16]:
        for _ in range(trials//4):
            K=rng.randrange(q); k0=rng.randrange(q); r=rng.randrange(q)
            a=tuple(rng.randrange(q) for _ in range(n))
            t0,t1=face_tables(K,k0,r,a,q)
            D0=(t0[(1,1)]-t0[(1,0)]-t0[(0,1)]+t0[(0,0)])%q
            D1=(t1[(1,1)]-t1[(1,0)]-t1[(0,1)]+t1[(0,0)])%q
            R=(r*prodmod(a[3:],q))%q if n>3 else r%q
            assert D0==(R*a[0])%q
            assert D1==(-R*(a[0]+1))%q
            assert (-(D0+D1))%q==R
    return {"q":q,"n_values":[3,4,8,16],"trials":trials,"passed":trials}



def null_vector(matrix, q: int):
    # matrix is rows x cols, find one nonzero vector in right nullspace.
    A=[[(x%q) for x in row] for row in matrix]
    rows=len(A); cols=len(A[0]) if rows else 0
    piv=[]; r=0
    for c in range(cols):
        pr=next((i for i in range(r,rows) if A[i][c]%q),None)
        if pr is None: continue
        A[r],A[pr]=A[pr],A[r]
        z=inv(A[r][c],q)
        A[r]=[(x*z)%q for x in A[r]]
        for i in range(rows):
            if i!=r and A[i][c]%q:
                f=A[i][c]%q
                A[i]=[(A[i][j]-f*A[r][j])%q for j in range(cols)]
        piv.append(c); r+=1
        if r==rows: break
    free=[c for c in range(cols) if c not in piv]
    if not free: return None
    f=free[0]; x=[0]*cols; x[f]=1
    for i in range(len(piv)-1,-1,-1):
        c=piv[i]
        x[c]=(-sum(A[i][j]*x[j] for j in free))%q
    assert any(x)
    assert all(sum(matrix[i][j]*x[j] for j in range(cols))%q==0 for i in range(rows))
    return x

def dot(u,v,q):
    return sum(a*b for a,b in zip(u,v))%q

def test_statement_independent_feature_lower_bound(rng):
    q=101; cases=400; recovery_trials=0
    max_support=0
    for _ in range(cases):
        m=rng.randrange(1,9); N=m+2
        phi=[tuple(rng.randrange(q) for _ in range(m)) for _ in range(N)]
        M=[[1]*N]+[[phi[j][i] for j in range(N)] for i in range(m)]
        alpha=null_vector(M,q)
        assert alpha is not None
        i=next(j for j,a in enumerate(alpha) if a%q)
        B=[j for j in range(N) if j!=i and alpha[j]%q]
        assert B
        ai=alpha[i]%q
        weights={j:(-alpha[j]*inv(ai,q))%q for j in B}
        assert sum(weights.values())%q==1
        bary=[sum(weights[j]*phi[j][c] for j in B)%q for c in range(m)]
        assert tuple(bary)==phi[i]
        max_support=max(max_support,1+len(B))
        for __ in range(3):
            K=rng.randrange(q); k0=rng.randrange(q); avec=tuple(rng.randrange(q) for _ in range(m))
            yA=(k0+dot(avec,phi[i],q))%q
            k1=(K-k0)%q
            yB={j:(k1-dot(avec,phi[j],q))%q for j in B}
            kh=(yA+sum(weights[j]*yB[j] for j in B))%q
            assert kh==K
            recovery_trials+=1
    return {"q":q,"random_feature_maps":cases,"false_key_recoveries":recovery_trials,"max_certificate_points":max_support,"dimension_range":[1,8]}

def main():
    rng=random.Random(0x28C0FFEE)
    out={
      "status":"PASS",
      "seed":"0x28C0FFEE",
      "common_correctness":test_common_correctness(rng),
      "singleton_false_pair":test_singleton_distribution(),
      "schwartz_zippel_controls":test_delta_nonzero_and_bound(),
      "finite_difference_identities":test_identity_direct(rng),
      "statement_independent_feature_lower_bound":test_statement_independent_feature_lower_bound(rng),
      "random_false_partition_attack":test_random_false_attack(rng),
      "exhaustive_false_partition_attack":test_exhaustive_false_attack(),
      "scope_notes":[
        "Tests validate the stated finite-field identities and explicit false-instance attack; they do not prove security for a surviving WKEM.",
        "The attack assumes the same complete local-evaluation interface used in Runs 26-27; noisy decoding only changes success by the probability that required local evaluations decode incorrectly.",
        "No external literature or network source is used by this checker."
      ]
    }
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=='__main__':
    main()
