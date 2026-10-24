#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter
from itertools import product
import hashlib
import json


def centered(x: int, q: int) -> int:
    x %= q
    return x - q if x > q // 2 else x


def dot(a, b):
    return sum(x*y for x, y in zip(a, b))


def mat_vec(A, u, q):
    return [sum(row[j]*u[j] for j in range(len(u))) % q for row in A]


def transpose_mat_vec(A, s, q):
    # A is n x m, return A^T s in Z_q^m
    n = len(A); m = len(A[0])
    return [sum(A[i][j]*s[i] for i in range(n)) % q for j in range(m)]


def cyclic_dist(a, b, q):
    return abs(centered(a-b, q))


def decode_bit(v, q):
    c0 = 0
    c1 = q // 2
    d0 = cyclic_dist(v, c0, q)
    d1 = cyclic_dist(v, c1, q)
    return 0 if d0 < d1 else 1


checks = []
def ok(name, cond, detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    checks.append({"name": name, "detail": detail})


# ---------------------------------------------------------------------------
# 1. Exact noisy projective identity.
# hp = A^T s + e ; z = s^T t ; if A u = t mod q then hp^T u = z + e^T u.
# Exhaust small matrices/vectors.
# ---------------------------------------------------------------------------
identity_cases = 0
for q in (5, 7, 11):
    for a0 in range(q):
        for a1 in range(q):
            A = [[a0, a1]]
            for s0 in range(q):
                s = [s0]
                Ats = transpose_mat_vec(A, s, q)
                for e0, e1 in product((-1,0,1), repeat=2):
                    hp = [(Ats[0]+e0) % q, (Ats[1]+e1) % q]
                    for u0, u1 in product(range(-2,3), repeat=2):
                        u = [u0,u1]
                        t = mat_vec(A,u,q)[0]
                        z = (s0*t) % q
                        lhs = dot(hp,u) % q
                        rhs = (z + e0*u0 + e1*u1) % q
                        ok(f"identity_{identity_cases}", lhs == rhs,
                           (q,A,s,(e0,e1),u,t,z,lhs,rhs))
                        identity_cases += 1


# ---------------------------------------------------------------------------
# 2. Exact one-bit wrapper.
# Setup masks a bit K by d = c_K - z. A witness computes hp^T u + d.
# If |e^T u| is below quarter-modulus decoding radius, it recovers K.
# If an adversary recovers K, then z = c_K - d exactly.
# ---------------------------------------------------------------------------
wrapper_cases = 0
for q in (101, 127):
    rho = (q // 4) - 2
    centers = [0, q//2]
    A = [[1,0,0,0]]
    for s0 in (1,7,31,50):
        s=[s0]
        t=1
        z=s0 % q
        for e in product(range(-2,3), repeat=4):
            hp = [(s0 + e[0]) % q, e[1] % q, e[2] % q, e[3] % q]
            # Include one canonical short witness plus several short kernel variants.
            witnesses = ([1,0,0,0],[1,1,0,0],[1,-1,0,0],[1,0,1,-1])
            for K in (0,1):
                d=(centers[K]-z) % q
                recovered_z=(centers[K]-d) % q
                ok(f"wrapper_inverse_{wrapper_cases}", recovered_z==z,
                   (q,s0,e,K,d,recovered_z,z))
                for u in witnesses:
                    if mat_vec(A,u,q)[0] != t:
                        continue
                    delta=dot(e,u)
                    if abs(delta) <= rho:
                        y=(dot(hp,u)+d)%q
                        got=decode_bit(y,q)
                        ok(f"wrapper_correct_{wrapper_cases}",got==K,
                           (q,e,u,delta,rho,K,y,got))
                        wrapper_cases += 1


# ---------------------------------------------------------------------------
# 3. Short-pseudowitness theorem.
# Any ambient u with Au=t and |e^T u|<=rho decodes the key, source-valid or not.
# The norm condition ||e||_inf ||u||_1 <= rho is a public sufficient condition.
# ---------------------------------------------------------------------------
pseudo_cases = 0
q=101; rho=20; A=[[1,0,0,0]]; t=1; s=[37]; z=37; centers=[0,q//2]
for e in product((-2,-1,0,1,2), repeat=4):
    Be=max(abs(x) for x in e)
    hp=[(37+e[0])%q,e[1]%q,e[2]%q,e[3]%q]
    for u1,u2,u3 in product(range(-3,4), repeat=3):
        u=[1,u1,u2,u3]
        assert mat_vec(A,u,q)[0]==t
        l1=sum(abs(x) for x in u)
        delta=dot(e,u)
        for K in (0,1):
            d=(centers[K]-z)%q
            if abs(delta)<=rho:
                got=decode_bit((dot(hp,u)+d)%q,q)
                ok(f"pseudo_exact_{pseudo_cases}",got==K,(e,u,delta,K,got))
                pseudo_cases += 1
            if Be*l1<=rho:
                ok(f"pseudo_norm_bound_{pseudo_cases}",abs(delta)<=rho,
                   (e,u,Be,l1,delta,rho))


# ---------------------------------------------------------------------------
# 4. Dense ambient solutions are not automatically useful once noise is present.
# For A=[1,0,...], both short and dense vectors solve Au=t. With e_i iid uniform
# in {-2,...,2}, compute exact distribution of delta=e^T u mod q.
# This is evidence only for anti-concentration, not a hardness theorem.
# ---------------------------------------------------------------------------
def error_distribution(u, q=101, B=2):
    ctr=Counter(); total=0
    for e in product(range(-B,B+1), repeat=len(u)):
        ctr[sum(ei*ui for ei,ui in zip(e,u))%q]+=1
        total+=1
    return ctr,total

def tv_from_uniform(ctr,total,q):
    return 0.5*sum(abs(ctr.get(x,0)/total - 1/q) for x in range(q))

anti = []
for u in ([1,0,0,0],[1,7,19,31],[1,5,25,24],[1,4,16,37,49]):
    ctr,total=error_distribution(u)
    rho_demo=6
    succ=sum(v for x,v in ctr.items() if abs(centered(x,101))<=rho_demo)/total
    tv=tv_from_uniform(ctr,total,101)
    anti.append({"u":u,"support":len(ctr),"decode_window_probability":succ,
                 "tv_from_uniform":tv,"max_point_probability":max(ctr.values())/total})

ok("anti_short_always_decodes", anti[0]["decode_window_probability"] == 1.0, anti[0])
ok("anti_dense_full_support_1", anti[1]["support"] == 101, anti[1])
ok("anti_dense_full_support_2", anti[2]["support"] == 101, anti[2])
ok("anti_dense_near_uniform_2", anti[2]["tv_from_uniform"] < 0.03, anti[2])
ok("anti_dense_window_not_correctness", anti[1]["decode_window_probability"] < 0.2, anti[1])


# ---------------------------------------------------------------------------
# 5. Exact masking hybrid: if z is uniform in Z_q, d=c_K-z is uniform and
# independent of K. Exhaustively compare distributions.
# ---------------------------------------------------------------------------
mask_cases=0
for q in (5,7,11,101):
    c=[0,q//2]
    for K in (0,1):
        ctr=Counter((c[K]-z)%q for z in range(q))
        ok(f"mask_uniform_{q}_{K}", all(ctr[x]==1 for x in range(q)),ctr)
        mask_cases += 1
    ctr0=Counter((c[0]-z)%q for z in range(q))
    ctr1=Counter((c[1]-z)%q for z in range(q))
    ok(f"mask_independent_{q}",ctr0==ctr1)


# ---------------------------------------------------------------------------
# 6. Multi-bit parallelization control. Each recovered bit yields the exact z_j
# for that row. No cryptographic security is inferred.
# ---------------------------------------------------------------------------
parallel_cases=0
q=101
centers=[0,q//2]
for kapp in range(1,7):
    Ks=list(product((0,1), repeat=kapp))
    # bounded sample for k=6; still exact per vector
    for Kvec in Ks[:min(len(Ks),16)]:
        zs=[(17*j+9)%q for j in range(kapp)]
        ds=[(centers[Kvec[j]]-zs[j])%q for j in range(kapp)]
        zrec=[(centers[Kvec[j]]-ds[j])%q for j in range(kapp)]
        ok(f"parallel_{parallel_cases}",zrec==zs,(kapp,Kvec,zs,ds,zrec))
        parallel_cases+=1


out={
  "run":115,
  "status":"PASS",
  "total_assertions":len(checks),
  "exact_identity_cases":identity_cases,
  "wrapper_correctness_cases":wrapper_cases,
  "short_pseudowitness_decode_cases":pseudo_cases,
  "masking_hybrid_cases":mask_cases,
  "parallel_cases":parallel_cases,
  "anti_concentration_examples":anti,
  "claims":[
    "For hp=A^T s+e and any ambient u with Au=t mod q, hp^T u=s^T t+e^T u mod q exactly.",
    "Publishing d=c_K-s^T t gives all-witness bit correctness whenever the projected error is inside the decoder radius; exact K recovery deterministically reveals s^T t as c_K-d.",
    "Any source-invalid ambient pseudowitness with projected error inside the correctness radius also recovers K; ||e||_inf||u||_1<=rho is a sufficient attack condition.",
    "Noise can make selected dense ambient solutions statistically broad in finite toys, so Run114's any-ambient-solution leak becomes a quantitative short/low-noise-pseudowitness requirement; this is not a general hiding theorem.",
    "If the hidden target value z is uniform, the offset d is exactly uniform and independent of K. Computational replacement requires an explicit QPT-valid targeted-LWE/hardcore theorem."
  ],
  "limitations":[
    "Finite algebra/functionality checks only; no computational security follows from passing.",
    "Dense anti-concentration examples do not prove security for arbitrary ambient solutions.",
    "Standard QPT-LWE is not silently promoted to pseudorandomness of the noiseless statement-derived inner product s^T t.",
    "A generic-NP compiler producing short valid preimages while excluding all source-invalid short preimages remains unconstructed."
  ]
}
print(json.dumps(out,indent=2,sort_keys=True))
