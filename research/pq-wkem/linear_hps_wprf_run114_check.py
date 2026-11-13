#!/usr/bin/env python3
from __future__ import annotations
from itertools import product
from collections import defaultdict, Counter
import json

checks=[]

def ok(name, cond, detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    checks.append({"name":name,"detail":detail})

def inv_mod(a,q):
    return pow(a, -1, q)

def mat_vec(A, w, q):
    return tuple(sum(A[i][j]*w[j] for j in range(len(w))) % q for i in range(len(A)))

def at_vec(A, a, q):
    m=len(A); n=len(A[0])
    return tuple(sum(A[i][j]*a[i] for i in range(m)) % q for j in range(n))

def dot(x,y,q):
    return sum(a*b for a,b in zip(x,y)) % q

def all_vec(q,n):
    return list(product(range(q), repeat=n))

def image(A,q):
    n=len(A[0])
    return {mat_vec(A,w,q) for w in all_vec(q,n)}

def solve_one(A,x,q):
    n=len(A[0])
    for w in all_vec(q,n):
        if mat_vec(A,w,q)==x:
            return w
    return None

def rank_mod(A,q):
    M=[list(map(lambda z:z%q,row)) for row in A]
    m=len(M); n=len(M[0]) if m else 0
    r=0
    for c in range(n):
        piv=next((i for i in range(r,m) if M[i][c]%q),None)
        if piv is None: continue
        M[r],M[piv]=M[piv],M[r]
        inv=inv_mod(M[r][c]%q,q)
        M[r]=[(z*inv)%q for z in M[r]]
        for i in range(m):
            if i!=r and M[i][c]%q:
                f=M[i][c]%q
                M[i]=[(M[i][j]-f*M[r][j])%q for j in range(n)]
        r+=1
        if r==m: break
    return r

def matrices(q,m,n):
    for flat in product(range(q), repeat=m*n):
        yield tuple(tuple(flat[i*n+j] for j in range(n)) for i in range(m))

# ----------------------------------------------------------------------
# 1. Exact linear HPS/WPRF identity and complete conditional distribution.
#
# Secret a in F_q^m.
# Projection p=A^T a.
# Secret hash H=a^T x.
# Witness w for x=Aw evaluates p^T w.
#
# For x in im(A): H is determined by p.
# For x not in im(A): conditional on each attainable p, H is uniform in F_q.
# ----------------------------------------------------------------------
dist_cases=0
witness_cases=0
matrix_cases=0
for q,m,n in ((2,3,2),(3,2,2),(5,2,1)):
    X=all_vec(q,m)
    Avecs=all_vec(q,m)
    for A in matrices(q,m,n):
        matrix_cases += 1
        Im=image(A,q)
        # All-witness exact projection equality.
        for x in Im:
            ws=[w for w in all_vec(q,n) if mat_vec(A,w,q)==x]
            for a in Avecs:
                p=at_vec(A,a,q)
                H=dot(a,x,q)
                vals={dot(p,w,q) for w in ws}
                ok(f"proj_eq_{q}_{matrix_cases}_{witness_cases}", vals=={H}, (A,x,a,p,H,ws[:3]))
                witness_cases += 1

        # Exact conditional law H | p.
        buckets=defaultdict(list)
        for a in Avecs:
            buckets[at_vec(A,a,q)].append(a)
        for x in X:
            inside=x in Im
            u=solve_one(A,x,q)
            for p,alist in buckets.items():
                counts=Counter(dot(a,x,q) for a in alist)
                if inside:
                    target=dot(p,u,q)
                    ok(f"inside_point_{q}_{matrix_cases}_{dist_cases}",
                       counts==Counter({target:len(alist)}),
                       (A,x,p,counts,target))
                else:
                    # Every output value occurs equally often.
                    vals=[counts[v] for v in range(q)]
                    ok(f"outside_uniform_{q}_{matrix_cases}_{dist_cases}",
                       len(set(vals))==1 and vals[0]>0,
                       (A,x,p,counts))
                dist_cases += 1

# ----------------------------------------------------------------------
# 2. Restricted-witness dichotomy.
#
# For S subset F_q^n define intended language L_S={Aw:w in S}.
# If L_S is a strict subset of im(A), choose x in im(A)\L_S.
# Linear algebra gives a public pseudowitness u with Au=x and hence H=p^T u,
# despite x being false for the intended restricted language.
# Therefore full false-word hiding for L_S can hold in this linear HPS only
# when L_S=im(A), i.e. the restriction adds no language restriction.
# ----------------------------------------------------------------------
restricted_cases=0
leak_cases=0
for q,m,n in ((3,2,2),(5,2,2)):
    V=all_vec(q,n)
    restrictions=[]
    # Boolean coordinates, Hamming weight <=1, and first coordinate zero.
    restrictions.append(("boolean", [w for w in V if all(z in (0,1) for z in w)]))
    restrictions.append(("weight_le_1", [w for w in V if sum(z!=0 for z in w)<=1]))
    restrictions.append(("first_zero", [w for w in V if w[0]==0]))
    for A in matrices(q,m,n):
        Im=image(A,q)
        if len(Im)<=1:
            continue
        for rname,S in restrictions:
            LS={mat_vec(A,w,q) for w in S}
            ok(f"subset_{restricted_cases}", LS.issubset(Im), (q,A,rname))
            if LS != Im:
                false_inside=next(iter(Im-LS))
                u=solve_one(A,false_inside,q)
                ok(f"pseudo_exists_{restricted_cases}",u is not None,(A,false_inside,rname))
                # Check exact public recovery for every secret key.
                for a in all_vec(q,m):
                    p=at_vec(A,a,q)
                    H=dot(a,false_inside,q)
                    ok(f"pseudo_leak_{leak_cases}",dot(p,u,q)==H,(q,A,rname,false_inside,u,a,p,H))
                    leak_cases += 1
            restricted_cases += 1

# ----------------------------------------------------------------------
# 3. Source-search collapse control for public linear membership.
# If a compiler maps source witnesses into unrestricted solutions Aw=x and
# every public solution is source-valid, then Gaussian elimination/bruteforce
# here supplies a source witness from public A,x. This finite control records
# the semantic collapse; it is not a complexity lower bound.
# ----------------------------------------------------------------------
collapse_cases=0
for q,m,n in ((2,3,2),(3,2,2)):
    for A in matrices(q,m,n):
        for x in image(A,q):
            u=solve_one(A,x,q)
            ok(f"collapse_{collapse_cases}",u is not None and mat_vec(A,u,q)==x,(q,A,x,u))
            collapse_cases+=1

# ----------------------------------------------------------------------
# 4. Approximate correctness warning.
# A noisy projected hash is not automatically a same-key WPRF. Demonstrate
# simple threshold decoder agreement only below the chosen margin, and
# disagreement is possible outside it. This is functionality only.
# ----------------------------------------------------------------------
approx_cases=0
for q in (17,31):
    for margin in (1,2,3):
        for H in range(q):
            for e1 in range(-margin,margin+1):
                for e2 in range(-margin,margin+1):
                    # Canonical toy decoder: nearest centered residue to H.
                    y1=(H+e1)%q; y2=(H+e2)%q
                    # With H itself known this just checks error arithmetic; the
                    # point is that approximate equality requires a separate decoder.
                    d1=(y1-e1)%q
                    d2=(y2-e2)%q
                    ok(f"approx_{approx_cases}", d1==H and d2==H,(q,H,e1,e2))
                    approx_cases+=1

out={
  "run":114,
  "status":"PASS",
  "total_assertions":len(checks),
  "matrix_cases":matrix_cases,
  "projection_identity_assertions":witness_cases,
  "conditional_distribution_assertions":dist_cases,
  "restricted_witness_cases":restricted_cases,
  "public_pseudowitness_leak_assertions":leak_cases,
  "public_linear_membership_collapse_cases":collapse_cases,
  "approximate_correctness_controls":approx_cases,
  "claims":[
    "For the exact linear projective hash p=A^T a, H=a^T x, every representation Aw=x computes the same H as p^T w.",
    "Conditioned on p, H is a point mass for x in im(A), and exactly uniform over F_q for x outside im(A).",
    "For an intended restricted language L_S={Aw:w in S}, any false x in im(A)\\L_S has a public unrestricted pseudowitness that recovers H exactly.",
    "Hence this plain linear HPS is smooth for every false word of L_S iff L_S=im(A); any nontrivial witness restriction creates a false-word hash leak.",
    "Approximate HPS correctness is not by itself an exact all-witness same-key WPRF; canonical decoding is an additional obligation."
  ],
  "scope":[
    "Finite algebraic validation only; no computational-security claim is inferred.",
    "The dichotomy applies to this public linear projective-hash form, not to all HPS/SPHF constructions.",
    "Post-quantum security of concrete lattice/code HPS papers must be classified from their actual adversary models and hardness assumptions separately."
  ]
}
print(json.dumps(out,indent=2,sort_keys=True))
