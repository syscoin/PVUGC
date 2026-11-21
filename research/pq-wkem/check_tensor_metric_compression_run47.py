#!/usr/bin/env python3
"""Run-47 deterministic checker: tensor metric amplification and CP compression audit.

Standard library only.  This validates finite algebra / exact distributions; it does not
claim cryptographic security.
"""
from __future__ import annotations
import itertools, json, math, random, hashlib
from fractions import Fraction

SEED = 470047
rng = random.Random(SEED)


def mat_vec(A, y, q=None):
    out=[]
    for row in A:
        v=sum(a*b for a,b in zip(row,y))
        out.append(v if q is None else v%q)
    return out


def kron_vec(a,b,q=None):
    out=[x*y for x in a for y in b]
    return out if q is None else [x%q for x in out]


def tensor_vec(v,t,q=None):
    out=[1]
    for _ in range(t): out=kron_vec(out,v,q)
    return out


def kron_mat(A,B,q):
    # rows indexed (i,k), cols indexed (j,l)
    return [[(A[i][j]*B[k][l])%q
             for j in range(len(A[0])) for l in range(len(B[0]))]
            for i in range(len(A)) for k in range(len(B))]


def tensor_mat(A,t,q):
    out=[[1]]
    for _ in range(t): out=kron_mat(out,A,q)
    return out


def dot(a,b,q=None):
    v=sum(x*y for x,y in zip(a,b))
    return v if q is None else v%q


def transpose(A): return [list(x) for x in zip(*A)]


def solve_linear(A,b,q):
    """Return one x with A x=b over F_q, or None. A is rows x cols."""
    M=[[x%q for x in row]+[bb%q] for row,bb in zip(A,b)]
    rows=len(M); cols=len(A[0])
    r=0; piv=[]
    for c in range(cols):
        p=next((i for i in range(r,rows) if M[i][c]%q),None)
        if p is None: continue
        M[r],M[p]=M[p],M[r]
        inv=pow(M[r][c],-1,q)
        M[r]=[(v*inv)%q for v in M[r]]
        for i in range(rows):
            if i!=r and M[i][c]%q:
                f=M[i][c]%q
                M[i]=[(x-f*y)%q for x,y in zip(M[i],M[r])]
        piv.append(c); r+=1
        if r==rows: break
    for i in range(r,rows):
        if all(M[i][c]%q==0 for c in range(cols)) and M[i][-1]%q:
            return None
    x=[0]*cols
    for i,c in enumerate(piv): x[c]=M[i][-1]%q
    return x


def rank(A,q):
    if not A: return 0
    M=[[x%q for x in row] for row in A]
    rows=len(M); cols=len(M[0]); r=0
    for c in range(cols):
        p=next((i for i in range(r,rows) if M[i][c]%q),None)
        if p is None: continue
        M[r],M[p]=M[p],M[r]
        inv=pow(M[r][c],-1,q)
        M[r]=[(x*inv)%q for x in M[r]]
        for i in range(r+1,rows):
            if M[i][c]%q:
                f=M[i][c]%q
                M[i]=[(x-f*y)%q for x,y in zip(M[i],M[r])]
        r+=1
    return r


def random_matrix(m,n,q): return [[rng.randrange(q) for _ in range(n)] for __ in range(m)]

# 1) exact tensor-preimage identities over F_q
q=101
tensor_identity_checks=0
for fixture in range(100):
    m=rng.randint(1,3); n=rng.randint(m+1,4); t=rng.randint(2,4)
    A=random_matrix(m,n,q); y=[rng.randrange(q) for _ in range(n)]
    u=mat_vec(A,y,q)
    B=tensor_mat(A,t,q); yt=tensor_vec(y,t,q); ut=tensor_vec(u,t,q)
    lhs=mat_vec(B,yt,q)
    assert lhs==ut
    tensor_identity_checks += len(lhs)

# 2) integer tensor norm identity
norm_checks=0
for fixture in range(200):
    n=rng.randint(2,5); t=rng.randint(1,5)
    y=[rng.randint(-3,3) for _ in range(n)]
    yt=tensor_vec(y,t,None)
    a=sum(v*v for v in yt)
    b=sum(v*v for v in y)**t
    assert a==b
    norm_checks += 1

# 3) Run-43 additive squared-norm gap amplification diagnostics.
# H is honest squared norm; false is H+4. stddev ratio after tensorization is ((H+4)/H)^(t/2).
gap_rows=[]
for H in [5,9,21,69,133,261,517]:
    for t in [max(1,H//4), max(1,H//2), H]:
        ratio=((H+4)/H)**(t/2)
        gap_rows.append({
            "H":H,"false_H":H+4,"t":t,
            "stddev_ratio":ratio,
            "squared_norm_ratio":((H+4)/H)**t,
            "log2_explicit_coords_if_N_2":float(t),
            "log2_explicit_coords_if_N_H":t*math.log2(H),
        })

# 4) exact one-corrupted-factor residual distribution.
# alpha_j are independent uniform F_q. With delta_1=c !=0 and all other delta=0,
# residual = c * prod_{j=2}^t alpha_j.
residual_distribution_checks=[]
for q0 in [5,7,11]:
    for t in [2,3,4]:
        counts=[0]*q0
        total=0
        for vals in itertools.product(range(q0), repeat=t-1):
            p=1
            for a in vals: p=(p*a)%q0
            counts[p]+=1; total+=1
        p0=Fraction(counts[0],total)
        p_nonzero=[Fraction(counts[x],total) for x in range(1,q0)]
        assert len(set(p_nonzero))==1
        formula_p0=1-Fraction((q0-1)**(t-1),q0**(t-1))
        formula_p1=Fraction((q0-1)**(t-2),q0**(t-1)) if t>=2 else Fraction(0)
        assert p0==formula_p0
        assert p_nonzero[0]==formula_p1
        # TV between D and nonzero shift D+c: only two exceptional points differ.
        tv=abs(p0-formula_p1)
        residual_distribution_checks.append({
            "q":q0,"t":t,"total":total,
            "p_zero":str(p0),"p_each_nonzero":str(formula_p1),
            "tv_to_nonzero_shift":str(tv),
            "optimal_bit_success_if_shifted_key":float(Fraction(1,2)+tv/2),
        })

# 5) large-q analytic controls: success for distinguishing D vs D+mu under optimal MAP.
large_q=[]
for q0 in [257,769,12289]:
    for t in [2,4,8,16,32]:
        p0=1-Fraction((q0-1)**(t-1),q0**(t-1))
        p1=Fraction((q0-1)**(t-2),q0**(t-1))
        tv=abs(p0-p1)
        large_q.append({"q":q0,"t":t,"p_zero":float(p0),"tv":float(tv),
                        "optimal_bit_success":float(Fraction(1,2)+tv/2)})

# 6) noiseless CP factor public recovery: z_j=A^T s_j. Publicly solve A^T shat=z_j,
# then u^T shat is invariant across solutions because u=Ay.
noiseless_public_recovery=0
invariance_checks=0
q0=101
for fixture in range(300):
    m=rng.randint(2,4); n=rng.randint(m,6); t=rng.randint(2,5)
    A=random_matrix(m,n,q0)
    y=[rng.randrange(q0) for _ in range(n)]
    u=mat_vec(A,y,q0)
    AT=transpose(A)
    alphas=[]; recovered=[]
    for j in range(t):
        s=[rng.randrange(q0) for _ in range(m)]
        z=mat_vec(AT,s,q0)
        sh=solve_linear(AT,z,q0)
        assert sh is not None
        alpha=dot(u,s,q0); alphah=dot(u,sh,q0)
        assert alpha==alphah
        alphas.append(alpha); recovered.append(alphah)
        invariance_checks += 1
    mask=1; maskh=1
    for a in alphas: mask=mask*a%q0
    for a in recovered: maskh=maskh*a%q0
    assert mask==maskh
    K=rng.randrange(2); mu=(q0-1)//2
    beta=(mask+mu*K)%q0
    assert ((beta-maskh)%q0)==(mu*K)%q0
    noiseless_public_recovery += 1

# 7) explicit noisy CP identity fixtures with one contracted unit error.
# Construct y=e0 and e1=e0 so <y,e1>=1.
noisy_cp_checks=0
for fixture in range(1000):
    q1=257; m=3; n=5; t=4
    A=random_matrix(m,n,q1)
    y=[1,0,0,0,0]; u=mat_vec(A,y,q1); AT=transpose(A)
    alpha=[]; z=[]
    for j in range(t):
        s=[rng.randrange(q1) for _ in range(m)]
        zj=mat_vec(AT,s,q1)
        if j==0: zj[0]=(zj[0]+1)%q1
        z.append(zj)
        alpha.append(dot(u,s,q1))
    witness_terms=[dot(y,zj,q1) for zj in z]
    wprod=1; aprod=1
    for v in witness_terms: wprod=wprod*v%q1
    for v in alpha: aprod=aprod*v%q1
    residual=(wprod-aprod)%q1
    expect=1
    for v in alpha[1:]: expect=expect*v%q1
    assert residual==expect
    noisy_cp_checks += 1

# 8) exact span dimension of t-th powers of vectors in an affine d-dimensional chart,
# via exponent-count vectors: number of degree <=t monomials in d affine parameters is C(d+t,t).
# We only verify finite small instances by Vandermonde-like sampled rank where field is large.
def monomial_exponents(d,t):
    # all exponent tuples total <= t
    out=[]
    def rec(pos,left,cur):
        if pos==d:
            out.append(tuple(cur)); return
        for e in range(left+1):
            cur.append(e); rec(pos+1,left-e,cur); cur.pop()
    rec(0,t,[]); return out

# Feature vector for (a + sum r_i b_i)^⊗t can be represented in symmetric coordinates by all monomials <=t
# when a,b_i independent; sampled feature-rank check validates the combinatorial count for tiny cases.
affine_span_checks=[]
q2=1009
for d in [1,2,3]:
    for t in [1,2,3,4]:
        exps=monomial_exponents(d,t); target=math.comb(d+t,t)
        assert len(exps)==target
        # sample target parameter points deterministically/randomly until feature matrix hits full rank
        rows=[]
        attempts=0
        while rank(rows,q2)<target and attempts<10*target:
            r=[rng.randrange(q2) for _ in range(d)]
            feat=[]
            for e in exps:
                v=1
                for ri,ei in zip(r,e): v=v*pow(ri,ei,q2)%q2
                feat.append(v)
            rows.append(feat); attempts+=1
        rr=rank(rows,q2)
        assert rr==target
        affine_span_checks.append({"d":d,"t":t,"dimension":target,"samples":len(rows)})


# 9) tensor relation kernel explosion controls. If k in ker(A), then
# k tensor z_2 tensor ... tensor z_t is in ker(A^{tensor t}); rank(A^{tensor t})=rank(A)^t.
tensor_kernel_checks=0
tensor_rank_checks=0
q3=101
for fixture in range(80):
    # force a nontrivial kernel with A=[I_m | random tail]
    m=rng.randint(1,2); n=m+rng.randint(1,2); t=rng.randint(2,3)
    tail=[[rng.randrange(q3) for _ in range(n-m)] for __ in range(m)]
    A=[[1 if i==j else 0 for j in range(m)] + tail[i] for i in range(m)]
    # k = (-tail[:,0], e_tail0) is in the kernel
    k=[(-tail[i][0])%q3 for i in range(m)] + [1] + [0]*(n-m-1)
    assert mat_vec(A,k,q3)==[0]*m
    B=tensor_mat(A,t,q3)
    assert rank(B,q3)==rank(A,q3)**t
    tensor_rank_checks += 1
    z=[k]
    for _ in range(t-1): z.append([rng.randrange(q3) for _ in range(n)])
    kt=[1]
    for v in z: kt=kron_vec(kt,v,q3)
    assert mat_vec(B,kt,q3)==[0]*(m**t)
    tensor_kernel_checks += 1

result={
    "run":47,
    "seed":SEED,
    "scope":"finite algebra and exact-distribution validation only; not a security proof",
    "tensor_preimage_coordinate_checks":tensor_identity_checks,
    "tensor_norm_identity_checks":norm_checks,
    "gap_amplification":gap_rows,
    "exact_one_corrupted_factor_distributions":residual_distribution_checks,
    "large_q_noise_controls":large_q,
    "noiseless_cp_public_recovery_fixtures":noiseless_public_recovery,
    "noiseless_solution_invariance_checks":invariance_checks,
    "noisy_cp_residual_identity_checks":noisy_cp_checks,
    "affine_tensor_power_span_checks":affine_span_checks,
    "tensor_relation_rank_checks":tensor_rank_checks,
    "tensor_relation_kernel_direction_checks":tensor_kernel_checks,
}
blob=json.dumps(result,sort_keys=True,indent=2)+"\n"
print(blob,end="")
