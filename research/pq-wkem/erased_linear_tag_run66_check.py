#!/usr/bin/env python3
import itertools, random, json, hashlib, math
from pathlib import Path

SEED = 660066
rng = random.Random(SEED)
Q = 257

def mod(x,q=Q): return x % q
def dot(a,b,q=Q): return sum(x*y for x,y in zip(a,b)) % q

def rref_nullspace(rows, ncols, q=Q):
    A=[[(x%q) for x in row] for row in rows]
    piv=[]
    r=0
    for c in range(ncols):
        pivrow=None
        for rr in range(r,len(A)):
            if A[rr][c]%q:
                pivrow=rr; break
        if pivrow is None: continue
        A[r],A[pivrow]=A[pivrow],A[r]
        inv=pow(A[r][c], -1, q)
        A[r]=[(v*inv)%q for v in A[r]]
        for rr in range(len(A)):
            if rr!=r and A[rr][c]%q:
                f=A[rr][c]%q
                A[rr]=[(A[rr][j]-f*A[r][j])%q for j in range(ncols)]
        piv.append(c)
        r+=1
        if r==len(A): break
    free=[c for c in range(ncols) if c not in piv]
    basis=[]
    for f in free:
        v=[0]*ncols
        v[f]=1
        for rr,p in enumerate(piv):
            v[p]=(-A[rr][f])%q
        basis.append(v)
    return basis, len(piv)

def lincomb(coeffs, vecs, q=Q):
    n=len(vecs[0])
    out=[0]*n
    for a,v in zip(coeffs,vecs):
        for j,x in enumerate(v):
            out[j]=(out[j]+a*x)%q
    return out

def onehot(m,i):
    v=[0]*m; v[i]=1; return v

def qviol(z,q=Q):
    out=[]
    m=len(z)
    for i in range(m):
        out.append((z[i]*(z[i]-1))%q)
    for i in range(m):
        for j in range(i+1,m):
            out.append((z[i]*z[j])%q)
    return out

def signed_lift(f):
    k=len(f)
    out={}
    for a in itertools.product((0,1), repeat=k):
        if a==f: continue
        dh=sum(x!=y for x,y in zip(a,f))
        out[a]=1 if ((dh+1)%2==0) else -1
    return out

def monomial(a,S):
    r=1
    for i in S: r*=a[i]
    return r

def delta_f(a,f):
    r=1
    for x,y in zip(a,f):
        r*= x if y else (1-x)
    return r

results={"seed":SEED,"q":Q}

# 1) General affine-hull theorem checks with arbitrary random source lifts.
affine_trials=0
affine_checks=0
null_dims=[]
for m in (3,4,6,8):
    D=m+12
    for _ in range(80):
        # source lift U_i = (1, e_i, random tail)
        U=[]
        for i in range(m):
            u=[1]+onehot(m,i)+[rng.randrange(Q) for _ in range(D-m-1)]
            U.append(u)
        diffs=[[(U[i][j]-U[0][j])%Q for j in range(D)] for i in range(1,m)]
        ns,rank=rref_nullspace(diffs,D,Q)
        assert ns
        null_dims.append(len(ns))
        # choose up to 6 secret linear tags from the entire constant-on-source space
        tags=[]
        for _t in range(min(6,len(ns))):
            coeff=[rng.randrange(Q) for _ in ns]
            L=lincomb(coeff,ns,Q)
            tags.append(L)
        lam=[0]*m
        lam[0]=1; lam[1]=1; lam[2]=Q-1 # 1+1-1 =1
        assert sum(lam)%Q==1
        forge=lincomb(lam,U,Q)
        # raw projection is normalized signed vector
        assert forge[0]==1
        assert forge[1:1+m]==lam
        for L in tags:
            vals=[dot(L,u,Q) for u in U]
            assert len(set(vals))==1
            assert dot(L,forge,Q)==vals[0]
            affine_checks += 1
        affine_trials += 1
results["affine_hull"]={
    "random_source_lift_trials":affine_trials,
    "secret_constant_linear_tag_checks":affine_checks,
    "min_nullspace_dimension":min(null_dims),
    "max_nullspace_dimension":max(null_dims),
    "forge_coefficients_centered":[1,1,-1],
}

# 2) Ideal nonlinear quadratic checksum: exact fixed-malformed detection.
# Exhaustively verify G(z)!=0 over normalized small centered vectors.
quad_vectors=0
for m in range(3,7):
    vals=(-2,-1,0,1,2)
    # enumerate first m-1 and force last to make integer sum 1 if in range
    for pre in itertools.product(vals, repeat=m-1):
        last=1-sum(pre)
        if last not in vals: continue
        z=list(pre)+[last]
        if sum(1 for x in z if x!=0)==1 and 1 in z:
            # exact one-hot
            continue
        g=qviol([x%Q for x in z],Q)
        assert any(g)
        quad_vectors += 1

# Exact 1/q zero probability by varying one random coefficient of r.
z=[1,1,Q-1,0,0]
g=qviol(z,Q)
nz=next(i for i,x in enumerate(g) if x)
exact_sweeps=0
for _ in range(100):
    r=[rng.randrange(Q) for _ in g]
    zeros=0
    for x in range(Q):
        r[nz]=x
        if dot(r,g,Q)==0:
            zeros+=1
    assert zeros==1
    exact_sweeps += 1
results["ideal_quadratic_checksum"]={
    "normalized_non_onehot_vectors_verified":quad_vectors,
    "fixed_malformed_support":3,
    "exact_single_coefficient_sweeps":exact_sweeps,
    "zeros_per_q_sweep":1,
    "proved_zero_probability_per_independent_hidden_check":f"1/{Q}",
}

# 3) Linearized quadratic lift bypass.
lin_bypass=0
poly_tag_checks=0
for m in range(3,11):
    lam=[0]*m
    lam[0]=1; lam[1]=1; lam[2]=Q-1
    # Y = diag(lam): affine combination of source quadratic lifts.
    Y=[[0]*m for _ in range(m)]
    for i in range(m): Y[i][i]=lam[i]
    assert sum(lam)%Q==1
    for i in range(m):
        assert Y[i][i]%Q==lam[i]%Q
        for j in range(m):
            if i!=j: assert Y[i][j]==0
    assert any(qviol(lam,Q))  # true nonlinear relation is violated
    lin_bypass += 1

    # Any linear tag constant on all degree<=D one-hot polynomial lifts
    # also has the same value on the affine forge.
    # For squarefree monomials, source one-hot features only have constant+singleton.
    for Ddeg in range(2,min(5,m)+1):
        subsets=[()]
        for d in range(1,Ddeg+1):
            subsets += list(itertools.combinations(range(m),d))
        phis=[]
        for i in range(m):
            e=onehot(m,i)
            phis.append([monomial(e,S) for S in subsets])
        forge=lincomb(lam,phis,Q)
        # sample tags with equal singleton coefficient, arbitrary higher-degree coefficients
        idx_single=[subsets.index((i,)) for i in range(m)]
        for _ in range(12):
            L=[rng.randrange(Q) for _ in subsets]
            common=rng.randrange(Q)
            for idx in idx_single: L[idx]=common
            vals=[dot(L,p,Q) for p in phis]
            assert len(set(vals))==1
            assert dot(L,forge,Q)==vals[0]
            poly_tag_checks += 1

results["linearized_lift_bypass"]={
    "dimensions_m_checked":list(range(3,11)),
    "quadratic_linearized_bypasses":lin_bypass,
    "polynomial_secret_tag_checks":poly_tag_checks,
    "forge_support":3,
    "true_quadratic_violation_nonzero":True,
}

# 4) Run-53 all-exclusions signed lifts cancel secret incidence tags exactly.
# 8 width-3 clauses, each uniquely rejects one f.
k=3
assignments=list(itertools.product((0,1), repeat=k))
blocks=assignments[:]
pseudolifts={}
for t in assignments:
    blk=[]
    for f in blocks:
        if t!=f:
            z={a:0 for a in assignments if a!=f}
            z[t]=1
        else:
            z=signed_lift(f)
        # normalization and first moments reproduce t
        assert sum(z.values())==1
        for v in range(k):
            assert sum(a[v]*coef for a,coef in z.items())==t[v]
        blk.append(z)
    pseudolifts[t]=blk

incidence_setups=200
incidence_cases=0
for _ in range(incidence_setups):
    theta=[[[rng.randrange(Q) for bit in range(2)] for v in range(k)]][0]  # theta[v][bit]
    # weights s[b][v], sum_b=0 for each v
    s=[[0]*k for _ in blocks]
    for v in range(k):
        acc=0
        for b in range(len(blocks)-1):
            s[b][v]=rng.randrange(Q); acc=(acc+s[b][v])%Q
        s[-1][v]=(-acc)%Q
        assert sum(s[b][v] for b in range(len(blocks)))%Q==0
    for t,blk in pseudolifts.items():
        total=0
        for b,z in enumerate(blk):
            for a,coef in z.items():
                rowtag=sum(s[b][v]*theta[v][a[v]] for v in range(k))%Q
                total=(total+coef*rowtag)%Q
        assert total==0
        incidence_cases+=1

results["hidden_incidence_tags"]={
    "false_formula_blocks":8,
    "false_assignments_with_exact_signed_pseudolifts":8,
    "random_erased_tag_setups":incidence_setups,
    "exact_zero_tag_pseudolift_cases":incidence_cases,
}

# 5) Proper-degree moment hierarchy: signed falsifying lift reproduces every degree<k polynomial moment.
moment_checks=0
full_degree_separations=0
for k in range(2,9):
    for f in itertools.product((0,1), repeat=k):
        z=signed_lift(f)
        inds=range(k)
        for d in range(0,k):
            for S in itertools.combinations(inds,d):
                lhs=sum(coef*monomial(a,S) for a,coef in z.items())
                rhs=monomial(f,S)
                assert lhs==rhs
                moment_checks+=1
        # degree-k point indicator delta_f separates exactly
        lhs=sum(coef*delta_f(a,f) for a,coef in z.items())
        rhs=delta_f(f,f)
        assert lhs==0 and rhs==1
        full_degree_separations+=1

results["proper_degree_hierarchy"]={
    "k_range":[2,8],
    "proper_moment_equalities_checked":moment_checks,
    "full_degree_point_indicator_separations":full_degree_separations,
    "claim":"signed falsifying lift matches every multilinear polynomial of degree < k",
}

# Deterministic canonical JSON and hashes.
script_path=Path(__file__)
results["checker_sha256"]=hashlib.sha256(script_path.read_bytes()).hexdigest()
print(json.dumps(results, sort_keys=True, indent=2))
