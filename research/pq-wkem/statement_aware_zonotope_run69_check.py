#!/usr/bin/env python3
import json, random
from itertools import product, combinations
from fractions import Fraction
from collections import defaultdict

SEED = 690069
Q = 257

def inv_mod(a,q):
    return pow(a % q, -1, q)

def rref_mod(A,b=None,q=Q):
    A=[[x % q for x in row] for row in A]
    m=len(A); n=len(A[0]) if m else 0
    aug=[row[:] + ([] if b is None else [b[i] % q]) for i,row in enumerate(A)]
    piv=[]; r=0
    for c in range(n):
        p=next((i for i in range(r,m) if aug[i][c] % q),None)
        if p is None: continue
        aug[r],aug[p]=aug[p],aug[r]
        z=inv_mod(aug[r][c],q)
        aug[r]=[(x*z) % q for x in aug[r]]
        for i in range(m):
            if i != r and aug[i][c] % q:
                f=aug[i][c] % q
                aug[i]=[(aug[i][j]-f*aug[r][j]) % q for j in range(len(aug[i]))]
        piv.append(c); r += 1
        if r == m: break
    return aug,piv

def affine_solution_mod(A,b,q):
    aug,piv=rref_mod(A,b,q)
    n=len(A[0]) if A else 0
    for row in aug:
        if all(x % q == 0 for x in row[:n]) and row[n] % q:
            return None,None
    free=[j for j in range(n) if j not in piv]
    x0=[0]*n
    prow={c:i for i,c in enumerate(piv)}
    for c,i in prow.items():
        x0[c]=aug[i][n] % q
    basis=[]
    for f in free:
        v=[0]*n; v[f]=1
        for c,i in prow.items():
            v[c]=(-aug[i][f]) % q
        basis.append(v)
    return x0,basis

def rank_cols(cols,q):
    if not cols: return 0
    A=[list(row) for row in zip(*cols)]
    return len(rref_mod(A,None,q)[1])

def in_span(cols,target,q):
    if not cols:
        return not any(target)
    A=[list(row) for row in zip(*cols)]
    return affine_solution_mod(A,target,q)[0] is not None

def monomials(n,D,max_exp=2):
    mons=[]
    for e in product(range(max_exp+1), repeat=n):
        if sum(e) <= D:
            mons.append(e)
    mons.sort(key=lambda e:(sum(e),e))
    return mons

def poly_mul(p,qpoly,mod):
    out=defaultdict(int)
    for a,ca in p.items():
        for b,cb in qpoly.items():
            e=tuple(x+y for x,y in zip(a,b))
            out[e]=(out[e]+ca*cb) % mod
    return {e:c for e,c in out.items() if c % mod}

def const_poly(n,c):
    return {(0,)*n:c}

def literal_falsity_poly(n,i,positive,mod):
    e=[0]*n; e[i]=1; e=tuple(e)
    if positive:
        return {(0,)*n:1, e:(-1) % mod}
    return {e:1}

def clause_falsity_poly(n,clause,mod):
    p=const_poly(n,1)
    for i,pos in clause:
        p=poly_mul(p,literal_falsity_poly(n,i,pos,mod),mod)
    return p

def bool_vanish_generator(n,i,h,mod):
    e1=[0]*n; e2=[0]*n
    e1[i]=1; e2[i]=2
    base={tuple(e2):1, tuple(e1):(-1) % mod}
    return poly_mul({tuple(h):1},base,mod)

def vec_from_poly(p,basis,mod):
    idx={e:i for i,e in enumerate(basis)}
    v=[0]*len(basis)
    for e,c in p.items():
        if e not in idx:
            raise AssertionError(("missing basis monomial",e))
        v[idx[e]]=c % mod
    return v

def eval_basis(basis,x,mod):
    out=[]
    for e in basis:
        z=1
        for xi,p in zip(x,e):
            z=(z*pow(xi,p,mod)) % mod
        out.append(z)
    return out

def dot(a,b,q):
    return sum(x*y for x,y in zip(a,b)) % q

def add_scaled(y,col,c,q):
    return [(a+c*b) % q for a,b in zip(y,col)]

def clause_false(cl,x):
    return all((x[i] == 0 if pos else x[i] == 1) for i,pos in cl)

def formula_valid(clauses,x):
    return all(not clause_false(cl,x) for cl in clauses)

def random_planted_3cnf(rng,n,m,w):
    clauses=[]
    for _ in range(m):
        vs=rng.sample(range(n),3)
        signs=[rng.choice([False,True]) for _ in range(3)]
        if not any((w[i] == 1 if p else w[i] == 0) for i,p in zip(vs,signs)):
            j=rng.randrange(3)
            signs[j]=bool(w[vs[j]])
        clauses.append(list(zip(vs,signs)))
    return clauses

def build_spaces(n,clauses,D,q):
    basis=monomials(n,D,2)
    idx={e:i for i,e in enumerate(basis)}
    G=[vec_from_poly(clause_falsity_poly(n,cl,q),basis,q) for cl in clauses]
    N=[]
    for i in range(n):
        for h in product([0,1],repeat=n):
            if h[i] or sum(h) > D-2: continue
            p=bool_vanish_generator(n,i,h,q)
            if all(e in idx for e in p):
                N.append(vec_from_poly(p,basis,q))
    u=[0]*len(basis); u[basis.index((0,)*n)]=1
    return basis,G,N,u

def public_dual_space(G,N,u,q):
    rows=[c[:] for c in G+N] + [u[:]]
    rhs=[0]*(len(G)+len(N))+[1]
    return affine_solution_mod(rows,rhs,q)

def sample_affine(rng,x0,nb,q):
    x=x0[:]
    for v in nb:
        c=rng.randrange(q)
        if c:
            x=[(a+c*b)%q for a,b in zip(x,v)]
    return x

def is_boolean_evaluation(lam,basis,q):
    n=len(basis[0])
    idx={e:i for i,e in enumerate(basis)}
    if lam[idx[(0,)*n]] % q != 1:
        return False,None
    bits=[]
    for i in range(n):
        e=[0]*n;e[i]=1
        z=lam[idx[tuple(e)]] % q
        if z not in (0,1):
            return False,None
        bits.append(z)
    ev=eval_basis(basis,bits,q)
    return (all((a-b)%q==0 for a,b in zip(lam,ev)), tuple(bits))

def true_instance_trials():
    rng=random.Random(SEED)
    cases=120
    exact_witness_decodes=0
    public_dual_decodes=0
    non_eval_duals=0
    total_resamples=0
    min_dim=10**9
    max_dim=0
    union_bound_log2=[]
    for _ in range(cases):
        n=4; m=8; D=4; q=Q
        w=tuple(rng.randrange(2) for _ in range(n))
        clauses=random_planted_3cnf(rng,n,m,w)
        basis,G,N,u=build_spaces(n,clauses,D,q)
        assert formula_valid(clauses,w)
        ell=eval_basis(basis,w,q)
        assert all(dot(ell,c,q)==0 for c in G+N)
        assert dot(ell,u,q)==1
        K=rng.randrange(q)
        y=[(K*z)%q for z in u]
        for c in G:
            y=add_scaled(y,c,rng.randrange(q),q)
        for c in N:
            y=add_scaled(y,c,rng.randrange(q),q)
        if dot(ell,y,q)==K:
            exact_witness_decodes += 1
        x0,nb=public_dual_space(G,N,u,q)
        assert x0 is not None
        d=len(nb); min_dim=min(min_dim,d); max_dim=max(max_dim,d)
        union_bound_log2.append(n-d*(q.bit_length()-1))  # conservative q>=2^(bitlen-1)
        # reject actual Boolean evaluation vectors; no SAT search is used
        tries=0
        while True:
            tries += 1
            lam=sample_affine(rng,x0,nb,q)
            isev,_=is_boolean_evaluation(lam,basis,q)
            if not isev:
                break
            assert tries < 1000
        total_resamples += tries-1
        non_eval_duals += 1
        assert all(dot(lam,c,q)==0 for c in G+N)
        assert dot(lam,u,q)==1
        if dot(lam,y,q)==K:
            public_dual_decodes += 1
    return {
        "cases": cases,
        "exact_witness_decodes": exact_witness_decodes,
        "public_non_evaluation_dual_decodes": public_dual_decodes,
        "non_evaluation_duals_constructed": non_eval_duals,
        "total_rejected_boolean_evaluation_samples": total_resamples,
        "dual_affine_dimension_min": min_dim,
        "dual_affine_dimension_max": max_dim,
        "conservative_log2_union_bound_max": max(union_bound_log2),
    }

def invalid_pointwise_uniformity():
    q=5; n=3; D=4
    # One clause x0 OR x1 OR x2; choose invalid 000.
    clauses=[[(0,True),(1,True),(2,True)]]
    basis,G,N,u=build_spaces(n,clauses,D,q)
    x=(0,0,0)
    ell=eval_basis(basis,x,q)
    assert dot(ell,G[0],q)==1
    hist=[0]*q
    K=3
    # N always vanishes on Boolean x, so enumerate the complete random
    # constraint multiplier exactly.
    for r in range(q):
        y=[(K*z)%q for z in u]
        y=add_scaled(y,G[0],r,q)
        hist[dot(ell,y,q)] += 1
    assert hist == [1]*q
    return {"q":q,"invalid_assignment":"000","histogram":hist}

FALSE_CLAUSES = [
    [(1, True), (2, False), (3, False)],
    [(0, True), (1, False), (2, False)],
    [(0, True), (1, False), (3, True)],
    [(1, False), (2, True), (3, False)],
    [(1, True), (2, True), (3, True)],
    [(0, False), (1, False), (3, True)],
    [(1, True), (2, False), (3, True)],
    [(0, False), (1, False), (2, False)],
    [(1, True), (2, True), (3, False)],
]

def false_complete_output_counterexample():
    q=Q;n=4;D=4
    clauses=FALSE_CLAUSES
    assignments=list(product([0,1],repeat=n))
    assert not any(formula_valid(clauses,x) for x in assignments)
    basis,G,N,u=build_spaces(n,clauses,D,q)
    W=G+N
    rW=rank_cols(W,q)
    rWu=rank_cols(W+[u],q)
    assert rWu == rW+1
    x0,nb=public_dual_space(G,N,u,q)
    assert x0 is not None
    rng=random.Random(SEED+1)
    decodes=0
    for _ in range(200):
        K=rng.randrange(q)
        y=[(K*z)%q for z in u]
        for c in G:
            y=add_scaled(y,c,rng.randrange(q),q)
        for c in N:
            y=add_scaled(y,c,rng.randrange(q),q)
        if dot(x0,y,q)==K:
            decodes += 1
    # Every Boolean candidate violates at least one clause, hence its marginal
    # over uniform r is exactly uniform, although the joint coefficient vector leaks.
    violated=[sum(1 for cl in clauses if clause_false(cl,x)) for x in assignments]
    assert min(violated)>=1
    return {
        "n":n,"clauses":len(clauses),"feature_dimension":len(basis),
        "boolean_vanishing_generators":len(N),
        "rank_W":rW,"rank_W_plus_u":rWu,
        "dual_affine_dimension":len(nb),
        "boolean_assignments":len(assignments),
        "minimum_violated_clauses_per_assignment":min(violated),
        "public_dual_exact_decodes":decodes,
    }

def solve_square_fraction(A,b):
    n=len(A)
    M=[[Fraction(x) for x in row]+[Fraction(y)] for row,y in zip(A,b)]
    r=0
    for c in range(n):
        p=next((i for i in range(r,n) if M[i][c] != 0),None)
        if p is None: return None
        M[r],M[p]=M[p],M[r]
        z=M[r][c]
        M[r]=[x/z for x in M[r]]
        for i in range(n):
            if i != r and M[i][c] != 0:
                z=M[i][c]
                M[i]=[M[i][j]-z*M[r][j] for j in range(n+1)]
        r += 1
    return [M[i][-1] for i in range(n)]

def l1_zonotope_lp_or2(H):
    # Basis (1,x1,x2,x1x2), W=span((1,-1,-1,1)), u=e0.
    s=len(H); M=4; d=M+s
    g=[1,-1,-1,1]; u=[1,0,0,0]
    eq=[g+[0]*s,u+[0]*s]; rhs=[0,1]
    ineq=[]
    for j,h in enumerate(H):
        a=[Fraction(v) for v in h]+[Fraction(0)]*s
        a[M+j]-=1
        ineq.append(a)
        a=[Fraction(-v) for v in h]+[Fraction(0)]*s
        a[M+j]-=1
        ineq.append(a)
        a=[Fraction(0)]*d; a[M+j]=-1
        ineq.append(a)
    need=d-len(eq)
    best=None; bestx=None
    for active in combinations(range(len(ineq)),need):
        A=[list(map(Fraction,r)) for r in eq]+[ineq[i] for i in active]
        b=[Fraction(v) for v in rhs]+[Fraction(0)]*need
        x=solve_square_fraction(A,b)
        if x is None: continue
        if any(sum(row[k]*x[k] for k in range(d)) > 0 for row in ineq):
            continue
        obj=sum(x[M+j] for j in range(s))
        if best is None or obj < best:
            best,bestx=obj,x
    if best is None:
        raise AssertionError("no LP vertex found")
    return best,bestx[:M]

def zonotope_trials():
    rng=random.Random(SEED+2)
    witnesses=[
        [1,1,0,0],
        [1,0,1,0],
        [1,1,1,1],
    ]
    cases=160; no_worse=0; strict=0; non_eval=0
    ratios=[]; attempts=0
    while no_worse < cases:
        attempts += 1
        assert attempts < 5000
        H=[[rng.randint(-4,4) for _ in range(4)] for __ in range(3)]
        try:
            best,lam=l1_zonotope_lp_or2(H)
        except AssertionError:
            continue
        wr=[]
        for ell in witnesses:
            wr.append(sum(abs(sum(h[i]*ell[i] for i in range(4))) for h in H))
        mn=Fraction(min(wr))
        assert best <= mn
        no_worse += 1
        if best < mn: strict += 1
        if not any(all(lam[i]==Fraction(ell[i]) for i in range(4)) for ell in witnesses):
            non_eval += 1
        if mn:
            ratios.append(float(best/mn))
    return {
        "cases":cases,
        "public_lp_no_worse_than_best_witness":no_worse,
        "strictly_better_cases":strict,
        "public_lp_non_witness_functional_cases":non_eval,
        "max_public_to_best_witness_radius_ratio":max(ratios) if ratios else 0.0,
        "sampling_attempts":attempts,
    }

def main():
    out={
        "run":69,
        "seed":SEED,
        "field_q":Q,
        "true_statement_statement_aware_mask":true_instance_trials(),
        "invalid_boolean_pointwise_uniformity":invalid_pointwise_uniformity(),
        "false_statement_complete_output_counterexample":false_complete_output_counterexample(),
        "public_zonotope_support_lp":zonotope_trials(),
    }
    print(json.dumps(out,sort_keys=True,indent=2))

if __name__=="__main__":
    main()
