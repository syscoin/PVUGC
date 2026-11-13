#!/usr/bin/env python3
import itertools, json, math, random, hashlib
from collections import Counter

SEED = 670067
rng = random.Random(SEED)

def powerset(scope):
    scope = tuple(sorted(scope))
    out = [()]
    for x in scope:
        out += [tuple(sorted(s + (x,))) for s in out]
    return out

def support_degree(n, d):
    out = [()]
    for k in range(1, d+1):
        out.extend(itertools.combinations(range(n), k))
    return [tuple(x) for x in out]

def support_scopes(scopes):
    s = {()}
    for q in scopes:
        s.update(powerset(q))
    return sorted(s, key=lambda x:(len(x), x))

def eval_poly(coeffs, point_set, q):
    total = 0
    P = set(point_set)
    for S,a in coeffs.items():
        if set(S).issubset(P):
            total = (total + a) % q
    return total

def mobius_reconstruct(support, evals, q):
    # support downward closed, evals[T] = F(1_T)
    out = {}
    for T in support:
        s = 0
        # only subsets of T
        Tlist = list(T)
        for r in range(len(Tlist)+1):
            for U in itertools.combinations(Tlist, r):
                sign = -1 if ((len(T)-len(U)) & 1) else 1
                s = (s + sign * evals[tuple(U)]) % q
        out[T] = s % q
    return out

def dot(a,b,q):
    return sum((x*y) for x,y in zip(a,b)) % q

def inv_mod(a,q):
    return pow(a % q, q-2, q)

def solve_linear_mod(A,b,q):
    # returns one solution with free vars 0, or None
    M = [list(map(lambda x:x%q,row)) + [bb%q] for row,bb in zip(A,b)]
    m = len(M)
    n = len(M[0])-1 if M else 0
    pivots=[]
    r=0
    for c in range(n):
        piv=None
        for rr in range(r,m):
            if M[rr][c] % q:
                piv=rr; break
        if piv is None: continue
        M[r],M[piv]=M[piv],M[r]
        inv=inv_mod(M[r][c],q)
        M[r]=[(x*inv)%q for x in M[r]]
        for rr in range(m):
            if rr!=r and M[rr][c]%q:
                f=M[rr][c]%q
                M[rr]=[(x-f*y)%q for x,y in zip(M[rr],M[r])]
        pivots.append(c); r+=1
        if r==m: break
    for rr in range(r,m):
        if all(M[rr][c]%q==0 for c in range(n)) and M[rr][n]%q:
            return None
    x=[0]*n
    for rr,c in enumerate(pivots):
        x[c]=M[rr][n]%q
    return x

def vec_from_coeffs(coeffs, support, q):
    return [coeffs.get(S,0)%q for S in support]

def coeffs_from_vec(v, support, q):
    return {S:(x%q) for S,x in zip(support,v)}

def add_vecs(vs, coeffs, q):
    n=len(vs[0])
    out=[0]*n
    for a,v in zip(coeffs,vs):
        for i,x in enumerate(v):
            out[i]=(out[i]+a*x)%q
    return out

def eval_functional_at_boolean(support, bits, q):
    supp={i for i,b in enumerate(bits) if b}
    return [1 if set(S).issubset(supp) else 0 for S in support]

def random_constraint_vanishing_at_w(support, w, q):
    v=[rng.randrange(q) for _ in support]
    # Adjust constant coefficient so evaluation at w is zero.
    ell=eval_functional_at_boolean(support,w,q)
    val=dot(v,ell,q)
    idx0=support.index(())
    v[idx0]=(v[idx0]-val)%q
    assert dot(v,ell,q)==0
    return v

def hidden_eval_from_vec(fvec,support,T,q):
    total=0
    Tset=set(T)
    for x,S in zip(fvec,support):
        if set(S).issubset(Tset):
            total=(total+x)%q
    return total

results = {
    "seed": SEED,
    "dense_reconstruction": {},
    "local_scope_reconstruction": {},
    "true_instance_key_recovery": {},
    "noisy_identity": {},
    "false_span_control": {},
}

# 1. Dense reconstructions.
dense_cases=0
dense_coeffs=0
for q in [17,101,257]:
    for n,d in [(6,2),(7,3),(8,4)]:
        supp=support_degree(n,d)
        for _ in range(12):
            coeff={S:rng.randrange(q) for S in supp}
            ev={T:eval_poly(coeff,T,q) for T in supp}
            rec=mobius_reconstruct(supp,ev,q)
            assert all(rec[S]%q==coeff[S]%q for S in supp)
            dense_cases += 1
            dense_coeffs += len(supp)
results["dense_reconstruction"] = {
    "cases": dense_cases,
    "coefficient_equalities": dense_coeffs,
}

# 2. Local supports, including width 10.
local_specs = [
    (24, 12, 5, 101),
    (32, 8, 6, 257),
    (40, 4, 10, 257),
]
local_cases=0
local_coeffs=0
max_support=0
details=[]
for n,T,R,q in local_specs:
    # make deterministic overlapping-ish scopes
    scopes=[]
    for j in range(T):
        start=(j*max(1,R//2)) % n
        scope=tuple(sorted({(start+i)%n for i in range(R)}))
        # ensure exact R if wrap caused weirdness
        if len(scope)<R:
            cand=list(range(n))
            for x in cand:
                if x not in scope:
                    scope=tuple(sorted(set(scope)|{x}))
                    if len(scope)==R: break
        scopes.append(scope)
    supp=support_scopes(scopes)
    max_support=max(max_support,len(supp))
    coeff={S:rng.randrange(q) for S in supp}
    ev={T0:eval_poly(coeff,T0,q) for T0 in supp}
    rec=mobius_reconstruct(supp,ev,q)
    assert rec==coeff
    local_cases += 1
    local_coeffs += len(supp)
    details.append({"n":n,"T":T,"R":R,"q":q,"support_size":len(supp),"bound":T*(2**R)})
results["local_scope_reconstruction"] = {
    "cases": local_cases,
    "coefficient_equalities": local_coeffs,
    "max_support_size": max_support,
    "details": details,
}

# 3. True satisfiable instances. Attack gets support, constraints, and evaluator, not planted witness.
q=257
n=8
d=3
supp=support_degree(n,d)
idx0=supp.index(())
trials=400
recovered=0
non_eval_duals=0
dual_solutions=0
for _ in range(trials):
    w=[rng.randrange(2) for _ in range(n)]
    H=[random_constraint_vanishing_at_w(supp,w,q) for __ in range(10)]
    rho=[rng.randrange(q) for __ in H]
    K=rng.randrange(q)
    u=[0]*len(supp); u[idx0]=1
    f=add_vecs([u]+H,[K]+rho,q)
    # black-box interpolation
    evals={}
    for T in supp:
        evals[T]=hidden_eval_from_vec(f,supp,T,q)
    rec=mobius_reconstruct(supp,evals,q)
    f2=vec_from_coeffs(rec,supp,q)
    assert f2==f
    # public lambda constraints: lambda(u)=1, lambda(h_j)=0.
    A=[u]+H
    b=[1]+[0]*len(H)
    lam=solve_linear_mod(A,b,q)
    assert lam is not None
    dual_solutions += 1
    assert dot(lam,u,q)==1
    assert all(dot(lam,h,q)==0 for h in H)
    guess=dot(lam,f2,q)
    assert guess==K
    recovered+=1
    # Diagnostic: is lam literally a Boolean evaluation functional?
    is_eval=False
    for bits in itertools.product([0,1], repeat=n):
        if eval_functional_at_boolean(supp,bits,q)==lam:
            is_eval=True; break
    if not is_eval:
        non_eval_duals += 1
results["true_instance_key_recovery"] = {
    "trials": trials,
    "exact_key_recoveries": recovered,
    "public_dual_solutions": dual_solutions,
    "synthesized_dual_not_any_boolean_evaluation": non_eval_duals,
    "support_size": len(supp),
    "queries_per_interpolation": len(supp),
}

# 4. Noisy residual identity.
noise_trials=1200
noise_ok=0
for _ in range(noise_trials):
    w=[rng.randrange(2) for _ in range(n)]
    H=[random_constraint_vanishing_at_w(supp,w,q) for __ in range(8)]
    rho=[rng.randrange(q) for __ in H]
    K=rng.randrange(q)
    u=[0]*len(supp); u[idx0]=1
    e=[rng.randrange(-3,4)%q for __ in supp]
    clean=add_vecs([u]+H,[K]+rho,q)
    f=[(x+y)%q for x,y in zip(clean,e)]
    lam=solve_linear_mod([u]+H,[1]+[0]*len(H),q)
    lhs=dot(lam,f,q)
    rhs=(K+dot(lam,e,q))%q
    assert lhs==rhs
    noise_ok+=1
results["noisy_identity"] = {
    "trials": noise_trials,
    "exact_residual_identities": noise_ok,
    "noise_support": "centered integers -3..3 reduced mod q",
}

# 5. False span control: h=1, exhaustive hidden rho gives key-independent output distribution.
qf=17
suppf=[()]
u=[1]
hist_by_key={}
for K in range(qf):
    ctr=Counter()
    for rho in range(qf):
        f=[(K+rho)%qf]
        # "interpolation" is identity; record full coefficient vector.
        ctr[tuple(f)] += 1
    hist_by_key[K]=ctr
base=hist_by_key[0]
assert all(hist_by_key[K]==base for K in range(qf))
results["false_span_control"] = {
    "field": qf,
    "keys_checked": qf,
    "hidden_coefficients_per_key": qf,
    "identical_histograms": True,
    "support_points_per_key": len(base),
}

out=json.dumps(results,sort_keys=True,indent=2)+"\n"
print(out)
