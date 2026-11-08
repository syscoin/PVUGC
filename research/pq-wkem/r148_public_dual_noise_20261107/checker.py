"""R148: exact public-dual extraction checks; stdlib + SymPy 1.14.0.
These are arithmetic checks, not cryptographic security experiments.
"""
from fractions import Fraction
from itertools import combinations, product
from random import Random
from sympy import Matrix, zeros
import json

# Monomials [1,x,y,x^2,xy,y^2]; columns: x^2-x, y^2-y, (1-x)(1-y).
M = Matrix([[0,0,1],[-1,0,-1],[0,-1,-1],[1,0,0],[0,0,1],[0,1,0]])
e0 = Matrix([1,0,0,0,0,0])
N=6
C=M.T.col_join(e0.T)
b=Matrix([0,0,0,1])
assert C.rank()==4

def eval_vec(x,y):
    return Matrix([1,x,y,x*x,x*y,y*y])

witnesses=[]
for x,y in product((0,1),repeat=2):
    v=eval_vec(x,y)
    if x or y:
        assert M.T*v == zeros(3,1)
        assert (e0.T*v)[0] == 1
        witnesses.append((x,y,v))

# Exact min-l1 over all basic feasible solutions of C lambda=b.
# A basic optimum for this equality LP can be taken with <=rank(C) signed coordinates.
candidates=[]
for z in range(1,C.rank()+1):
    for inds in combinations(range(N),z):
        A=C[:,list(inds)]
        if A.rank()!=z or A.row_join(b).rank()!=z:
            continue
        vals=A.gauss_jordan_solve(b)[0]
        lam=Matrix([0]*N)
        for i,v in zip(inds,vals): lam[i]=v
        assert C*lam == b
        candidates.append((sum(abs(v) for v in lam), lam))
assert candidates
bestl1,best=min(candidates,key=lambda p:(p[0],tuple(p[1])))

# Exact minimum isotropic Gaussian-variance dual: C.T (C C.T)^-1 b.
lmin=C.T*(C*C.T).inv()*b
assert C*lmin==b
sq=lambda v:sum(z*z for z in v)
assert sq(lmin) <= min(sq(v) for x,y,v in witnesses)
assert bestl1 <= min(sum(abs(z) for z in v) for x,y,v in witnesses)

# Noise-bounded modular demonstration uses INTEGER public dual only;
# rational lmin does NOT authorize reducing its coefficients modulo q.
q=65521; delta=64; K=1; limit=2048
rng=Random(148)
for trial in range(limit):
    r=Matrix([rng.randrange(q) for _ in range(3)])
    eta=Matrix([rng.randrange(-1,2) for _ in range(N)])
    P=(M*r+delta*K*e0+eta).applyfunc(lambda z:int(z)%q)
    # For an integral lambda, congruence is valid under modular reduction.
    def dec(lam):
        raw=int((lam.T*P)[0])%q
        return min((0,1),key=lambda k:min((raw-delta*k)%q,(delta*k-raw)%q))
    assert all(dec(v)==K for _,_,v in witnesses)
    assert all(z.q==1 for z in best)
    assert dec(best)==K

summary={
 'checks':'PASS', 'tested_modular_tapes':limit,
 'M_shape':list(M.shape),'constraint_rank':int(C.rank()),
 'valid_assignments':[[x,y] for x,y,v in witnesses],
 'public_min_l1_dual':[str(z) for z in best],
 'public_min_l1':str(bestl1),
 'public_min_var_dual':[str(z) for z in lmin],
 'public_min_var_norm_sq':str(sq(lmin)),
 'smallest_honest_l1':str(min(sum(abs(z) for z in v) for _,_,v in witnesses)),
 'smallest_honest_l2_sq':str(min(sq(v) for _,_,v in witnesses)),
 'modular_demo':{'q':q,'delta':delta,'eta_range':[-1,1], 'K':K,'notes':'only a 2-variable easy TRUE instance; not a hard-TRUE or QPT result'},
}
print(json.dumps(summary,sort_keys=True,indent=2))
