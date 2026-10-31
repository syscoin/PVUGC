#!/usr/bin/env python3
import json, math, random, hashlib
from fractions import Fraction
from itertools import product, combinations
from collections import Counter

SEED = 640064
random.seed(SEED)


def dot(a,b):
    return sum(x*y for x,y in zip(a,b))

def mat_vec(A,x):
    return [dot(row,x) for row in A]

def transpose(A):
    return [list(c) for c in zip(*A)] if A else []

def mat_mul(A,B):
    BT=transpose(B)
    return [[dot(r,c) for c in BT] for r in A]

def eye(n):
    return [[Fraction(int(i==j)) for j in range(n)] for i in range(n)]

def inverse(A):
    n=len(A)
    M=[list(map(Fraction,row))+eye(n)[i] for i,row in enumerate(A)]
    for c in range(n):
        p=next((r for r in range(c,n) if M[r][c]),None)
        if p is None: raise ValueError('singular')
        M[c],M[p]=M[p],M[c]
        invp=1/M[c][c]
        M[c]=[v*invp for v in M[c]]
        for r in range(n):
            if r!=c and M[r][c]:
                f=M[r][c]
                M[r]=[a-f*b for a,b in zip(M[r],M[c])]
    return [row[n:] for row in M]

def rank(A):
    if not A: return 0
    M=[list(map(Fraction,row)) for row in A]
    m,n=len(M),len(M[0]); r=0
    for c in range(n):
        p=next((i for i in range(r,m) if M[i][c]),None)
        if p is None: continue
        M[r],M[p]=M[p],M[r]
        invp=1/M[r][c]
        M[r]=[v*invp for v in M[r]]
        for i in range(m):
            if i!=r and M[i][c]:
                f=M[i][c]
                M[i]=[a-f*b for a,b in zip(M[i],M[r])]
        r+=1
        if r==m: break
    return r

def min_variance_dual(C,d,Sigma):
    # lambda = Sigma^-1 C^T (C Sigma^-1 C^T)^-1 d
    Sinv=inverse(Sigma)
    CT=transpose(C)
    middle=mat_mul(mat_mul(C,Sinv),CT)
    middle_inv=inverse(middle)
    tmp=mat_vec(middle_inv,d)
    return mat_vec(mat_mul(Sinv,CT),tmp)

def qform(x,S):
    return dot(x,mat_vec(S,x))

def solve_affine_particular(C,d):
    # simple RREF, free vars zero
    A=[list(map(Fraction,row))+[Fraction(rhs)] for row,rhs in zip(C,d)]
    m=len(A); n=len(C[0]); piv=[]; r=0
    for c in range(n):
        p=next((i for i in range(r,m) if A[i][c]),None)
        if p is None: continue
        A[r],A[p]=A[p],A[r]
        f=1/A[r][c]; A[r]=[v*f for v in A[r]]
        for i in range(m):
            if i!=r and A[i][c]:
                f=A[i][c]; A[i]=[a-f*b for a,b in zip(A[i],A[r])]
        piv.append(c); r+=1
    for i in range(r,m):
        if all(A[i][j]==0 for j in range(n)) and A[i][-1]!=0: raise ValueError('inconsistent')
    x=[Fraction(0) for _ in range(n)]
    for i,c in enumerate(piv): x[c]=A[i][-1]
    return x,piv

def nullspace(C):
    A=[list(map(Fraction,row)) for row in C]
    m=len(A); n=len(A[0]); piv=[]; r=0
    for c in range(n):
        p=next((i for i in range(r,m) if A[i][c]),None)
        if p is None: continue
        A[r],A[p]=A[p],A[r]
        f=1/A[r][c]; A[r]=[v*f for v in A[r]]
        for i in range(m):
            if i!=r and A[i][c]:
                f=A[i][c]; A[i]=[a-f*b for a,b in zip(A[i],A[r])]
        piv.append(c); r+=1
    free=[j for j in range(n) if j not in piv]
    basis=[]
    for fcol in free:
        x=[Fraction(0) for _ in range(n)]; x[fcol]=1
        for i,c in enumerate(piv): x[c]=-A[i][fcol]
        basis.append(x)
    return basis

def rand_full_rank_constraints(N,r):
    while True:
        V=[[Fraction(random.randint(-3,3)) for _ in range(N)] for _ in range(r)]
        if rank(V)!=r: continue
        u=[Fraction(random.randint(-3,3)) for _ in range(N)]
        C=V+[u]
        if rank(C)==r+1:
            return V,u,C

def random_spd(N):
    # integer L, Sigma=L L^T + I
    L=[[Fraction(random.randint(-2,2)) for _ in range(N)] for _ in range(N)]
    S=mat_mul(L,transpose(L))
    for i in range(N): S[i][i]+=1
    return S

def fracstr(x):
    return str(x.numerator) if x.denominator==1 else f'{x.numerator}/{x.denominator}'

results={"seed":SEED}

# Exact OR2 fixture.
g=[Fraction(1),Fraction(-1),Fraction(-1),Fraction(1)]
u=[Fraction(1),0,0,0]
C=[g,u]; d=[Fraction(0),Fraction(1)]
S=eye(4)
lstar=min_variance_dual(C,d,S)
expected=[Fraction(1),Fraction(1,3),Fraction(1,3),Fraction(-1,3)]
assert lstar==expected
w10=[Fraction(1),1,0,0]; w01=[Fraction(1),0,1,0]; w11=[Fraction(1),1,1,1]
for w in [w10,w01,w11]: assert mat_vec(C,w)==d
assert mat_vec(C,lstar)==d
alt=[Fraction(1),Fraction(-1),Fraction(1),Fraction(-1)]
assert mat_vec(C,alt)==d
assert alt not in [w10,w01,w11]
results["or2_exact"]={
    "lambda_star":[fracstr(x) for x in lstar],
    "lambda_star_norm2":fracstr(qform(lstar,S)),
    "witness_norm2":[fracstr(qform(w,S)) for w in [w10,w01,w11]],
    "integral_alt":[fracstr(x) for x in alt],
    "integral_alt_norm2":fracstr(qform(alt,S)),
    "integral_alt_l1":fracstr(sum(abs(x) for x in alt)),
}

# General r-OR Walsh dual theorem and exact iid symmetric histogram controls.
walsh=[]
for r in range(2,9):
    subsets=list(range(1<<r))
    delta=[Fraction(-1 if (s.bit_count()%2) else 1) for s in subsets]
    T=1 # singleton {0}, nonempty proper for r>=2
    lam=[Fraction(-1 if ((s&T).bit_count()%2) else 1) for s in subsets]
    assert lam[0]==1 and dot(delta,lam)==0
    allones=[Fraction(1) for _ in subsets]
    assert dot(delta,allones)==0
    assert any(x<0 for x in lam)
    # lambda_T = 2 eval_{T^c} - eval_all
    W=((1<<r)-1)^T
    evalW=[Fraction(1 if (s & ~W)==0 else 0) for s in subsets]
    combo=[2*a-b for a,b in zip(evalW,allones)]
    assert combo==lam
    walsh.append({"r":r,"coordinates":1<<r,"annihilator_dot":fracstr(dot(delta,lam)),"l2sq":fracstr(dot(lam,lam)),"two_witness_identity":True})
results["or_clause_walsh_duals"]=walsh

# Exact histogram equality under iid symmetric ternary noise for r=2,3.
hists={}
for r in (2,3):
    n=1<<r; T=1
    lam=[-1 if ((s&T).bit_count()%2) else 1 for s in range(n)]
    ones=[1]*n
    ha=Counter(); hw=Counter()
    for e in product((-1,0,1), repeat=n):
        ha[sum(a*b for a,b in zip(lam,e))]+=1
        hw[sum(e)]+=1
    assert ha==hw
    hists[str(r)]={"vectors":3**n,"support":sorted(ha.keys()),"histogram":{str(k):ha[k] for k in sorted(ha)}}
results["iid_symmetric_exact_histograms"]=hists

# Random exact public-covariance theorem controls.
random_controls=[]
instances=120
feasible_vectors_checked=0
for t in range(instances):
    N=random.randint(4,7); r=random.randint(1,N-2)
    V,u,C=rand_full_rank_constraints(N,r)
    d=[Fraction(0)]*r+[Fraction(1)]
    Sigma=random_spd(N)
    lmin=min_variance_dual(C,d,Sigma)
    assert mat_vec(C,lmin)==d
    # generate feasible vectors by particular + random nullspace directions
    part,piv=solve_affine_particular(C,d)
    ns=nullspace(C)
    qmin=qform(lmin,Sigma)
    qs=[]
    for _ in range(12):
        x=part[:]
        for b in ns:
            coeff=Fraction(random.randint(-3,3))
            x=[a+coeff*bb for a,bb in zip(x,b)]
        assert mat_vec(C,x)==d
        qx=qform(x,Sigma)
        assert qmin <= qx
        qs.append(qx); feasible_vectors_checked+=1
    random_controls.append({"N":N,"dimV":r,"nullity":len(ns),"min_variance":float(qmin),"min_sampled_feasible_variance":float(min(qs))})
results["public_covariance_controls"]={
    "instances":instances,
    "feasible_vectors_checked":feasible_vectors_checked,
    "all_minimum_inequalities_passed":True,
    "max_ratio_min_to_sampled":max(rc["min_variance"]/rc["min_sampled_feasible_variance"] if rc["min_sampled_feasible_variance"] else 0 for rc in random_controls),
}

# Monte Carlo OR2 iid Gaussian midpoint-decoding diagnostic.
# K in {0,1}, means 0 and Delta. Public lstar variance 4/3 sigma^2; witness variances 2,2,4.
Delta=8.0; sigma=1.0; trials=100000
# Box-Muller via random.gauss.
counts={"public_min":0,"w10":0,"w01":0,"w11":0,"public_integral_alt":0}
for _ in range(trials):
    K=random.getrandbits(1)
    e=[random.gauss(0,sigma) for _ in range(4)]
    vecs={"public_min":[1,1/3,1/3,-1/3],"w10":[1,1,0,0],"w01":[1,0,1,0],"w11":[1,1,1,1],"public_integral_alt":[1,-1,1,-1]}
    for name,l in vecs.items():
        residual=Delta*K+sum(a*b for a,b in zip(l,e))
        guess=1 if residual>Delta/2 else 0
        counts[name]+=int(guess==K)
results["gaussian_or2_diagnostic"]={
    "trials":trials,"Delta":Delta,"sigma":sigma,
    "success":{k:v/trials for k,v in counts.items()},
    "theoretical_variances":{"public_min":4/3,"w10":2,"w01":2,"w11":4,"public_integral_alt":4},
    "note":"Monte Carlo validates implementation only; theorem is exact linear algebra/Gaussian projection."
}

print(json.dumps(results, indent=2, sort_keys=True))
