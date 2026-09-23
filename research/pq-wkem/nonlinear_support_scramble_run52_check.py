#!/usr/bin/env python3
import itertools, json, random, hashlib
from fractions import Fraction

Q = 101
SEED = 5200520052
rng = random.Random(SEED)

def invmod(a, q=Q):
    a %= q
    if a == 0:
        raise ZeroDivisionError
    return pow(a, q-2, q)

def mat_mul(A,B,q=Q):
    if not A or not B:
        return []
    n,k,m = len(A), len(B), len(B[0])
    assert len(A[0]) == k
    return [[sum(A[i][t]*B[t][j] for t in range(k)) % q for j in range(m)] for i in range(n)]

def mat_vec(A,v,q=Q):
    return [sum(a*b for a,b in zip(row,v)) % q for row in A]

def vec_mat(v,A,q=Q):
    return [sum(v[i]*A[i][j] for i in range(len(v))) % q for j in range(len(A[0]))]

def transpose(A):
    return [list(x) for x in zip(*A)]

def dot(a,b,q=Q):
    return sum(x*y for x,y in zip(a,b)) % q

def rref(A,q=Q):
    M=[[(x%q) for x in row] for row in A]
    rows=len(M); cols=len(M[0]) if rows else 0
    piv=[]
    r=0
    for c in range(cols):
        p=next((i for i in range(r,rows) if M[i][c]%q),None)
        if p is None: continue
        M[r],M[p]=M[p],M[r]
        z=invmod(M[r][c],q)
        M[r]=[(z*x)%q for x in M[r]]
        for i in range(rows):
            if i!=r and M[i][c]%q:
                f=M[i][c]%q
                M[i]=[(M[i][j]-f*M[r][j])%q for j in range(cols)]
        piv.append(c); r+=1
        if r==rows: break
    return M,piv

def rank(A,q=Q):
    return len(rref(A,q)[1])

def inverse(A,q=Q):
    n=len(A)
    assert n and all(len(row)==n for row in A)
    aug=[[(x%q) for x in A[i]]+[1 if i==j else 0 for j in range(n)] for i in range(n)]
    R,piv=rref(aug,q)
    if piv[:n] != list(range(n)):
        raise ValueError("singular")
    return [row[n:] for row in R]

def solve_linear(A,b,q=Q):
    # Solve A x=b, return one solution or None.
    m=len(A); n=len(A[0]) if m else 0
    aug=[[(x%q) for x in A[i]]+[b[i]%q] for i in range(m)]
    R,piv=rref(aug,q)
    for row in R:
        if all(x%q==0 for x in row[:n]) and row[n]%q:
            return None
    x=[0]*n
    for i,c in enumerate(piv):
        if c<n:
            x[c]=R[i][n]%q
    return x

def random_invertible(n,q=Q):
    while True:
        A=[[rng.randrange(q) for _ in range(n)] for _ in range(n)]
        if rank(A,q)==n:
            return A

def monomials(n,D):
    return [tuple(S) for d in range(D+1) for S in itertools.combinations(range(n),d)]

def points_unisolvent(n,D):
    # Indicator points 1_S for |S|<=D, in matching subset order.
    return [tuple(1 if i in S else 0 for i in range(n)) for d in range(D+1) for S in itertools.combinations(range(n),d)]

def phi(point, mons, q=Q):
    out=[]
    for T in mons:
        z=1
        for i in T:
            z=(z*point[i])%q
        out.append(z)
    return out

def random_vanishing_basis(ev, dim, q=Q):
    M=len(ev)
    # Generate independent rows v with ev.v=0.
    basis=[]
    pivot = next(i for i,a in enumerate(ev) if a%q)
    while len(basis)<dim:
        v=[rng.randrange(q) for _ in range(M)]
        s=sum(ev[i]*v[i] for i in range(M) if i!=pivot)%q
        v[pivot]=(-s*invmod(ev[pivot],q))%q
        if rank(basis+[v],q)>len(basis):
            basis.append(v)
    return basis

def separator(V,r,q=Q):
    # lambda dot v =0 for every v in V, lambda dot r=1
    A=[list(v) for v in V]+[list(r)]
    b=[0]*len(V)+[1]
    return solve_linear(A,b,q)

def nonlinear_coeffs(tau, count, salt, q=Q):
    # deliberately nonlinear/shared-seed coefficients
    t=list(tau)
    out=[]
    for i in range(count):
        a=t[(i+salt)%len(t)]
        b=t[(2*i+1+salt)%len(t)]
        c=t[(3*i+2+salt)%len(t)]
        out.append((a*b + c*c + (i+1)*a*b*c + salt + 7*i) % q)
    return out

def lincomb(coeffs,basis,q=Q):
    if not basis:
        return []
    M=len(basis[0])
    return [sum(coeffs[j]*basis[j][i] for j in range(len(basis)))%q for i in range(M)]

def additive_share_3(K,q=Q):
    a=rng.randrange(q); b=rng.randrange(q)
    return [a,b,(K-a-b)%q]

def additive_reconstruct(shares,q=Q):
    return sum(shares)%q

def shamir_share_2of3(K,q=Q):
    a=rng.randrange(q)
    xs=[1,2,3]
    return [(K+a*x)%q for x in xs]

def shamir_reconstruct_two(vals, idxs, q=Q):
    # interpolate p(0) from two shares with x=1,2,3
    x1,x2=idxs
    y1,y2=vals
    return (y1*(-x2)*invmod(x1-x2,q) + y2*(-x1)*invmod(x2-x1,q))%q

results={
    "seed":SEED,
    "field":Q,
    "unisolvent_cases":0,
    "unisolvent_total_dimension":0,
    "nonlinear_support_fixtures":0,
    "nonlinear_exact_share_recoveries":0,
    "threshold_trials":0,
    "threshold_key_recoveries":0,
    "scramble_trials":0,
    "scramble_matrix_recoveries":0,
    "scramble_capsule_unmasks":0,
    "scramble_capsule_interpolations":0,
    "scramble_share_recoveries":0,
}

# 1. Explicit unisolvent recovery sets.
for n,D in [(3,1),(4,2),(5,2),(6,2),(6,3)]:
    mons=monomials(n,D)
    pts=points_unisolvent(n,D)
    assert len(mons)==len(pts)
    Phi_cols=[phi(p,mons) for p in pts]
    Phi=transpose(Phi_cols)
    assert rank(Phi,Q)==len(mons)
    I=mat_mul(Phi,inverse(Phi,Q),Q)
    assert I==[[1 if i==j else 0 for j in range(len(mons))] for i in range(len(mons))]
    results["unisolvent_cases"]+=1
    results["unisolvent_total_dimension"]+=len(mons)

# common polynomial space for support tests
n,D=4,2
mons=monomials(n,D)
M=len(mons)
w0=(1,0,1,0)
ev=phi(w0,mons)
r=[0]*M; r[0]=1  # constant polynomial; evaluates to 1
assert dot(ev,r,Q)==1

# 2. Arbitrarily correlated nonlinear masks supported in V_j.
for trial in range(1200):
    tau=[rng.randrange(Q) for _ in range(4)]
    share=rng.randrange(Q)
    V=random_vanishing_basis(ev, min(5,M-1), Q)
    lam=separator(V,r,Q)
    assert lam is not None
    coeff=nonlinear_coeffs(tau,len(V),trial%17,Q)
    R=lincomb(coeff,V,Q)
    C=[(share*r[i]+R[i])%Q for i in range(M)]
    got=dot(lam,C,Q)
    assert got==share
    assert dot(ev,R,Q)==0
    results["nonlinear_support_fixtures"]+=1
    results["nonlinear_exact_share_recoveries"]+=1

# 3. N-of-N and 2-of-3 threshold reconstruction with one shared nonlinear seed.
for trial in range(600):
    K=rng.randrange(Q)
    if trial%2==0:
        shares=additive_share_3(K,Q)
        mode="3of3"
    else:
        shares=shamir_share_2of3(K,Q)
        mode="2of3"
    tau=[rng.randrange(Q) for _ in range(5)]
    recovered=[]
    for j,s in enumerate(shares):
        V=random_vanishing_basis(ev,4,Q)
        lam=separator(V,r,Q)
        assert lam is not None
        coeff=nonlinear_coeffs(tau,len(V),j+11,Q)
        R=lincomb(coeff,V,Q)
        C=[(s*r[i]+R[i])%Q for i in range(M)]
        recovered.append(dot(lam,C,Q))
    if mode=="3of3":
        got=additive_reconstruct(recovered,Q)
    else:
        got=shamir_reconstruct_two([recovered[0],recovered[2]],[1,3],Q)
    assert got==K
    results["threshold_trials"]+=1
    results["threshold_key_recoveries"]+=1

# 4. Secret coefficient scramble + public linear evaluation adapter.
n2,D2=5,2
mons2=monomials(n2,D2)
pts2=points_unisolvent(n2,D2)
M2=len(mons2)
Phi=transpose([phi(p,mons2,Q) for p in pts2])  # columns phi(p)
Phi_inv=inverse(Phi,Q)

for trial in range(180):
    S=random_invertible(M2,Q)
    S_inv=inverse(S,Q)
    S_inv_T=transpose(S_inv)
    # Public adapter keys psi(p)=S^{-T} phi(p) on all public points.
    Psi=transpose([mat_vec(S_inv_T,phi(p,mons2,Q),Q) for p in pts2])
    recovered_S_inv_T=mat_mul(Psi,Phi_inv,Q)
    assert recovered_S_inv_T==S_inv_T
    recovered_S_inv=transpose(recovered_S_inv_T)
    recovered_S=inverse(recovered_S_inv,Q)
    assert recovered_S==S
    results["scramble_trials"]+=1
    results["scramble_matrix_recoveries"]+=1

    # Build a nonlinear-mask capsule, scramble it, recover/unmask and quotient-decode.
    w=(1,0,1,1,0)
    ev2=phi(w,mons2,Q)
    r2=[0]*M2; r2[0]=1
    V2=random_vanishing_basis(ev2,6,Q)
    lam2=separator(V2,r2,Q)
    assert lam2 is not None
    tau=[rng.randrange(Q) for _ in range(4)]
    coeff=nonlinear_coeffs(tau,len(V2),trial%19,Q)
    R2=lincomb(coeff,V2,Q)
    s=rng.randrange(Q)
    C=[(s*r2[i]+R2[i])%Q for i in range(M2)]
    Cscr=mat_vec(S,C,Q)
    Cun=mat_vec(recovered_S_inv,Cscr,Q)
    assert Cun==C
    results["scramble_capsule_unmasks"]+=1

    # Even without reconstructing S, a public ordinary evaluator for the
    # scrambled capsule on an unisolvent set interpolates the unscrumbled C.
    EvalMat=transpose(Phi)  # rows are phi(p)^T
    vals=[dot(phi(p,mons2,Q),C,Q) for p in pts2]
    Cinterp=mat_vec(inverse(EvalMat,Q),vals,Q)
    assert Cinterp==C
    results["scramble_capsule_interpolations"]+=1

    got=dot(lam2,Cinterp,Q)
    assert got==s
    results["scramble_share_recoveries"]+=1

payload={
    "status":"ok",
    "claim_scope":"finite-field algebra validation only; not a cryptographic security proof",
    "results":results,
}
print(json.dumps(payload, sort_keys=True, separators=(",",":")))
