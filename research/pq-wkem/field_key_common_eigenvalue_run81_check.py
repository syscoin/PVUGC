#!/usr/bin/env python3
import json, math, random, itertools
from fractions import Fraction

SEED = 20260924214323
rng = random.Random(SEED)

def inv(a,p): return pow(a%p,-1,p)

def rank(A,p):
    A=[[(x%p) for x in row] for row in A]
    m=len(A); n=len(A[0]) if m else 0; r=0
    for c in range(n):
        k=next((i for i in range(r,m) if A[i][c]%p),None)
        if k is None: continue
        A[r],A[k]=A[k],A[r]
        z=inv(A[r][c],p)
        A[r]=[(z*x)%p for x in A[r]]
        for i in range(m):
            if i!=r and A[i][c]%p:
                z=A[i][c]%p
                A[i]=[(x-z*y)%p for x,y in zip(A[i],A[r])]
        r+=1
        if r==m: break
    return r

def det(A,p):
    A=[[(x%p) for x in row] for row in A]
    n=len(A); out=1
    for c in range(n):
        k=next((i for i in range(c,n) if A[i][c]),None)
        if k is None: return 0
        if k!=c:
            A[c],A[k]=A[k],A[c]
            out=(-out)%p
        pivot=A[c][c]%p
        out=(out*pivot)%p
        z=inv(pivot,p)
        for i in range(c+1,n):
            if A[i][c]:
                f=(A[i][c]*z)%p
                for j in range(c,n):
                    A[i][j]=(A[i][j]-f*A[c][j])%p
    return out%p

def outer(u,v,p):
    return [[(a*b)%p for b in v] for a in u]

def madd(A,B,p):
    return [[(x+y)%p for x,y in zip(ra,rb)] for ra,rb in zip(A,B)]

def mmul(A,B,p):
    Bt=list(zip(*B))
    return [[sum(x*y for x,y in zip(row,col))%p for col in Bt] for row in A]

def mtrans(A): return [list(x) for x in zip(*A)]

def eye(n,p):
    return [[1 if i==j else 0 for j in range(n)] for i in range(n)]

def shift(A,k,p):
    return [[(A[i][j]+(k if i==j else 0))%p for j in range(len(A))] for i in range(len(A))]

def roots_det(A,p):
    n=len(A)
    out=[]
    for lam in range(p):
        M=[[(A[i][j]-(lam if i==j else 0))%p for j in range(n)] for i in range(n)]
        if det(M,p)==0: out.append(lam)
    return out

def rand_vec(n,p):
    return [rng.randrange(p) for _ in range(n)]

def uv_product(t,r,p):
    U=[[rng.randrange(p) for _ in range(r)] for __ in range(t)]
    V=[[rng.randrange(p) for _ in range(r)] for __ in range(t)]
    return U,V,mmul(U,mtrans(V),p)

def frob(A,B,p):
    return sum(x*y for ra,rb in zip(A,B) for x,y in zip(ra,rb))%p

def block(A,br,bc,s):
    return [row[bc*s:(bc+1)*s] for row in A[br*s:(br+1)*s]]

def block_inner(R,B,t,p):
    s=len(B)
    return [[frob(block(R,i,j,s),B,p) for j in range(t)] for i in range(t)]

def randomizer(ts,r,p):
    R=[[0]*ts for _ in range(ts)]
    us=[];vs=[]
    for _ in range(r):
        u=rand_vec(ts,p); v=rand_vec(ts,p)
        us.append(u);vs.append(v)
        R=madd(R,outer(u,v,p),p)
    return R,us,vs

def direct_uv_from_witness(us,vs,x,y,t,p):
    s=len(x); r=len(us)
    U=[[0]*r for _ in range(t)]
    V=[[0]*r for _ in range(t)]
    for j in range(r):
        for a in range(t):
            ub=us[j][a*s:(a+1)*s]
            vb=vs[j][a*s:(a+1)*s]
            U[a][j]=sum(ub[z]*x[z] for z in range(s))%p
            V[a][j]=sum(vb[z]*y[z] for z in range(s))%p
    return U,V,mmul(U,mtrans(V),p)

def p_full_col(t,r,q):
    x=Fraction(1,1)
    for i in range(r):
        x *= Fraction(q**t-q**i,q**t)
    return x

def p_invertible(r,q):
    x=Fraction(1,1)
    for i in range(r):
        x *= Fraction(q**r-q**i,q**r)
    return x

def p_delta_bound(t,r,q):
    return (1-p_full_col(t,r,q)) + (1-p_invertible(r,q))

def source_false_code_p3():
    # I and multiplication by sqrt(-1) over F3. Every nonzero aI+bJ is rank 2.
    return [
        [[1,0],[0,1]],
        [[0,2],[1,0]],
    ]

def kron_ones(B,t,p):
    s=len(B)
    return [[B[i%s][j%s]%p for j in range(t*s)] for i in range(t*s)]

def lincomb(mats,coeff,p):
    Z=[[0]*len(mats[0][0]) for _ in range(len(mats[0]))]
    for M,a in zip(mats,coeff):
        if a:
            Z=[[ (z+a*m)%p for z,m in zip(rz,rm)] for rz,rm in zip(Z,M)]
    return Z

def build_N(Bs,Lams,t,p):
    s=len(Bs[0])
    N=[[0]*(t*s) for _ in range(t*s)]
    for br in range(t):
        for bc in range(t):
            coeff=[L[br][bc]%p for L in Lams]
            B=lincomb(Bs,coeff,p)
            for i in range(s):
                for j in range(s):
                    N[br*s+i][bc*s+j]=B[i][j]
    return N

out={"seed":SEED,
     "scope":"finite algebra/correctness validation only; no QPT or computational hiding inferred"}

# A. Exact witness-view identity <R,J⊗xy^T>_t = U V^T.
identity_checks=0
for p,t,r,s in [(5,3,2,2),(7,4,3,3),(17,4,3,2)]:
    for _ in range(120):
        x=rand_vec(s,p)
        while not any(x): x=rand_vec(s,p)
        y=rand_vec(s,p)
        while not any(y): y=rand_vec(s,p)
        B=outer(x,y,p)
        R,us,vs=randomizer(t*s,r,p)
        got=block_inner(R,B,t,p)
        U,V,want=direct_uv_from_witness(us,vs,x,y,t,p)
        assert got==want
        assert rank(got,p)<=r
        identity_checks+=1
out["honest_view_exact_UVt_identity_checks"]=identity_checks

# B. Exact tiny fixed-delta and two-capsule ambiguity census: q=3,t=2,r=1.
p=3;t=2;r=1
vecs=list(itertools.product(range(p), repeat=t))
root_counts={}
total=0
fixed={1:0,2:0}
for u in vecs:
    for v in vecs:
        X=outer(u,v,p)
        roots=set(roots_det(X,p))
        nz=tuple(sorted(x for x in roots if x!=0))
        root_counts[nz]=root_counts.get(nz,0)+1
        for d in fixed:
            fixed[d]+=int(d in roots)
        total+=1
assert total==81
pfix={str(d):Fraction(c,total) for d,c in fixed.items()}
bound=p_delta_bound(t,r,p)
for v in pfix.values(): assert v<=bound
two_fail=0
for roots1,c1 in root_counts.items():
    for roots2,c2 in root_counts.items():
        if set(roots1)&set(roots2):
            two_fail += c1*c2
two_fail=Fraction(two_fail,total*total)
union_bound=r*bound
assert two_fail<=union_bound
out["tiny_exact_census"]={
    "q":p,"t":t,"r":r,
    "fixed_nonzero_delta_probabilities":{k:[v.numerator,v.denominator] for k,v in pfix.items()},
    "fixed_delta_upper_bound":[bound.numerator,bound.denominator],
    "two_capsule_spurious_common_root_probability":[two_fail.numerator,two_fail.denominator],
    "two_capsule_union_upper_bound":[union_bound.numerator,union_bound.denominator],
}

# C. Random field-key recovery; K is a direct field value.
recovery=[]
for p,t,r,trials in [(17,4,3,1000),(257,4,3,1200),(257,6,5,700)]:
    failures=0;missing=0;extras=0
    for _ in range(trials):
        K=rng.randrange(p)
        _,_,X1=uv_product(t,r,p); _,_,X2=uv_product(t,r,p)
        D1=shift(X1,K,p); D2=shift(X2,K,p)
        common=set(roots_det(D1,p))&set(roots_det(D2,p))
        if K not in common: missing+=1
        if common!={K}:
            failures+=1
            extras+=len(common-{K})
    b=float(r*p_delta_bound(t,r,p))
    assert missing==0
    recovery.append({"q":p,"t":t,"r":r,"trials":trials,
                     "missing_true_key":missing,"ambiguous_trials":failures,
                     "total_extra_common_roots":extras,
                     "theorem_union_bound_per_witness":b})
out["two_capsule_key_recovery_controls"]=recovery

# D. Complete-public-output algebra over a tiny false MinRank code.
# B1,B2 all nonzero combinations rank 2 over F3; anchor coordinate ell=(1,0).
p=3;t=2;r=1
Bs=source_false_code_p3()
for a in itertools.product(range(p),repeat=2):
    if any(a):
        assert rank(lincomb(Bs,a,p),p)==2
fourier_identity_checks=0
key_sensitive_gap_checks=0
for _ in range(700):
    # independent character per source coordinate
    Lams=[[[rng.randrange(p) for _ in range(t)] for __ in range(t)] for ___ in Bs]
    N=build_N(Bs,Lams,t,p)
    # direct phase identity for one randomizer
    R,_,_=randomizer(t*2,r,p)
    # Because M_i=J_t tensor B_i, every lifted block is exactly B_i.
    # block_inner therefore takes the source-sized B_i directly.
    Ci=[block_inner(R,B,t,p) for B in Bs]
    lhs=sum(frob(L,C,p) for L,C in zip(Lams,Ci))%p
    rhs=frob(R,N,p)
    assert lhs==rhs
    fourier_identity_checks+=1
    sigma=sum(Lams[0][i][i] for i in range(t))%p  # ell=(1,0)
    if sigma:
        assert rank(N,p)>=2
        key_sensitive_gap_checks+=1
out["full_output_character_identity_checks"]=fourier_identity_checks
out["key_sensitive_false_gap_checks"]=key_sensitive_gap_checks

# D2. Exact additive-character magnitude control for r=1 over F3.
# For omega a primitive cube root, c0+c1*omega+c2*omega^2 has real value
# c0-c1 when c1=c2. The theorem predicts E[omega^(u^T N v)] = 3^-rank(N).
fourier_exact=0
vec4=list(itertools.product(range(3), repeat=4))
for _ in range(24):
    Lams=[[[rng.randrange(3) for _ in range(t)] for __ in range(t)] for ___ in Bs]
    N=build_N(Bs,Lams,t,3)
    d=rank(N,3)
    counts=[0,0,0]
    for u in vec4:
        for v in vec4:
            e=sum(u[i]*sum(N[i][j]*v[j] for j in range(4)) for i in range(4))%3
            counts[e]+=1
    assert counts[1]==counts[2]
    assert Fraction(counts[0]-counts[1], len(vec4)**2) == Fraction(1,3**d)
    fourier_exact+=1
out["exact_F3_additive_character_magnitude_checks"]=fourier_exact

# E. All-witness simultaneous correctness ledger.
# Bound: W*r*(p_def+p_sing). We show the field-bit or repetition tradeoff.
ledger=[]
for N,lam,t,r in [(256,128,16,15),(1024,128,32,31),(4096,128,64,63),
                  (16384,128,64,63)]:
    # Conservative choose qbits = N+lam+ceil(log2(4r))+2, approximating q >= 2^qbits.
    qbits=N+lam+math.ceil(math.log2(max(1,4*r)))+2
    # With q >=2^qbits and r=t-1:
    # pdelta < (1+2^-1)/(2^qbits-1) < 2/(2^qbits-1)
    # simultaneous <=2^N*r*that. record a log2-safe upper exponent using
    # 2/(2^qbits-1) < 2^(2-qbits) for qbits>=2.
    log2_simul_upper=N+math.log2(r)+2-qbits
    # If instead q~2^lam, L independent capsules give <=2^N*r*(~2/q)^(L-1).
    # conservative pdelta <=2^(2-lam).
    denom=max(1,lam-2)
    L=1+math.ceil((N+math.log2(r)+lam)/denom)
    ledger.append({"witness_bits_N":N,"security_bits":lam,"t":t,"r":r,
                   "large_field_bits_conservative":qbits,
                   "log2_simultaneous_failure_upper_bound":log2_simul_upper,
                   "capsules_needed_with_q_about_2^lambda_conservative":L})
out["all_witness_correctness_tradeoff"]=ledger

# F. Fourier/min-rank-only statistical bound remains bad with two capsules:
# output dimension over Fq is 2*k*t^2; crude pairwise TV exponent in base q is k*t^2-rD.
spectral_rows=[]
for k,D,t in [(20,3,4),(100,3,8),(256,8,16),(1024,10,32)]:
    r=t-1
    exponent=k*t*t-r*D
    spectral_rows.append({"k":k,"D":D,"t":t,"r":r,
                          "base_q_exponent_in_crude_TV_bound":exponent,
                          "crude_bound_nontrivial":exponent<0})
out["two_capsule_minrank_only_spectral_rows"]=spectral_rows
out["status"]="PASS"
print(json.dumps(out,indent=2,sort_keys=True))
