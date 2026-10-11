#!/usr/bin/env python3
"""Run 89 checker: dimension/rank-ceiling floor for the additive-share spectral bucket.

Standard library only.  When run from the PVUGC repository root, this checker imports
research/pq-wkem/literature-20260924/rank_field_extensions.py for tiny exact
Hair--Sahai source-space controls.  It does not test cryptographic hardness.
"""
from __future__ import annotations
import hashlib, importlib.util, json, math, os, random, sys
from itertools import combinations, product

SEED = 20260925061319
rng = random.Random(SEED)


def modinv(a,p): return pow(a%p,-1,p)

def rank_mod(mat,p):
    if not mat: return 0
    A=[[(x%p) for x in row] for row in mat]
    m=len(A); n=len(A[0]); r=0
    for c in range(n):
        piv=next((i for i in range(r,m) if A[i][c]),None)
        if piv is None: continue
        A[r],A[piv]=A[piv],A[r]
        inv=modinv(A[r][c],p)
        A[r]=[(x*inv)%p for x in A[r]]
        for i in range(m):
            if i!=r and A[i][c]:
                f=A[i][c]
                A[i]=[(x-f*y)%p for x,y in zip(A[i],A[r])]
        r+=1
        if r==m: break
    return r


def partial_fraction_sum(s,a,p,jmom=0):
    """Sum (-1)^|x| prod_{i<jmom} x_i / (|x|-a) on {0,1}^s."""
    total=0
    for bits in product((0,1), repeat=s):
        if jmom and not all(bits[i] for i in range(jmom)):
            continue
        wt=sum(bits)
        total=(total + ((-1)**wt)*modinv(wt-a,p))%p
    return total


def constant_block_fd(N,R,p,T):
    """Constant-weight block of Run-82 A_{T,0}; rows/cols indexed 0..N."""
    s=R+1
    assert len(T)==s
    T=set(T); a=N+1
    M=[[0]*(N+1) for _ in range(N+1)]
    for bits in product((0,1), repeat=s):
        wt=sum(bits); lam=(((-1)**wt)*modinv(wt-a,p))%p
        b=[0]*N
        for idx,val in zip(sorted(T),bits): b[idx]=val
        v=[1]+b
        for i in range(N+1):
            if v[i]:
                for j in range(N+1):
                    if v[j]: M[i][j]=(M[i][j]+lam)%p
    return M


def flatten(M): return [x for row in M for x in row]


def fd_independence_control(N,R,p):
    s=R+1
    assert 1 <= R <= N-2 and p>N+1
    core=tuple(range(max(0,s-2)))
    U=[i for i in range(N) if i not in core]
    mats=[]; labels=[]
    for i,j in combinations(U,2):
        T=tuple(sorted(core+(i,j)))
        M=constant_block_fd(N,R,p,T)
        mats.append(flatten(M)); labels.append((i,j,T))
        # unique pair entry, shifted by +1 because matrix coordinate 0 is constant bit.
        val=M[i+1][j+1]
        assert val%p != 0
        for k,l,T2 in labels[:-1]:
            if (k,l)!=(i,j):
                # Existing matrix for another pair must be zero at this new pair coordinate.
                old=constant_block_fd(N,R,p,T2)
                assert old[i+1][j+1]%p == 0
    rk=rank_mod(mats,p)
    predicted=math.comb(N-R+1,2)
    assert len(mats)==predicted and rk==predicted
    # exact moment ratio check S2/S0 = a(a-1)/(s(s-1))
    S0=partial_fraction_sum(s,N+1,p,0)
    S2=partial_fraction_sum(s,N+1,p,2)
    rhs=(S0*(N+1)*N*modinv(s*(s-1),p))%p
    assert S0 and S2==rhs and S2
    return {"N":N,"R":R,"p":p,"independent_fd_matrices":rk,
            "effective_column_rank_ceiling":N+1,"lower_bound_ge_ceiling":rk>=N+1,
            "S0":S0,"S2":S2}


def spectral_floor(N,R,k,t,r,q):
    c=N+1
    assert 2*r<t
    # Each fixed nonzero frequency has exactly q^(k t^2 -1) characters;
    # every blow-up matrix has rank <= t*c.
    exp = k*t*t - 1 - 2*r*t*c
    strict_floor = (k-c)*t*t + c*t - 1  # using 2r <= t-1
    assert exp >= strict_floor
    return {"N":N,"R":R,"k_used":k,"t":t,"r":r,"q":q,"c":c,
            "log_q_bucket_floor":exp,"log_q_floor_from_2r_lt_t":strict_floor,
            "bucket_floor_gt_one":exp>0}


def load_repo_dependency():
    path=os.path.join(os.getcwd(),'research','pq-wkem','literature-20260924','rank_field_extensions.py')
    if not os.path.exists(path): return None,None
    spec=importlib.util.spec_from_file_location('rfdep',path)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod,path


def actual_source_dimension_controls():
    rf,path=load_repo_dependency()
    if rf is None: return {"dependency_found":False,"cases":[]}
    cases=[]
    for N,R,p in [(2,1,7),(3,1,7),(4,2,19),(5,2,23)]:
        F=rf.Field(p); S=rf.spec(N,R,F)
        eq=lambda w,F,N=N: F.sub(F.sum(w),N+1)
        words,enc,basis=rf.table_space(S,[eq])
        cases.append({"N":N,"R":R,"p":p,"actual_false_source_dimension":len(basis),
                      "effective_column_rank_ceiling":N+1,
                      "fd_independence_lower_bound": (math.comb(N-R+1,2) if R<=N-2 else 0)})
    return {"dependency_found":True,"dependency_path":path,"cases":cases}


def main():
    indep=[]
    for N,R,p in [(3,1,7),(4,2,19),(5,2,23),(6,2,29),(8,3,67),(10,3,101)]:
        indep.append(fd_independence_control(N,R,p))

    # Hair--Sahai choice R=floor(log2 N): verify finite controls for
    # k>=c from N=5 and k>=2c from N=9.  The proof note gives elementary
    # all-N inequalities; these checks are finite implementation controls.
    asym=[]
    for N in range(5,129):
        R=int(math.log2(N))
        k0=math.comb(N-R+1,2)
        assert k0>=N+1
        if N>=9: assert k0>=2*(N+1)
        asym.append({"N":N,"R":R,"k_lower":k0,"c":N+1,"ge_2c":k0>=2*(N+1)})

    floors=[]
    # representative correctness-compatible 2r<t choices; use only proved k lower bound
    for N,R,q in [(5,2,23),(8,3,67),(16,4,257),(32,5,65537)]:
        k0=math.comb(N-R+1,2)
        for t in (3,5,9):
            r=(t-1)//2
            floors.append(spectral_floor(N,R,k0,t,r,q))
            assert floors[-1]['bucket_floor_gt_one']

    actual=actual_source_dimension_controls()
    if actual['dependency_found']:
        expected={(2,1):1,(3,1):4,(4,2):5,(5,2):15}
        for c in actual['cases']:
            assert c['actual_false_source_dimension']==expected[(c['N'],c['R'])]

    # Common right-support invariance control: random invertible right transform preserves <=c rank ceiling.
    # Tiny direct block blow-ups from arbitrary c-supported blocks.
    inv_controls=0
    p=7; m=8; c=4; t=3
    for _ in range(120):
        # common c-dimensional row support: matrices A = X * P where P has c rows.
        P=[[rng.randrange(p) for _ in range(m)] for __ in range(c)]
        blocks=[]
        for __ in range(t*t):
            X=[[rng.randrange(p) for _ in range(c)] for ___ in range(m)]
            A=[[sum(X[i][h]*P[h][j] for h in range(c))%p for j in range(m)] for i in range(m)]
            blocks.append(A)
        big=[[0]*(t*m) for _ in range(t*m)]
        for bi,A in enumerate(blocks):
            u,v=divmod(bi,t)
            for i in range(m):
                for j in range(m): big[u*m+i][v*m+j]=A[i][j]
        assert rank_mod(big,p)<=t*c
        inv_controls+=1

    out={
      "status":"PASS","seed":SEED,
      "theorem_scope":"finite algebra/dimension/rank-ceiling validation only; no cryptographic hardness or QPT extraction claim",
      "fd_independence_controls":indep,
      "hair_sahai_logR_bound_cases":len(asym),
      "hair_sahai_logR_first":asym[:5],"hair_sahai_logR_last":asym[-3:],
      "spectral_floor_controls":floors,
      "actual_source_dimension_controls":actual,
      "common_support_blowup_rank_controls":inv_controls,
    }
    print(json.dumps(out,sort_keys=True,indent=2))

if __name__=='__main__': main()
