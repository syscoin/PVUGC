#!/usr/bin/env python3
import json, random, math
from itertools import product
from collections import Counter
from fractions import Fraction

SEED = 0x31B11E

def inv_mod(a,q):
    return pow(a % q, -1, q)

def dot(a,b,q):
    return sum(x*y for x,y in zip(a,b)) % q

def rank(A,q):
    if not A:
        return 0
    A=[[x%q for x in row] for row in A]
    m,n=len(A),len(A[0])
    r=0
    for c in range(n):
        p=next((i for i in range(r,m) if A[i][c]),None)
        if p is None:
            continue
        A[r],A[p]=A[p],A[r]
        z=inv_mod(A[r][c],q)
        A[r]=[(x*z)%q for x in A[r]]
        for i in range(m):
            if i != r and A[i][c]:
                f=A[i][c]
                A[i]=[(A[i][j]-f*A[r][j])%q for j in range(n)]
        r += 1
        if r == m:
            break
    return r

def mat_inv(A,q):
    n=len(A)
    aug=[[A[i][j]%q for j in range(n)] +
         [1 if i==j else 0 for j in range(n)] for i in range(n)]
    for c in range(n):
        p=next((i for i in range(c,n) if aug[i][c]),None)
        if p is None:
            raise ValueError("singular")
        aug[c],aug[p]=aug[p],aug[c]
        z=inv_mod(aug[c][c],q)
        aug[c]=[(x*z)%q for x in aug[c]]
        for i in range(n):
            if i != c and aug[i][c]:
                f=aug[i][c]
                aug[i]=[(aug[i][j]-f*aug[c][j])%q for j in range(2*n)]
    return [row[n:] for row in aug]

def find_minor(M,q):
    if not M or not M[0]:
        return [],[]
    rows=[]
    for i in range(len(M)):
        if rank([M[j] for j in rows+[i]],q) > len(rows):
            rows.append(i)
    L=len(rows)
    if L == 0:
        return [],[]
    cols=[]
    for c in range(len(M[0])):
        X=[[M[i][j] for j in cols+[c]] for i in rows]
        if rank(X,q) > len(cols):
            cols.append(c)
            if len(cols)==L:
                break
    assert len(cols)==L
    return rows,cols

def bilinear_recover(F,A,B,it,jt,q):
    block=[[F[i][j] for j in B] for i in A]
    rr,cc=find_minor(block,q)
    L=len(rr)
    if L == 0:
        return None,0
    I=[A[x] for x in rr]
    J=[B[x] for x in cc]
    P=[[F[i][j] for j in J] for i in I]
    Pinv=mat_inv(P,q)
    row=[F[it][j] for j in J]
    col=[F[i][jt] for i in I]
    tmp=[sum(row[k]*Pinv[k][j] for k in range(L))%q for j in range(L)]
    val=sum(tmp[j]*col[j] for j in range(L))%q
    return val,L

def setup(q,r,T,rng,K=None):
    n=2*T+1
    U=[[rng.randrange(q) for _ in range(r)] for _ in range(n)]
    V=[[rng.randrange(q) for _ in range(r)] for _ in range(n)]
    k0=rng.randrange(q)
    if K is None:
        K=rng.randrange(q)
    k1=(K-k0)%q
    F0=[[(k0+dot(U[i],V[j],q))%q for j in range(n)] for i in range(n)]
    F1=[[(k1-dot(U[i],V[j],q))%q for j in range(n)] for i in range(n)]
    return U,V,k0,k1,K,F0,F1

def attack(q,r,T,rng,trials):
    ok=0
    rank_pairs=Counter()
    honest=0
    for _ in range(trials):
        U,V,k0,k1,K,F0,F1=setup(q,r,T,rng)
        A0=list(range(T)); A1=list(range(T,2*T))
        B0=list(range(T)); B1=list(range(T,2*T))
        it=jt=2*T
        # same-representation correctness at several public points
        for i,j in [(0,0),(T,T),(it,jt)]:
            honest += ((F0[i][j]+F1[i][j])%q == K)
        z0,l0=bilinear_recover(F0,A0,B0,it,jt,q)
        z1,l1=bilinear_recover(F1,A1,B1,it,jt,q)
        rank_pairs[(l0,l1)] += 1
        if z0 is not None and z1 is not None and (z0+z1)%q == K:
            ok += 1
    return {
        "q":q,"r":r,"T":T,"trials":trials,
        "honest_same_point_ok":honest,
        "honest_same_point_total":3*trials,
        "false_key_recovery_ok":ok,
        "rank_pairs":{f"{a},{b}":n for (a,b),n in sorted(rank_pairs.items())},
    }

def delta_distribution(q,r,same_axis):
    cnt=Counter()
    if same_axis:
        for u in product(range(q), repeat=r):
            for v in product(range(q), repeat=r):
                for vp in product(range(q), repeat=r):
                    cnt[(dot(u,v,q)-dot(u,vp,q))%q]+=1
        c=Fraction(1,q**r)
    else:
        for u in product(range(q), repeat=r):
            for v in product(range(q), repeat=r):
                for up in product(range(q), repeat=r):
                    for vp in product(range(q), repeat=r):
                        cnt[(dot(u,v,q)-dot(up,vp,q))%q]+=1
        c=Fraction(1,q**(2*r))
    total=sum(cnt.values())
    got=[Fraction(cnt[a],total) for a in range(q)]
    want=[(c if a==0 else 0)+(1-c)*Fraction(1,q) for a in range(q)]
    assert got==want
    # pairwise TV between a nonzero shift and original is exactly c
    shift=1
    tv=sum(abs(got[a]-got[(a-shift)%q]) for a in range(q))/2
    assert tv==c
    return {
        "q":q,"r":r,"case":"same_row_or_column" if same_axis else "different_row_and_column",
        "distribution":[f"{x.numerator}/{x.denominator}" for x in got],
        "expected_spike_weight":f"{c.numerator}/{c.denominator}",
        "key_shift_tv":f"{tv.numerator}/{tv.denominator}",
    }

def paff(q,r,T):
    p=Fraction(1,1)
    # T-1 random differences spanning F_q^r
    for h in range(r):
        p *= Fraction(q**(T-1)-q**h, q**(T-1))
    return p

def exhaustive_tiny():
    q=2;r=1;T=2;n=2*T+1
    supports=[set(),set()]
    ok=[0,0]; total=[0,0]
    for K in (0,1):
        for uf in product(range(q), repeat=n*r):
            U=[list(uf[i*r:(i+1)*r]) for i in range(n)]
            for vf in product(range(q), repeat=n*r):
                V=[list(vf[j*r:(j+1)*r]) for j in range(n)]
                for k0 in range(q):
                    k1=(K-k0)%q
                    def f0(i,j): return (k0+dot(U[i],V[j],q))%q
                    def f1(i,j): return (k1-dot(U[i],V[j],q))%q
                    A0=list(range(T));A1=list(range(T,2*T))
                    B0=list(range(T));B1=list(range(T,2*T));it=jt=2*T
                    S0=[(i,j) for i in A0 for j in B0]+[(it,j) for j in B0]+[(i,jt) for i in A0]
                    S1=[(i,j) for i in A1 for j in B1]+[(it,j) for j in B1]+[(i,jt) for i in A1]
                    tr=tuple(f0(i,j) for i,j in S0)+tuple(f1(i,j) for i,j in S1)
                    supports[K].add(tr)
                    F0=[[f0(i,j) for j in range(n)] for i in range(n)]
                    F1=[[f1(i,j) for j in range(n)] for i in range(n)]
                    z0,_=bilinear_recover(F0,A0,B0,it,jt,q)
                    z1,_=bilinear_recover(F1,A1,B1,it,jt,q)
                    total[K]+=1
                    ok[K]+= (z0 is not None and z1 is not None and (z0+z1)%q==K)
    return {
        "q":q,"r":r,"T":T,
        "setups_per_key":total[0],
        "attack_success_by_key":ok,
        "support_sizes":[len(s) for s in supports],
        "cross_key_support_intersection":len(supports[0]&supports[1]),
    }

def main():
    rng=random.Random(SEED)
    local=[
        delta_distribution(3,1,True),
        delta_distribution(3,2,True),
        delta_distribution(5,1,True),
        delta_distribution(3,1,False),
    ]
    attacks=[
        attack(101,1,4,rng,500),
        attack(101,3,6,rng,500),
        attack(101,8,11,rng,500),
        attack(257,12,16,rng,350),
        attack(2,8,20,rng,2000),
        attack(3,4,12,rng,1200),
    ]
    bounds=[]
    for q,r,T in [(101,8,11),(2,8,20),(2,32,65),(3,16,33)]:
        p=paff(q,r,T)
        bounds.append({
            "q":q,"r":r,"T":T,
            "p_affine_factor":f"{p.numerator}/{p.denominator}",
            "four_factor_success_lower_bound_float":float(p**4),
            "union_failure_upper_bound":float(4*(1-p)),
        })
    tiny=exhaustive_tiny()
    out={
        "seed":SEED,
        "local_pair_exact_controls":local,
        "random_false_completion_attacks":attacks,
        "sufficient_event_bounds":bounds,
        "exhaustive_tiny":tiny,
        "claims":{
            "tests_validate_algebra_not_security":True,
            "generic_np_complete_construction":False,
            "stopping_condition_met":False,
        },
    }
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
