import itertools, json, math, random
from collections import Counter
from fractions import Fraction


def inv(a, q):
    return pow(a % q, -1, q)


def vadd(a,b,q):
    return [(x+y)%q for x,y in zip(a,b)]


def vsub(a,b,q):
    return [(x-y)%q for x,y in zip(a,b)]


def smul(c,a,q):
    return [(c*x)%q for x in a]


def dot(a,b,q):
    return sum(x*y for x,y in zip(a,b))%q


def mm(A,B,q):
    if not A or not B:
        return []
    return [[sum(A[i][k]*B[k][j] for k in range(len(B)))%q
             for j in range(len(B[0]))] for i in range(len(A))]


def mv(A,x,q):
    return [sum(a*b for a,b in zip(row,x))%q for row in A]


def transpose(A):
    return [list(x) for x in zip(*A)] if A else []


def matadd(A,B,q):
    return [[(x+y)%q for x,y in zip(ra,rb)] for ra,rb in zip(A,B)]


def outer(x,q):
    return [[a*b%q for b in x] for a in x]


def rank(A,q):
    A=[row[:] for row in A]
    if not A:
        return 0
    m,n=len(A),len(A[0]); r=0
    for c in range(n):
        p=next((i for i in range(r,m) if A[i][c]%q),None)
        if p is None:
            continue
        A[r],A[p]=A[p],A[r]
        s=inv(A[r][c],q)
        A[r]=[(s*x)%q for x in A[r]]
        for i in range(m):
            if i!=r and A[i][c]%q:
                f=A[i][c]%q
                A[i]=[(A[i][j]-f*A[r][j])%q for j in range(n)]
        r+=1
        if r==m: break
    return r


def inverse_square(A,q):
    n=len(A)
    aug=[A[i][:]+[1 if i==j else 0 for j in range(n)] for i in range(n)]
    r=0
    for c in range(n):
        p=next((i for i in range(r,n) if aug[i][c]%q),None)
        if p is None:
            raise ValueError("singular")
        aug[r],aug[p]=aug[p],aug[r]
        s=inv(aug[r][c],q)
        aug[r]=[(s*x)%q for x in aug[r]]
        for i in range(n):
            if i!=r and aug[i][c]%q:
                f=aug[i][c]%q
                aug[i]=[(aug[i][j]-f*aug[r][j])%q for j in range(2*n)]
        r+=1
    return [row[n:] for row in aug]


def right_inverse(T,q):
    # T is m x c, full row rank. Find R (c x m) with T R = I.
    m=len(T); c=len(T[0])
    # find m pivot columns greedily by rank increase
    piv=[]; current=[[] for _ in range(m)]
    for j in range(c):
        cand=[current[i]+[T[i][j]] for i in range(m)]
        if rank(cand,q)>len(piv):
            piv.append(j); current=cand
            if len(piv)==m: break
    if len(piv)!=m:
        raise ValueError("not full row rank")
    B=[[T[i][j] for j in piv] for i in range(m)]
    Binv=inverse_square(B,q)
    R=[[0]*m for _ in range(c)]
    for row_idx,j in enumerate(piv):
        R[j]=Binv[row_idx][:]
    assert mm(T,R,q)==[[1 if i==j else 0 for j in range(m)] for i in range(m)]
    return R


def trace_HMHt(H,M,q):
    HM=mm(H,M,q)
    Ht=transpose(H)
    X=mm(HM,Ht,q)
    return sum(X[i][i] for i in range(len(X)))%q


def rep(H,x,k,q):
    u=mv(H,x,q)
    b=(k-dot(u,u,q))%q
    return [1,b]+u


def Q(v,q):
    return (v[0]*v[1]+sum(x*x for x in v[2:]))%q


def orbit_stats(labels,q):
    m=len(labels[0])
    tau=[0]*m
    M=[[0]*m for _ in range(m)]
    for x in labels:
        tau=vadd(tau,x,q)
        M=matadd(M,outer(x,q),q)
    return tau,M


def orbit_sum_formula(H,labels,k,q):
    tau,M=orbit_stats(labels,q)
    h=len(labels)%q
    u=mv(H,tau,q)
    b=(h*k-trace_HMHt(H,M,q))%q
    return [h,b]+u


def orbit_sum_direct(H,labels,k,q):
    out=[0]*(len(H)+2)
    for x in labels:
        out=vadd(out,rep(H,x,k,q),q)
    return out


def padded_two_cycle(H,xa,xb,k,q,rng):
    va=rep(H,xa,k,q); vb=rep(H,xb,k,q)
    ra=[rng.randrange(q) for _ in va]
    rb=[rng.randrange(q) for _ in va]
    ya=vadd(va,vsub(ra,rb,q),q)
    yb=vadd(vb,vsub(rb,ra,q),q)
    return ya,yb,vadd(ya,yb,q)


def test_same_key():
    q=101; m=7; t=6
    rng=random.Random(2401)
    for _ in range(600):
        H=[[rng.randrange(q) for _ in range(m)] for _ in range(t)]
        x=[rng.randrange(q) for _ in range(m)]
        k=rng.randrange(q)
        v=rep(H,x,k,q)
        assert Q(v,q)==k
    return {"trials":600,"q":q,"m":m,"t":t}


def test_balanced_exhaustive():
    q=5; m=1; t=4
    x1=[1]; x2=[q-1]
    tau,M=orbit_stats([x1,x2],q)
    assert tau==[0]
    assert rank(M,q)==1
    counts=Counter()
    key_dists={k:Counter() for k in range(q)}
    for hs in itertools.product(range(q), repeat=t):
        H=[[h] for h in hs]
        y=trace_HMHt(H,M,q)
        counts[y]+=1
        for k in range(q):
            z=orbit_sum_formula(H,[x1,x2],k,q)
            key_dists[k][z[1]]+=1
    total=q**t
    assert total==625
    ordered=[counts[i] for i in range(q)]
    assert ordered==[145,120,120,120,120],ordered
    tv_u=sum(abs(Fraction(counts[i],total)-Fraction(1,q)) for i in range(q))/2
    assert tv_u==Fraction(4,125),tv_u
    pair_tvs=[]
    for k in range(q):
        for kp in range(k+1,q):
            tv=sum(abs(Fraction(key_dists[k][i],total)-Fraction(key_dists[kp][i],total))
                   for i in range(q))/2
            pair_tvs.append(tv)
    assert set(pair_tvs)=={Fraction(1,25)}

    # Direct complex-character magnitude check: every nonzero frequency is 1/25.
    mags=[]
    for lam in range(1,q):
        s=0j
        for y,c in counts.items():
            s += c*complex(math.cos(2*math.pi*lam*y/q), math.sin(2*math.pi*lam*y/q))
        mags.append(abs(s/total))
    for mag in mags:
        assert abs(mag-1/25)<1e-12,(mag,mags)
    bound=0.5*math.sqrt(q-1)*q**(-t/2)
    assert float(tv_u)<=bound+1e-15
    return {
        "q":q,"m":m,"t":t,"mask_counts":ordered,
        "tv_to_uniform":f"{tv_u.numerator}/{tv_u.denominator}",
        "pairwise_key_tv":f"{pair_tvs[0].numerator}/{pair_tvs[0].denominator}",
        "nonzero_character_magnitudes":mags,
        "tv_uniform_bound":bound,
    }


def explicit_labels(q,m):
    labels=[]
    for i in range(m):
        ea=[0]*m; eb=[0]*m
        ea[i]=2%q; eb[i]=(-1)%q
        labels.append((ea,eb))
    return labels


def recover_from_explicit_orbits(orbit_sums,q,m,t):
    # tau_i=e_i => last coordinates are columns of H
    Hrec=[[0]*m for _ in range(t)]
    for i,z in enumerate(orbit_sums):
        for r in range(t):
            Hrec[r][i]=z[2+r]
    # any orbit recovers k; use all and require consistency
    ks=[]
    for i,z in enumerate(orbit_sums):
        col=[Hrec[r][i] for r in range(t)]
        k=((z[1] + 5*dot(col,col,q))*inv(2,q))%q
        ks.append(k)
    assert len(set(ks))==1
    return Hrec,ks[0]


def test_full_padded_attack():
    q=101; m=6; t=5
    rng=random.Random(2402)
    labels=explicit_labels(q,m)
    for _ in range(400):
        H=[[rng.randrange(q) for _ in range(m)] for _ in range(t)]
        k=rng.randrange(q)
        sums=[]
        for xa,xb in labels:
            ya,yb,z=padded_two_cycle(H,xa,xb,k,q,rng)
            assert z==vadd(ya,yb,q)
            assert z==orbit_sum_formula(H,[xa,xb],k,q)
            sums.append(z)
        Hrec,krec=recover_from_explicit_orbits(sums,q,m,t)
        assert Hrec==H
        assert krec==k
    return {"trials":400,"q":q,"m":m,"t":t,"all_seed_and_key_recoveries":400}


def test_exhaustive_small_joint():
    q=5; m=2; t=2
    labels=explicit_labels(q,m)
    total=0
    for vals in itertools.product(range(q), repeat=t*m):
        H=[list(vals[r*m:(r+1)*m]) for r in range(t)]
        for k in range(q):
            sums=[orbit_sum_formula(H,[xa,xb],k,q) for xa,xb in labels]
            Hrec,krec=recover_from_explicit_orbits(sums,q,m,t)
            assert Hrec==H and krec==k
            total+=1
    assert total==(q**(t*m))*q
    return {"q":q,"m":m,"t":t,"complete_cases":total}


def random_full_row_rank_T(q,m,c,rng):
    while True:
        T=[[rng.randrange(q) for _ in range(c)] for _ in range(m)]
        if rank(T,q)==m:
            return T


def test_general_rank_recovery():
    q=103; m=4; c=7; t=5
    rng=random.Random(2403)
    for _ in range(300):
        H=[[rng.randrange(q) for _ in range(m)] for _ in range(t)]
        T=random_full_row_rank_T(q,m,c,rng)
        U=mm(H,T,q)
        R=right_inverse(T,q)
        Hrec=mm(U,R,q)
        assert Hrec==H
        # Synthetic orbit equation with random symmetric M and nonzero h.
        M=[[0]*m for _ in range(m)]
        for i in range(m):
            for j in range(i,m):
                a=rng.randrange(q); M[i][j]=a; M[j][i]=a
        h=rng.randrange(1,q); k=rng.randrange(q)
        zb=(h*k-trace_HMHt(H,M,q))%q
        krec=((zb+trace_HMHt(Hrec,M,q))*inv(h,q))%q
        assert krec==k
    return {"trials":300,"q":q,"m":m,"c":c,"t":t}


def main():
    out={
      "status":"PASS",
      "same_key":test_same_key(),
      "balanced_orbit":test_balanced_exhaustive(),
      "full_padded_attack":test_full_padded_attack(),
      "exhaustive_small_joint":test_exhaustive_small_joint(),
      "general_rank_recovery":test_general_rank_recovery(),
    }
    print(json.dumps(out,indent=2,sort_keys=True))


if __name__=="__main__":
    main()
