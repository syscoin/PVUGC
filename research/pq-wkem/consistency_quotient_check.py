import itertools, random, json, math
from fractions import Fraction
from collections import Counter, defaultdict


def inv(a,q):
    return pow(a%q,-1,q)


def rref(A,q):
    A=[[x%q for x in row] for row in A]
    if not A: return A,[]
    m,n=len(A),len(A[0]); r=0; piv=[]
    for c in range(n):
        p=next((i for i in range(r,m) if A[i][c]),None)
        if p is None: continue
        A[r],A[p]=A[p],A[r]
        s=inv(A[r][c],q)
        A[r]=[(s*x)%q for x in A[r]]
        for i in range(m):
            if i!=r and A[i][c]:
                t=A[i][c]
                A[i]=[(A[i][j]-t*A[r][j])%q for j in range(n)]
        piv.append(c); r+=1
        if r==m: break
    return A,piv


def rank(A,q): return len(rref(A,q)[1])


def nullspace(A,q):
    R,piv=rref(A,q)
    n=len(A[0]) if A else 0
    free=[j for j in range(n) if j not in piv]
    out=[]
    for f in free:
        x=[0]*n; x[f]=1
        for i,c in enumerate(piv):
            x[c]=(-R[i][f])%q
        out.append(x)
    return out


def transpose(A): return [list(x) for x in zip(*A)]


def mv(A,x,q):
    return [sum(a*b for a,b in zip(row,x))%q for row in A]


def mm(A,B,q):
    return [[sum(A[i][k]*B[k][j] for k in range(len(B)))%q
             for j in range(len(B[0]))] for i in range(len(A))]


def vadd(a,b,q): return [(x+y)%q for x,y in zip(a,b)]
def dot(a,b,q): return sum(x*y for x,y in zip(a,b))%q


def span_fixed_n(basis,n,q):
    if not basis: return [tuple([0]*n)]
    d=len(basis)
    return [tuple(sum(c*basis[i][j] for i,c in enumerate(coeffs))%q for j in range(n))
            for coeffs in itertools.product(range(q),repeat=d)]


def canonical_rowspace(rows,q):
    if not rows:
        return tuple()
    R,piv=rref(rows,q)
    rr=len(piv)
    return tuple(tuple(R[i]) for i in range(rr))


def all_subspaces(q,n,r):
    if r==0: return [tuple()]
    seen={}
    for vals in itertools.product(range(q), repeat=r*n):
        A=[list(vals[i*n:(i+1)*n]) for i in range(r)]
        if rank(A,q)!=r: continue
        key=canonical_rowspace(A,q)
        seen[key]=key
    return list(seen)


def qbinom(n,k,q):
    if k<0 or k>n: return 0
    if k==0: return 1
    out=1
    for i in range(k):
        out=out*(q**(n-i)-1)//(q**(k-i)-1)
    return out


def alpha(q,N,r):
    if r>=N: return Fraction(0,1)
    return Fraction(q**(N-r)-1,q**N-1)


def pcomp(q,N,D,r):
    if r>N-D: return Fraction(0,1)
    prod=Fraction(1,1)
    for i in range(r):
        prod *= Fraction(q**(N-D)-q**i, q**(N-D))
    return Fraction(q**(D*r)*qbinom(N-D,r,q), qbinom(N,r,q))*prod


def cfinite(q,N):
    out=Fraction(1,1)
    for j in range(1,N+1):
        out*=Fraction(q**j-1,q**j)
    return out


def quotient_sufficiency():
    q=2
    Phi=[
        [1,0,0],
        [0,1,0],
        [0,0,1],
        [1,1,0],
        [0,1,1],
    ]
    assert rank(Phi,q)==3
    Pt=transpose(Phi)
    Kbasis=nullspace(Pt,q)
    K=span_fixed_n(Kbasis,5,q)
    assert len(K)==2**2

    Nsamples=[
        (0,0,0,0,0),
        (1,0,0,0,0),
        (1,0,0,0,0),
        (0,1,0,1,0),
        (0,0,1,0,1),
        (1,1,0,0,0),
    ]
    out=Counter()
    stat=Counter()
    for n in Nsamples:
        s=tuple(mv(Pt,n,q))
        stat[s]+=1
        for k in K:
            o=tuple(vadd(n,k,q))
            out[o]+=1

    bys=defaultdict(dict)
    for o,cnt in out.items():
        s=tuple(mv(Pt,o,q))
        bys[s][o]=cnt
    for s,fiber_counts in bys.items():
        assert len(set(fiber_counts.values()))==1
        assert sum(fiber_counts.values()) == stat[s]*len(K)
        allfiber=[x for x in itertools.product(range(q),repeat=5)
                  if tuple(mv(Pt,x,q))==s]
        assert len(allfiber)==len(K)
        assert set(allfiber)==set(fiber_counts)

    image=set(tuple(mv(Phi,x,q)) for x in itertools.product(range(q),repeat=3))
    total=len(Nsamples)*len(K)
    fourier_checks=0
    for z in itertools.product(range(q),repeat=5):
        num=sum(cnt*(1 if dot(z,o,q)==0 else -1) for o,cnt in out.items())
        phiO=Fraction(num,total)
        numN=sum(1 if dot(z,n,q)==0 else -1 for n in Nsamples)
        phiN=Fraction(numN,len(Nsamples))
        if z in image:
            assert phiO==phiN
        else:
            assert phiO==0
        fourier_checks+=1

    return {
        "q":q,
        "phi_shape":[5,3],
        "kernel_size":len(K),
        "noise_multiset_size":len(Nsamples),
        "output_support":len(out),
        "quotient_values":len(stat),
        "fourier_modes_checked":fourier_checks,
    }


def mat_vec_map_for_splice():
    q=2
    L1=[[1,0,0],[0,0,1]]
    L2=[[0,1,0],[0,0,1]]
    def M(x):
        return [[1,0],[0,1],[x,(1+x)%2]]
    def vec(A): return tuple(v for row in A for v in row)
    cols=[]
    for idx in range(6):
        G=[[0,0] for _ in range(3)]
        G[idx//2][idx%2]=1
        y=vec(mm(L1,G,q))+vec(mm(L2,G,q))
        cols.append(y)
    Phi=[list(row) for row in zip(*cols)]
    assert rank(Phi,q)==6
    image=set(tuple(mv(Phi,x,q)) for x in itertools.product(range(q),repeat=6))
    honest0=vec(mm(L1,M(0),q))+vec(mm(L2,M(0),q))
    honest1=vec(mm(L1,M(1),q))+vec(mm(L2,M(1),q))
    splice=vec(mm(L1,M(1),q))+vec(mm(L2,M(0),q))
    assert honest0 in image and honest1 in image and splice not in image

    Kbasis=nullspace(transpose(Phi),q)
    K=span_fixed_n(Kbasis,8,q)
    def char(z):
        return Fraction(sum(1 if dot(z,k,q)==0 else -1 for k in K),len(K))
    assert char(honest0)==1 and char(honest1)==1 and char(splice)==0

    rng=random.Random(12345)
    for _ in range(100):
        Z1=[[rng.randrange(2) for _ in range(2)] for _ in range(2)]
        Z2=[[rng.randrange(2) for _ in range(2)] for _ in range(2)]
        y=vec(Z1)+vec(Z2)
        lhs=tuple(mv(transpose(Phi),y,q))
        L1t=transpose(L1); L2t=transpose(L2)
        G1=mm(L1t,Z1,q); G2=mm(L2t,Z2,q)
        rhs=vec([[G1[i][j]^G2[i][j] for j in range(2)] for i in range(3)])
        assert lhs==rhs
    return {
        "phi_shape":[8,6],
        "kernel_size":len(K),
        "honest_modes_survive":2,
        "spliced_mode_character":"0",
        "adjoint_trials":100,
    }


def sum_subspace_mixture():
    q=2; N=3; m=1; C=2; kblocks=2
    lines=all_subspaces(q,N,m)
    assert len(lines)==7
    wvec={W:span_fixed_n([list(row) for row in W],N,q) for W in lines}
    counts=Counter()
    pair_image_counts=Counter()
    for W1 in lines:
        for W2 in lines:
            sumkey=canonical_rowspace([list(r) for r in W1+W2],q)
            R=len(sumkey)
            pair_image_counts[(R,sumkey)]+=1
            V1=wvec[W1]; V2=wvec[W2]
            for cols1 in itertools.product(V1,repeat=C):
                for cols2 in itertools.product(V2,repeat=C):
                    E=tuple(tuple((cols1[j][i]+cols2[j][i])%q for j in range(C))
                            for i in range(N))
                    counts[(R,sumkey,E)]+=1

    for R in (1,2):
        vals=[c for (r,w),c in pair_image_counts.items() if r==R]
        assert len(set(vals))==1
    uniform_checks=0
    for (R,W) in {(r,w) for (r,w,e) in counts}:
        vals=[cnt for (r,w,e),cnt in counts.items() if r==R and w==W]
        assert len(set(vals))==1
        expected=(q**R)**C
        assert len(vals)==expected
        uniform_checks+=1
    rankdist=Counter()
    for (R,W),cnt in pair_image_counts.items():
        rankdist[R]+=cnt
    return {
        "q":q,"N":N,"m":m,"columns":C,"blocks":kblocks,
        "line_count":len(lines),
        "pair_rank_counts":{str(r):rankdist[r] for r in sorted(rankdist)},
        "conditional_uniform_sum_subspaces":True,
        "conditional_uniform_noise_fibers_checked":uniform_checks,
    }


def completion_exhaustive():
    q=2; N=4; D=2
    results={}
    for r in range(0,N-D+1):
        spaces=all_subspaces(q,N,r)
        event=total=0
        alpha_hits=0
        for W in spaces:
            basis=[list(row) for row in W]
            if all(row[0]==0 for row in basis):
                alpha_hits+=1
            V=span_fixed_n(basis,N,q)
            for cols in itertools.product(V,repeat=N):
                E=[[cols[j][i] for j in range(N)] for i in range(N)]
                total+=1
                E22=[row[D:] for row in E[D:]]
                if rank(E22,q)==r:
                    event+=1
        obs=Fraction(event,total)
        theory=pcomp(q,N,D,r)
        assert obs==theory,(r,obs,theory)
        aobs=Fraction(alpha_hits,len(spaces))
        atheory=alpha(q,N,r)
        assert aobs==atheory,(r,aobs,atheory)
        results[str(r)]={
            "subspaces":len(spaces),
            "complete_samples":total,
            "completion_events":event,
            "pcomp":f"{theory.numerator}/{theory.denominator}",
            "rank1_bias":f"{atheory.numerator}/{atheory.denominator}",
        }
    return results


def mixture_tradeoff():
    q=2; N=4; D=2
    cN=cfinite(q,N)
    safe=alpha(q,N,N-D+1)
    rng=random.Random(777)
    checked=0
    worst_slack=None
    for _ in range(1000):
        weights=[rng.randrange(1,20) for _ in range(N+1)]
        den=sum(weights)
        pi=[Fraction(w,den) for w in weights]
        atk=sum(pi[r]*pcomp(q,N,D,r) for r in range(N+1))
        hon=sum(pi[r]*alpha(q,N,r) for r in range(N+1))
        unsafe=sum(pi[:N-D+1])
        assert atk >= cN*cN*unsafe
        assert hon <= unsafe + safe
        bound=atk/(cN*cN)+safe
        assert hon <= bound
        slack=bound-hon
        worst_slack=slack if worst_slack is None or slack<worst_slack else worst_slack
        checked+=1
    return {
        "q":q,"N":N,"D":D,
        "finite_c":f"{cN.numerator}/{cN.denominator}",
        "finite_c_squared":f"{(cN*cN).numerator}/{(cN*cN).denominator}",
        "safe_rank1_bias":f"{safe.numerator}/{safe.denominator}",
        "random_mixtures_checked":checked,
        "minimum_verified_bound_slack":f"{worst_slack.numerator}/{worst_slack.denominator}",
    }


out={
    "status":"PASS",
    "quotient_sufficiency":quotient_sufficiency(),
    "dual_splice_filter":mat_vec_map_for_splice(),
    "sum_subspace_mixture":sum_subspace_mixture(),
    "completion_exhaustive":completion_exhaustive(),
    "mixture_tradeoff":mixture_tradeoff(),
}
print(json.dumps(out,indent=2,sort_keys=True))
