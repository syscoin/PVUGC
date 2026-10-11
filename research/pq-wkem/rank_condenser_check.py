import itertools, math, random, json
from fractions import Fraction
from collections import Counter, defaultdict


def inv(a,q): return pow(a%q,-1,q)


def rref(A,q):
    A=[list(map(lambda x:x%q,row)) for row in A]
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
                s=A[i][c]
                A[i]=[(A[i][j]-s*A[r][j])%q for j in range(n)]
        piv.append(c); r+=1
        if r==m: break
    return A,piv


def rank(A,q): return len(rref(A,q)[1])


def mm(A,B,q):
    return [[sum(A[i][k]*B[k][j] for k in range(len(B)))%q
             for j in range(len(B[0]))] for i in range(len(A))]


def transpose(A): return [list(x) for x in zip(*A)]


def subspaces(q,N,D):
    seen={}
    for vals in itertools.product(range(q), repeat=D*N):
        A=[list(vals[i*N:(i+1)*N]) for i in range(D)]
        if rank(A,q)!=D: continue
        R,piv=rref(A,q)
        key=tuple(tuple(row) for row in R[:D])
        seen[key]=[list(row) for row in key]
    return list(seen.values())


def qbinom(n,k,q):
    if k<0 or k>n: return 0
    out=1
    for i in range(k):
        out=out*(q**(n-i)-1)//(q**(k-i)-1)
    return out


def completion_prob(q,N,D,m):
    prod=Fraction(1,1)
    for i in range(m):
        prod *= Fraction(q**(N-D)-q**i, q**(N-D))
    return Fraction(q**(D*m)*qbinom(N-D,m,q), qbinom(N,m,q)) * prod


def full_restriction_prob(q,N,m):
    out=Fraction(1,1)
    for i in range(m):
        out *= Fraction(q**N-q**i, q**N)
    return out


def image_key(M,q):
    R,p=rref(transpose(M),q)
    return tuple(tuple(row) for row in R[:len(p)])


def rank_mixture_control():
    q=2; N=4; m=2
    counts=Counter(); by_image=defaultdict(Counter)
    for vals in itertools.product(range(q), repeat=N*m):
        T=[list(vals[i*m:(i+1)*m]) for i in range(N)]
        r=rank(T,q)
        counts[r]+=1
        by_image[r][image_key(T,q)]+=1
    assert counts==Counter({2:210,1:45,0:1}),counts
    assert set(by_image[1].values())=={3}
    assert set(by_image[2].values())=={6}
    return counts,{r:len(v) for r,v in by_image.items()}


def condenser_control():
    q=2; N=6; D=2; d=3; T=160
    spaces=subspaces(q,N,D)
    assert len(spaces)==651
    rng=random.Random(20260922)
    maps=[[[rng.randrange(q) for _ in range(N)] for _ in range(d)]
          for _ in range(T)]
    goods=[]
    for rows in spaces:
        B=transpose(rows)
        cnt=sum(rank(mm(L,B,q),q)==D for L in maps)
        goods.append(cnt)
    p=Fraction(21,32)
    bound=len(spaces)*math.exp(-float(p)*T/8)
    assert min(goods)>=math.floor(float(p*T/2))
    return {
        "subspaces":len(spaces),"maps":T,
        "p_exact":f"{p.numerator}/{p.denominator}",
        "min_good":min(goods),"max_good":max(goods),
        "mean_good":sum(goods)/len(goods),
        "required_half_mean":float(p*T/2),
        "union_bound":bound,
    }


def splice_control():
    q=2
    def M(x):
        return [[1,0],[0,1],[x,(1+x)%2]]
    L1=[[1,0,0],[0,0,1]]
    L2=[[0,1,0],[0,0,1]]
    glob=[rank(M(x),q) for x in (0,1)]
    local={
      "L1_x0":rank(mm(L1,M(0),q),q),
      "L1_x1":rank(mm(L1,M(1),q),q),
      "L2_x0":rank(mm(L2,M(0),q),q),
      "L2_x1":rank(mm(L2,M(1),q),q),
    }
    assert glob==[2,2]
    assert local=={"L1_x0":2,"L1_x1":1,"L2_x0":1,"L2_x1":2}
    assert all(max(rank(mm(L1,M(x),q),q),rank(mm(L2,M(x),q),q))==2
               for x in (0,1))

    lines=[[[1,0]],[[0,1]],[[1,1]]]
    def residual_zero_prob(A):
        zero=tot=0
        for line in lines:
            u=line[0]
            for coeffs in itertools.product((0,1), repeat=2):
                E=[[u[i]*coeffs[j]%2 for j in range(2)] for i in range(2)]
                val=sum(A[i][j]*E[i][j] for i in range(2) for j in range(2))%2
                zero += (val==0); tot += 1
        return Fraction(zero,tot)
    p1=residual_zero_prob(mm(L1,M(1),q))
    p2=residual_zero_prob(mm(L1,M(0),q))
    assert p1==Fraction(2,3)
    assert p2==Fraction(1,2)

    n=63; p=Fraction(2,3)
    h=sum(Fraction(math.comb(n,k))*p**k*(1-p)**(n-k)
          for k in range(n//2+1,n+1))
    xor=h*h+(1-h)*(1-h)
    return {
      "global_ranks":glob,"local_ranks":local,
      "rank1_zero_residual":f"{p1.numerator}/{p1.denominator}",
      "rank2_zero_residual":f"{p2.numerator}/{p2.denominator}",
      "majority_repetitions":n,
      "majority_success":float(h),
      "xor_splice_success":float(xor),
    }


def inherited_attack_control():
    cases=[]
    for q,N,D,m,expected in [
        (2,4,2,1,Fraction(9,16)),
        (2,4,2,2,Fraction(9,64)),
        (3,3,2,1,Fraction(4,9)),
    ]:
        full=full_restriction_prob(q,N,m)
        comp=completion_prob(q,N,D,m)
        got=full*comp
        assert got==expected,(q,N,D,m,full,comp,got)
        cases.append({
            "q":q,"N":N,"D":D,"m":m,
            "full_rank_restriction":f"{full.numerator}/{full.denominator}",
            "conditional_completion":f"{comp.numerator}/{comp.denominator}",
            "lower_bound":f"{got.numerator}/{got.denominator}",
        })
    return cases


out={
  "status":"PASS",
  "condenser":condenser_control(),
  "rank_mixture":{},
  "inherited_completion":inherited_attack_control(),
  "splicing":splice_control(),
}
counts,images=rank_mixture_control()
out["rank_mixture"]={
    "q":2,"N":4,"m":2,
    "rank_counts":{str(k):v for k,v in sorted(counts.items())},
    "image_subspace_counts":{str(k):v for k,v in sorted(images.items())},
    "maps_per_rank1_image":3,
    "maps_per_rank2_image":6,
}
print(json.dumps(out,indent=2,sort_keys=True))
