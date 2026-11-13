#!/usr/bin/env python3
from fractions import Fraction
from itertools import product, combinations
from collections import defaultdict
import json, random, math

def dot2(a,b):
    return sum(x*y for x,y in zip(a,b)) & 1

def xorv(*vs):
    return tuple(sum(x[i] for x in vs) & 1 for i in range(len(vs[0])))

def canonical_or(a,b):
    # x0,x1,y0,y1,q00,q01,q10,q11
    z=[1-a,a,1-b,b,0,0,0,0]
    z[4 + 2*a + b]=1
    return tuple(z)

def or_linear_accepts(z):
    x0,x1,y0,y1,q00,q01,q10,q11=z
    return (
        (x0+x1)%2==1 and
        (y0+y1)%2==1 and
        (q00+q01+q10+q11)%2==1 and
        (q10+q11-x1)%2==0 and
        (q01+q11-y1)%2==0 and
        (q01+q10+q11)%2==1
    )

def rank_f2(vs):
    if not vs: return 0
    n=len(vs[0]); rows=[]
    for v in vs:
        x=sum((b&1)<<i for i,b in enumerate(v))
        rows.append(x)
    r=0
    for c in range(n):
        p=next((i for i in range(r,len(rows)) if (rows[i]>>c)&1),None)
        if p is None: continue
        rows[r],rows[p]=rows[p],rows[r]
        for i in range(len(rows)):
            if i!=r and ((rows[i]>>c)&1): rows[i]^=rows[r]
        r+=1
    return r

def character_bias(weights,z):
    # weights dict e_tuple -> Fraction, normalized
    return sum(w*(1 if dot2(e,z)==0 else -1) for e,w in weights.items())

def solve_sign_pattern(zs, signs):
    n=len(zs[0])
    for bits in product((0,1), repeat=n):
        got=tuple(1 if dot2(bits,z)==0 else -1 for z in zs)
        if got==signs:
            return bits
    raise AssertionError("pattern not realizable")

def odd_span_tests():
    zs=[canonical_or(0,1),canonical_or(1,0),canonical_or(1,1)]
    bad=xorv(*zs)
    assert all(or_linear_accepts(z) for z in zs)
    assert or_linear_accepts(bad)
    assert sum(zs[0])==3 and sum(zs[1])==3 and sum(zs[2])==3
    assert sum(bad)==5
    assert bad[:4]==(1,0,1,0)
    assert bad[4:]==(0,1,1,1)
    assert rank_f2(zs)==3

    # Tight construction for gamma=9/10: all-plus with mass 17/20,
    # each one-minus sign pattern with mass 1/20.
    gamma=Fraction(9,10)
    p=(1-gamma)/2
    patterns=[
        ((1,1,1),1-3*p),
        ((-1,1,1),p),
        ((1,-1,1),p),
        ((1,1,-1),p),
    ]
    weights={}
    for signs,w in patterns:
        e=solve_sign_pattern(zs,signs)
        weights[e]=weights.get(e,Fraction(0))+w
    phis=[character_bias(weights,z) for z in zs]
    phib=character_bias(weights,bad)
    assert phis==[gamma]*3
    assert phib==3*gamma-2

    # Random rational distributions: validate exact stronger inequality
    # phi(z1+z2+z3) >= phi(z1)+phi(z2)+phi(z3)-2.
    rng=random.Random(130013)
    states=list(product((0,1), repeat=8))
    checked=0
    min_slack=None
    for _ in range(400):
        raw=[rng.randrange(0,20) for _ in states]
        if sum(raw)==0: raw[0]=1
        total=sum(raw)
        w={e:Fraction(x,total) for e,x in zip(states,raw) if x}
        ps=[character_bias(w,z) for z in zs]
        pb=character_bias(w,bad)
        slack=pb-(sum(ps)-2)
        assert slack>=0
        min_slack=slack if min_slack is None or slack<min_slack else min_slack
        checked+=1

    return {
        "canonical_valid_weights":[sum(z) for z in zs],
        "bad_odd_span_weight":sum(bad),
        "valid_vectors_rank":rank_f2(zs),
        "tight_gamma":[gamma.numerator,gamma.denominator],
        "tight_valid_bias":[phis[0].numerator,phis[0].denominator],
        "tight_bad_bias":[phib.numerator,phib.denominator],
        "random_rational_distributions_checked":checked,
        "minimum_exact_inequality_slack":[min_slack.numerator,min_slack.denominator],
    }

def invmod(a,q):
    return pow(a%q,-1,q)

def rref(rows,q):
    A=[list(x%q for x in row) for row in rows]
    if not A: return [],[]
    m=len(A); n=len(A[0]); r=0;piv=[]
    for c in range(n):
        p=next((i for i in range(r,m) if A[i][c]%q),None)
        if p is None: continue
        A[r],A[p]=A[p],A[r]
        z=invmod(A[r][c],q)
        A[r]=[(z*x)%q for x in A[r]]
        for i in range(m):
            if i!=r and A[i][c]%q:
                z=A[i][c]
                A[i]=[(A[i][j]-z*A[r][j])%q for j in range(n)]
        piv.append(c);r+=1
        if r==m: break
    return A,piv

def rank(rows,q):
    return len(rref(rows,q)[1]) if rows else 0

def all_subspaces(n,m,q):
    # Small-fixture exhaustive enumeration via canonical RREF keys.
    vecs=[v for v in product(range(q),repeat=n) if any(v)]
    seen={}
    for bs in combinations(vecs,m):
        R,piv=rref(bs,q)
        if len(piv)!=m: continue
        key=tuple(tuple(row) for row in R[:m])
        seen[key]=key
    return list(seen.values())

def span(basis,q):
    m=len(basis); n=len(basis[0])
    return [tuple(sum(c[i]*basis[i][j] for i in range(m))%q for j in range(n))
            for c in product(range(q),repeat=m)]

def qbinom(n,k,q):
    if k<0 or k>n: return 0
    if k==0 or k==n: return 1
    num=1;den=1
    for i in range(k):
        num*=q**(n-i)-1
        den*=q**(k-i)-1
    return num//den

def orthogonal_contains_colspace(U_basis, M_cols, q):
    # all U vectors are orthogonal to all columns of M
    return all(sum(u[i]*c[i] for i in range(len(u)))%q==0
               for u in U_basis for c in M_cols)

def rank_rep_cols(n,r):
    cols=[]
    for j in range(n):
        col=[0]*n
        if j<r: col[j]=1
        cols.append(tuple(col))
    return cols

def subspace_character_tests():
    fixtures=[]
    for q,n in [(2,3),(2,4),(3,3)]:
        for m in range(1,n):
            subs=all_subspaces(n,m,q)
            assert len(subs)==qbinom(n,m,q)
            for r in range(n+1):
                Mcols=rank_rep_cols(n,r)
                hits=sum(orthogonal_contains_colspace(U,Mcols,q) for U in subs)
                empirical=Fraction(hits,len(subs))
                expected=(Fraction(qbinom(n-r,m,q),qbinom(n,m,q))
                          if m<=n-r else Fraction(0))
                assert empirical==expected
            alpha=Fraction(q**(n-m)-1,q**n-1)
            # r=1 formula
            e1=(Fraction(qbinom(n-1,m,q),qbinom(n,m,q))
                if m<=n-1 else Fraction(0))
            assert alpha==e1
            fixtures.append({
                "q":q,"n":n,"m":m,"subspaces":len(subs),
                "rank1_bias":[alpha.numerator,alpha.denominator]
            })
    return fixtures

def mat_inv(A,q):
    n=len(A)
    aug=[list(A[i])+[1 if i==j else 0 for j in range(n)] for i in range(n)]
    R,piv=rref(aug,q)
    if piv[:n]!=list(range(n)): return None
    return [row[n:] for row in R]

def matmul(A,B,q):
    return [[sum(A[i][k]*B[k][j] for k in range(len(B)))%q
             for j in range(len(B[0]))] for i in range(len(A))]

def reconstruct_hidden_block(cols,D,m,q):
    n=len(cols); bottom=list(range(D,n)); right=list(range(D,n))
    # E22 rows bottom, cols right. find m row/col pivot.
    for I in combinations(bottom,m):
        for J in combinations(right,m):
            P=[[cols[j][i] for j in J] for i in I]
            Pinv=mat_inv(P,q)
            if Pinv is None: continue
            E12=[[cols[j][i] for j in J] for i in range(D)]
            E21=[[cols[j][i] for j in range(D)] for i in I]
            return matmul(matmul(E12,Pinv,q),E21,q)
    return None

def completion_probability_formula(n,D,m,q):
    if m>n-D: return Fraction(0)
    pU=Fraction(q**(D*m)*qbinom(n-D,m,q),qbinom(n,m,q))
    pG=Fraction(1)
    for i in range(m):
        pG*=Fraction(q**(n-D)-q**i,q**(n-D))
    return pU*pG

def completion_exact_fixture(n,D,m,q):
    subs=all_subspaces(n,m,q)
    hit=0;total=0;recovered=0
    for basis in subs:
        U=span(basis,q)
        for cols in product(U, repeat=n):
            total+=1
            rec=reconstruct_hidden_block(cols,D,m,q)
            if rec is None: continue
            hit+=1
            true=[[cols[j][i] for j in range(D)] for i in range(D)]
            assert rec==true
            recovered+=1
    empirical=Fraction(hit,total)
    expected=completion_probability_formula(n,D,m,q)
    assert empirical==expected
    return {
        "q":q,"n":n,"D":D,"m":m,"samples_exhausted":total,
        "completion_events":hit,
        "probability":[empirical.numerator,empirical.denominator],
        "all_hidden_blocks_recovered":recovered==hit
    }

def safe_boundary_trace_fixture(n,D,q):
    m=n-D+1
    subs=all_subspaces(n,m,q)
    post=defaultdict(lambda:[0]*q)
    total=0
    for basis in subs:
        U=span(basis,q)
        for cols in product(U,repeat=n):
            outside=[]
            trv=0
            for j,col in enumerate(cols):
                for i in range(n):
                    if i<D and j<D:
                        if i==j: trv=(trv+col[i])%q
                    else:
                        outside.append(col[i])
            post[tuple(outside)][trv]+=1
            total+=1
    uniform=all(len(set(c))==1 for c in post.values())
    assert uniform
    best=Fraction(sum(max(c) for c in post.values()),total)
    assert best==Fraction(1,q)
    alpha=Fraction(q**(D-1)-1,q**n-1)
    return {
        "q":q,"n":n,"D":D,"m":m,
        "samples_exhausted":total,"outside_views":len(post),
        "hidden_trace_uniform_given_outside":uniform,
        "best_trace_guess":[best.numerator,best.denominator],
        "rank1_bias":[alpha.numerator,alpha.denominator]
    }

def scale_table():
    out=[]
    for n,D in [(8,3),(16,4),(24,4),(32,4),(32,8)]:
        q=2;m=n-D+1
        alpha=Fraction(2**(D-1)-1,2**n-1)
        out.append({
            "q":2,"n":n,"D":D,"safe_boundary_m":m,
            "rank1_bias":float(alpha),
            "inverse_square_scale":float(1/(float(alpha)**2))
        })
    return out

def main():
    out={
        "status":"PASS",
        "odd_span":odd_span_tests(),
        "subspace_character":subspace_character_tests(),
        "unsafe_completion":[
            completion_exact_fixture(4,2,1,2),
            completion_exact_fixture(4,2,2,2),
            completion_exact_fixture(3,2,1,3),
        ],
        "safe_boundary_trace":[
            safe_boundary_trace_fixture(3,2,2),
            safe_boundary_trace_fixture(4,2,2),
            safe_boundary_trace_fixture(3,2,3),
        ],
        "scale_table":scale_table(),
    }
    print(json.dumps(out,sort_keys=True))

if __name__=="__main__":
    main()
