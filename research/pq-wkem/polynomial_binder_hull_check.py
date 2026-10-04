#!/usr/bin/env python3
import itertools, json, random, hashlib, math
from collections import Counter

SEED=270927
rng=random.Random(SEED)

def inv(a,q): return pow(a%q,-1,q)

def bits(n): return list(itertools.product([0,1], repeat=n))

def parity(x): return sum(x)&1

def monomials(n,r):
    out=[]
    for t in range(r+1):
        out += list(itertools.combinations(range(n),t))
    return out

def eval_mono(x,T,q):
    z=1
    for i in T: z=(z*x[i])%q
    return z

def feature(x,mons,q): return tuple(eval_mono(x,T,q) for T in mons)

def avg_vec(S,mons,q):
    den=inv(len(S),q)
    return tuple((sum(eval_mono(x,T,q) for x in S)*den)%q for T in mons)

def dot(a,b,q): return sum(x*y for x,y in zip(a,b))%q

def poly_eval(coeffs,x,mons,q): return dot(coeffs,feature(x,mons,q),q)

def rref(mat,q):
    A=[list(map(lambda z:z%q,row)) for row in mat]
    if not A: return A, []
    rows=len(A); cols=len(A[0]); piv=[]; rr=0
    for c in range(cols):
        p=next((i for i in range(rr,rows) if A[i][c]%q),None)
        if p is None: continue
        A[rr],A[p]=A[p],A[rr]
        z=inv(A[rr][c],q); A[rr]=[(v*z)%q for v in A[rr]]
        for i in range(rows):
            if i!=rr and A[i][c]%q:
                f=A[i][c]%q; A[i]=[(u-f*v)%q for u,v in zip(A[i],A[rr])]
        piv.append(c); rr+=1
        if rr==rows: break
    return A,piv

def rank(mat,q): return len(rref(mat,q)[1])

def aff_hull_intersects(A,B,q):
    # solve sum alpha_i A_i = sum beta_j B_j and both sums of coeffs =1
    # variables alpha then beta; augmented equations
    if not A or not B: return False
    d=len(A[0]); na=len(A); nb=len(B)
    eq=[]
    for k in range(d):
        eq.append([A[i][k] for i in range(na)] + [(-B[j][k])%q for j in range(nb)] + [0])
    eq.append([1]*na+[0]*nb+[1])
    eq.append([0]*na+[1]*nb+[1])
    M=[row[:-1] for row in eq]; aug=eq
    return rank(M,q)==rank(aug,q)

def rowspace_key_recoverable(S1,S2,phi,q):
    # hidden variables k1,k2,a1..am with a2=-a1; observations
    # f1=k1+a.phi(x), f2=k2-a.phi(y); target K=k1+k2
    m=len(phi[next(iter(S1))])
    rows=[]
    for x in S1:
        rows.append([1,0]+list(phi[x]))
    for y in S2:
        rows.append([0,1]+[(-v)%q for v in phi[y]])
    target=[1,1]+[0]*m
    return rank(rows,q)==rank(rows+[target],q)

def test_general_feature_theorem():
    counts=0
    for q,d,m in [(3,2,4),(5,2,3)]:
        X=[tuple(x) for x in itertools.product(range(q), repeat=d)]
        for _ in range(240):
            phi={x: tuple(rng.randrange(q) for _ in range(m)) for x in X}
            S1=set(rng.sample(X,rng.randint(1,min(5,len(X)))))
            S2=set(rng.sample(X,rng.randint(1,min(5,len(X)))))
            A=[phi[x] for x in S1]; B=[phi[x] for x in S2]
            h=aff_hull_intersects(A,B,q)
            k=rowspace_key_recoverable(S1,S2,phi,q)
            assert h==k
            counts+=1
    return counts

def test_parity_moments():
    checks=0; topdiff=[]
    for q in [3,5,101]:
        for n in range(2,10):
            E=[x for x in bits(n) if parity(x)==0]
            O=[x for x in bits(n) if parity(x)==1]
            for r in range(n):
                mons=monomials(n,r)
                assert avg_vec(E,mons,q)==avg_vec(O,mons,q)
                checks+=1
            full=(tuple(range(n)),)
            ae=avg_vec(E,full,q)[0]; ao=avg_vec(O,full,q)[0]
            assert ae!=ao
            topdiff.append((q,n,ae,ao))
    return checks,topdiff

def test_random_polynomial_recovery():
    q=101;n=8;r=5; mons=monomials(n,r)
    E=[x for x in bits(n) if parity(x)==0]
    O=[x for x in bits(n) if parity(x)==1]
    invE=inv(len(E),q); invO=inv(len(O),q)
    ok=0
    for _ in range(500):
        coeff=[rng.randrange(q) for _ in mons]
        K=rng.randrange(q); k0=rng.randrange(q); k1=(K-k0)%q
        a0=sum((k0+poly_eval(coeff,x,mons,q))%q for x in E)*invE%q
        neg=[(-c)%q for c in coeff]
        a1=sum((k1+poly_eval(neg,x,mons,q))%q for x in O)*invO%q
        rec=(a0+a1)%q
        assert rec==K
        ok+=1
    return ok,len(mons)

def exhaustive_false_distribution_low_degree():
    q=3;n=3;r=2;mons=monomials(n,r)
    E=[x for x in bits(n) if parity(x)==0]
    O=[x for x in bits(n) if parity(x)==1]
    counters=[]; decoder_ok=0
    invE=inv(len(E),q); invO=inv(len(O),q)
    for K in range(q):
        C=Counter()
        for coeff in itertools.product(range(q), repeat=len(mons)):
            neg=[(-c)%q for c in coeff]
            for k0 in range(q):
                k1=(K-k0)%q
                t0=tuple((k0+poly_eval(coeff,x,mons,q))%q for x in E)
                t1=tuple((k1+poly_eval(neg,x,mons,q))%q for x in O)
                tr=t0+t1; C[tr]+=1
                rec=(sum(t0)*invE + sum(t1)*invO)%q
                assert rec==K; decoder_ok+=1
        counters.append(C)
    # exact supports disjoint, as key is deterministic from transcript
    inter={}
    for a in range(q):
        for b in range(a+1,q):
            inter[f'{a}-{b}']=len(set(counters[a]) & set(counters[b]))
            assert inter[f'{a}-{b}']==0
    return {"q":q,"n":n,"r":r,"basis_dim":len(mons),"setups_per_key":sum(counters[0].values()),"distinct_transcripts_per_key":[len(c) for c in counters],"support_intersections":inter,"decoder_checks":decoder_ok}

def exhaustive_parity_character_hiding():
    q=5;n=4
    E=[x for x in bits(n) if parity(x)==0]
    O=[x for x in bits(n) if parity(x)==1]
    def chi(x):
        z=1
        for b in x: z=z*((1-2*b)%q)%q
        return z
    assert all(chi(x)==1 for x in E)
    assert all(chi(x)==q-1 for x in O)
    counters=[]
    for K in range(q):
        C=Counter()
        for a in range(q):
            for k0 in range(q):
                k1=(K-k0)%q
                t0=tuple((k0+a*chi(x))%q for x in E)
                # P1=-a chi
                t1=tuple((k1-a*chi(x))%q for x in O)
                C[t0+t1]+=1
        counters.append(C)
    for c in counters[1:]: assert c==counters[0]
    return {"q":q,"n":n,"setups_per_key":sum(counters[0].values()),"distinct_transcripts":len(counters[0]),"all_key_distributions_identical":True}

def test_missing_point_certificate():
    q=101; checks=0
    for n in range(2,9):
        all1=(1,)*n
        X=[x for x in bits(n) if x!=all1]
        lamb={x: (1 if ((n-sum(x)+1)%2==0) else -1)%q for x in X}
        # formula is (-1)^(n-|A|+1)
        assert sum(lamb.values())%q==1
        for T in monomials(n,n-1):
            lhs=sum(lamb[x]*eval_mono(x,T,q) for x in X)%q
            assert lhs==1
            checks+=1
        # degree-n monomial is zero on all proper points, 1 at all1
        T=tuple(range(n)); lhs=sum(lamb[x]*eval_mono(x,T,q) for x in X)%q
        assert lhs==0
    return checks


def gf_mul(a,b,d,poly):
    mask=(1<<d)-1; res=0
    aa=a; bb=b
    while bb:
        if bb&1: res ^= aa
        bb >>= 1
        aa <<= 1
        if aa & (1<<d): aa ^= poly
    return res & mask

def gf_pow(a,e,d,poly):
    z=1
    while e:
        if e&1: z=gf_mul(z,a,d,poly)
        a=gf_mul(a,a,d,poly); e>>=1
    return z

def gf_trace(a,d,poly):
    z=0; y=a
    for _ in range(d):
        z ^= y
        y=gf_mul(y,y,d,poly)
    assert z in (0,1)
    return z

def rwise_even_code(d,r,poly):
    n=1<<d
    words=[]
    for coeff in itertools.product(range(n), repeat=r):
        w=[]
        for t in range(n):
            val=0; pw=1
            for a in coeff:
                val ^= gf_mul(a,pw,d,poly)
                pw=gf_mul(pw,t,d,poly)
            w.append(gf_trace(val,d,poly))
        assert sum(w)%2==0
        words.append(tuple(w))
    return words

def test_rwise_even_odd_generators():
    fixtures=[]
    for d,r,poly in [(3,2,0b1011),(3,3,0b1011),(3,4,0b1011),(4,2,0b10011)]:
        W=rwise_even_code(d,r,poly); n=1<<d
        O=[tuple((1-b if i==0 else b) for i,b in enumerate(w)) for w in W]
        assert all(parity(w)==0 for w in W)
        assert all(parity(w)==1 for w in O)
        # Verify all t<=r all-ones moments exactly on both supports.
        checks=0
        for t in range(r+1):
            want=len(W)//(1<<t)
            for T in itertools.combinations(range(n),t):
                ce=sum(all(w[i] for i in T) for w in W)
                co=sum(all(w[i] for i in T) for w in O)
                assert ce==want and co==want
                checks+=1
        fixtures.append({"d":d,"n":n,"r":r,"support":len(W),"moment_subsets_checked":checks})
    return fixtures

def test_efficient_rwise_polynomial_attack():
    q=101; d=3; n=8; r=3; poly=0b1011
    E=rwise_even_code(d,r,poly)
    O=[tuple((1-b if i==0 else b) for i,b in enumerate(w)) for w in E]
    mons=monomials(n,r); den=inv(len(E),q)
    ok=0
    for _ in range(200):
        coeff=[rng.randrange(q) for _ in mons]
        neg=[(-c)%q for c in coeff]
        K=rng.randrange(q); k0=rng.randrange(q); k1=(K-k0)%q
        av0=sum((k0+poly_eval(coeff,x,mons,q))%q for x in E)*den%q
        av1=sum((k1+poly_eval(neg,x,mons,q))%q for x in O)*den%q
        assert (av0+av1)%q==K
        ok+=1
    return {"q":q,"n":n,"r":r,"support_each":len(E),"public_evaluations_per_attack":2*len(E),"basis_dim":len(mons),"recoveries":ok}

def main():
    theorem=test_general_feature_theorem()
    pm,top=test_parity_moments()
    rec,bd=test_random_polynomial_recovery()
    low=exhaustive_false_distribution_low_degree()
    high=exhaustive_parity_character_hiding()
    miss=test_missing_point_certificate()
    rwise=test_rwise_even_odd_generators()
    eff=test_efficient_rwise_polynomial_attack()
    out={
      "seed":SEED,
      "general_function_space_theorem_random_checks":theorem,
      "parity_low_degree_moment_equalities":pm,
      "parity_degree_n_differences_checked":len(top),
      "random_degree5_false_key_recoveries":rec,
      "degree5_basis_dimension_n8":bd,
      "exhaustive_low_degree_false_distribution":low,
      "exhaustive_degree_n_parity_character_control":high,
      "missing_point_certificate_monomial_checks":miss,
      "rwise_even_odd_generator_fixtures":rwise,
      "efficient_constant_degree_attack":eff,
      "status":"algebraic validation only; no security claim"
    }
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=='__main__': main()
