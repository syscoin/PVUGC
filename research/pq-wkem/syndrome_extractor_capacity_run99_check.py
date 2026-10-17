#!/usr/bin/env python3
from fractions import Fraction
from itertools import product
import json, math

SEED_TAG = "run99-deterministic-no-rng"

def eprob(q, beta, a):
    beta = Fraction(beta)
    return (1 + (q-1)*beta)/q if a % q == 0 else (1-beta)/q

def dot(a,b,q):
    return sum(x*y for x,y in zip(a,b)) % q

def matvec(H,x,q):
    return tuple(dot(row,x,q) for row in H)

def rowspace(H,q):
    k=len(H); m=len(H[0])
    out=[]
    for a in product(range(q), repeat=k):
        out.append(tuple(sum(a[i]*H[i][j] for i in range(k))%q for j in range(m)))
    return out

def kernel(H,q):
    m=len(H[0])
    return [x for x in product(range(q), repeat=m) if all(v==0 for v in matvec(H,x,q))]

def wt(x):
    return sum(1 for a in x if a)

def noise_dist(q,m,beta):
    d={}
    for e in product(range(q), repeat=m):
        p=Fraction(1)
        for a in e: p*=eprob(q,beta,a)
        d[e]=p
    assert sum(d.values(),Fraction(0))==1
    return d

def syndrome_dist(H,q,ed):
    z={}
    for e,p in ed.items():
        he=matvec(H,e,q)
        z[he]=z.get(he,Fraction(0))+p
    return z

def masked_dist(H,q,ed):
    V=kernel(H,q); inv=Fraction(1,len(V)); out={}
    for e,p in ed.items():
        for v in V:
            x=tuple((e[i]+v[i])%q for i in range(len(e)))
            out[x]=out.get(x,Fraction(0))+p*inv
    return out,V

def tv(P,Q):
    keys=set(P)|set(Q)
    return sum(abs(P.get(x,Fraction(0))-Q.get(x,Fraction(0))) for x in keys)/2

def chi2_uniform(P,N):
    # sum (p-u)^2/u = N sum p^2 - 1
    return Fraction(N,1)*sum(p*p for p in P.values())-1

def shift_dist(P,a,q):
    # distribution of X+a
    return {tuple((x[i]+a[i])%q for i in range(len(a))):p for x,p in P.items()}

def entropy(P):
    h=0.0
    for p in P.values():
        if p:
            x=float(p); h-=x*math.log(x)
    return h

def h2(x):
    if x<=0 or x>=1:
        return 0.0 if x in (0,1) else float('nan')
    return -x*math.log(x)-(1-x)*math.log(1-x)

def macwilliams(H,q,z):
    C=rowspace(H,q); V=kernel(H,q)
    m=len(H[0]); r=m-len(H)
    direct=sum(Fraction(z)**wt(c) for c in C)
    A=1+(q-1)*Fraction(z); B=1-Fraction(z)
    dual=Fraction(1,q**r)*sum((A**(m-wt(v)))*(B**wt(v)) for v in V)
    assert direct==dual
    return direct, Fraction(1,q**r)*(A**m)

def random_linear_extractor_benchmark(q,m,k,beta):
    ed=noise_dist(q,m,beta)
    cp=sum(p*p for p in ed.values())
    chi=[]
    for flat in product(range(q), repeat=k*m):
        H=[tuple(flat[i*m:(i+1)*m]) for i in range(k)]
        Z=syndrome_dist(H,q,ed)
        chi.append(chi2_uniform(Z,q**k))
    mean=sum(chi,Fraction(0))/len(chi)
    expected=Fraction(q**k-1,1)*cp
    assert mean==expected
    cp1=sum(eprob(q,beta,a)**2 for a in range(q))
    assert cp==cp1**m
    closed=Fraction(1+(q-1)*Fraction(beta)**2,q)**m
    assert cp==closed
    return {
        "q":q,"m":m,"k":k,"beta":str(Fraction(beta)),
        "matrices_enumerated":q**(k*m),
        "mean_chi2":str(mean),
        "expected_chi2":str(expected),
        "product_collision_probability":str(cp),
    }

def monomial_invariance_check(H,q,beta,perm,scales):
    # H' columns are a permutation plus nonzero rescaling of H columns.
    k=len(H); m=len(H[0])
    Hp=[]
    for i in range(k):
        Hp.append(tuple((H[i][perm[j]]*scales[j])%q for j in range(m)))
    ed=noise_dist(q,m,beta)
    Z=syndrome_dist(H,q,ed)
    Zp=syndrome_dist(Hp,q,ed)
    assert Z==Zp
    return True

def repetition_invariance_check(H,q,beta_inner,ell):
    # Repeat every source coordinate ell times. Sums of ell iid E_beta_inner
    # equal E_{beta_inner**ell}, so the syndrome law is exactly unchanged
    # at matched per-source-coordinate signal.
    k=len(H); m=len(H[0])
    Hrep=[]
    for i in range(k):
        row=[]
        for j in range(m):
            row.extend([H[i][j]]*ell)
        Hrep.append(tuple(row))
    ed_rep=noise_dist(q,m*ell,beta_inner)
    Zrep=syndrome_dist(Hrep,q,ed_rep)
    beta_outer=Fraction(beta_inner)**ell
    ed=noise_dist(q,m,beta_outer)
    Z=syndrome_dist(H,q,ed)
    assert Zrep==Z
    return {
        "q":q,"m":m,"k":k,"ell":ell,
        "beta_inner":str(Fraction(beta_inner)),
        "beta_outer":str(beta_outer),
        "chi2":str(chi2_uniform(Z,q**k)),
    }

def zero_column_padding_check(H,q,beta,pad):
    # Adding columns that are zero in the row-space lets the mask be fully
    # uniform there; those coordinates factor out and cannot improve hiding.
    Hp=[tuple(row)+(0,)*pad for row in H]
    ed=noise_dist(q,len(H[0]),beta)
    edp=noise_dist(q,len(H[0])+pad,beta)
    Z=syndrome_dist(H,q,ed)
    Zp=syndrome_dist(Hp,q,edp)
    assert Z==Zp
    return True

def exact_fixture(H,q,beta):
    k=len(H); m=len(H[0]); r=m-k
    active=sum(1 for j in range(m) if any(H[i][j] % q for i in range(k)))
    ed=noise_dist(q,m,beta)
    Z=syndrome_dist(H,q,ed)
    D,V=masked_dist(H,q,ed)
    U_m={x:Fraction(1,q**m) for x in product(range(q), repeat=m)}
    U_k={x:Fraction(1,q**k) for x in product(range(q), repeat=k)}
    tvD=tv(D,U_m); tvZ=tv(Z,U_k)
    assert tvD==tvZ
    chiD=chi2_uniform(D,q**m); chiZ=chi2_uniform(Z,q**k)
    assert chiD==chiZ

    # exact coset lift formula D(x)=q^{-r} Pr[Z=Hx]
    for x in product(range(q), repeat=m):
        assert D[x] == Fraction(1,q**r)*Z[matvec(H,x,q)]

    # random-direction bit leakage equals average shift-TV in syndrome space
    avg_ambient=Fraction(0)
    for h in product(range(q), repeat=m):
        avg_ambient += tv(D,shift_dist(D,h,q)) / (q**m)
    avg_syn=Fraction(0)
    for a in product(range(q), repeat=k):
        avg_syn += tv(Z,shift_dist(Z,a,q)) / (q**k)
    assert avg_ambient==avg_syn
    assert tvZ <= avg_syn <= 2*tvZ

    z=Fraction(beta)**2
    W,zero_term=macwilliams(H,q,z)
    C=rowspace(H,q)
    S=sum(z**wt(c) for c in C if any(c))
    assert W==1+S
    assert chiZ==S
    assert W>=zero_term

    # exact entropy/capacity necessary inequality for actual TV hiding
    HZ=entropy(Z)
    HE=sum(entropy({a:eprob(q,beta,a) for a in range(q)}) for _ in [0])
    assert HZ <= min(k*math.log(q), active*HE)+1e-12
    eps=float(tvZ)
    deficit=k*math.log(q)-HZ
    fannes_rhs=eps*math.log(q**k-1)+h2(eps) if q**k>1 else 0.0
    assert deficit <= fannes_rhs+1e-10
    source_lower=k*math.log(q)-active*HE
    if source_lower>0:
        assert source_lower <= fannes_rhs+1e-10

    return {
        "q":q,"m":m,"active_columns":active,"k":k,"r":r,"beta":str(Fraction(beta)),
        "tv_masked_to_uniform":str(tvD),
        "tv_syndrome_to_uniform":str(tvZ),
        "random_direction_key_tv":str(avg_syn),
        "chi2":str(chiZ),
        "S":str(S),
        "macwilliams_zero_word_lower":str(zero_term-1),
        "syndrome_entropy_nats":HZ,
        "noise_entropy_per_coordinate_nats":HE,
        "entropy_source_lower_nats":source_lower,
    }

def entropy_rate(q,beta):
    beta=float(beta); eta=(1-1/q)*(1-beta)
    H=h2(eta)+eta*math.log(q-1) if eta>0 else 0.0
    return H/math.log(q),eta

def main():
    fixtures=[
        ([[1,0,1],[0,1,1]],3,Fraction(1,2)),
        ([[1,1,0,1],[0,1,1,2]],3,Fraction(3,4)),
        ([[1,0,2],[0,1,3]],5,Fraction(2,3)),
        ([[1,1,1,0],[0,1,2,1]],5,Fraction(4,5)),
    ]
    rows=[exact_fixture(H,q,beta) for H,q,beta in fixtures]

    # Random-linear extractor benchmark: averaged over every tiny matrix H,
    # E[chi2(H E || U)] = (q^k-1) * CP(E)^m exactly.
    extractor_benchmarks=[
        random_linear_extractor_benchmark(2,3,1,Fraction(1,2)),
        random_linear_extractor_benchmark(3,2,1,Fraction(2,3)),
        random_linear_extractor_benchmark(2,3,2,Fraction(3,4)),
    ]

    # Hamming-isometry and padding controls: transformations that preserve the
    # low-weight source geometry do not magically improve the q-symmetric
    # syndrome distribution.
    invariance_checks=0
    H0=[[1,0,1],[0,1,1]]
    assert monomial_invariance_check(H0,3,Fraction(1,2),[2,0,1],[2,1,2]); invariance_checks+=1
    assert zero_column_padding_check(H0,3,Fraction(1,2),1); invariance_checks+=1
    repetition=[
        repetition_invariance_check([[1,1]],3,Fraction(1,2),2),
        repetition_invariance_check([[1,0,1],[0,1,1]],2,Fraction(1,2),2),
    ]
    invariance_checks += len(repetition)

    # Asymptotic/parameter ledger: t=beta^d and exact necessary entropy-rate ceiling.
    param=[]
    for q,d,c,lam in [
        (65537,64,2,2**20),
        (65537,256,2,2**20),
        (1000003,512,3,2**20),
        (1000000007,1024,2,2**20),
    ]:
        loglam=math.log(lam)
        t=math.exp(-c*loglam)
        beta=math.exp(math.log(t)/d)
        Hq,eta=entropy_rate(q,beta)
        chi_rate=1-math.log(1+(q-1)*beta*beta, q)
        coarse=2*math.log(1/t)/(d*math.log(q))
        assert chi_rate <= coarse + 1e-12
        param.append({
            "q":q,"d":d,"c":c,"lambda":lam,
            "t=lambda^-c":t,"beta":beta,"eta_nonzero_noise_mass":eta,
            "necessary_actual_TV_rate_ceiling":Hq,
            "necessary_small_chi2_rate_ceiling":chi_rate,
            "coarse_small_chi2_ceiling":coarse,
        })

    # Exact q-symmetric entropy formula controls.
    entropy_checks=0
    for q in [3,5,17,257]:
        for beta in [Fraction(1,4),Fraction(1,2),Fraction(3,4),Fraction(15,16)]:
            P={a:eprob(q,beta,a) for a in range(q)}
            H=entropy(P)
            eta=(1-1/q)*(1-float(beta))
            form=h2(eta)+eta*math.log(q-1)
            assert abs(H-form)<1e-12
            entropy_checks+=1

    out={
        "run":99,"seed_tag":SEED_TAG,"status":"PASS",
        "counts":{
            "exact_small_code_fixtures":len(rows),
            "q_symmetric_entropy_formula_checks":entropy_checks,
            "parameter_tradeoff_rows":len(param),
            "random_linear_extractor_benchmarks":len(extractor_benchmarks),
            "geometry_preserving_invariance_checks":invariance_checks,
        },
        "fixtures":rows,
        "random_linear_extractor_benchmarks":extractor_benchmarks,
        "repetition_invariance":repetition,
        "parameter_tradeoff":param,
        "validated":[
            "masked capsule distribution is exactly a uniform lift of the q-ary symmetric noise syndrome",
            "TV and chi-square to uniform are exactly preserved by passing to the quotient syndrome",
            "random-direction one-bit key TV equals average syndrome shift-TV and lies between syndrome-TV and twice syndrome-TV",
            "Run-96/98 spectral sum S is exactly syndrome chi-square",
            "MacWilliams identity gives an exact dual expression and a zero-dual-word lower bound on S+1",
            "actual negligible statistical hiding requires active-column source rate no larger than normalized q-ary symmetric noise entropy up to continuity slack",
            "small-chi-square certification imposes the stronger exact rate ceiling 1-log_q(1+(q-1)beta^2)",
            "a uniformly random linear syndrome map meets the Renyi-2 threshold in expectation: E chi2=(q^k-1) CP(E)^m",
            "row-space basis changes/monomial coordinate isometries preserve the q-symmetric syndrome law, and zero-column padding does not improve it",
            "coordinate repetition with beta_inner^ell fixed exactly preserves the syndrome distribution"
        ],
        "limitations":[
            "rate/entropy conditions are necessary, not sufficient, for statement-derived source codes",
            "large chi-square does not alone prove large TV; the actual-TV barrier comes from syndrome equivalence plus entropy continuity",
            "no claim Jin 2026/2063 satisfies or violates these rate conditions without its exact source parameters",
            "arbitrary-QPT true-instance final-key recovery to ORIGINAL witness remains unproved",
            "checks validate exact finite-field probability identities and parameter arithmetic, not cryptographic hardness",
            "random-linear extraction is only a benchmark: the statement-derived syndrome map cannot be replaced by an independent random map without preserving true witness relations"
        ]
    }
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
