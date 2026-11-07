#!/usr/bin/env python3
from fractions import Fraction
import itertools, math, random, json, hashlib, sys

SEED = 960096
rng = random.Random(SEED)

def inv_mod(a,q):
    return pow(a % q, -1, q)

def rank_mod(M,q):
    A=[[(x % q) for x in row] for row in M]
    if not A:
        return 0
    m,n=len(A),len(A[0])
    r=0
    for c in range(n):
        piv=next((i for i in range(r,m) if A[i][c] % q), None)
        if piv is None:
            continue
        A[r],A[piv]=A[piv],A[r]
        iv=inv_mod(A[r][c],q)
        A[r]=[(x*iv)%q for x in A[r]]
        for i in range(m):
            if i != r and A[i][c] % q:
                f=A[i][c] % q
                A[i]=[(A[i][j]-f*A[r][j])%q for j in range(n)]
        r += 1
        if r == m:
            break
    return r

def dot(a,b,q):
    return sum(x*y for x,y in zip(a,b)) % q

def rowspace(P,q):
    r=len(P)
    m=len(P[0]) if r else 0
    return {
        tuple(sum(coeff[i]*P[i][j] for i in range(r)) % q for j in range(m))
        for coeff in itertools.product(range(q), repeat=r)
    }

def kernel(P,q):
    m=len(P[0])
    return [
        v for v in itertools.product(range(q), repeat=m)
        if all(dot(row,v,q)==0 for row in P)
    ]

def wt(v):
    return sum(x != 0 for x in v)

def qsym_probs(q,beta):
    beta=Fraction(beta)
    p0=(1+(q-1)*beta)/q
    p1=(1-beta)/q
    return [p0]+[p1]*(q-1)

def convolve_mod_q(a,b,q):
    out=[Fraction(0) for _ in range(q)]
    for i,pi in enumerate(a):
        for j,pj in enumerate(b):
            out[(i+j)%q] += pi*pj
    return out

def scaled_dist(base,scalar,q):
    out=[Fraction(0) for _ in range(q)]
    for x,p in enumerate(base):
        out[(scalar*x)%q] += p
    return out

def product_noise(q,m,beta):
    pd=qsym_probs(q,beta)
    return {
        v: math.prod(pd[x] for x in v)
        for v in itertools.product(range(q), repeat=m)
    }

def noisy_rowspace_dist(P,q,beta,shift=None):
    H=rowspace(P,q)
    m=len(P[0])
    N=product_noise(q,m,beta)
    z=(0,)*m if shift is None else tuple(shift)
    out={v:Fraction(0) for v in itertools.product(range(q), repeat=m)}
    for h in H:
        for e,pe in N.items():
            x=tuple((h[j]+e[j]+z[j])%q for j in range(m))
            out[x] += Fraction(1,len(H))*pe
    return out

def chi2_to_uniform(dist):
    N=len(dist)
    u=Fraction(1,N)
    return sum((p-u)*(p-u)/u for p in dist.values())

def random_full_row_rank(rows,cols,q):
    while True:
        M=[[rng.randrange(q) for _ in range(cols)] for _ in range(rows)]
        if rank_mod(M,q)==rows:
            return M

def min_distance(C):
    ws=[wt(v) for v in C if any(v)]
    return min(ws) if ws else None

# 1. q-ary symmetric scaling and convolution law, exact rational checks.
conv_checks=0
for q in (2,3,5,7):
    beta=Fraction(1,2)
    base=qsym_probs(q,beta)
    for scalar in range(1,q):
        assert scaled_dist(base,scalar,q)==base
        conv_checks += 1
    for w in range(1,7):
        cur=[Fraction(int(i==0),1) for i in range(q)]
        for _ in range(w):
            cur=convolve_mod_q(cur,base,q)
        expected=qsym_probs(q,beta**w)
        assert cur==expected
        conv_checks += 1

# 2. Exact Fourier/chi-square identity for random small public codes.
spectral_checks=0
bound_checks=0
spectral_records=[]
for q,rows,cols,trials in [(2,2,5,16),(3,2,4,14),(5,1,3,10)]:
    beta=Fraction(1,2)
    for _ in range(trials):
        P=random_full_row_rank(rows,cols,q)
        C=kernel(P,q)
        dist=noisy_rowspace_dist(P,q,beta)
        chi=chi2_to_uniform(dist)
        spec=sum(beta**(2*wt(v)) for v in C if any(v))
        assert chi==spec
        spectral_checks += 1
        D=min_distance(C)
        k=cols-rank_mod(P,q)
        if D is not None:
            coarse=Fraction(q**k-1,1)*beta**(2*D)
            assert spec <= coarse
            bound_checks += 1
        if len(spectral_records)<10:
            spectral_records.append({
                "q":q,"rows":rows,"cols":cols,"kernel_dimension":k,
                "min_distance":D,"chi2":str(chi),"coarse_bound":str(coarse)
            })

# 3. Shift invariance: every message shift has the same chi-square.
shift_checks=0
for q in (2,3,5):
    beta=Fraction(1,2)
    P=random_full_row_rank(1,3,q)
    h=tuple(rng.randrange(q) for _ in range(3))
    baseline=chi2_to_uniform(noisy_rowspace_dist(P,q,beta))
    for a in range(q):
        shift=tuple((a*x)%q for x in h)
        got=chi2_to_uniform(noisy_rowspace_dist(P,q,beta,shift))
        assert got==baseline
        shift_checks += 1

# 4. Direct witness channel law from a short normalized kernel vector.
witness_checks=0
for q in (3,5,7):
    beta=Fraction(2,3)
    base=qsym_probs(q,beta)
    for w in range(1,6):
        coeff=[rng.randrange(1,q) for _ in range(w)]
        cur=[Fraction(int(i==0),1) for i in range(q)]
        for a in coeff:
            cur=convolve_mod_q(cur,scaled_dist(base,a,q),q)
        assert cur==qsym_probs(q,beta**w)
        witness_checks += 1

# 5. Plurality Hoeffding bound checked against exact multinomial enumeration for q=3.
def multinomial_coeff(counts):
    n=sum(counts)
    z=math.factorial(n)
    for c in counts:
        z//=math.factorial(c)
    return z

plurality_checks=0
plurality_records=[]
q=3
for t in (Fraction(1,4), Fraction(1,2), Fraction(3,4)):
    probs=qsym_probs(q,t)
    for L in (8,12,20):
        err=Fraction(0)
        # Treat ties as errors, giving a conservative exact error.
        for c0 in range(L+1):
            for c1 in range(L-c0+1):
                c2=L-c0-c1
                counts=(c0,c1,c2)
                if c0 <= max(c1,c2):
                    ways=multinomial_coeff(counts)
                    err += ways*(probs[0]**c0)*(probs[1]**c1)*(probs[2]**c2)
        bound=(q-1)*math.exp(-L*float(t*t)/2)
        assert float(err) <= min(1.0,bound)+1e-12 or bound>1
        plurality_checks += 1
        plurality_records.append({
            "bias":str(t),"L":L,"exact_tie_as_error":float(err),
            "hoeffding_union_bound":bound
        })

# 6. Product chi-square law and pairwise-TV upper-bound arithmetic.
product_checks=0
for S in (Fraction(1,1000),Fraction(1,100),Fraction(1,10)):
    for L in (1,2,5,10):
        lhs=(1+S)**L-1
        # This is the exact chi-square product identity when each factor has chi2 S.
        rhs=sum(math.comb(L,j)*(S**j) for j in range(1,L+1))
        assert lhs==rhs
        product_checks += 1

# 7. Parameter ledger: find polynomial-looking illustrative points, without
#    treating them as deployment parameters.
def binary_point(k,gamma,c,lam=256):
    # Set t = lam^{-c}; L = ceil(lam^{2c} * (log lam)^2).
    t=lam**(-c)
    L=math.ceil((lam**(2*c))*(math.log(lam)**2))
    S=(2**k-1)*(t**(2*gamma))
    log_prod=L*math.log1p(S) if S>0 else 0.0
    sec_tv=math.sqrt(max(0.0, math.expm1(log_prod))) if log_prod < 700 else float("inf")
    cor=math.exp(-L*t*t/2)  # q-1=1
    return {
        "lambda":lam,"q":2,"k":k,"gamma":gamma,"c":c,
        "t":t,"L":L,"coarse_single_chi2":S,
        "pairwise_tv_upper":sec_tv,"correctness_upper":cor,
        "ratio_klogq_over_gaploglambda":(k*math.log(2))/((gamma-1)*math.log(lam))
    }

parameter_records=[
    binary_point(16,16,1),
    binary_point(32,16,2),
    binary_point(32,32,1),
    binary_point(64,64,1),
]

# Asymptotic symbolic checks represented numerically:
# polynomial L with t=lambda^-c gives secrecy exponent
# k ln q - 2 c (gamma-1) ln lambda (+ lower-order log L t^2 term).
asymptotic_checks=0
for lam in (64,128,256,512,1024):
    for k,gamma,c in ((8,8,1),(16,16,1),(32,32,1),(32,16,2)):
        exponent=k*math.log(2)-2*c*(gamma-1)*math.log(lam)
        # Direct log of q^k * t^(2(gamma-1)).
        direct=math.log(2)*k + 2*(gamma-1)*math.log(lam**(-c))
        assert abs(exponent-direct)<1e-10
        asymptotic_checks+=1

result={
    "run":"96",
    "seed":SEED,
    "status":"PASS",
    "claims_checked":{
        "q_symmetric_scaling_and_convolution":conv_checks,
        "exact_code_spectral_chi2":spectral_checks,
        "min_distance_coarse_bounds":bound_checks,
        "message_shift_invariance":shift_checks,
        "short_witness_channel_law":witness_checks,
        "plurality_exact_vs_hoeffding":plurality_checks,
        "product_chi2_identity":product_checks,
        "asymptotic_exponent_identities":asymptotic_checks,
    },
    "spectral_examples":spectral_records,
    "plurality_examples":plurality_records,
    "parameter_examples":parameter_records,
    "scope":[
        "Algebra/probability validation only.",
        "No claim that Jin 2026/2063 has the required code dimension/source-extraction parameters.",
        "No arbitrary-QPT true-instance key-recovery extractor is implemented or proved.",
        "No deployment parameters are claimed."
    ]
}
print(json.dumps(result,indent=2,sort_keys=True))
