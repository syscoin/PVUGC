#!/usr/bin/env python3
import itertools, json, math, random
from collections import Counter

SEED = 790079001
rng = random.Random(SEED)

def zmat(m,n): return [[0]*n for _ in range(m)]
def madd(A,B): return [[a^b for a,b in zip(x,y)] for x,y in zip(A,B)]
def rank2(A):
    A=[r[:] for r in A]
    m=len(A); n=len(A[0]) if m else 0
    rr=0
    for c in range(n):
        p=next((i for i in range(rr,m) if A[i][c]),None)
        if p is None: continue
        A[rr],A[p]=A[p],A[rr]
        for i in range(m):
            if i!=rr and A[i][c]:
                A[i]=[x^y for x,y in zip(A[i],A[rr])]
        rr+=1
        if rr==m: break
    return rr

def outer(u,v): return [[a&b for b in v] for a in u]
def frob(A,B): return sum(a*b for ra,rb in zip(A,B) for a,b in zip(ra,rb))&1
def block(A,p,q,t):
    n=len(A); s=n//t
    return [row[q*s:(q+1)*s] for row in A[p*s:(p+1)*s]]
def syndrome(R,B,t):
    return [[frob(block(R,p,q,t),B) for q in range(t)] for p in range(t)]
def flatten(Cs): return tuple(x for C in Cs for row in C for x in row)
def lincomb(mats,a):
    Z=zmat(len(mats[0]),len(mats[0][0]))
    for M,c in zip(mats,a):
        if c: Z=madd(Z,M)
    return Z
def randvec(n): return [rng.getrandbits(1) for _ in range(n)]
def lowrank(n,r):
    R=zmat(n,n)
    for _ in range(r): R=madd(R,outer(randvec(n),randvec(n)))
    return R
def add_eye(C):
    C=[r[:] for r in C]
    for i in range(len(C)): C[i][i]^=1
    return C
def allvec(n): return itertools.product((0,1), repeat=n)
def bitmat(bits,t):
    it=iter(bits)
    return [[next(it) for _ in range(t)] for __ in range(t)]
def character_phase(lambdas,ell):
    return sum(ell[i]*sum(lambdas[i][p][p] for p in range(len(lambdas[i])))
               for i in range(len(lambdas))) & 1
def character_N(lambdas,Bs,t):
    s=len(Bs[0]); N=zmat(t*s,t*s)
    for p in range(t):
        for q in range(t):
            a=[L[p][q] for L in lambdas]
            B=lincomb(Bs,a)
            for i in range(s):
                for j in range(s):
                    N[p*s+i][q*s+j]=B[i][j]
    return N
def transcript_character(x,lambdas):
    # x is flattened tuple of k t x t matrices
    k=len(lambdas); t=len(lambdas[0]); z=0; acc=0
    for i in range(k):
        for p in range(t):
            for q in range(t):
                acc ^= x[z] & lambdas[i][p][q]
                z+=1
    return acc
def fourier(count,total,lambdas):
    num=0
    for x,c in count.items():
        num += c * (1 if transcript_character(x,lambdas)==0 else -1)
    return num/total
def rowspace_rank(vs):
    return rank2([list(v) for v in vs]) if vs else 0

# True source: every a=(1,b) is an honest rank-one matrix with fixed anchor ell(a)=1.
T1=[[1,0],[0,0]]
T2=[[0,1],[0,0]]
TRUE_B=[T1,T2]
ELL_TRUE=[1,0]
assert all(rank2(lincomb(TRUE_B,a))==1 for a in [(1,0),(1,1)])
assert all((sum(x*y for x,y in zip(ELL_TRUE,a))&1)==1 for a in [(1,0),(1,1)])

# False source: every nonzero combination has rank D=2; anchor functional is entry (0,0).
F1=[[1,0],[0,1]]
F2=[[0,1],[1,1]]
FALSE_B=[F1,F2]
ELL_FALSE=[M[0][0] for M in FALSE_B]
assert ELL_FALSE==[1,0]
false_nonzero_ranks={}
for a in [(1,0),(0,1),(1,1)]:
    false_nonzero_ranks[str(a)]=rank2(lincomb(FALSE_B,a))
    assert false_nonzero_ranks[str(a)]==2
D=2

# 1. Deterministic anchor-shift correctness: t=3,r=1 => ranks <=1 vs >=2.
correctness=0
rank0_hist=Counter(); rank1_hist=Counter()
t=3; r=1; s=2; n=t*s
for _ in range(1000):
    R=lowrank(n,r)
    b=rng.getrandbits(1)
    a=(1,b)
    base=[syndrome(R,B,t) for B in TRUE_B]
    for mu in (0,1):
        Cs=[]
        for i,C in enumerate(base):
            X=[row[:] for row in C]
            if mu and ELL_TRUE[i]:
                X=add_eye(X)
            Cs.append(X)
        W=lincomb(Cs,a)
        rw=rank2(W)
        if mu==0:
            assert rw<=r
            rank0_hist[rw]+=1
        else:
            assert rw>=t-r
            rank1_hist[rw]+=1
        correctness+=1

# 2. Exhaustive false full-output distribution for t=2,r=1.
t=2; s=2; n=4
vecs=list(allvec(n))
counts=[Counter(),Counter()]
for u in vecs:
    for v in vecs:
        R=outer(u,v)
        base=[syndrome(R,B,t) for B in FALSE_B]
        for mu in (0,1):
            Cs=[]
            for i,C in enumerate(base):
                X=[row[:] for row in C]
                if mu and ELL_FALSE[i]: X=add_eye(X)
                Cs.append(X)
            counts[mu][flatten(Cs)] += 1
total=len(vecs)**2
keys=set(counts[0])|set(counts[1])
tv_single=0.5*sum(abs(counts[0].get(x,0)-counts[1].get(x,0))/total for x in keys)

# 3. Exhaust all 2^(k*t^2)=256 characters: exact bias and shifted spectrum.
fourier_checks=0; flip_chars=0; flip_min_rank=99
for bits in allvec(2*t*t):
    z=0; lambdas=[]
    for _ in range(2):
        lambdas.append(bitmat(bits[z:z+t*t],t)); z+=t*t
    N=character_N(lambdas,FALSE_B,t)
    rn=rank2(N)
    phase=character_phase(lambdas,ELL_FALSE)
    h0=fourier(counts[0],total,lambdas)
    h1=fourier(counts[1],total,lambdas)
    want=2**(-rn)
    assert abs(h0-want)<1e-12
    assert abs(h1-(((-1)**phase)*want))<1e-12
    if phase:
        flip_chars+=1
        flip_min_rank=min(flip_min_rank,rn)
        assert rn>=D
    fourier_checks+=2
assert flip_chars==128 and flip_min_rank==D

# 4. Two-share parity secret sharing: b1 xor b2 = mu.
# Exact distribution using support convolution.
def pairdist(mu):
    C=Counter()
    for z in (0,1):
        A=counts[z]; B=counts[z^mu]
        for x,cx in A.items():
            for y,cy in B.items():
                C[x+y]+=cx*cy
    return C
pair=[pairdist(0),pairdist(1)]
pair_total=2*total*total
pair_keys=set(pair[0])|set(pair[1])
tv_pair=0.5*sum(abs(pair[0].get(x,0)-pair[1].get(x,0))/pair_total for x in pair_keys)

# Fourier support of parity sharing: message-dependent share phase is all ones.
share_support={}
for T in range(2,9):
    even=[b for b in allvec(T) if (sum(b)&1)==0]
    # g=e0 turns even-parity coset into odd-parity coset.
    surviving=[]
    message_dep=[]
    for h in allvec(T):
        vals0={sum(x*y for x,y in zip(h,b))&1 for b in even}
        avg0=sum(1 if v==0 else -1 for v in vals0) if False else None
        # exact character average
        a0=sum((1 if (sum(x*y for x,y in zip(h,b))&1)==0 else -1) for b in even)/len(even)
        if abs(a0)>1e-12:
            surviving.append(h)
            if h[0]:
                message_dep.append(h)
    assert surviving==[(0,)*T,(1,)*T]
    assert message_dep==[(1,)*T]
    share_support[T]={"surviving_characters":2,"message_dependent_min_active_capsules":T}

# 5. Min-rank-only statistical ledger for anchor shift:
# TV <= 2^((k*t^2-1)/2-rD), correctness requires 2r<t.
ledger=[]
for k,D0,t0 in [(2,2,3),(20,3,3),(20,3,5),(64,6,7),(100,8,9)]:
    r0=(t0-1)//2
    exponent=(k*t0*t0-1)/2-r0*D0
    ledger.append({"k":k,"D":D0,"t":t0,"r_max":r0,
                   "log2_minrank_only_TV_bound":exponent,
                   "nontrivial_bound": exponent<0})

# 6. Outer parity sharing cannot remove the entropy ratio under the same
# min-rank-only bound: TV <= 2^(T*L/2-rD*T), best d=T.
outer_ledger=[]
for T in (2,4,8,16):
    k=20; D0=3; t0=5; r0=2; L=k*t0*t0
    exponent=T*L/2-r0*D0*T
    outer_ledger.append({"shares":T,"log2_crude_TV_bound":exponent})

# 7. Linear compression barrier. The affine normalized witness set ell(a)=1
# spans the whole k-dimensional space for k>=2.
compression=[]
for k in range(2,9):
    vals=[a for a in allvec(k) if a[0]==1]
    rk=rowspace_rank(vals)
    assert rk==k
    # A linear sketch H y supports all queries a.y only if each a is in row(H).
    # Therefore its row rank must be k.
    compression.append({"k":k,"normalized_query_count":len(vals),"span_rank":rk,"minimum_linear_sketch_rank":rk})

report={
    "seed":SEED,
    "scope":"finite algebra/distribution validation only; security claims require written reductions",
    "true_anchor_shift_correctness_checks":correctness,
    "mu0_rank_histogram":dict(sorted(rank0_hist.items())),
    "mu1_rank_histogram":dict(sorted(rank1_hist.items())),
    "false_source_nonzero_ranks":false_nonzero_ranks,
    "false_single_capsule_total_randomness_pairs":total,
    "false_single_capsule_support_sizes":[len(counts[0]),len(counts[1])],
    "false_single_capsule_exact_TV":tv_single,
    "full_character_fourier_checks":fourier_checks,
    "message_dependent_character_count":flip_chars,
    "message_dependent_minimum_spliced_rank":flip_min_rank,
    "two_share_parity_exact_TV":tv_pair,
    "two_share_support_sizes":[len(pair[0]),len(pair[1])],
    "parity_share_fourier_support":share_support,
    "anchor_shift_minrank_only_ledger":ledger,
    "outer_parity_minrank_only_ledger":outer_ledger,
    "linear_compression_controls":compression,
    "status":"PASS"
}
print(json.dumps(report,sort_keys=True,indent=2))
