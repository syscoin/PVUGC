#!/usr/bin/env python3
import itertools, json, math, random

SEED = 202609241019
rng = random.Random(SEED)

def mat_zero(m,n): return [[0]*n for _ in range(m)]
def mat_add(A,B): return [[a^b for a,b in zip(ra,rb)] for ra,rb in zip(A,B)]
def mat_scale_add(A,B,c):
    return mat_add(A,B) if c else [r[:] for r in A]
def transpose(A): return [list(x) for x in zip(*A)]
def mat_mul(A,B):
    Bt=transpose(B)
    return [[sum(x*y for x,y in zip(r,c))&1 for c in Bt] for r in A]
def rank2(A):
    A=[row[:] for row in A]
    m=len(A); n=len(A[0]) if m else 0
    r=0
    for c in range(n):
        p=next((i for i in range(r,m) if A[i][c]),None)
        if p is None: continue
        A[r],A[p]=A[p],A[r]
        for i in range(m):
            if i!=r and A[i][c]:
                A[i]=[x^y for x,y in zip(A[i],A[r])]
        r+=1
        if r==m: break
    return r

def vec_outer(u,v):
    return [[a&b for b in v] for a in u]

def rand_vec(n):
    return [rng.getrandbits(1) for _ in range(n)]

def low_rank_sum(n,r):
    R=mat_zero(n,n)
    for _ in range(r):
        R=mat_add(R,vec_outer(rand_vec(n),rand_vec(n)))
    return R

def frob(A,B):
    return sum(a*b for ra,rb in zip(A,B) for a,b in zip(ra,rb))&1

def block(A,p,q,t):
    n=len(A); bs=n//t
    return [row[q*bs:(q+1)*bs] for row in A[p*bs:(p+1)*bs]]

def block_inner(A,B,t):
    return [[frob(block(A,p,q,t), block(B,p,q,t)) for q in range(t)] for p in range(t)]

def lincomb(mats, coeffs):
    Z=mat_zero(len(mats[0]),len(mats[0][0]))
    for M,c in zip(mats,coeffs):
        if c: Z=mat_add(Z,M)
    return Z

def char_splice(mats,lambdas,t):
    # N block(p,q)=sum_i lambda_i[p][q] M_i block(p,q)
    n=len(mats[0]); bs=n//t
    N=mat_zero(n,n)
    for p in range(t):
        for q in range(t):
            B=mat_zero(bs,bs)
            for M,L in zip(mats,lambdas):
                if L[p][q]:
                    B=mat_add(B,block(M,p,q,t))
            for i in range(bs):
                for j in range(bs):
                    N[p*bs+i][q*bs+j]=B[i][j]
    return N

def char_eval(transcript,lambdas):
    s=0
    for C,L in zip(transcript,lambdas):
        s ^= frob(C,L)
    return s

def kron(A,B):
    ma,na=len(A),len(A[0]); mb,nb=len(B),len(B[0])
    Z=mat_zero(ma*mb,na*nb)
    for i in range(ma):
        for j in range(na):
            if A[i][j]:
                for x in range(mb):
                    for y in range(nb):
                        Z[i*mb+x][j*nb+y]=B[x][y]
    return Z

def all_bits(n):
    return itertools.product((0,1), repeat=n)

def enumerate_rank1_sum_distribution(n,r,mats,t=1):
    # exhaustive over all (u_j,v_j), feasible only tiny n,r
    counts={}
    total=0
    vecs=list(all_bits(n))
    pairs=list(itertools.product(vecs,vecs))
    for choices in itertools.product(pairs, repeat=r):
        R=mat_zero(n,n)
        for u,v in choices:
            R=mat_add(R,vec_outer(u,v))
        if t==1:
            out=tuple(frob(R,M) for M in mats)
        else:
            out=tuple(x for M in mats for row in block_inner(R,M,t) for x in row)
        counts[out]=counts.get(out,0)+1
        total+=1
    return counts,total

def tv_to_uniform(counts,total,L):
    univ=1<<L
    return 0.5*sum(abs(counts.get(tuple((x>>j)&1 for j in range(L)),0)/total-1/univ)
                   for x in range(univ))

def fourier_from_counts(counts,total,mask,L):
    s=0
    for out,c in counts.items():
        parity=sum(((mask>>j)&1)*out[j] for j in range(L))&1
        s += c * (1 if parity==0 else -1)
    return s/total

def kernel_basis(A):
    # Returns nullspace basis over F2
    M=[r[:] for r in A]
    m=len(M); n=len(M[0]) if m else 0
    piv=[]; rr=0
    for c in range(n):
        p=next((i for i in range(rr,m) if M[i][c]),None)
        if p is None: continue
        M[rr],M[p]=M[p],M[rr]
        for i in range(m):
            if i!=rr and M[i][c]:
                M[i]=[x^y for x,y in zip(M[i],M[rr])]
        piv.append(c); rr+=1
        if rr==m: break
    free=[c for c in range(n) if c not in piv]
    out=[]
    for f in free:
        v=[0]*n; v[f]=1
        for i,c in reversed(list(enumerate(piv))):
            v[c]=sum(M[i][j]*v[j] for j in free)&1
        out.append(v)
    return out

def stacked(A_list):
    return [row[:] for A in A_list for row in A]

def common_right_kernel_dim(mats):
    return len(kernel_basis(stacked(mats)))

report={"seed":SEED,"scope":"finite algebra/identity validation only; no cryptographic security inferred"}

# A. Exact blockwise character identity on random instances.
char_identity=0
for n,t,k in [(4,2,2),(6,3,3)]:
    for _ in range(120):
        mats=[[[rng.getrandbits(1) for _ in range(n)] for _ in range(n)] for _ in range(k)]
        R=low_rank_sum(n,2)
        tr=[block_inner(R,M,t) for M in mats]
        lambdas=[[[rng.getrandbits(1) for _ in range(t)] for _ in range(t)] for _ in range(k)]
        N=char_splice(mats,lambdas,t)
        assert char_eval(tr,lambdas)==frob(R,N)
        char_identity+=1

# B. Global MinRank gap does not control all blockwise characters.
# One-dimensional code generated by diag(E11,E11), global rank 2.
E=[[1,0],[0,0]]
Z=[[0,0],[0,0]]
Msplit=[
    [1,0,0,0],
    [0,0,0,0],
    [0,0,1,0],
    [0,0,0,0],
]
assert rank2(Msplit)==2
L=[[[1,0],[0,0]]]
N=char_splice([Msplit],L,2)
assert rank2(N)==1
split_fixture={"source_minrank":2,"spliced_character_rank":rank2(N)}

# C. Kronecker repair: a false F2 2x2 code with all nonzero rank 2.
B1=[[1,0],[0,1]]
B2=[[0,1],[1,1]]
base=[B1,B2]
base_ranks={}
for a in [(1,0),(0,1),(1,1)]:
    base_ranks[str(a)]=rank2(lincomb(base,a))
    assert base_ranks[str(a)]==2
J=[[1,1],[1,1]]
lift=[kron(J,B) for B in base]
assert all(rank2(M)==2 for M in lift)
min_char_rank=99
nonzero_chars=0
for bits in all_bits(2*2*2):
    if not any(bits): continue
    lambdas=[]
    z=0
    for _ in range(2):
        lambdas.append([[bits[z],bits[z+1]],[bits[z+2],bits[z+3]]]); z+=4
    N=char_splice(lift,lambdas,2)
    if any(any(r) for r in N):
        nonzero_chars+=1
        min_char_rank=min(min_char_rank,rank2(N))
        assert rank2(N)>=2
assert nonzero_chars==255
kron_control={"base_nonzero_ranks":base_ranks,"nonzero_characters":nonzero_chars,"minimum_character_rank":min_char_rank}

# Honest rank-one preservation under J lift.
u=[1,0]; v=[1,1]
H=vec_outer(u,v)
assert rank2(H)==1 and rank2(kron(J,H))==1

# D. Exact Fourier formula in scalar case.
# Full-rank code over F2: I and companion A; all nonzero combinations rank2.
counts,total=enumerate_rank1_sum_distribution(2,1,base,t=1)
fourier_checks=0
for mask in range(1,4):
    coeff=[(mask>>i)&1 for i in range(2)]
    d=rank2(lincomb(base,coeff))
    got=fourier_from_counts(counts,total,mask,2)
    want=2**(-d)
    assert abs(got-want)<1e-12
    fourier_checks+=1
scalar_tv=tv_to_uniform(counts,total,2)

# r=2 exact formula too (2x2 manageable: 256^2=65536 choices)
counts2,total2=enumerate_rank1_sum_distribution(2,2,base,t=1)
for mask in range(1,4):
    coeff=[(mask>>i)&1 for i in range(2)]
    d=rank2(lincomb(base,coeff))
    got=fourier_from_counts(counts2,total2,mask,2)
    want=2**(-2*d)
    assert abs(got-want)<1e-12
    fourier_checks+=1

# E. Decoder correctness inequality rank(<R,M>_t) <= rank(R) rank(M).
rank_ineq=0
honest_lowrank=0
uniform_false_positive=0
uniform_trials=3000
n=8;t=4
for _ in range(500):
    # R rank <=2, M rank1
    R=low_rank_sum(n,2)
    M=vec_outer(rand_vec(n),rand_vec(n))
    C=block_inner(R,M,t)
    assert rank2(C)<=rank2(R)*rank2(M)
    rank_ineq+=1
    if rank2(C)<=2: honest_lowrank+=1
for _ in range(uniform_trials):
    C=[[rng.getrandbits(1) for _ in range(t)] for _ in range(t)]
    if rank2(C)<=2: uniform_false_positive+=1

# F. Common-kernel distinguisher for zero-padding, and invariance under invertible scrambling.
# 4x2 rectangular basis -> 4x4 zero-column padding => common right kernel dim>=2.
rect=[
 [[1,0],[0,1],[1,1],[0,1]],
 [[0,1],[1,1],[1,0],[1,1]],
]
pad=[ [row+[0,0] for row in A] for A in rect]
ck0=common_right_kernel_dim(pad)
assert ck0>=2

def rand_invertible(n):
    while True:
        A=[[rng.getrandbits(1) for _ in range(n)] for _ in range(n)]
        if rank2(A)==n: return A

kernel_invariance=0
for _ in range(100):
    P=rand_invertible(4); Q=rand_invertible(4)
    scr=[mat_mul(mat_mul(P,A),Q) for A in pad]
    assert common_right_kernel_dim(scr)==ck0
    # nontrivial basis mix in dimension2: swap or replace second by sum
    if rng.getrandbits(1):
        scr=[scr[1],mat_add(scr[0],scr[1])]
    assert common_right_kernel_dim(scr)==ck0
    kernel_invariance+=1

# Uniform random generator controls: observed common kernel, plus exact union bound.
uniform_kernel_nonzero=0
trials=5000
k=2;n=4
for _ in range(trials):
    mats=[[[rng.getrandbits(1) for _ in range(n)] for _ in range(n)] for __ in range(k)]
    if common_right_kernel_dim(mats)>0: uniform_kernel_nonzero+=1
union_bound=(2**n-1)*2**(-k*n)
# Exact probability: the common right kernel is nonzero iff the stacked
# (kn) x n uniform matrix has column rank < n.
full_col_prob=1.0
for i in range(n):
    full_col_prob *= (1-2**(i-k*n))
exact_common_kernel_prob=1-full_col_prob

# G. Parameter ledger for the Fourier sufficient condition.
# Statistical TV sufficient bound: 2^(L/2-rD-1), L=k*t^2.
# Exact incompatibility of THIS sufficient route if r<t and D<=k*t/2.
param_rows=[]
for k,D,t in [(20,3,4),(20,3,8),(4,2,3),(100,3,4),(8,4,5)]:
    max_r=t-1
    exponent=k*t*t/2-max_r*D-1
    param_rows.append({"k":k,"D":D,"t":t,"max_r":max_r,
                       "best_log2_TV_upper_bound_exponent":exponent,
                       "bound_nontrivial": exponent<0,
                       "criterion_D_gt_k_t_over_2": D>k*t/2})

# Scalar witness-bias repetition cost controls.
scalar_cost=[]
for r in [1,2,4,8,16]:
    bias=2**(-r)  # Fourier bias; Bernoulli mean shift=bias/2
    # Hoeffding: error <= exp(-T*bias^2/8) for midpoint test (conservative)
    T=math.ceil(8*128*math.log(2)/(bias*bias))
    scalar_cost.append({"r":r,"bias":bias,"repetitions_for_2^-128_Hoeffding_bound":T})

def number_rank_q(m,n,s,q=2):
    num=1
    den=1
    for i in range(s):
        num *= (q**m-q**i)*(q**n-q**i)
        den *= (q**s-q**i)
    return num//den

uniform_rank_le2_exact=sum(number_rank_q(4,4,s,2) for s in range(3))/2**16

# H. Multi-witness same-message correctness control.
multi_witness_checks=0
for _ in range(300):
    R=low_rank_sum(8,2)
    W1=vec_outer([1,0,0,0,0,0,0,0],[1,1,0,0,0,0,0,0])
    W2=vec_outer([0,1,0,0,0,0,0,0],[0,0,1,1,0,0,0,0])
    assert rank2(W1)==rank2(W2)==1
    C1=block_inner(R,W1,4); C2=block_inner(R,W2,4)
    assert rank2(C1)<=2 and rank2(C2)<=2
    multi_witness_checks += 2

# I. Random left-projection control for a possible de-structuring bridge.
# Fixed rank-3 matrix B (4x4). For uniform P in F2^(4x4), PB has rank<3
# iff P restricted to the 3-dim column space of B is not injective.
Bproj=[[1,0,0,0],[0,1,0,0],[0,0,1,0],[0,0,0,0]]
proj_fail=0
proj_total=0
for bits in all_bits(16):
    P=[list(bits[i*4:(i+1)*4]) for i in range(4)]
    if rank2(mat_mul(P,Bproj))<=2:
        proj_fail+=1
    proj_total+=1
proj_exact=proj_fail/proj_total
proj_formula=1.0
for i in range(3):
    proj_formula *= (1-2**(i-4))
proj_formula=1-proj_formula
assert abs(proj_exact-proj_formula)<1e-15
# Union-bound ledger for the actual small scalar-descent validation dimensions:
# b=6 columns, k=20-dimensional code, false threshold D=3.
projection_union_bound_exponent=20+3+1-6

report.update({
 "blockwise_character_identity_checks":char_identity,
 "blockwise_splicing_fixture":split_fixture,
 "kronecker_character_control":kron_control,
 "honest_rank1_preserved_by_kronecker":True,
 "scalar_fourier_exact_checks":fourier_checks,
 "scalar_r1_total_variation_from_uniform":scalar_tv,
 "rank_output_inequality_checks":rank_ineq,
 "honest_rank_le_2_count":honest_lowrank,
 "uniform_4x4_rank_le_2_hits":uniform_false_positive,
 "uniform_4x4_trials":uniform_trials,
 "uniform_4x4_rank_le_2_exact_probability":uniform_rank_le2_exact,
 "multi_witness_same_message_lowrank_checks":multi_witness_checks,
 "padded_common_right_kernel_dimension":ck0,
 "scrambler_kernel_invariance_checks":kernel_invariance,
 "uniform_pair_common_kernel_nonzero_hits":uniform_kernel_nonzero,
 "uniform_pair_trials":trials,
 "uniform_pair_nonzero_common_kernel_union_bound":union_bound,
 "uniform_pair_nonzero_common_kernel_exact_probability":exact_common_kernel_prob,
 "fourier_parameter_rows":param_rows,
 "scalar_bias_repetition_costs":scalar_cost,
 "left_projection_exact_failure_rank3_to_4rows":proj_exact,
 "left_projection_formula_failure_rank3_to_4rows":proj_formula,
 "left_projection_union_bound_exponent_example_k20_D3_b6":projection_union_bound_exponent,
 "status":"PASS"
})
print(json.dumps(report,sort_keys=True,indent=2))
