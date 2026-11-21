#!/usr/bin/env python3
import itertools, json, math, random, hashlib

P = 2
SEED = 630063
rng = random.Random(SEED)

def add_poly(a,b,p=P):
    out=dict(a)
    for m,c in b.items():
        v=(out.get(m,0)+c)%p
        if v: out[m]=v
        elif m in out: del out[m]
    return out

def scale_poly(a,c,p=P):
    c%=p
    return {m:(c*v)%p for m,v in a.items() if (c*v)%p}

def mul_poly(a,b,p=P):
    out={}
    for m,c in a.items():
        for n,d in b.items():
            u=m|n
            v=(out.get(u,0)+c*d)%p
            if v: out[u]=v
            elif u in out: del out[u]
    return out

def mono(mask): return {mask:1}
def one(): return {0:1}
def var(i): return {1<<i:1}
def one_minus_var(i,p=P): return {0:1, 1<<i:(-1)%p}

def eval_poly(f,a,p=P):
    s=0
    for m,c in f.items():
        if (m & a)==m:
            s=(s+c)%p
    return s

def maxdeg(f):
    return max((m.bit_count() for m in f), default=-1)

def ambient_masks(n,D):
    out=[]
    for r in range(D+1):
        for C in itertools.combinations(range(n),r):
            m=0
            for i in C: m|=1<<i
            out.append(m)
    return out

def poly_vec(f,basis,p=P):
    ix={m:i for i,m in enumerate(basis)}
    v=[0]*len(basis)
    for m,c in f.items():
        if m not in ix:
            raise ValueError('polynomial outside ambient cutoff')
        v[ix[m]]=c%p
    return v

def row_reduce(rows,p=P):
    if not rows: return [],[]
    A=[list(map(lambda x:x%p,r)) for r in rows if any(x%p for x in r)]
    if not A: return [],[]
    n=len(A[0]); piv=[]; r=0
    for c in range(n):
        pivot=next((i for i in range(r,len(A)) if A[i][c]%p),None)
        if pivot is None: continue
        A[r],A[pivot]=A[pivot],A[r]
        inv=pow(A[r][c],-1,p)
        A[r]=[(x*inv)%p for x in A[r]]
        for i in range(len(A)):
            if i!=r and A[i][c]%p:
                f=A[i][c]%p
                A[i]=[(A[i][j]-f*A[r][j])%p for j in range(n)]
        piv.append(c); r+=1
        if r==len(A): break
    return A[:r],piv

def independent_basis(rows,p=P):
    rr,_=row_reduce(rows,p)
    return rr

def solve_linear(A,b,p=P):
    if not A:
        return [0]*0 if not b else None
    M=[list(row)+[rhs%p] for row,rhs in zip(A,b)]
    m=len(M); n=len(M[0])-1; r=0; piv=[]
    for c in range(n):
        pivot=next((i for i in range(r,m) if M[i][c]%p),None)
        if pivot is None: continue
        M[r],M[pivot]=M[pivot],M[r]
        inv=pow(M[r][c],-1,p)
        M[r]=[(x*inv)%p for x in M[r]]
        for i in range(m):
            if i!=r and M[i][c]%p:
                f=M[i][c]%p
                M[i]=[(M[i][j]-f*M[r][j])%p for j in range(n+1)]
        piv.append(c); r+=1
    for i in range(r,m):
        if all(M[i][j]%p==0 for j in range(n)) and M[i][n]%p:
            return None
    x=[0]*n
    for i,c in enumerate(piv): x[c]=M[i][n]%p
    return x

def contains(rows,target,p=P):
    rb=independent_basis(rows,p)
    r1=len(rb)
    r2=len(independent_basis(rb+[target],p))
    return r1==r2

def dual_separator(Vbasis,const_index=0,p=P):
    # lambda annihilates V and lambda[const_index]=1
    N=len(Vbasis[0]) if Vbasis else const_index+1
    A=[row[:] for row in Vbasis]
    b=[0]*len(A)
    e=[0]*N; e[const_index]=1
    A.append(e); b.append(1)
    return solve_linear(A,b,p)

def truncated_ideal_basis(gens,n,D,p=P):
    basis=ambient_masks(n,D); ix={m:i for i,m in enumerate(basis)}
    candidates=[]
    # monomials suffice because arbitrary multipliers are their linear span.
    for g in gens:
        for mm in basis:
            h=mul_poly({mm:1},g,p)
            if not h: continue
            if maxdeg(h)>D: continue
            v=[0]*len(basis)
            for m,c in h.items(): v[ix[m]]=c%p
            candidates.append(v)
    return independent_basis(candidates,p), basis

def rand_span_vec(B,p=P):
    if not B: return [0]*0
    n=len(B[0]); out=[0]*n
    for row in B:
        a=rng.randrange(p)
        if a:
            out=[(x+a*y)%p for x,y in zip(out,row)]
    return out

def eval_vec(v,basis,a,p=P):
    return sum(c for c,m in zip(v,basis) if (m&a)==m)%p

def clause_falsity(n, positive=(), negative=(), p=P):
    # Clause OR( x_i for positive, not x_i for negative ).
    # Falsity polynomial is product[(1-x_i) positive] * product[x_i negative].
    f={0:1}
    for i in positive: f=mul_poly(f,one_minus_var(i,p),p)
    for i in negative: f=mul_poly(f,var(i),p)
    return f

def delta_assignment(a,n,p=P):
    f={0:1}
    for i in range(n):
        f=mul_poly(f,var(i) if ((a>>i)&1) else one_minus_var(i,p),p)
    return f

def vec_add(a,b,p=P): return [(x+y)%p for x,y in zip(a,b)]
def vec_scale(a,c,p=P): return [(c*x)%p for x in a]
def dot(a,b,p=P): return sum(x*y for x,y in zip(a,b))%p

checks={}

# A. Multi-witness correctness for one genuinely nonlinear clause.
n=2; D=2
true_gens=[clause_falsity(n,positive=(0,1))]
VB,basis=truncated_ideal_basis(true_gens,n,D,P)
valid=[a for a in range(1<<n) if all(eval_poly(g,a,P)==0 for g in true_gens)]
assert len(valid)==3
trials=300; evals=0
for _ in range(trials):
    v=rand_span_vec(VB,P)
    K=rng.randrange(P)
    F=v[:]
    F[basis.index(0)]^=K  # p=2
    for a in valid:
        assert eval_vec(F,basis,a,P)==K
        evals+=1
# Complete-public-output audit: because every mask vanishes at a valid witness, 1 cannot lie in V.
const=[1 if m==0 else 0 for m in basis]
assert not contains(VB,const,P)
lam_true=dual_separator(VB,basis.index(0),P)
assert lam_true is not None and dot(lam_true,const,P)==1 and all(dot(lam_true,row,P)==0 for row in VB)
public_recoveries=0
for _ in range(300):
    v=rand_span_vec(VB,P); K=rng.randrange(P); F=v[:]; F[basis.index(0)]^=K
    assert dot(lam_true,F,P)==K
    public_recoveries+=1
checks['true_multi_witness']={'span_dimension':len(VB),'valid_witnesses':len(valid),'capsules':trials,'witness_evaluations':evals,'public_dual_weight':sum(bool(x) for x in lam_true),'public_no_witness_recoveries':public_recoveries}

# B. False contradiction where 1 is in V_D: exact coset hiding.
n=1; D=1
false_easy=[clause_falsity(n,positive=(0,)), clause_falsity(n,negative=(0,))]
VB,basis=truncated_ideal_basis(false_easy,n,D,P)
const=[1 if m==0 else 0 for m in basis]
assert contains(VB,const,P)
# exhaustive V over basis coordinates
span=set()
for coeffs in itertools.product(range(P), repeat=len(VB)):
    x=[0]*len(basis)
    for a,row in zip(coeffs,VB): x=vec_add(x,vec_scale(row,a,P),P)
    span.add(tuple(x))
dists=[]
ci=basis.index(0)
for K in range(P):
    d={tuple((x[i]+(K if i==ci else 0))%P for i in range(len(x))) for x in span}
    dists.append(d)
assert all(d==dists[0] for d in dists)
checks['false_full_certificate']={'span_dimension':len(VB),'ambient_dimension':len(basis),'support_size':len(span),'key_supports_identical':True}

# C. False contradiction at insufficient cutoff: nonzero V but 1 absent and public dual extracts key.
n=3; D=1
chain=[clause_falsity(n,positive=(0,)), clause_falsity(n,negative=(0,),positive=(1,)), clause_falsity(n,negative=(1,),positive=(2,)), clause_falsity(n,negative=(2,))]
# At D=1 only endpoint degree-1 generators contribute, giving a nonzero span but no certificate.
VB,basis=truncated_ideal_basis(chain,n,D,P)
const=[1 if m==0 else 0 for m in basis]
assert len(VB)>0 and not contains(VB,const,P)
lam=dual_separator(VB,basis.index(0),P)
assert lam is not None and dot(lam,const,P)==1 and all(dot(lam,row,P)==0 for row in VB)
recoveries=0
for _ in range(500):
    v=rand_span_vec(VB,P); K=rng.randrange(P)
    F=v[:]; F[basis.index(0)]^=K
    assert dot(lam,F,P)==K
    recoveries+=1
checks['insufficient_cutoff_dual_attack']={'span_dimension':len(VB),'ambient_dimension':len(basis),'dual_weight':sum(bool(x) for x in lam),'recoveries':recoveries}

# D. Same compact contradiction reaches certificate at higher cutoff (diagnostic, no general bound claim).
threshold=None; dims={}
for D in range(0,n+1):
    VB,basis=truncated_ideal_basis(chain,n,D,P)
    const=[1 if m==0 else 0 for m in basis]
    dims[str(D)]={'ambient':len(basis),'span':len(VB),'contains_one':contains(VB,const,P)}
    if threshold is None and dims[str(D)]['contains_one']: threshold=D
assert threshold==2
checks['compact_chain_diagnostic']={'n':n,'first_cutoff_with_one':threshold,'by_cutoff':dims}

# E. All-exclusions exact threshold D=k, k=2..6.
all_excl=[]
for k in range(2,7):
    gens=[delta_assignment(a,k,P) for a in range(1<<k)]
    # D=k-1: every nonzero monomial multiple remains degree k, so V=0.
    VBlo,blo=truncated_ideal_basis(gens,k,k-1,P)
    clo=[1 if m==0 else 0 for m in blo]
    assert len(VBlo)==0 and not contains(VBlo,clo,P)
    # D=k: assignment indicators form a basis of full Boolean function space.
    VBhi,bhi=truncated_ideal_basis(gens,k,k,P)
    chi=[1 if m==0 else 0 for m in bhi]
    assert len(VBhi)==1<<k and contains(VBhi,chi,P)
    # Explicit identity sum delta_a = 1.
    s={}
    for g in gens: s=add_poly(s,g,P)
    assert s=={0:1}
    all_excl.append({'k':k,'D_below':k-1,'below_span_dim':len(VBlo),'D_at':k,'ambient_at':len(bhi),'span_at':len(VBhi)})
checks['all_exclusions_threshold']=all_excl

# F. General full-degree certificate construction on unsat CNFs, checked for all-exclusions and compact chain.
def assignment_indicator_multiple_of_falsified_clause(a,n,g,p=P):
    # Search monomial assignment-literal product over variables not already enough; easiest verify delta belongs to full ideal span.
    # For checker we use linear span at D=n rather than claiming a particular monomial for arbitrary g.
    return delta_assignment(a,n,p)

full_degree_cases=[]
for name,n,gens in [('chain3',3,chain),('all_excl4',4,[delta_assignment(a,4,P) for a in range(16)])]:
    assert all(any(eval_poly(g,a,P)!=0 for g in gens) for a in range(1<<n))
    VB,basis=truncated_ideal_basis(gens,n,n,P)
    const=[1 if m==0 else 0 for m in basis]
    assert contains(VB,const,P)
    full_degree_cases.append({'name':name,'n':n,'ambient':len(basis),'span':len(VB)})
checks['full_degree_unsat_certificate']=full_degree_cases

# G. Exact dichotomy census over deterministic small random CNFs/cutoffs.
def random_clause(n):
    width=rng.randint(1,min(3,n))
    vs=rng.sample(range(n),width)
    pos=[]; neg=[]
    for i in vs:
        (pos if rng.randrange(2) else neg).append(i)
    return clause_falsity(n,tuple(pos),tuple(neg),P)

census={'cases':0,'contains_one':0,'dual_cases':0,'dual_recoveries':0,'true_formulas':0,'false_formulas':0}
for n in (2,3,4):
    for case in range(30):
        gens=[random_clause(n) for _ in range(rng.randint(2,6))]
        has_witness=any(all(eval_poly(g,a,P)==0 for g in gens) for a in range(1<<n))
        census['true_formulas' if has_witness else 'false_formulas']+=1
        D=rng.randint(0,n)
        VB,basis=truncated_ideal_basis(gens,n,D,P)
        const=[1 if m==0 else 0 for m in basis]
        has1=contains(VB,const,P)
        census['cases']+=1
        if has1:
            census['contains_one']+=1
            # Algebraic identity: shifting K by 1 stays in same coset.
            assert contains(VB,const,P)
        else:
            census['dual_cases']+=1
            lam=dual_separator(VB,basis.index(0),P)
            assert lam is not None
            assert dot(lam,const,P)==1 and all(dot(lam,row,P)==0 for row in VB)
            for _ in range(8):
                v=rand_span_vec(VB,P) if VB else [0]*len(basis)
                K=rng.randrange(P); F=v[:]; F[basis.index(0)]^=K
                assert dot(lam,F,P)==K
                census['dual_recoveries']+=1
checks['dichotomy_census']=census

# H. Noise identity: public dual always reduces noisy capsule to K+lambda(e).
noise_trials=1000
noise_identity=0
# reuse chain D=1 dual
n=3;D=1; VB,basis=truncated_ideal_basis(chain,n,D,P); const=[1 if m==0 else 0 for m in basis]; lam=dual_separator(VB,basis.index(0),P)
for _ in range(noise_trials):
    v=rand_span_vec(VB,P); K=rng.randrange(P)
    e=[rng.randrange(P) for _ in basis]
    F=[(v[i]+e[i]+(K if basis[i]==0 else 0))%P for i in range(len(basis))]
    rhs=(K+dot(lam,e,P))%P
    assert dot(lam,F,P)==rhs
    noise_identity+=1
checks['noisy_dual_identity']={'trials':noise_identity,'statement':'lambda(F)=K+lambda(e) exactly; no hardness conclusion'}

# I. Resource table only, exact combinatorics.
resource=[]
for n,D in [(64,3),(64,4),(128,4),(128,5),(256,4)]:
    M=sum(math.comb(n,i) for i in range(D+1))
    resource.append({'n':n,'D':D,'ambient_coefficients':M,'bytes_at_16_bits_each':2*M})
checks['resource_table']=resource

out={
    'run':63,
    'seed':SEED,
    'field_prime':P,
    'status':'PASS',
    'claims_scope':[
        'Finite tests validate the implemented Boolean-quotient algebra and exact identities only.',
        'Security is not inferred from passing tests.',
        'The noiseless coset dichotomy is an algebraic theorem for this candidate.',
        'The noisy dual identity does not provide an LWE/SIS reduction.',
        'No arbitrary-QPT early-key-recovery-to-source-witness reduction is claimed.'
    ],
    'checks':checks
}
print(json.dumps(out,sort_keys=True,indent=2))
