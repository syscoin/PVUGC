#!/usr/bin/env python3
"""R155 finite checks: unknown-support nonlinear mask, known-key span learner.
Standard library only; no cryptographic hardness claim.
"""
import itertools, json, random, fractions, hashlib
Q=101; N=8; D=4
rng=random.Random(15520261108)
def inv(a,q): return pow(a%q,-1,q)
def rref_solve(mat,b,q):
    m=len(mat); n=len(mat[0]) if m else 0
    A=[[int(t)%q for t in row]+[b[i]%q] for i,row in enumerate(mat)]
    pivots=[]; r=0
    for j in range(n):
        t=next((i for i in range(r,m) if A[i][j]),None)
        if t is None:continue
        A[r],A[t]=A[t],A[r];z=inv(A[r][j],q)
        A[r]=[(z*u)%q for u in A[r]]
        for i in range(m):
            if i!=r and A[i][j]:
                h=A[i][j];A[i]=[(v-h*w)%q for v,w in zip(A[i],A[r])]
        pivots.append(j);r+=1
        if r==m: break
    if any(not any(row[:n]) and row[n] for row in A):return None
    sol=[0]*n
    for i,j in enumerate(pivots):sol[j]=A[i][n]
    return sol

def independent(colset,col,q):
    n=len(col)
    A=[[v[i] for v in colset] for i in range(n)]
    return rref_solve(A,col,q) is None

def span_key(samples,v,C,q):
    # Solve C = sum_j alpha_j * samples[j] + K * v.
    mat=[[s[i] for s in samples]+[v[i]] for i in range(len(v))]
    ans=rref_solve(mat,C,q)
    return None if ans is None else ans[-1]

basis=[]
while len(basis)<D:
    v=[0,0]+[rng.randrange(Q) for _ in range(N-2)]
    if independent(basis,v,Q):basis.append(v)
message_vector=[1,1,0,0,0,0,0,0]
assert independent(basis,message_vector,Q)
checks=0

def sample_mask():
    r=[rng.randrange(Q) for _ in range(4)]
    vals=[r[0]*r[1],r[1]**2+r[2],r[2]*r[3]+r[0],r[0]**3+r[3]]
    return [sum((vals[j]*basis[j][i] for j in range(D)))%Q for i in range(N)]

trials=512; failures=0; recovered=0; witness_checks=0
for t in range(trials):
    K=rng.randrange(Q)
    samples=[sample_mask() for _ in range(4*N)]
    F=sample_mask();C=[(K*message_vector[i]+F[i])%Q for i in range(N)]
    # Distinct ORIGINAL-witness evaluation functionals e0 and e1.
    for idx in [0,1]:
        assert C[idx]==K
        witness_checks+=1
    got=span_key(samples,message_vector,C,Q)
    if got==K:recovered+=1
    else: failures+=1
    checks+=3

# Exact finite distribution for a rare-mode mask source, demonstrating
# the universal expected rank-increment inequality with an arbitrary law.
F=fractions.Fraction
small_q=3; small_N=3
vectors=[(0,0,0),(1,0,0),(0,1,0),(0,0,1)]
prob=[F(1,2),F(1,4),F(1,8),F(1,8)]
assert sum(prob)==1
p_out=[]
# dynamic programming on canonical subspaces for m=0..8,
# avoiding 4**m full sequences and exact rational arithmetic.
def canonical_span(vs):
    if not vs:return tuple()
    A=[[int(z)%small_q for z in v] for v in vs]
    n=small_N; nr=len(A);r=0
    for j in range(n):
        t=next((i for i in range(r,nr) if A[i][j]),None)
        if t is None:continue
        A[r],A[t]=A[t],A[r]
        mul=inv(A[r][j],small_q)
        A[r]=[(u*mul)%small_q for u in A[r]]
        for i in range(nr):
            if i!=r and A[i][j]:
                z=A[i][j];A[i]=[(a-z*b)%small_q for a,b in zip(A[i],A[r])]
        r+=1
        if r==nr:break
    return tuple(tuple(row) for row in A[:r])

states={tuple():F(1)}
for m in range(9):
    probability=F(0)
    for sp,weight in states.items():
        for v,p in zip(vectors,prob):
            if independent(sp,v,small_q):probability+=weight*p
    p_out.append(probability)
    assert probability<=F(small_N,m+1)
    if m:
        assert p_out[-1]<=p_out[-2]
    next_states={}
    for sp,weight in states.items():
        for v,p in zip(vectors,prob):
            dst=canonical_span(sp+(v,))
            next_states[dst]=next_states.get(dst,F(0))+weight*p
    states=next_states
    checks+=1

report={
    'run':'R155-KNOWN-KEY-SAMPLE-SPAN-20261108',
    'q':Q,'N':N,'hidden_mask_span_dim':D,
    'nonlinear_mask':'(r0*r1, r1^2+r2, r2*r3+r0, r0^3+r3) times fixed hidden independent mask basis',
    'witness_evaluators':2,
    'trials':trials,
    'sample_count_per_trial':4*N,
    'recovered_without_witness':recovered,
    'failures':failures,
    'witness_exact_checks':witness_checks,
    'exact_skew_law_probabilities':[[p.numerator,p.denominator] for p in p_out],
    'theorem':'P[target outside span(m iid samples)] <= N/(m+1); conditional public known-key sampler; exact linear witness evaluators',
    'checks':checks,
    'scope':'finite algebra only; no QPT hardness or full WKEM'
}
print(json.dumps(report,sort_keys=True,indent=2))
