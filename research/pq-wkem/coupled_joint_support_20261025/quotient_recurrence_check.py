#!/usr/bin/env python3
"""Standalone exact-field test of the published pivot–Schur quotient-slice recurrence.

Field/gate formulas are reproduced from the pinned full_extension_certificate.py
in syscoin/PVUGC commit c8343d87d7ad880dd4aa2deed02d9f681e2c4569.
This script is a constructive exact-algebra/reproduction test, NOT QPT security.
"""
import hashlib
import json
import random

POLY=0x13

def gf16mul(a,b):
    v=0
    for _ in range(4):
        if b&1:v^=a
        a<<=1
        if a&16:a^=POLY
        b>>=1
    return v
F=[[gf16mul(a,b) for b in range(16)] for a in range(16)]
def fpow(a,n):
    v=1
    while n:
        if n&1:v=F[v][a]
        a=F[a][a];n>>=1
    return v

def ftrace(a):
    t=0
    for _ in range(4):t^=a;a=F[a][a]
    assert t in (0,1)
    return t
KAPPA=next(a for a in range(1,16) if ftrace(a))

def gf256mul(a,b):
    a0,a1=a&15,a>>4
    b0,b1=b&15,b>>4
    t=F[a1][b1]
    return (F[a0][b0]^F[t][KAPPA]) | ((F[a0][b1]^F[a1][b0]^t)<<4)
E=[[gf256mul(a,b) for b in range(256)] for a in range(256)]
def epow(a,n):
    v=1
    while n:
        if n&1:v=E[v][a]
        a=E[a][a];n>>=1
    return v
INV=[0]+[epow(a,254) for a in range(1,256)]
INVF=[0]+[fpow(a,14) for a in range(1,16)]
THETA=16
COUNT=0

def check(x,why):
    global COUNT
    COUNT+=1
    if not x:raise AssertionError(f'assertion {COUNT}: {why}')

def zeros(rows,cols):return [[0]*cols for _ in range(rows)]
def ident(n):return [[int(i==j) for j in range(n)] for i in range(n)]
def mm(A,B):
    rows=len(A); mid=len(B); cols=len(B[0]); C=zeros(rows,cols)
    for i in range(rows):
        for t in range(mid):
            a=A[i][t]
            if a:
                for j in range(cols):C[i][j]^=E[a][B[t][j]]
    return C

def madd(A,B):return [[x^y for x,y in zip(a,b)] for a,b in zip(A,B)]
def mscale(s,M):return [[E[s][a] for a in row] for row in M]
def submatrix(M,rows,cols):return [[M[i][j] for j in cols] for i in rows]

def rref_with_pivots(M):
    A=[a[:] for a in M]; m=len(A);n=len(A[0]);row=0;pc=[];pr=[]
    for j in range(n):
        z=next((i for i in range(row,m) if A[i][j]),None)
        if z is None:continue
        A[row],A[z]=A[z],A[row]
        pr.append(z)  # only columns used elsewhere; row permutation isn't needed
        inv=INV[A[row][j]]
        for col in range(j,n):A[row][col]=E[inv][A[row][col]]
        for i in range(m):
            if i!=row and A[i][j]:
                f=A[i][j]
                for col in range(j,n):A[i][col]^=E[f][A[row][col]]
        pc.append(j);row+=1
        if row==m:break
    return A,pc

def invmat(M):
    n=len(M); W=[a[:]+b for a,b in zip(M,ident(n))]
    for j in range(n):
        k=next((t for t in range(j,n) if W[t][j]),None)
        check(k is not None,'pivot inverse exists')
        W[j],W[k]=W[k],W[j]
        v=INV[W[j][j]]
        for t in range(2*n):W[j][t]=E[v][W[j][t]]
        for i in range(n):
            if i!=j and W[i][j]:
                v=W[i][j]
                for t in range(2*n):W[i][t]^=E[v][W[j][t]]
    return [r[n:] for r in W]

def rank(M):return len(rref_with_pivots(M)[1])

def rank_factor(M):
    """Public canonical rank factorization M=A B with left/right inverses.

    Full column/row bases are chosen solely from public M, not hidden factors.
    """
    N=len(M);_,pivotcols=rref_with_pivots(M);R=len(pivotcols)
    A=[[M[i][j] for j in pivotcols] for i in range(N)]
    # Deterministic independent pivot rows of A.
    _,pivotrows=rref_with_pivots([[A[i][j] for i in range(N)] for j in range(R)])
    check(len(pivotrows)==R,'A has full column rank')
    Ainv=invmat(submatrix(A,pivotrows,list(range(R))))
    B=mm(Ainv,[M[i][:] for i in pivotrows]);check(mm(A,B)==M,'AB=public Q0')
    # B[:,pivotcolumnsB] is invertible, giving a public right inverse.
    _,bp=rref_with_pivots(B);check(len(bp)==R,'B full row rank')
    Binv=invmat(submatrix(B,list(range(R)),bp))
    # L_A=Ainv * row_selector; R_B=column_selector * Binv.
    left=zeros(R,N);right=zeros(N,R)
    for i in range(R):
        for j in range(R):
            left[i][pivotrows[j]]=Ainv[i][j]
            right[bp[i]][j]=Binv[i][j]
    check(mm(left,A)==ident(R),'left inverse')
    check(mm(B,right)==ident(R),'right inverse')
    return A,B,left,right

N_ORIG=2
M_CONSTRAINT=5  # four quotient coordinates: j=0,1,2,3, so recurrence is nontrivial
L=10
H=4
N=2*L+H
K_DIM=N_ORIG+M_CONSTRAINT

def zpoly(e):return F[e][e]^e^1
NODES=[e for e in range(1,16) if zpoly(e)][:L]
check(len(NODES)==L,'off-domain nodes')

def sl2(rng):
    while True:
        p,q=rng.randrange(16),rng.randrange(16)
        if p or q:break
    free=rng.randrange(16)
    if p:r=free;t=F[INVF[p]][1^F[q][r]]
    else:t=free;r=INVF[q]
    check(F[p][t]^F[q][r]==1,'SL2 det 1')
    return p,q,r,t

def setup(seed):
    rng=random.Random(seed);nodes=[]
    for e in NODES:
        bmask=[rng.randrange(16) for _ in range(N_ORIG)]
        alpha=[]
        for i in range(N_ORIG):
            a2=bmask[i]^E[THETA][fpow(e,i)]
            a=epow(a2,128)
            check(E[a][a]==a2,'shear Frobenius lift')
            alpha.append(a)
        T=sl2(rng);mu=rng.randrange(16,256);orientation=rng.randrange(2)
        U=[[rng.randrange(256) for _ in range(3)] for _ in range(N)]
        V=[[rng.randrange(256) for _ in range(N)] for _ in range(3)]
        nodes.append((e,alpha,T,mu,orientation,U,V))
    return nodes,rng.randrange(1,256)

def quotient_eval(e,rho):
    lam=fpow(e,8);s0=fpow(zpoly(e),8);t=0
    for j,c in enumerate(rho):t^=E[c][fpow(lam,j)]
    return E[s0][t]

def gate(node,y):
    e,alpha,(p,q,r,t),mu,orientation,_,_=node
    z,w1,w2,*rho=y
    a=w1^w2;b=z
    A=E[p][a]^E[q][b]
    B=E[r][a]^E[t][b]
    C=E[F[p][r]][a]^E[F[q][t]][z]
    eta=0
    for i,w in enumerate((w1,w2)):
        C^=E[E[alpha[i]][alpha[i]]][w]
        eta^=E[alpha[i]][w]
    S=quotient_eval(e,rho)^eta
    pi=z^E[mu][A if orientation==0 else B]
    if orientation==0:As=A;Bs=B^E[mu][C]
    else:As=A^E[mu][C];Bs=B
    return [[C,As,S],[Bs,pi,0],[S,0,pi]]

def build_matrices(nodes,key):
    Cs=[]
    for j in range(K_DIM):
        y=tuple(int(i==j) for i in range(K_DIM))
        M=zeros(N,N)
        for node in nodes:
            _,_,_,_,_,U,V=node
            M=madd(M,mm(mm(U,gate(node,y)),V))
        if j==0:
            for i in range(N):M[i][i]^=key
        Cs.append(M)
    return Cs

def public_eval(Cs,y):
    M=zeros(N,N)
    for j,c in enumerate(y):
        if c:M=madd(M,mscale(c,Cs[j]))
    return M

def compress(Cs):
    # The package literally retains the ORIGINAL coefficient matrices and
    # just the first two quotient coefficient matrices; no secret factors.
    return Cs[:N_ORIG+1]+Cs[N_ORIG+1:N_ORIG+3]

def prepare_expand(Q0,Q1):
    A,B,left,right=rank_factor(Q0)
    T=mm(mm(left,Q1),right)
    check(mm(mm(A,T),B)==Q1,'Q1 lies in same quotient factor space')
    return A,B,T

def expand(comp):
    A,B,T=prepare_expand(comp[N_ORIG+1],comp[N_ORIG+2])
    out=comp[:]
    curr=T
    for j in range(2,M_CONSTRAINT-1):
        curr=mm(curr,T)
        out.append(mm(mm(A,curr),B))
    return out

def verified_encode(Cs):
    """Generic public-tensor serializer; never silently changes malformed input."""
    candidate=compress(Cs)
    try:
        if expand(candidate)==Cs:
            return {'kind':'recurrence','matrices':candidate}
    except (ValueError,IndexError,AssertionError):
        pass
    return {'kind':'raw','matrices':Cs}

def verified_decode(pkg):
    if pkg['kind']=='raw':return pkg['matrices']
    return expand(pkg['matrices'])

def run(seed):
    nodes,key=setup(seed)
    Cs=build_matrices(nodes,key)
    Q0,Q1=Cs[N_ORIG+1],Cs[N_ORIG+2]
    check(rank(Q0)==2*L,'quotient rank 2L')
    # Verify the exact local public quotient basis and all spectral ratios.
    for node in nodes:
        e,_,_,_,_,U,V=node
        R=zeros(N,N)
        for i in range(N):
            for j in range(N):
                R[i][j]=E[U[i][0]][V[2][j]]^E[U[i][2]][V[0][j]]
        check(rank(R)==2,'node quotient derivative has rank 2')
        s0=quotient_eval(e,[1,0,0,0])
        check(s0!=0,'quotient base nonzero')
        for power in range(4):
            q=quotient_eval(e,[int(j==power) for j in range(4)])
            check(q==E[s0][fpow(fpow(e,8),power)],'geometric node quotient weights')
    comp=compress(Cs)
    check(len(comp)==N_ORIG+3,'n+3 public matrix package')
    pkg=verified_encode(Cs)
    check(pkg['kind']=='recurrence','honest matrices compress to recurrence form')
    expanded=verified_decode(pkg)
    check(len(expanded)==len(Cs),'full coefficient list regenerated')
    bad=[[row[:] for row in C] for C in Cs]
    bad[N_ORIG+3][0][0]^=1  # Modify only a later public quotient slice.
    malformed=verified_encode(bad)
    check(malformed['kind']=='raw','inconsistent malicious quotient has exact fallback')
    check(verified_decode(malformed)==bad,'fallback preserves arbitrary full public input')
    for j,(x,y) in enumerate(zip(expanded,Cs)):
        check(x==y,f'exact expanded coefficient {j}')
    _,_,Lft,Rgt=rank_factor(Q0)
    G=mm(Rgt,Lft)  # Reflexive public generalized inverse Q0 G Q0 = Q0.
    check(mm(mm(Q0,G),Q0)==Q0,'public generalized inverse')
    Q2=mm(mm(Q1,G),Q1)
    Q3=mm(mm(Q2,G),Q1)
    check(Q2==Cs[N_ORIG+3],'quotient second power recurrence')
    check(Q3==Cs[N_ORIG+4],'quotient third power recurrence')
    rng=random.Random(seed^0xace351)
    for _ in range(75):
        y=tuple(rng.randrange(256) for _ in range(K_DIM))
        check(public_eval(expanded,y)==public_eval(Cs,y),'arbitrary E-source exact evaluation')
    for w in (0,1):
        y=(1,w,w,0,0,0,0)
        M=public_eval(expanded,y)
        for i in range(N):M[i][i]^=key
        check(rank(M)<=2*L,'two valid original witnesses share one capability')
    payload={'seed':seed,'key':key,'L':L,'N':N,'quotient_dimensions':M_CONSTRAINT-1,
             'full_matrices':len(Cs),'retained_matrices':len(comp),
             'quotient_rank':rank(Q0),
             'public_coeff_hash':hashlib.sha256(bytes(sum((sum(c,[]) for c in Cs),[]))).hexdigest()}
    return payload

def main():
    runs=[run(s) for s in (1471,20393,44221)]
    assert len({x['public_coeff_hash'] for x in runs})==3
    Nreal=32913; Lreal=16374;nreal=11000;mreal=16000;Qbytes=32
    full=(nreal+mreal)*Nreal*Nreal*Qbytes
    compressed=(nreal+3)*Nreal*Nreal*Qbytes
    assert full==935941451616000
    assert compressed<full
    print(json.dumps({'version':'1.0','field':'GF(16) inside GF(256)',
       'algebra':'Q_j=Q0 (G Q1)^j, Q0 G Q0=Q0',
       'fixture_runs':runs,'total_assertions':COUNT,
       'large_full_bytes':full,'large_compressed_bytes':compressed,
       'large_saved_bytes':full-compressed,'compression_percent':round((1-compressed/full)*100,8),
       'scope':'exact algebra and toy correctness; no QPT secrecy'},sort_keys=True,indent=2))

if __name__=='__main__':main()
