#!/usr/bin/env python3
from fractions import Fraction
from itertools import combinations
from math import comb, log2, ceil
import json, sys

ASSERTS=0

def check(c,msg='assertion failed'):
    global ASSERTS
    ASSERTS+=1
    if not c: raise AssertionError(msg)

def det_bareiss(A):
    A=[list(map(int,r)) for r in A]
    n=len(A)
    if n==0: return 1
    check(all(len(r)==n for r in A),'det square')
    if n==1: return A[0][0]
    sign=1; prev=1
    for k in range(n-1):
        piv=next((i for i in range(k,n) if A[i][k]),None)
        if piv is None: return 0
        if piv!=k:
            A[k],A[piv]=A[piv],A[k]; sign=-sign
        pivot=A[k][k]
        for i in range(k+1,n):
            for j in range(k+1,n):
                num=A[i][j]*pivot-A[i][k]*A[k][j]
                check(num%prev==0,'Bareiss divisibility')
                A[i][j]=num//prev
        prev=pivot
    return sign*A[n-1][n-1]

def rank_q(A):
    A=[[Fraction(x) for x in r] for r in A]
    if not A:return 0
    nr=len(A); nc=len(A[0]); rr=0
    for c in range(nc):
        p=next((i for i in range(rr,nr) if A[i][c]),None)
        if p is None: continue
        A[rr],A[p]=A[p],A[rr]
        z=A[rr][c]
        A[rr]=[x/z for x in A[rr]]
        for i in range(nr):
            if i!=rr and A[i][c]:
                f=A[i][c]
                A[i]=[x-f*y for x,y in zip(A[i],A[rr])]
        rr+=1
        if rr==nr: break
    return rr

def rank_mod(A,p):
    A=[[x%p for x in r] for r in A]
    if not A:return 0
    nr=len(A);nc=len(A[0]);rr=0
    for c in range(nc):
        q=next((i for i in range(rr,nr) if A[i][c]),None)
        if q is None:continue
        A[rr],A[q]=A[q],A[rr]
        z=pow(A[rr][c],-1,p)
        A[rr]=[(z*x)%p for x in A[rr]]
        for i in range(nr):
            if i!=rr and A[i][c]:
                f=A[i][c]
                A[i]=[(x-f*y)%p for x,y in zip(A[i],A[rr])]
        rr+=1
        if rr==nr: break
    return rr

def nonzero_minor(A,r):
    if r==0:return ((),(),1)
    nr=len(A); nc=len(A[0])
    for rs in combinations(range(nr),r):
      for cs in combinations(range(nc),r):
        d=det_bareiss([[A[i][j] for j in cs] for i in rs])
        if d:return rs,cs,d
    raise AssertionError('no nonzero minor')

def int_kernel_basis_from_minor(C):
    # Build a Cramer/adjugate-style integer basis. Returns vectors and pivot det.
    r=rank_q(C); B=len(C[0])
    if r==0:
        return [[1 if i==j else 0 for i in range(B)] for j in range(B)],1,(),()
    rs,pcs,delta=nonzero_minor(C,r)
    free=[j for j in range(B) if j not in pcs]
    D=[[C[i][j] for j in pcs] for i in rs]
    out=[]
    for f in free:
        cf=[C[i][f] for i in rs]
        v=[0]*B; v[f]=delta
        for jj,pcol in enumerate(pcs):
            Dj=[row[:] for row in D]
            for ii in range(r): Dj[ii][jj]=cf[ii]
            v[pcol]=-det_bareiss(Dj)
        out.append(v)
    return out,delta,rs,pcs

def matvec(A,x):
    return [sum(a*b for a,b in zip(r,x)) for r in A]

def matmul(A,B):
    # A rxc, B cxk
    return [[sum(A[i][t]*B[t][j] for t in range(len(B))) for j in range(len(B[0]))] for i in range(len(A))]

def transpose(A): return [list(x) for x in zip(*A)]

def reshape_col(v,rows,n):
    check(len(v)==rows*n,'reshape')
    return [v[i*n:(i+1)*n] for i in range(rows)]

def primes_upto(n):
    out=[]
    for x in range(2,n+1):
        ok=True
        d=2
        while d*d<=x:
            if x%d==0:ok=False;break
            d+=1
        if ok:out.append(x)
    return out

def ceil_half_log(r):
    if r<=1:return 0
    return ceil((r/2)*log2(r))

def hs_bound(N):
    R=int(log2(N))
    check(R>=1)
    K=(2*N*R+1)*comb(2*R,R)
    m=(N+1)*K
    # For paper's integer forms ell_{j,t}, max base <= 2^(R-1)*(2NR) <= N^2 R.
    amax=(2**(R-1))*(2*N*R)
    check(amax<=N*N*R)
    ellmax=(N+1)*(amax**N)
    hmax=ellmax**R
    H0=max(1,hmax.bit_length())
    B=2**N
    # Conservative determinant height for a BxB assignment presentation.
    Hdet0=B*H0+ceil_half_log(B)+2
    Hker=Hdet0
    HQ=H0+Hker+N+3  # E times an integer kernel vector: <= B products.
    q=m*(N+1)
    kmax=min(B,q)
    Hdet1=kmax*HQ+ceil_half_log(kmax)+2
    Hdet2=(N+1)*HQ+ceil_half_log(N+1)+2
    HDelta=Hdet0+Hdet1+Hdet2
    check(comb(2*R,R)>=2**R)
    check(2**R>=N/2)
    check(m>=N**3*R)
    return {
      'N':N,'R':R,'K':K,'m':m,'assignment_count':B,
      'integer_weight_bit_bound':H0,
      'constraint_minor_bit_bound':Hdet0,
      'source_minor_bit_bound':Hdet1,
      'stack_minor_bit_bound':Hdet2,
      'combined_certificate_bit_bound':HDelta,
      'log2_HDelta_over_2^m':log2(HDelta)-m,
    }

def toy_specialization():
    C=[[2,2,2,2]]
    # Each column of E is a flattened 2x3 effective matrix.
    M0=[0,0,0, 0,0,0]
    M1=[1,-1,0, 0,0,0]
    M2=[0,1,-1, 0,0,0]
    M3=[1,0,-1, 0,0,0]
    E=transpose([M0,M1,M2,M3])
    KB,d0,rs,pcs=int_kernel_basis_from_minor(C)
    check(d0==2)
    check(len(KB)==3)
    for v in KB: check(matvec(C,v)==[0])
    # Their free-coordinate 3x3 minor is d0*I.
    frees=[j for j in range(4) if j not in pcs]
    Fminor=[[KB[j][i] for i in frees] for j in range(3)]
    check(abs(det_bareiss(Fminor))==abs(d0)**3)
    Q=matmul(E,transpose(KB))  # 6 x 3
    k=rank_q(Q); check(k==2)
    _,src_cols,d1=nonzero_minor(Q,k)
    check(abs(d1)==4)
    selected=[[Q[i][j] for j in src_cols] for i in range(6)]
    # Stack the two selected 2x3 matrices: 4x3.
    mats=[reshape_col([selected[i][j] for i in range(6)],2,3) for j in range(k)]
    G=[row for M in mats for row in M]
    s=rank_q(G); check(s==2)
    _,_,d2=nonzero_minor(G,s)
    check(abs(d2)==4)
    z=[1,1,1]
    check(matvec(G,z)==[0]*len(G))
    Delta=abs(d0*d1*d2); check(Delta==32)
    census=[]
    for p in primes_upto(97):
        rc=rank_mod(C,p); rq=rank_mod(Q,p); rg=rank_mod(G,p)
        bad=(Delta%p==0)
        if not bad:
            check((rc,rq,rg)==(1,2,2),'good-prime ranks changed')
            check(all(x%p==0 for x in matvec(G,z)),'kernel vector lost')
            check(rg==2 and len(z)==3,'kernel dimension must be one')
        census.append({'p':p,'divides_certificate':bad,'ranks':[rc,rq,rg]})
    check([x['p'] for x in census if x['divides_certificate']]==[2])
    return {
      'C':C,'E_shape':[len(E),len(E[0])],
      'constraint_pivot_det':d0,'source_minor_det':d1,'stack_minor_det':d2,
      'combined_certificate_abs':Delta,
      'rational_common_right_kernel_generator':z,
      'prime_census':census,
    }

def main():
    toy=toy_specialization()
    bounds=[hs_bound(N) for N in [4,5,8,16,32,64]]
    check(next(x for x in bounds if x['N']==5)['m']==756)
    # Once N is moderate, even the deliberately coarse certificate-count bound is tiny.
    check(all(x['log2_HDelta_over_2^m'] < -400 for x in bounds))
    out={
      'run':250,'status':'PASS','python':sys.version.split()[0],
      'assertions':ASSERTS,
      'theorem_checked':{
        'specialization':'For a fixed integer presentation, ranks/source dimension/common-right-kernel dimension can change only at primes dividing a product of explicit nonzero minors.',
        'random_prime':'The number of bad primes in [2^m,2^(m+1)) is at most log2(|Delta|)/m; combined with the paper interval prime density this contributes O(log2|Delta|/2^m).',
        'height':'For the direct Boolean-assignment presentation, log2|Delta| <= 2^N*poly(N), while Hair-Sahai m = Omega(N^3 log N), so the bad-prime probability is negligible despite the presentation being exponential-size.',
        'boundary':'This does not prove a polynomial-height rational kernel basis, so it does not by itself make the Run248 quotient/LLL attack universal.'
      },
      'toy_specialization':toy,
      'hair_sahai_conservative_bounds':bounds,
      'scope':{
        'proved':'integer-presentation specialization lemma; explicit toy orientation preservation; conservative asymptotic bad-prime counting bound for the direct assignment presentation',
        'not_proved':'every eligible prime is good; small-height rational common-kernel lifts for arbitrary circuits; concrete-group QPT attack/security; ORIGINAL-witness extraction; practical WKEM'
      }
    }
    print(json.dumps(out,sort_keys=True,indent=2))

if __name__=='__main__': main()
