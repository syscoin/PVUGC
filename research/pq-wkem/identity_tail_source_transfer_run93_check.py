#!/usr/bin/env python3
"""Run 93 deterministic algebra checker: identity-tail trapdoor conditioning.

This validates only finite-field identities, norm transfer, correctness bounds,
and the related-trapdoor transversality control. It is NOT a security proof.
Standard library only.
"""
import json, random, math, hashlib

SEED=202609250219
rng=random.Random(SEED)

def inv(a,q): return pow(a%q,-1,q)
def matmul(A,B,q):
    return [[sum(A[i][k]*B[k][j] for k in range(len(B)))%q for j in range(len(B[0]))] for i in range(len(A))]
def matvec(A,x,q): return [sum(a*b for a,b in zip(row,x))%q for row in A]
def transpose(A): return [list(x) for x in zip(*A)]
def dot(a,b,q=None):
    z=sum(x*y for x,y in zip(a,b))
    return z if q is None else z%q
def ctr(x,q):
    x%=q
    return x-q if x>q//2 else x
def cvec(x,q): return [ctr(v,q) for v in x]
def rank_mod(A,q):
    A=[row[:] for row in A]; r=0
    if not A:return 0
    for c in range(len(A[0])):
        p=next((i for i in range(r,len(A)) if A[i][c]%q),None)
        if p is None: continue
        A[r],A[p]=A[p],A[r]
        s=inv(A[r][c],q); A[r]=[(s*v)%q for v in A[r]]
        for i in range(len(A)):
            if i!=r and A[i][c]%q:
                t=A[i][c]%q
                A[i]=[(x-t*y)%q for x,y in zip(A[i],A[r])]
        r+=1
        if r==len(A):break
    return r
def solve_square(M,b,q):
    n=len(M); A=[M[i][:]+[b[i]%q] for i in range(n)]
    r=0
    for c in range(n):
        p=next(i for i in range(r,n) if A[i][c]%q)
        A[r],A[p]=A[p],A[r]
        s=inv(A[r][c],q); A[r]=[(s*v)%q for v in A[r]]
        for i in range(n):
            if i!=r:
                t=A[i][c]%q
                if t:A[i]=[(x-t*y)%q for x,y in zip(A[i],A[r])]
        r+=1
    return [A[i][-1]%q for i in range(n)]
def rand_full_A(n,m,q):
    while True:
        A=[[rng.randrange(q) for _ in range(m)] for _ in range(n)]
        M=[row[:n] for row in A]
        if rank_mod(M,q)==n:return A,M
def solve_A(A,M,D,q):
    # Set trailing unknowns zero, solve first n coordinates for each target column.
    n=len(A); m=len(A[0]); ell=len(D[0]); K=[[0]*ell for _ in range(m)]
    for j in range(ell):
        x=solve_square(M,[D[i][j] for i in range(n)],q)
        for i in range(n):K[i][j]=x[i]
    assert matmul(A,K,q)==D
    return K
def stack(A,B): return A+B
def hcat(A,B): return [a+b for a,b in zip(A,B)]
def eye(n): return [[int(i==j) for j in range(n)] for i in range(n)]
def frob(A,q=None):
    if q is None:return math.sqrt(sum(v*v for row in A for v in row))
    return math.sqrt(sum(ctr(v,q)**2 for row in A for v in row))
def norm2(v): return math.sqrt(sum(x*x for x in v))
def make_target_with_relation(n,ell,q,a,h):
    # Choose all columns except h randomly; force h so T a = 0 and a[h]=1.
    assert a[h]%q==1
    T=[[0]*ell for _ in range(n)]
    for i in range(n):
        acc=0
        for j in range(ell):
            if j==h:continue
            T[i][j]=rng.randrange(q)
            acc=(acc+T[i][j]*a[j])%q
        T[i][h]=(-acc)%q
    assert matvec(T,a,q)==[0]*n
    return T

out={"run":93,"seed":SEED,"scope":"algebraic/source-transfer checks only; no cryptographic hiding claim"}
q=65537;n=3;m=6;ell=4;h=1
identity_checks=prefix_checks=capsule_checks=norm_checks=0
max_noise=0
for rep in range(80):
    # Small normalized relation.
    a=[rng.choice([-2,-1,0,1,2])%q for _ in range(ell)]
    a[h]=1
    T=make_target_with_relation(n,ell,q,a,h)
    A0,M=rand_full_A(n,m,q)
    B=[[rng.randrange(q) for _ in range(ell)] for _ in range(n)]
    D=[[(T[i][j]-B[i][j])%q for j in range(ell)] for i in range(n)]
    K0=solve_A(A0,M,D,q)
    A=hcat(A0,B)
    K=stack(K0,eye(ell))
    assert matmul(A,K,q)==T
    z=matvec(K,a,q)
    assert matvec(A,z,q)==[0]*n
    assert z[m:]==[x%q for x in a]
    identity_checks+=4

    # Exact centered lower norm and safe Frobenius upper bound.
    ac=cvec(a,q); zc=cvec(z,q)
    assert norm2(zc)+1e-12 >= norm2(ac)
    rawtop=[sum(ctr(K0[i][j],q)*ac[j] for j in range(ell)) for i in range(m)]
    assert all(abs(ctr(z[i],q)) <= abs(rawtop[i]) for i in range(m))
    kappa=math.sqrt(frob(K0,q)**2+1)
    assert norm2(zc) <= kappa*norm2(ac)+1e-9
    norm_checks+=3

    # Prefix preservation.
    for _ in range(3):
        S=[[rng.randrange(q) for _ in range(n)] for __ in range(2)]
        SA=matmul(S,A,q)
        assert matvec(SA,z,q)==[0,0]
        prefix_checks+=1

    # One-bit release correctness identity.
    Delta=q//2
    for bit in (0,1):
        s=[rng.randrange(q) for _ in range(n)]
        e=[rng.choice([-1,0,1]) for _ in range(m+ell)]
        At=transpose(A)
        base=matvec(At,s,q)
        u=[0]*(m+ell);u[m+h]=1
        c=[(base[i]+e[i]+bit*Delta*u[i])%q for i in range(m+ell)]
        lhs=ctr(dot(z,c,q),q)
        noise=dot(cvec(z,q),e)
        # congruence, and no claim about centered equality if wrap occurs
        assert dot(z,c,q)==(noise+bit*Delta)%q
        assert z[m+h]==1
        max_noise=max(max_noise,abs(noise))
        capsule_checks+=2

# Exact public projection identity K^T c = T^T s + K^T e + bit Delta e_h.
projection_checks=0
for _ in range(120):
    a=[1,1,0]
    T=make_target_with_relation(2,3,257,a,0)
    A0,M=rand_full_A(2,4,257); B=[[rng.randrange(257) for _ in range(3)] for _ in range(2)]
    D=[[(T[i][j]-B[i][j])%257 for j in range(3)] for i in range(2)]
    K0=solve_A(A0,M,D,257); A=hcat(A0,B);K=stack(K0,eye(3))
    s=[rng.randrange(257) for _ in range(2)]
    e=[rng.choice([-1,0,1]) for _ in range(7)]
    bit=rng.randrange(2);Delta=64
    u=[0]*7;u[4]=1
    c=[(v+ee+bit*Delta*uu)%257 for v,ee,uu in zip(matvec(transpose(A),s,257),e,u)]
    left=matvec(transpose(K),c,257)
    right=[(x+y+bit*Delta*(j==0))%257 for j,(x,y) in enumerate(zip(matvec(transpose(T),s,257),matvec(transpose(K),e,257)))]
    assert left==right
    projection_checks+=1

# Information-theoretic correlation control: real K always satisfies AK=T;
# uniform independent K does so with probability q^(-n*ell) for full-row-rank A.
q2=5; A2=[[1,2]]; T2=[[3,4]]; satisfying=0; total=0
for a in range(q2):
  for b in range(q2):
    for c in range(q2):
      for d in range(q2):
        K2=[[a,b],[c,d]]; total+=1
        if matmul(A2,K2,q2)==T2:satisfying+=1
assert satisfying*q2**(1*2)==total
out["independent_K_exact_control"]={"q":q2,"n":1,"ell":2,"total":total,"satisfying":satisfying,"probability":f"{satisfying}/{total}","expected":"q^(-n*ell)=1/25"}

# Related-trapdoor transversality control: same-direction M=u^T is rank deficient;
# independent direction is admissible.
q3=7;L=4;u=[1,1,0,0]
M_same=[u[:]]
M_trans=[[0,0,1,0]]
assert rank_mod(M_same+[u],q3)==1
assert rank_mod(M_trans+[u],q3)==2
out["rtlwe_transversality_control"]={
    "q":q3,"L":L,
    "rank_same_direction_stack":rank_mod(M_same+[u],q3),
    "rank_transverse_stack":rank_mod(M_trans+[u],q3),
    "interpretation":"same-direction preimage query fails the full-rank gate in WWW22 Assumption 4.1"
}

out.update({
 "identity_checks":identity_checks,
 "prefix_checks":prefix_checks,
 "capsule_checks":capsule_checks,
 "norm_checks":norm_checks,
 "projection_checks":projection_checks,
 "max_abs_sampled_noise_inner_product":max_noise,
 "status":"PASS"
})
print(json.dumps(out,sort_keys=True,indent=2))
