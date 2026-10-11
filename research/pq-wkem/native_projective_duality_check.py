from fractions import Fraction
from itertools import product
from math import comb
import random, json

def dot(a,b):
    return sum((x&1)*(y&1) for x,y in zip(a,b)) & 1

def mv(A,z):
    return [dot(row,z) for row in A]

def tv(A):
    return [list(col) for col in zip(*A)]

def rank2(A):
    A=[row[:] for row in A]
    if not A: return 0
    m,n=len(A),len(A[0]); r=0
    for c in range(n):
        p=next((i for i in range(r,m) if A[i][c]),None)
        if p is None: continue
        A[r],A[p]=A[p],A[r]
        for i in range(m):
            if i!=r and A[i][c]:
                A[i]=[(A[i][j]^A[r][j]) for j in range(n)]
        r+=1
        if r==m: break
    return r

def solve2(A,b):
    M=[row[:] + [bb] for row,bb in zip(A,b)]
    m=len(M); n=len(A[0]); r=0; piv=[]
    for c in range(n):
        p=next((i for i in range(r,m) if M[i][c]),None)
        if p is None: continue
        M[r],M[p]=M[p],M[r]
        for i in range(m):
            if i!=r and M[i][c]:
                M[i]=[M[i][j]^M[r][j] for j in range(n+1)]
        piv.append(c); r+=1
    for i in range(r,m):
        if not any(M[i][:n]) and M[i][n]:
            return None
    x=[0]*n
    for i,c in enumerate(piv):
        x[c]=M[i][n]
    return x

def random_full_row(rng,m,n):
    while True:
        A=[[rng.randrange(2) for _ in range(n)] for _ in range(m)]
        if rank2(A)==m: return A

def parity_sign(bit):
    return 1 if bit==0 else -1

def bsc_prob(e,p):
    w=sum(e); n=len(e)
    return (p**w)*((1-p)**(n-w))

def conditional_distribution(A,b,r,p):
    m=len(A); n=len(A[0]); AT=tv(A)
    ss=[list(s) for s in product([0,1], repeat=m) if dot(b,s)==r]
    out={}
    for s in ss:
        base=mv(AT,s)
        for e in product([0,1], repeat=n):
            y=tuple(base[j]^e[j] for j in range(n))
            out[y]=out.get(y,Fraction(0,1))+Fraction(1,len(ss))*bsc_prob(e,p)
    return out

def fourier_of_dist(P,z):
    return sum(prob*parity_sign(dot(z,list(y))) for y,prob in P.items())

def conv_poly(a,b):
    out=[0]*(len(a)+len(b)-1)
    for i,x in enumerate(a):
        for j,y in enumerate(b):
            out[i+j]+=x*y
    return out

def pow_poly(base,k):
    out=[1]
    for _ in range(k):
        out=conv_poly(out,base)
    return out

def macwilliams_rhs(A,b):
    m=len(A); n=len(A[0]); AT=tv(A)
    acc=[0]*(n+1)
    for s in product([0,1], repeat=m):
        x=mv(AT,list(s)); w=sum(x)
        poly=conv_poly(pow_poly([1,1],n-w), pow_poly([1,-1],w))
        sign=parity_sign(dot(b,list(s)))
        for i,c in enumerate(poly): acc[i]+=sign*c
    den=2**m
    assert all(c%den==0 for c in acc)
    return [c//den for c in acc]

def projective_weight_enum(A,b):
    n=len(A[0]); counts=[0]*(n+1)
    for z in product([0,1], repeat=n):
        if mv(A,list(z))==b:
            counts[sum(z)]+=1
    return counts

def canonical_local(a,r):
    out=[]
    for j in range(r):
        bit=(a>>j)&1
        out.extend([1-bit,bit])
    out.extend([1 if idx==a else 0 for idx in range(1<<r)])
    return out

def failed_single_reject(rej,r):
    out=[]
    for j in range(r):
        bit=(rej>>j)&1
        out.extend([1-bit,bit])
    out.extend([0 if idx==rej else 1 for idx in range(1<<r)])
    return out

def xor_vecs(vs):
    if not vs: return []
    out=[0]*len(vs[0])
    for v in vs:
        out=[a^b for a,b in zip(out,v)]
    return out

def local_equations_hold(v,rej,r):
    wires=[]
    off=0
    for j in range(r):
        x0,x1=v[off],v[off+1]; off+=2
        if (x0^x1)!=1: return False
        wires.append(x1)
    q=v[off:]
    if sum(q)%2 != 1: return False
    for j in range(r):
        marg=sum(q[a] for a in range(1<<r) if ((a>>j)&1))%2
        if marg!=wires[j]: return False
    accept=sum(q[a] for a in range(1<<r) if a!=rej)%2
    return accept==1

def nullspace_rows(M):
    A=[row[:] for row in M]
    m=len(A); n=len(A[0]) if A else 0; r=0; piv=[]
    for c in range(n):
        p=next((i for i in range(r,m) if A[i][c]),None)
        if p is None: continue
        A[r],A[p]=A[p],A[r]
        for i in range(m):
            if i!=r and A[i][c]:
                A[i]=[A[i][j]^A[r][j] for j in range(n)]
        piv.append(c); r+=1
        if r==m: break
    free=[j for j in range(n) if j not in piv]
    basis=[]
    for f in free:
        x=[0]*n; x[f]=1
        for i,c in enumerate(piv):
            x[c]=A[i][f]
        basis.append(x)
    return basis

def replicate_columns(A,L):
    return [[bit for bit in row for _ in range(L)] for row in A]

def majority(bits):
    ones=sum(bits); n=len(bits)
    if 2*ones<n: return 0
    if 2*ones>n: return 1
    return None

def replication_sim():
    rng=random.Random(2026092111)
    A=[[1,0,1,0,1],
       [0,1,1,0,1],
       [0,0,1,1,1]]
    assert rank2(A)==3
    b=[1,1,0]
    z=solve2(A,b); assert z is not None
    L=9; p=0.08
    AR=replicate_columns(A,L); ATR=tv(AR)
    trials=5000; rec=0; honest=0
    for _ in range(trials):
        s=[rng.randrange(2) for _ in range(3)]
        K=rng.randrange(2)
        e=[1 if rng.random()<p else 0 for _ in range(5*L)]
        e0=1 if rng.random()<p else 0
        base=mv(ATR,s)
        c=[x^y for x,y in zip(base,e)]
        d=dot(b,s)^e0^K
        decoded=[]
        fail=False
        for j in range(5):
            bit=majority(c[j*L:(j+1)*L])
            if bit is None: fail=True; break
            decoded.append(bit)
        if not fail:
            shat=solve2(tv(A),decoded)
            if shat is not None:
                Khat=d^dot(b,shat)
                rec += (Khat==K)
        idx=[]
        for j,val in enumerate(z):
            if val: idx.append(j*L)
        Kwh=d
        for jj in idx: Kwh ^= c[jj]
        honest += (Kwh==K)
    return {"trials":trials,"L":L,"p":p,"public_key_recoveries":rec,
            "honest_witness_recoveries":honest,"projective_weight":sum(z)}

def main():
    rng=random.Random(111)
    duality_cases=0
    mac_cases=0
    for _ in range(20):
        m,n=3,5
        A=random_full_row(rng,m,n)
        b=[rng.randrange(2) for _ in range(m)]
        if not any(b): b[0]=1
        p=Fraction(1,4); rho=Fraction(1,2)
        P0=conditional_distribution(A,b,0,p)
        P1=conditional_distribution(A,b,1,p)
        for z in product([0,1], repeat=n):
            z=list(z)
            f0=fourier_of_dist(P0,z)
            f1=fourier_of_dist(P1,z)
            az=mv(A,z)
            target0 = (rho**sum(z)) if az==[0]*m else Fraction(0,1)
            targetb = (rho**sum(z)) if az==b else Fraction(0,1)
            assert f0 == target0 + targetb
            assert f1 == target0 - targetb
        duality_cases+=1
        assert macwilliams_rhs(A,b)==projective_weight_enum(A,b)
        mac_cases+=1

    local_cases=0; annihilator_checks=0
    for r in (2,3,4):
        for rej in range(1<<r):
            acc=[canonical_local(a,r) for a in range(1<<r) if a!=rej]
            fail=failed_single_reject(rej,r)
            assert xor_vecs(acc)==fail
            assert local_equations_hold(fail,rej,r)
            N=nullspace_rows(acc)
            for e in N:
                assert all(dot(e,v)==0 for v in acc)
                assert dot(e,fail)==0
                annihilator_checks+=1
            local_cases+=1

    rep=replication_sim()
    out={"native_projective_duality_cases":duality_cases,
         "macwilliams_exact_cases":mac_cases,
         "single_reject_span_cases":local_cases,
         "annihilator_basis_checks":annihilator_checks,
         "replication_simulation":rep}
    print(json.dumps(out,sort_keys=True))

if __name__=="__main__":
    main()
