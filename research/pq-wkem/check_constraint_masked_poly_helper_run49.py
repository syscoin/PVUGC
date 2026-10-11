#!/usr/bin/env python3
import json, random, itertools, hashlib, math
from collections import defaultdict

Q = 257
PHASE = 64
SEED = 490049

# Monomial basis degree <=2 in x,y:
# (1, x, y, x^2, x y, y^2)
N = 6
MON2 = [(0,0),(1,0),(0,1),(2,0),(1,1),(0,2)]

def mod(x): return x % Q
def center(x):
    x %= Q
    return x if x <= Q//2 else x-Q

def dot(a,b,q=Q):
    return sum(x*y for x,y in zip(a,b)) % q

def mat_vec(A,x,q=Q):
    return [sum(a*b for a,b in zip(row,x)) % q for row in A]

def mat_mul(A,B,q=Q):
    if not A or not B:
        return []
    nr,nk,nc=len(A),len(B),len(B[0])
    return [[sum(A[i][k]*B[k][j] for k in range(nk)) % q
             for j in range(nc)] for i in range(nr)]

def mat_t_vec(A,s,q=Q):
    return [sum(A[i][j]*s[i] for i in range(len(A))) % q
            for j in range(len(A[0]))]

def rank_mod(M,q=Q):
    if not M: return 0
    A=[[x%q for x in row] for row in M]
    nr,nc=len(A),len(A[0]); r=0
    for c in range(nc):
        piv=next((i for i in range(r,nr) if A[i][c] % q),None)
        if piv is None: continue
        A[r],A[piv]=A[piv],A[r]
        inv=pow(A[r][c],-1,q)
        A[r]=[(v*inv)%q for v in A[r]]
        for i in range(nr):
            if i != r and A[i][c] % q:
                f=A[i][c] % q
                A[i]=[(A[i][j]-f*A[r][j])%q for j in range(nc)]
        r += 1
        if r==nr: break
    return r

def mat_inv(M,q=Q):
    n=len(M)
    A=[[M[i][j]%q for j in range(n)] +
       [1 if i==j else 0 for j in range(n)] for i in range(n)]
    for c in range(n):
        piv=next(i for i in range(c,n) if A[i][c] % q)
        A[c],A[piv]=A[piv],A[c]
        inv=pow(A[c][c],-1,q)
        A[c]=[(v*inv)%q for v in A[c]]
        for i in range(n):
            if i!=c and A[i][c] % q:
                f=A[i][c] % q
                A[i]=[(A[i][j]-f*A[c][j])%q for j in range(2*n)]
    return [row[n:] for row in A]

def signed_permutation(rng,n):
    perm=list(range(n)); rng.shuffle(perm)
    signs=[rng.choice([-1,1]) for _ in range(n)]
    D=[[0]*n for _ in range(n)]
    for i,j in enumerate(perm):
        D[i][j]=signs[i] % Q
    return D,perm,signs

def poly_eval(coeffs,x,y,q=Q):
    vals=[1,x,y,x*x,x*y,y*y]
    return sum(c*v for c,v in zip(coeffs,vals)) % q

def feature(x,y,q=Q):
    return [1%q,x%q,y%q,(x*x)%q,(x*y)%q,(y*y)%q]

def addv(a,b,q=Q):
    return [(x+y)%q for x,y in zip(a,b)]
def scalev(c,a,q=Q):
    return [(c*x)%q for x in a]

# false degree-2 constraint masks
V_FALSE = [
    [0,-1,0,1,0,0],       # x^2-x
    [0,0,-1,0,0,1],       # y^2-y
    [2,1,1,0,0,0],        # x+y+2
    [0,2,0,1,1,0],        # x(x+y+2)
    [0,0,2,0,1,1],        # y(x+y+2)
]
XSTAR = [1,-1,-1,-1,3,-1]  # annihilator / pseudo moments

V_TRUE = [
    [0,-1,0,1,0,0],       # x^2-x
    [0,0,-1,0,0,1],       # y^2-y
    [-1,1,1,0,0,0],       # x+y-1
    [0,-1,0,1,1,0],       # x(x+y-1)
    [0,0,-1,0,1,1],       # y(x+y-1)
]
W10 = [1,1,0,1,0,0]
W01 = [1,0,1,0,0,1]

def helper_from_D(rng,D,V):
    P=[]
    mask_coeffs=[]
    for row in D:
        coeff=row[:]
        cs=[rng.randrange(Q) for _ in V]
        for c,v in zip(cs,V):
            coeff=addv(coeff,scalev(c,v))
        P.append(coeff)
        mask_coeffs.append(cs)
    return P,mask_coeffs

def native_relation(sign):
    # sign=False: x+y+2=0; sign=True: x+y-1=0
    if sign:
        g=[-1,1,1,0,0,0]
    else:
        g=[2,1,1,0,0,0]
    A=[
        [1,0,0,0,0,0],
        [0,-1,0,1,0,0],
        [0,0,-1,0,0,1],
        g,
    ]
    u=[1,0,0,0]
    return [[v%Q for v in row] for row in A],u

def circular_distance(a,b,q=Q):
    d=(a-b)%q
    return min(d,q-d)

def decode_bit(r):
    return 0 if circular_distance(r,0) < circular_distance(r,PHASE) else 1

def capsule(A,u,y,K,s,e,e0):
    a=[(v+err)%Q for v,err in zip(mat_t_vec(A,s),e)]
    b=(dot(u,s)+e0+PHASE*K)%Q
    res=(b-dot([v%Q for v in y],a))%Q
    return a,b,res,decode_bit(res)

# ---------- Run-45 Laurent dual machinery ----------

def monomials(num_vars,max_deg):
    # exponent tuples total degree <= max_deg
    out=[]
    def rec(pos,left,prefix):
        if pos==num_vars-1:
            out.append(tuple(prefix+[left]))
            return
        for e in range(left+1):
            rec(pos+1,left-e,prefix+[e])
    for total in range(max_deg+1):
        rec(0,total,[])
    return out

def poly_add_dict(p,q,modulus=None):
    r=defaultdict(int); r.update(p)
    for m,c in q.items(): r[m]+=c
    if modulus:
        r={m:c%modulus for m,c in r.items() if c%modulus}
    else:
        r={m:c for m,c in r.items() if c}
    return dict(r)

def poly_scale_shift(poly,coeff,shift):
    out={}
    for exps,c in poly.items():
        out[tuple(e+s for e,s in zip(exps,shift))]=c*coeff
    return out

def chain_generators(n):
    # vars x0..xn,y1..yn => total 2n+1
    nv=2*n+1
    gens=[]
    def unit(idx):
        e=[0]*nv; e[idx]=1; return tuple(e)
    zero=(0,)*nv
    # g0=x0
    gens.append({unit(0):1})
    # gi=xi - yi*x_{i-1}
    # y_i index (n+1)+(i-1)
    for i in range(1,n+1):
        a={unit(i):1}
        e=[0]*nv; e[i-1]=1; e[(n+1)+(i-1)]=1
        a[tuple(e)]=-1
        gens.append(a)
    # g_{n+1}=x_n -1
    gens.append({unit(n):1, zero:-1})
    return gens

def total_deg_monom(exps): return sum(exps)
def poly_degree(poly):
    return max((sum(m) for m in poly), default=-1)

def laurent_image_exponent(exps,n):
    # output exponents on y1..yn under psi
    # y_i -> +e_i
    # x_i -> product_{k=i+1}^n y_k^{-1}
    out=[0]*n
    # x_i exponents
    for i in range(n+1):
        a=exps[i]
        if not a: continue
        for k in range(i+1,n+1): # y_k
            out[k-1] -= a
    # y_i exponents
    for i in range(1,n+1):
        out[i-1] += exps[(n+1)+(i-1)]
    return tuple(out)

def lambda_chain(poly,n):
    # constant term after psi
    total=0
    for exps,c in poly.items():
        if all(v==0 for v in laurent_image_exponent(exps,n)):
            total += c
    return total

def multiply_monom_poly(mult,poly):
    return {tuple(a+b for a,b in zip(mult,m)):c for m,c in poly.items()}

def main():
    rng=random.Random(SEED)
    report={"seed":SEED,"q":Q,"phase":PHASE}

    # 1. Degree-2 quotient structure.
    assert all(dot([v%Q for v in XSTAR],[c%Q for c in row])==0 for row in V_FALSE)
    r=rank_mod([[c%Q for c in row] for row in V_FALSE])
    assert r==5
    report["degree2_mask_rank"]=r
    report["degree2_quotient_dimension"]=N-r
    report["xstar_centered"]=XSTAR
    report["xstar_mask_pairings"]=[
        center(dot([v%Q for v in XSTAR],[c%Q for c in row])) for row in V_FALSE
    ]

    # 2. Nonlinear helper pseudo-transfer.
    pseudo_transfer=0
    distinct_helpers=set()
    for _ in range(2000):
        D,_,_=signed_permutation(rng,N)
        P,_=helper_from_D(rng,D,V_FALSE)
        y_public=[dot(row,[v%Q for v in XSTAR]) for row in P]
        y_secret=mat_vec(D,[v%Q for v in XSTAR])
        assert y_public==y_secret
        pseudo_transfer+=1
        distinct_helpers.add(tuple(tuple(row) for row in P))
    report["nonlinear_false_helper_pseudo_transfer_checks"]=pseudo_transfer
    report["distinct_false_helpers_seen"]=len(distinct_helpers)
    report["uniform_mask_affine_coset_size_per_row"]=Q**5

    # 3. Honest true-helper evaluation.
    honest_eval=0
    for _ in range(500):
        D,_,_=signed_permutation(rng,N)
        P,_=helper_from_D(rng,D,V_TRUE)
        for x,y,wvec in [(1,0,W10),(0,1,W01)]:
            public=[poly_eval(row,x,y) for row in P]
            secret=mat_vec(D,[v%Q for v in wvec])
            assert public==secret
            honest_eval+=1
    report["true_helper_witness_evaluations"]=honest_eval

    # 4. Full false and true noisy capsules.
    false_caps=0; true_caps=0; max_false_noise=0; max_true_noise=0
    Afalse,ufalse=native_relation(False)
    Atrue,utrue=native_relation(True)
    for trial in range(2000):
        # false helper/capsule
        D,perm,signs=signed_permutation(rng,N)
        Dinv=mat_inv(D)
        AD=mat_mul(Afalse,Dinv)
        P,_=helper_from_D(rng,D,V_FALSE)
        ystar=[dot(row,[v%Q for v in XSTAR]) for row in P]
        assert mat_vec(AD,ystar)==ufalse
        K=rng.randrange(2)
        s=[rng.randrange(Q) for _ in range(len(ufalse))]
        e=[rng.choice([-1,0,1]) for _ in range(N)]
        e0=rng.choice([-1,0,1])
        _,_,res,dec=capsule(AD,ufalse,[center(v) for v in ystar],K,s,e,e0)
        assert dec==K
        noise=center((res-PHASE*K)%Q)
        max_false_noise=max(max_false_noise,abs(noise))
        false_caps+=1

        # true helper/capsule, alternating witnesses
        D2,perm2,signs2=signed_permutation(rng,N)
        D2inv=mat_inv(D2)
        AD2=mat_mul(Atrue,D2inv)
        P2,_=helper_from_D(rng,D2,V_TRUE)
        if trial % 2:
            x,y,wvec=1,0,W10
        else:
            x,y,wvec=0,1,W01
        yw=[poly_eval(row,x,y) for row in P2]
        assert mat_vec(AD2,yw)==utrue
        K2=rng.randrange(2)
        s2=[rng.randrange(Q) for _ in range(len(utrue))]
        e2=[rng.choice([-1,0,1]) for _ in range(N)]
        e02=rng.choice([-1,0,1])
        _,_,res2,dec2=capsule(AD2,utrue,[center(v) for v in yw],K2,s2,e2,e02)
        assert dec2==K2
        n2=center((res2-PHASE*K2)%Q)
        max_true_noise=max(max_true_noise,abs(n2))
        true_caps+=1
    report["false_full_capsule_recoveries"]=false_caps
    report["true_full_capsule_recoveries"]=true_caps
    report["max_abs_false_noise_observed"]=max_false_noise
    report["max_abs_true_noise_observed"]=max_true_noise
    report["deterministic_false_noise_bound"]=1+sum(abs(v) for v in XSTAR)

    # 5. Exhaustive bounded errors for one false transformed fixture.
    D,_,_=signed_permutation(rng,N)
    Dinv=mat_inv(D)
    AD=mat_mul(Afalse,Dinv)
    P,_=helper_from_D(rng,D,V_FALSE)
    ystar=[dot(row,[v%Q for v in XSTAR]) for row in P]
    assert mat_vec(AD,ystar)==ufalse
    s=[3,5,7,11]
    ex_ok=0; ex_total=0; ex_max=0
    ycent=[center(v) for v in ystar]
    assert sum(abs(v) for v in ycent)==sum(abs(v) for v in XSTAR)==8
    for K in [0,1]:
        for vals in itertools.product([-1,0,1], repeat=N+1):
            e=list(vals[:N]); e0=vals[N]
            _,_,res,dec=capsule(AD,ufalse,ycent,K,s,e,e0)
            ex_total+=1
            ex_ok += int(dec==K)
            ex_max=max(ex_max,abs(center((res-PHASE*K)%Q)))
    assert ex_ok==ex_total
    assert ex_max<=9
    report["exhaustive_false_bounded_error"]={"success":ex_ok,"total":ex_total,"max_abs_noise":ex_max}

    # 6. Run-45 Laurent dual: exhaustive allowed generator multiples for n<=5.
    laurent_counts={}
    total_mults=0
    for n in range(1,6):
        T=n
        gens=chain_generators(n)
        nv=2*n+1
        checked=0
        for g in gens:
            dg=poly_degree(g)
            maxm=T-dg
            if maxm < 0:
                continue
            for mult in monomials(nv,maxm):
                prod=multiply_monom_poly(mult,g)
                val=lambda_chain(prod,n)
                assert val==0
                checked+=1
        assert lambda_chain({(0,)*nv:1},n)==1
        laurent_counts[str(n)]=checked
        total_mults += checked
    report["run45_laurent_allowed_multiple_checks"]=laurent_counts
    report["run45_laurent_total_checks"]=total_mults

    # 7. Random sparse ideal-masked helper controls for chain duals.
    sparse_controls=0
    for n in range(2,6):
        T=n
        nv=2*n+1
        basis_mons=monomials(nv,T)
        # random base polynomial f
        for _trial in range(100):
            f={}
            for m in rng.sample(basis_mons,min(8,len(basis_mons))):
                c=rng.randint(-5,5)
                if c: f[m]=c
            P=dict(f)
            gens=chain_generators(n)
            for g in gens:
                dg=poly_degree(g)
                maxm=T-dg
                if maxm<0: continue
                mons=monomials(nv,maxm)
                for __ in range(3):
                    mult=rng.choice(mons)
                    c=rng.randint(-5,5)
                    if not c: continue
                    term=multiply_monom_poly(mult,g)
                    P=poly_add_dict(P,{m:c*v for m,v in term.items()})
            assert lambda_chain(P,n)==lambda_chain(f,n)
            sparse_controls+=1
    report["run45_sparse_masked_helper_controls"]=sparse_controls

    print(json.dumps(report,sort_keys=True,indent=2))

if __name__=="__main__":
    main()
