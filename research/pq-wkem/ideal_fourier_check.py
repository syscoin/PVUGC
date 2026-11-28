import itertools, json, math, random
from collections import Counter
from fractions import Fraction

P=101

def inv(a,p=P):
    return pow(a%p,-1,p)

def rref(A,p=P):
    A=[[(x%p) for x in row] for row in A]
    m=len(A); n=len(A[0]) if m else 0
    piv=[]; r=0
    for c in range(n):
        k=next((i for i in range(r,m) if A[i][c]%p),None)
        if k is None: continue
        A[r],A[k]=A[k],A[r]
        z=inv(A[r][c],p)
        A[r]=[(z*x)%p for x in A[r]]
        for i in range(m):
            if i!=r and A[i][c]%p:
                z=A[i][c]%p
                A[i]=[(A[i][j]-z*A[r][j])%p for j in range(n)]
        piv.append(c); r+=1
        if r==m: break
    return A,piv

def solve(A,b,p=P):
    # Solve A x = b over F_p, choosing free variables as zero.
    if len(A)!=len(b):
        raise ValueError("row mismatch")
    n=len(A[0]) if A else 0
    aug=[[(x%p) for x in row]+[bb%p] for row,bb in zip(A,b)]
    m=len(aug); r=0; piv=[]
    for c in range(n):
        k=next((i for i in range(r,m) if aug[i][c]%p),None)
        if k is None:
            continue
        aug[r],aug[k]=aug[k],aug[r]
        z=inv(aug[r][c],p)
        aug[r]=[(z*x)%p for x in aug[r]]
        for i in range(m):
            if i!=r and aug[i][c]%p:
                z=aug[i][c]%p
                aug[i]=[(aug[i][j]-z*aug[r][j])%p for j in range(n+1)]
        piv.append(c); r+=1
        if r==m:
            break
    for i in range(r,m):
        if all(aug[i][j]%p==0 for j in range(n)) and aug[i][n]%p:
            return None
    x=[0]*n
    for i,c in enumerate(piv):
        x[c]=aug[i][n]%p
    if any(sum(A[i][j]*x[j] for j in range(n))%p != b[i]%p for i in range(len(A))):
        raise AssertionError("internal linear-solver error")
    return x

def span_contains(columns,target,p=P):
    if not columns:
        return all(x%p==0 for x in target)
    n=len(target)
    A=[[columns[j][i]%p for j in range(len(columns))] for i in range(n)]
    return solve(A,target,p) is not None

def quotient_functional(columns,target,p=P):
    rows=[list(c) for c in columns]+[list(target)]
    b=[0]*len(columns)+[1]
    return solve(rows,b,p)

def masks(n,maxdeg):
    return [m for m in range(1<<n) if m.bit_count()<=maxdeg]

def poly_mul_mono(poly,mono,n,p=P):
    out=[0]*(1<<n)
    for mask,c in enumerate(poly):
        if c:
            out[mask|mono]=(out[mask|mono]+c)%p
    return out

def xor_constraint(n,i,j,p=P):
    out=[0]*(1<<n)
    out[0]=-1%p
    out[1<<i]=(out[1<<i]+1)%p
    out[1<<j]=(out[1<<j]+1)%p
    out[(1<<i)|(1<<j)]=(out[(1<<i)|(1<<j)]-2)%p
    return out

def dot(a,b,p=P):
    return sum(x*y for x,y in zip(a,b))%p

def true_ideal_coset_test():
    n=2
    g=xor_constraint(n,0,1)
    cols=[poly_mul_mono(g,m,n) for m in masks(n,1)]
    one=[0]*(1<<n); one[0]=1
    assert not span_contains(cols,one)
    lam=quotient_functional(cols,one)
    assert lam is not None
    assert dot(lam,one)==1
    assert all(dot(lam,c)==0 for c in cols)

    rng=random.Random(1801)
    recover=0
    for _ in range(500):
        K=rng.randrange(P)
        coeff=[rng.randrange(P) for _ in cols]
        ct=[(K*one[i]+sum(coeff[j]*cols[j][i] for j in range(len(cols))))%P
            for i in range(len(one))]
        if dot(lam,ct)==K:
            recover+=1
    assert recover==500
    return {
        "field":P,
        "feature_dimension":1<<n,
        "mask_generators":len(cols),
        "public_lambda":[int(x) for x in lam],
        "keys_recovered":recover,
        "trials":500,
    }


def true_unique_witness_pseudofunctional_test():
    n=3
    g=[0]*(1<<n)
    g[0]=1
    g[0b111]=-1%P
    cols=[poly_mul_mono(g,m,n) for m in masks(n,1)]
    one=[1]+[0]*((1<<n)-1)
    assert not span_contains(cols,one)
    lam=quotient_functional(cols,one)
    assert lam is not None
    witness_eval=[1]*(1<<n)
    assert lam != witness_eval
    assert dot(lam,one)==1
    assert all(dot(lam,c)==0 for c in cols)
    rng=random.Random(1802)
    recovered=0
    for _ in range(300):
        K=rng.randrange(P)
        coeff=[rng.randrange(P) for _ in cols]
        ct=[(K*one[i]+sum(coeff[j]*cols[j][i] for j in range(len(cols))))%P
            for i in range(len(one))]
        recovered += (dot(lam,ct)==K)
    assert recovered==300
    return {
        "constraint":"1-x*y*z=0",
        "unique_boolean_witness":[1,1,1],
        "public_lambda":[int(x) for x in lam],
        "equals_unique_witness_evaluation":False,
        "keys_recovered":recovered,
        "trials":300,
    }

def false_contradiction_test():
    n=1
    g1=[0,1]
    g2=[-1%P,1]
    cols=[g1,g2]
    one=[1,0]
    assert span_contains(cols,one)
    dists=[]
    for K in [0,1,17]:
        C=Counter()
        for a in range(P):
            for b in range(P):
                ct=((K+a*g1[0]+b*g2[0])%P,
                    (a*g1[1]+b*g2[1])%P)
                C[ct]+=1
        dists.append(C)
    assert dists[0]==dists[1]==dists[2]
    return {
        "field":P,
        "support_size":len(dists[0]),
        "each_ciphertext_multiplicity":next(iter(dists[0].values())),
        "keys_compared":[0,1,17],
        "identical":True,
    }

def odd_triangle_certificate_test():
    n=3
    gs=[xor_constraint(n,i,(i+1)%n) for i in range(n)]
    cols=[]
    for j,g in enumerate(gs):
        for m in masks(n,2):
            cols.append(poly_mul_mono(g,m,n))
    one=[0]*(1<<n); one[0]=1
    A=[[cols[j][i] for j in range(len(cols))] for i in range(1<<n)]
    sol=solve(A,one)
    assert sol is not None
    nz=sum(1 for x in sol if x%P)
    acc=[0]*(1<<n)
    for j,a in enumerate(sol):
        for i,x in enumerate(cols[j]):
            acc[i]=(acc[i]+a*x)%P
    assert acc==one
    return {
        "variables":n,
        "degree_bound_multiplier":2,
        "generators":len(cols),
        "certificate_nonzero_terms":nz,
        "one_in_mask_span":True,
    }

def walsh(f):
    n=(len(f)).bit_length()-1
    N=1<<n
    out=[]
    for a in range(N):
        s=Fraction(0,1)
        for y,val in enumerate(f):
            parity=(a & y).bit_count()&1
            s += val * (-1 if parity else 1)
        out.append(s/N)
    return out

def fourier_qpt_test():
    n=4; N=1<<n
    sem=0b0011
    non=0b1010
    aa=Fraction(1,4)
    bb=Fraction(3,20)
    Delta=[]
    rho0=[]; rho1=[]
    for y in range(N):
        cs=-1 if ((sem&y).bit_count()&1) else 1
        cn=-1 if ((non&y).bit_count()&1) else 1
        d=aa*cs+bb*cn
        Delta.append(d)
        rho0.append(1+d)
        rho1.append(1-d)
        assert rho0[-1]>=0 and rho1[-1]>=0
    f=[Fraction(1 if d>=0 else -1,1) for d in Delta]
    corr=sum(f[i]*Delta[i] for i in range(N))/N
    delta=corr/2
    fhat=walsh(f); dhat=walsh(Delta)
    B2=sum(x*x for x in dhat)
    assert B2==sum(x*x for x in Delta)/N
    eta2=sum(dhat[a]*dhat[a] for a in range(N) if a!=sem)
    eta=Fraction(3,20)
    assert eta2==eta*eta
    psem=fhat[sem]*fhat[sem]
    lower=(max(Fraction(0,1),2*delta-eta)**2)/B2
    assert psem>=lower

    fr=Delta[:]
    frhat=walsh(fr)
    clean_prob_sum=sum(x*x for x in frhat)
    parseval=sum(x*x for x in fr)/N
    assert clean_prob_sum==parseval

    return {
        "group":"F2^4",
        "semantic_label":sem,
        "nonsemantic_label":non,
        "semantic_Delta_coefficient":str(aa),
        "nonsemantic_Delta_coefficient":str(bb),
        "predictor_advantage_delta":str(delta),
        "B_squared":str(B2),
        "eta":str(eta),
        "semantic_sampling_mass":str(psem),
        "proved_lower_bound":str(lower),
        "randomized_clean_flag_total_probability":str(clean_prob_sum),
        "parseval_randomized_predictor":str(parseval),
    }

def multiplicity_test():
    gamma=Fraction(1,7)
    rows=[]
    for M in [1,2,4,8,16,32,64]:
        B2=M*gamma*gamma
        assert B2==Fraction(M,49)
        rows.append({"M":M,"gamma":"1/7","B_squared":str(B2)})
    return rows

out={
    "status":"PASS",
    "true_ideal_coset_public_quotient":true_ideal_coset_test(),
    "true_unique_witness_pseudofunctional":true_unique_witness_pseudofunctional_test(),
    "false_contradiction_perfect_hiding":false_contradiction_test(),
    "false_odd_triangle_certificate":odd_triangle_certificate_test(),
    "qpt_fourier_algebra":fourier_qpt_test(),
    "witness_multiplicity":multiplicity_test(),
}
print(json.dumps(out,indent=2,sort_keys=True))
