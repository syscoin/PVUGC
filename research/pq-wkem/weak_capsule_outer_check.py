import itertools, math, random, json
from math import comb

def bsc_prob(y,x,p):
    return (1-p) if y==x else p

def exact_guess_and_hash_check():
    L=4
    p=0.35
    g=1-p
    def helper(x): return x[0]^x[1]
    X=list(itertools.product((0,1), repeat=L))
    Y=X[:]
    joint={}
    for x in X:
        px=2**(-L)
        for y in Y:
            py=1.0
            for xi,yi in zip(x,y):
                py*=bsc_prob(yi,xi,p)
            s=helper(x)
            joint[(x,y,s)]=px*py
    pg0=0.0
    for y in Y:
        pg0 += max(joint[(x,y,helper(x))] for x in X)
    pg1=0.0
    for y in Y:
        for s in (0,1):
            vals=[joint[(x,y,s)] for x in X if helper(x)==s]
            if vals: pg1 += max(vals)
    assert abs(pg0-g**L)<1e-12
    assert pg1 <= 2*pg0 + 1e-12
    As=X[:]
    tvsum=0.0
    for a in As:
        P={}
        E={}
        for x in X:
            k=sum(ai*xi for ai,xi in zip(a,x))&1
            s=helper(x)
            for y in Y:
                mass=joint[(x,y,s)]
                P[(k,y,s)]=P.get((k,y,s),0.0)+mass
                E[(y,s)]=E.get((y,s),0.0)+mass
        tv=0.0
        for y in Y:
            for s in (0,1):
                for k in (0,1):
                    tv += abs(P.get((k,y,s),0.0)-0.5*E.get((y,s),0.0))
        tvsum += 0.5*tv
    avg_tv=tvsum/len(As)
    bound=0.5*math.sqrt((2**1)*pg1)
    assert avg_tv <= bound + 1e-12
    return {
        "L":L, "bsc_cross":p, "single_bit_guess":g,
        "Pguess_before_helper":pg0,
        "Pguess_after_helper":pg1,
        "helper_leakage_bound":2*pg0,
        "avg_hash_statistical_distance":avg_tv,
        "leftover_bound":bound,
    }

def fourier_to_guess_check():
    import cmath
    q=8; A=1; b=1; Delta=q//2
    vals=[0,1,q-1]
    probs={v:1/3 for v in vals}
    P=[{},{}]
    for K in (0,1):
        for s in range(q):
            for e in vals:
                for e0 in vals:
                    c=(A*s+e)%q
                    d=(b*s+e0+Delta*K)%q
                    P[K][(c,d)]=P[K].get((c,d),0.0)+1/(q*9)
    support=set(P[0])|set(P[1])
    tv=0.5*sum(abs(P[0].get(y,0)-P[1].get(y,0)) for y in support)
    omega=cmath.exp(2j*cmath.pi/q)
    Sodd=0.0
    for z in range(q):
        for t in range(q):
            if t%2==1 and (A*z+t*b)%q==0:
                he=sum(probs[e]*(omega**(z*e)) for e in vals)
                he0=sum(probs[e]*(omega**(t*e)) for e in vals)
                Sodd += abs(he*he0)**2
    assert tv <= math.sqrt(Sodd)+1e-12
    g=(1+tv)/2
    gbound=(1+min(1.0,math.sqrt(Sodd)))/2
    assert g<=gbound+1e-12
    return {"q":q,"TV":tv,"odd_spectral_mass":Sodd,
            "sqrt_mass_bound":math.sqrt(Sodd),
            "optimal_guess":g,"guess_bound":gbound}

def inv(a,p): return pow(a%p,-1,p)

def rref(M,p):
    A=[[v%p for v in row] for row in M]
    if not A: return A,[]
    m,n=len(A),len(A[0]); r=0; piv=[]
    for c in range(n):
        z=next((i for i in range(r,m) if A[i][c]),None)
        if z is None: continue
        A[r],A[z]=A[z],A[r]
        q=inv(A[r][c],p); A[r]=[(q*v)%p for v in A[r]]
        for i in range(m):
            if i!=r and A[i][c]:
                q=A[i][c]
                A[i]=[(A[i][j]-q*A[r][j])%p for j in range(n)]
        piv.append(c); r+=1
        if r==m: break
    return A,piv

def nullspace_rows(M,p):
    R,piv=rref(M,p)
    n=len(M[0]); out=[]
    for f in [j for j in range(n) if j not in piv]:
        x=[0]*n; x[f]=1
        for i,c in enumerate(piv):
            x[c]=(-R[i][f])%p
        out.append(x)
    return out

def solve(A,b,p):
    aug=[row[:] + [bb%p] for row,bb in zip(A,b)]
    R,_=rref(aug,p); n=len(A[0])
    for row in R:
        if all(row[j]==0 for j in range(n)) and row[n]:
            return None
    x=[0]*n
    for row in R:
        c=next((j for j in range(n) if row[j]),None)
        if c is not None: x[c]=row[n]%p
    return x

def matvec(A,x,p):
    return [sum(a*b for a,b in zip(row,x))%p for row in A]

def lagrange_eval(xs,ys,x,p):
    s=0
    for i,(xi,yi) in enumerate(zip(xs,ys)):
        num=1; den=1
        for j,xj in enumerate(xs):
            if i==j: continue
            num=num*(x-xj)%p
            den=den*(xi-xj)%p
        s=(s+yi*num*inv(den,p))%p
    return s

def rs_decode_by_subsets(received, alphas, k, t, p):
    n=len(alphas)
    seen=None
    for idxs in itertools.combinations(range(n),k):
        xs=[alphas[i] for i in idxs]
        ys=[received[i] for i in idxs]
        cand=[lagrange_eval(xs,ys,a,p) for a in alphas]
        dist=sum(c!=r for c,r in zip(cand,received))
        if dist<=t:
            if seen is not None and cand!=seen:
                return None
            seen=cand
    return seen

def rs_coset_check():
    p=17; n=8; k=4; t=2
    alphas=list(range(1,n+1))
    G=[[pow(a,j,p) for a in alphas] for j in range(k)]
    H=nullspace_rows(G,p)
    assert len(H)==n-k
    rng=random.Random(10091)
    ok=0
    for trial in range(200):
        X=[rng.randrange(p) for _ in range(n)]
        S=matvec(H,X,p)
        x0=solve(H,S,p)
        assert x0 is not None
        c=[(x-y)%p for x,y in zip(X,x0)]
        assert matvec(H,c,p)==[0]*(n-k)
        wt=rng.randrange(t+1)
        pos=rng.sample(range(n),wt)
        err=[0]*n
        for j in pos:
            err[j]=rng.randrange(1,p)
        noisy=[(X[j]+err[j])%p for j in range(n)]
        recv=[(noisy[j]-x0[j])%p for j in range(n)]
        chat=rs_decode_by_subsets(recv,alphas,k,t,p)
        assert chat is not None
        Xhat=[(x0[j]+chat[j])%p for j in range(n)]
        assert Xhat==X
        ok+=1
    return {"field":p,"n":n,"k":k,"t":t,"trials":200,"recovered":ok}

def bin_tail(n,p,t):
    return sum(comb(n,i)*(p**i)*((1-p)**(n-i)) for i in range(t+1,n+1))

def parameter_example():
    m=8; n=255; k=223; t=(n-k)//2
    L=m*n
    helper=(n-k)*m
    kappa=256
    g=0.75
    pbit=2e-5
    psym=1-(1-pbit)**m
    fail=bin_tail(n,psym,t)
    h=-math.log2(g)
    log2_eps=-1 + (kappa+helper-L*h)/2
    return {
        "GF_symbol_bits":m,"RS_n":n,"RS_k":k,"RS_t":t,
        "raw_bits":L,"helper_bits":helper,"key_bits":kappa,
        "hypothetical_false_guess_bound_g":g,
        "hypothetical_honest_bit_error":pbit,
        "symbol_error_upper":psym,
        "correctness_failure_upper":fail,
        "correctness_bits":-math.log2(fail),
        "statistical_distance_log2_upper":log2_eps,
        "statistical_security_bits":-log2_eps,
    }

def main():
    out={
        "fourier_to_guess":fourier_to_guess_check(),
        "exact_small_security":exact_guess_and_hash_check(),
        "rs_coset_recovery":rs_coset_check(),
        "illustrative_outer_parameters":parameter_example()
    }
    print(json.dumps(out,sort_keys=True))

if __name__=="__main__":
    main()
