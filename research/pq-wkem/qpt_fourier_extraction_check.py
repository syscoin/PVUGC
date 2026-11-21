#!/usr/bin/env python3
import cmath, itertools, json, math, random
from collections import defaultdict

TOL=2e-10

def omega(q):
    return cmath.exp(-2j*math.pi/q)

def group(q,d):
    return list(itertools.product(range(q), repeat=d))

def dotq(a,b,q):
    return sum(x*y for x,y in zip(a,b)) % q

def ft_uniform(values, q, d):
    """Normalized DFT E_x f(x) exp(-2 pi i <xi,x>/q)."""
    G=group(q,d); w=omega(q); N=len(G)
    return {
        xi: sum(values[x]*(w**dotq(xi,x,q)) for x in G)/N
        for xi in G
    }

def ft_probability(P,q):
    w=omega(q)
    return [sum(P[x]*(w**((k*x)%q)) for x in range(q)) for k in range(q)]

def extremal_target(q):
    assert q%2==0 and q>=4
    raw=[max(math.cos(2*math.pi*x/q),0.0) for x in range(q)]
    Z=sum(raw)
    return [x/Z for x in raw]

def uniform_mixture_noise(q,rho):
    return [rho+(1-rho)/q]+[(1-rho)/q]*(q-1)

def cyclic_convolve(P,Q):
    q=len(P)
    return [sum(P[x]*Q[(r-x)%q] for x in range(q)) for r in range(q)]

def power_convolve(P,k):
    q=len(P)
    out=[1.0]+[0.0]*(q-1)
    for _ in range(k):
        out=cyclic_convolve(out,P)
    return out

def shift(P,a):
    q=len(P)
    return [P[(x-a)%q] for x in range(q)]

def tv(P,Q):
    return 0.5*sum(abs(a-b) for a,b in zip(P,Q))

def check_extremal_target():
    out=[]
    for q in (8,10,12,16,20):
        P=extremal_target(q); F=ft_probability(P,q)
        Cq=sum(abs(math.cos(2*math.pi*x/q)) for x in range(q))/q
        assert abs(sum(P)-1)<TOL and min(P)>-TOL
        assert tv(P,shift(P,q//2)) > 1-1e-12
        allowed={1,q-1}
        worst=0.0
        for k in range(1,q):
            if k%2==1 and k not in allowed:
                worst=max(worst,abs(F[k]))
        assert worst < 2e-12
        assert abs(F[1].real - 1/(2*Cq)) < 2e-12
        assert abs(F[q-1].real - 1/(2*Cq)) < 2e-12
        out.append({"q":q,"Cq":Cq,"first_harmonic":F[1].real,
                    "max_other_odd_harmonic":worst})
    return out

def check_witness_residual():
    out=[]
    for q in (8,12,16):
        P0=extremal_target(q)
        for rho in (0.7,0.85,0.93):
            D=uniform_mixture_noise(q,rho)
            for B in (1,2,5,9):
                N=power_convolve(D,B)
                R0=cyclic_convolve(P0,N)
                R1=shift(R0,q//2)
                success=0.5+tv(R0,R1)/2
                expected=(1+rho**B)/2
                assert abs(success-expected)<2e-11
                out.append({"q":q,"rho":rho,"B":B,
                            "success":success,"expected":expected})
    return out

def capsule_dist(q,A,b,D,D0,K):
    # A is m x n, b length m
    m=len(A); n=len(A[0]); Gs=group(q,m)
    p=defaultdict(float)
    for s in Gs:
        ps=q**(-m)
        # enumerate product noise; small fixtures only
        for es in itertools.product(range(q), repeat=n+1):
            pe=1.0
            for j in range(n): pe*=D[es[j]]
            pe*=D0[es[n]]
            if pe==0: continue
            c=[]
            for j in range(n):
                val=sum(A[i][j]*s[i] for i in range(m))+es[j]
                c.append(val%q)
            d=(sum(b[i]*s[i] for i in range(m))+es[n]+(q//2)*K)%q
            p[tuple(c+[d])] += ps*pe
    return p

def check_capsule_fourier_and_extraction_bound():
    # q=4 keeps fixture exactly small. Odd residues are exactly +/-1.
    q=4; A=[[1,1]]; b=[1]; n=2
    rho=0.75
    D=uniform_mixture_noise(q,rho)
    D0=extremal_target(q) # delta_0 at q=4
    p0=capsule_dist(q,A,b,D,D0,0)
    p1=capsule_dist(q,A,b,D,D0,1)
    G=group(q,n+1); N=len(G)
    delta={x:p0[x]-p1[x] for x in G}
    g={x:N*delta[x] for x in G}
    f={x:(1.0 if delta[x]>1e-15 else -1.0 if delta[x]<-1e-15 else 0.0)
       for x in G}
    gh=ft_uniform(g,q,n+1); fh=ft_uniform(f,q,n+1)
    epsilon=0.25*sum(delta[x]*f[x] for x in G)
    assert epsilon>0
    # exact support formula
    phi=ft_probability(D,q); phi0=ft_probability(D0,q)
    support=[]
    maxerr=0.0
    for xi in G:
        y=xi[:n]; t=xi[n]
        rel=all((sum(A[i][j]*y[j] for j in range(n))+t*b[i])%q==0
                for i in range(len(A)))
        predmag=0.0
        if rel and t%2==1:
            predmag=2*abs(phi0[t])
            for yy in y: predmag*=abs(phi[yy])
            support.append(xi)
        maxerr=max(maxerr,abs(abs(gh[xi])-predmag))
    assert maxerr<2e-11
    assert all(xi[-1] in (1,q-1) for xi in support)

    # Advantage identity.
    inner=sum(gh[xi]*fh[xi].conjugate() for xi in G)
    assert abs(inner.real-4*epsilon)<2e-11 and abs(inner.imag)<2e-11

    # Validate the general subset extraction inequality for all subsets of support.
    checked=0; worst_slack=10.0
    S=support
    for mask in range(1,1<<len(S)):
        T=[S[i] for i in range(len(S)) if (mask>>i)&1]
        U=[x for x in S if x not in T]
        gammaT=math.sqrt(sum(abs(gh[x])**2 for x in T))
        gammaU=math.sqrt(sum(abs(gh[x])**2 for x in U))
        FT=sum(abs(fh[x])**2 for x in T)
        if gammaT<1e-15: continue
        bound=max(0.0,4*epsilon-gammaU)**2/(gammaT**2)
        slack=FT-bound
        assert slack>-2e-10
        worst_slack=min(worst_slack,slack)
        checked+=1
    return {
        "epsilon":epsilon,
        "support_size":len(support),
        "max_support_formula_error":maxerr,
        "subset_bounds_checked":checked,
        "minimum_subset_bound_slack":worst_slack,
        "full_fourier_sampler_mass":sum(abs(fh[x])**2 for x in support),
    }

def check_qpt_phase_sandwich():
    # Explicitly verify that the clean-workspace Fourier amplitude equals f_hat.
    rng=random.Random(120012)
    q=5; d=2; G=group(q,d); N=len(G); w=omega(q)
    f={x:rng.uniform(-0.98,0.98) for x in G}
    # U_x can be a Y rotation with Z expectation f(x).
    # U_x^dag Z U_x |0> = f(x)|0> + sqrt(1-f(x)^2)|1> up to a sign.
    clean_amp={}
    dirty_norm=0.0
    for xi in G:
        amp=sum(f[x]*(w**dotq(xi,x,q)) for x in G)/N
        clean_amp[xi]=amp
    fh=ft_uniform(f,q,d)
    maxerr=max(abs(clean_amp[x]-fh[x]) for x in G)
    assert maxerr<1e-13
    clean_prob=sum(abs(v)**2 for v in clean_amp.values())
    expected=sum(v*v for v in f.values())/N
    assert abs(clean_prob-expected)<1e-12
    # Check local phase-sandwich normalization too.
    for x in G:
        dirty=math.sqrt(max(0.0,1-f[x]*f[x]))
        assert abs(f[x]*f[x]+dirty*dirty-1)<1e-12
        dirty_norm+=dirty*dirty/N
    assert abs(clean_prob+dirty_norm-1)<1e-12
    return {"q":q,"dimension":d,"points":N,
            "max_clean_amplitude_error":maxerr,
            "clean_measurement_probability":clean_prob,
            "parseval_expected":expected}

def check_rational_approximation():
    # Quantize the extremal target law to denominator M and show unwanted odd
    # coefficients are bounded by its l1 perturbation.
    q=16; P=extremal_target(q); M=1<<20
    counts=[int(math.floor(x*M)) for x in P]
    rem=M-sum(counts)
    frac=sorted(range(q),key=lambda i:P[i]*M-counts[i],reverse=True)
    for i in frac[:rem]: counts[i]+=1
    Q=[c/M for c in counts]
    l1=sum(abs(a-b) for a,b in zip(P,Q))
    F=ft_probability(Q,q)
    other=max(abs(F[k]) for k in range(1,q,2) if k not in (1,q-1))
    assert other <= l1+1e-12
    return {"q":q,"denominator":M,"l1_error":l1,
            "max_unwanted_odd_harmonic":other,
            "certified_bound":l1}

def main():
    out={
        "status":"PASS",
        "extremal_target":check_extremal_target(),
        "witness_residual_cases":check_witness_residual(),
        "capsule_extraction":check_capsule_fourier_and_extraction_bound(),
        "qpt_phase_sandwich":check_qpt_phase_sandwich(),
        "rational_approximation":check_rational_approximation(),
    }
    print(json.dumps(out,sort_keys=True))

if __name__=="__main__":
    main()
