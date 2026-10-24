#!/usr/bin/env python3
from __future__ import annotations

from fractions import Fraction
from itertools import product
from decimal import Decimal, getcontext
from math import comb, sqrt
import json

getcontext().prec = 80

def fracdec(x: Fraction) -> Decimal:
    return Decimal(x.numerator) / Decimal(x.denominator)

def qsym_prob(q: int, beta: Fraction, a: int) -> Fraction:
    if a % q == 0:
        return (Fraction(1,1) + (q-1)*beta) / q
    return (Fraction(1,1) - beta) / q

def vecs(q: int, m: int):
    return list(product(range(q), repeat=m))

def vadd(a,b,q):
    return tuple((x+y)%q for x,y in zip(a,b))

def vsub(a,b,q):
    return tuple((x-y)%q for x,y in zip(a,b))

def dot(a,b,q):
    return sum(x*y for x,y in zip(a,b)) % q

def wt(v):
    return sum(x != 0 for x in v)

def product_noise(q:int,m:int,beta:Fraction):
    d={}
    for x in vecs(q,m):
        p=Fraction(1,1)
        for a in x:
            p*=qsym_prob(q,beta,a)
        d[x]=p
    return d

def uniform_vec(q,m):
    vs=vecs(q,m)
    p=Fraction(1, len(vs))
    return {x:p for x in vs}

checks=[]
def ok(name, cond, detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    checks.append({"name":name,"detail":detail})

# -------------------------------------------------------------------------
# 1. Random-direction orientation normal form.
# For m=1 and P=0, c=d+b h.  The invertible public transform
# (h,c) -> (u,v)=(c,c-h) gives (D,U) for b=0 and (U,D) for b=1.
# Check q=2 and q=3 exactly by full enumeration.
# -------------------------------------------------------------------------
orientation_records=[]
for q,beta in [(2,Fraction(1,2)), (3,Fraction(2,5))]:
    m=1
    D=product_noise(q,m,beta)
    U=uniform_vec(q,m)
    hs=vecs(q,m)
    for b in (0,1):
        actual={}
        for h in hs:
            ph=Fraction(1,len(hs))
            for d,pd in D.items():
                c=vadd(d, tuple((b*z)%q for z in h), q)
                u=c
                v=vsub(c,h,q)
                actual[(u,v)]=actual.get((u,v),Fraction(0))+ph*pd
        target={}
        for x,px in (D.items() if b==0 else U.items()):
            for y,py in (U.items() if b==0 else D.items()):
                target[(x,y)]=target.get((x,y),Fraction(0))+px*py
        ok(f"orientation_q{q}_b{b}", actual==target)
    orientation_records.append({"q":q,"beta":str(beta),"states":q*q})

# -------------------------------------------------------------------------
# 2. Forward-only orientation distinguisher reduction.
# For every deterministic A(u,v)->bit on q=2 and q=3 one-coordinate domains:
#   epsilon = Pr[A decodes b]-1/2
# equals the acceptance gap of
#   B(z): pick t; t=0 accept iff A(z,U)=0;
#                   t=1 accept iff A(U,z)=1
# between z~D and z~U.
# No inverse/adjoint of A is used.
# -------------------------------------------------------------------------
forward_records=[]
for q,beta in [(2,Fraction(1,2)),(3,Fraction(2,5))]:
    D=product_noise(q,1,beta)
    U=uniform_vec(q,1)
    states=vecs(q,1)
    pairs=[(u,v) for u in states for v in states]
    total_A=1 << len(pairs)
    if q==3:
        assert total_A==512
    for mask in range(total_A):
        def abit(u,v):
            i=pairs.index((u,v))
            return (mask>>i)&1
        p0=sum(D[u]*U[v]*(1-abit(u,v)) for u in states for v in states)
        p1=sum(U[u]*D[v]*abit(u,v) for u in states for v in states)
        success=(p0+p1)/2
        eps=success-Fraction(1,2)

        accD=Fraction(0)
        accU=Fraction(0)
        for z,pz in D.items():
            accD += pz*Fraction(1,2)*sum(U[u]*(1-abit(z,u)) for u in states)
            accD += pz*Fraction(1,2)*sum(U[u]*abit(u,z) for u in states)
        for z,pz in U.items():
            accU += pz*Fraction(1,2)*sum(U[u]*(1-abit(z,u)) for u in states)
            accU += pz*Fraction(1,2)*sum(U[u]*abit(u,z) for u in states)
        ok(f"forward_orientation_q{q}_A{mask}", accD-accU==eps)
    forward_records.append({"q":q,"deterministic_decoders":total_A})

# -------------------------------------------------------------------------
# 3. Standard forward hybrid: any B distinguishing D^L from U^L gives,
# by choosing a random hybrid coordinate, a one-sample D-vs-U distinguisher
# with signed gap exactly gap(B)/L.
# Exhaust every deterministic B for q=2,m=1,L=2.
# -------------------------------------------------------------------------
q=2; beta=Fraction(1,2); L=2
D=product_noise(q,1,beta); U=uniform_vec(q,1); states=vecs(q,1)
tuples=list(product(states, repeat=L))
def dist_tuple(parts):
    out={}
    for z in tuples:
        p=Fraction(1)
        for i,zi in enumerate(z):
            p*=parts[i][zi]
        out[z]=p
    return out
H0=dist_tuple([U,U]); H1=dist_tuple([D,U]); H2=dist_tuple([D,D])
for mask in range(1<<len(tuples)):
    def bfun(z):
        return (mask>>tuples.index(z))&1
    vals=[]
    for H in (H0,H1,H2):
        vals.append(sum(p*bfun(z) for z,p in H.items()))
    big_gap=vals[2]-vals[0]
    random_hybrid_gap=((vals[1]-vals[0])+(vals[2]-vals[1]))/2
    ok(f"hybrid_L2_B{mask}", random_hybrid_gap==big_gap/2)
hybrid_record={"q":2,"L":2,"deterministic_distinguishers":1<<len(tuples)}

# -------------------------------------------------------------------------
# 4. Spectral-tail extraction inequality, exhaustive deterministic A.
#
# Binary m=2, P=0 => C=F_2^2, beta=1/2, L=1, total-weight threshold B=1.
# For each A(h,c), compute
#   rho = E[(-1)^(A+b)] = 2 epsilon,
#   M_low = E_h sum_{0<wt(y)<=B} |fhat_h(y)|^2.
# T_low=1/2, T_high=1/16.
#
# The theorem says if |rho| > sqrt(T_high/2), then
# M_low >= 2 (|rho|-sqrt(T_high/2))^2 / T_low.
# Exhaust all 2^16 deterministic response tables.
# -------------------------------------------------------------------------
m=2
xs=vecs(2,m)
hs=xs
D2=product_noise(2,m,Fraction(1,2))
beta2=Fraction(1,2)
Tlow=sum(beta2**(2*wt(y)) for y in xs if 0<wt(y)<=1)
Thigh=sum(beta2**(2*wt(y)) for y in xs if wt(y)>1)

# Each h owns a four-bit truth table in c; precompute Walsh spectra.
truths=[]
for t in range(16):
    f=[1 if ((t>>i)&1)==0 else -1 for i in range(4)]
    fh={}
    for y in xs:
        fh[y]=sum(Fraction(f[i]*((-1)**dot(y,x,2)),1) for i,x in enumerate(xs))/4
    truths.append((f,fh))
lowm={t:sum(fh[y]*fh[y] for y in xs if 0<wt(y)<=1)
      for t,(f,fh) in enumerate(truths)}
rho_ht={}
for hi,h in enumerate(hs):
    for t,(f,fh) in enumerate(truths):
        e0=sum(D2[x]*f[xs.index(x)] for x in xs)
        e1=sum(D2[x]*f[xs.index(vadd(x,h,2))] for x in xs)
        rho_ht[(hi,t)]=(e0-e1)/2

sqrt_hi=(fracdec(Thigh)/Decimal(2)).sqrt()
applicable=0
violations=0
minimum_margin=None
for ts in product(range(16), repeat=4):
    rho=sum(rho_ht[(hi,ts[hi])] for hi in range(4))/4
    arho=abs(rho)
    if fracdec(arho)>sqrt_hi:
        applicable+=1
        M=sum(lowm[ts[hi]] for hi in range(4))/4
        delta=fracdec(arho)-sqrt_hi
        lower=Decimal(2)*delta*delta/fracdec(Tlow)
        margin=fracdec(M)-lower
        if minimum_margin is None or margin<minimum_margin:
            minimum_margin=margin
        if margin < Decimal("-1e-50"):
            violations+=1
ok("spectral_tail_exhaustive_no_violations", violations==0, violations)
ok("spectral_tail_expected_applicable_count", applicable==13312, applicable)
spectral_tail_record={
    "q":2,"m":2,"L":1,"beta":"1/2","B":1,
    "T_low":str(Tlow),"T_high":str(Thigh),
    "deterministic_decoders":65536,
    "theorem_applicable":applicable,
    "violations":violations,
    "minimum_decimal_margin":str(minimum_margin)
}

# -------------------------------------------------------------------------
# 5. Tuple product-spectrum identity and two-temperature tail certificate.
# For C=F2^2, L=3, enumerate all Y tuples.
# T_all(beta) = (1+S_C(beta))^L - 1.
# For beta<beta', W>B integer:
# T_>B(beta) <= (beta/beta')^(2(B+1))*T_all(beta').
# -------------------------------------------------------------------------
C=xs; L=3; B=2
b=Fraction(1,3); bp=Fraction(1,2)
Ys=list(product(C,repeat=L))
def totalw(Y): return sum(wt(y) for y in Y)
def Sc(code,z):
    return sum(z**(2*wt(y)) for y in code if any(y))
Tall_enum=sum(b**(2*totalw(Y)) for Y in Ys if totalw(Y)>0)
Tall_prod=(1+Sc(C,b))**L-1
ok("product_spectrum_identity",Tall_enum==Tall_prod,(Tall_enum,Tall_prod))
Ttail=sum(b**(2*totalw(Y)) for Y in Ys if totalw(Y)>B)
cert=(b/bp)**(2*(B+1))*((1+Sc(C,bp))**L-1)
ok("two_temperature_tail_certificate",Ttail<=cert,(Ttail,cert))
two_temp_record={
    "q":2,"m":2,"L":L,"B":B,"beta":str(b),"beta_prime":str(bp),
    "T_all":str(Tall_enum),"T_tail":str(Ttail),"certificate":str(cert)
}

# -------------------------------------------------------------------------
# 6. Run-97 bent-family regression.
# Its toy source has C=F2^m and beta=1-1/r.  The genuine witness threshold
# B=1 leaves enormous high channel spectral mass, so the new criterion
# correctly does NOT falsely certify that decoder family.
# -------------------------------------------------------------------------
bent=[]
for r in (2,4,8,16):
    m=3*r+1
    beta=Fraction(r-1,r)
    # T_high for L=1 and B=1.
    Th=sum(Fraction(comb(m,j))*beta**(2*j) for j in range(2,m+1))
    kappa=Fraction(1,1)-Fraction(1,2)*(1-beta)**2
    rho=beta**(r+1)*kappa**r  # exact Run-97 signed correlation
    gate=fracdec(rho)- (fracdec(Th)/Decimal(2)).sqrt()
    ok(f"bent_not_certified_r{r}",gate<=0,(rho,Th))
    bent.append({"r":r,"m":m,"beta":str(beta),"rho":str(rho),
                 "T_high":str(Th),"delta_gate_decimal":str(gate)})

# -------------------------------------------------------------------------
# 7. A synthetic one-dimensional positive spectrum fixture.
# C={0,y}, wt(y)=4, beta=1/2, L=64, B=16 (=4 nonzero tuple components).
# This is NOT a cryptographic source; it only demonstrates that the theorem's
# quantitative premises are simultaneously satisfiable.
# -------------------------------------------------------------------------
d=4; beta=Fraction(1,2); L=64; maxj=4
a=beta**(2*d)
Tlow_pos=sum(Fraction(comb(L,j))*a**j for j in range(1,maxj+1))
Ttail_pos=sum(Fraction(comb(L,j))*a**j for j in range(maxj+1,L+1))
epsilon=Fraction(1,20)
rho=2*epsilon
delta=fracdec(rho)-(fracdec(Ttail_pos)/Decimal(2)).sqrt()
lower=Decimal(2)*delta*delta/fracdec(Tlow_pos)
ok("positive_fixture_delta",delta>0,delta)
ok("positive_fixture_inverse_poly_mass",lower>Decimal("0.01"),lower)
positive_record={
    "dimension":1,"source_word_weight":d,"beta":str(beta),"L":L,
    "B":d*maxj,"epsilon":str(epsilon),
    "T_low":str(Tlow_pos),"T_high":str(Ttail_pos),
    "delta_decimal":str(delta),"forced_low_response_mass_decimal":str(lower)
}

out={
    "run":101,
    "status":"PASS",
    "total_assertions":len(checks),
    "orientation_records":orientation_records,
    "forward_orientation_records":forward_records,
    "hybrid_record":hybrid_record,
    "spectral_tail_exhaustive":spectral_tail_record,
    "two_temperature":two_temp_record,
    "run97_bent_regression":bent,
    "synthetic_positive_fixture":positive_record,
    "scope":[
        "Exact finite identities/probability inequalities only.",
        "No computational hardness or QPT source-extraction theorem is inferred from passing tests.",
        "The coherent Fourier extractor still requires a coherently re-runnable adversary implementation and adjoint."
    ]
}
print(json.dumps(out,indent=2,sort_keys=True))
