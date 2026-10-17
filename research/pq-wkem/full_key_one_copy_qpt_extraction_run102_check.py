#!/usr/bin/env python3
from __future__ import annotations
from fractions import Fraction
from itertools import product
import json, math

def vecs(q,m):
    return list(product(range(q), repeat=m))

def wt(v):
    return sum(x != 0 for x in v)

def dot(a,b,q):
    return sum(x*y for x,y in zip(a,b)) % q

def vadd(a,b,q):
    return tuple((x+y)%q for x,y in zip(a,b))

def qsym_prob(q,beta,a):
    if a % q == 0:
        return (Fraction(1)+(q-1)*beta)/q
    return (Fraction(1)-beta)/q

def noise_dist(q,m,beta):
    out={}
    for x in vecs(q,m):
        p=Fraction(1)
        for z in x:
            p*=qsym_prob(q,beta,z)
        out[x]=p
    return out

checks=[]
def ok(name, cond, detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    checks.append({"name":name,"detail":detail})

# ----------------------------------------------------------------------
# 1. Full-key exact recovery identity: binary toy, kappa=2, L=2, m=1,
# P=0, beta=1/2.  D is q-symmetric Bernoulli noise.
# Decoder is the exact MAP decoder bit-by-bit over the two repetitions.
# Ties are broken toward 0.  Enumerate K,h,D exactly.
# ----------------------------------------------------------------------
q=2; m=1; kappa=2; L=2; beta=Fraction(1,2)
D1=noise_dist(q,m,beta)
Hs=vecs(q,m)

def bit_map_decode(hs, cs):
    # Exact posterior under uniform bit prior.
    scores=[]
    for b in (0,1):
        s=Fraction(1)
        for h,c in zip(hs,cs):
            d=((c[0]-b*h[0])%2,)
            s*=D1[d]
        scores.append(s)
    return 1 if scores[1] > scores[0] else 0

def decode_key(hflat,cflat):
    out=[]
    for i in range(kappa):
        hs=[hflat[i*L+j] for j in range(L)]
        cs=[cflat[i*L+j] for j in range(L)]
        out.append(bit_map_decode(hs,cs))
    return tuple(out)

keys=list(product((0,1),repeat=kappa))
hflats=list(product(Hs,repeat=kappa*L))
dflats=list(product(list(D1.keys()),repeat=kappa*L))

p_rec=Fraction(0)
# Also accumulate scalar Fourier response f_{a,h}(c) by exact deterministic A.
# For this tiny classical decoder, f is just +/-1.
for K in keys:
    pK=Fraction(1,len(keys))
    for hflat in hflats:
        ph=Fraction(1,len(hflats))
        for dflat in dflats:
            pd=Fraction(1)
            c=[]
            for idx,d in enumerate(dflat):
                pd*=D1[d]
                i=idx//L
                h=hflat[idx]
                c.append(((d[0]+K[i]*h[0])%2,))
            khat=decode_key(hflat,tuple(c))
            if khat==K:
                p_rec += pK*ph*pd
baseline=Fraction(1,2**kappa)
Delta=p_rec-baseline
ok("map_recovery_exact", p_rec==Fraction(121,256), p_rec)
ok("map_delta_exact", Delta==Fraction(57,256), Delta)

# Fourier domain: Y is one binary frequency per capsule coordinate.
Yset=list(product((0,1), repeat=kappa*L))
Cset=list(product(Hs, repeat=kappa*L))

# Compute exact RHS E_{a,h} sum_Y fhat beta^W Gamma.
# For binary q=2 Gamma is 0 or 1 exactly:
# Gamma = prod_i [1+(-1)^(a_i+sigma_i)]/2,
# hence indicator sigma_i=a_i for all i.
rhs=Fraction(0)
M_by_B={B:Fraction(0) for B in range(1,kappa*L+1)}
for a in keys:
    pa=Fraction(1,len(keys))
    for hflat in hflats:
        ph=Fraction(1,len(hflats))
        # Truth table over c.
        f={}
        for cflat in Cset:
            khat=decode_key(hflat,cflat)
            f[cflat] = -1 if (sum(a[i]*khat[i] for i in range(kappa))%2) else 1
        # normalized Walsh coefficients
        fhat={}
        for Y in Yset:
            s=Fraction(0)
            for cflat,val in f.items():
                parity=sum(Y[t]*cflat[t][0] for t in range(kappa*L))%2
                s += val * (-1 if parity else 1)
            fhat[Y]=s/Fraction(len(Cset))
        for Y in Yset:
            W=sum(Y)
            sig=[]
            for i in range(kappa):
                sig_i=sum(hflat[i*L+j][0]*Y[i*L+j] for j in range(L))%2
                sig.append(sig_i)
            gamma=1 if tuple(sig)==tuple(a) else 0
            rhs += pa*ph*fhat[Y]*(beta**W)*gamma
            if W>0:
                for B in M_by_B:
                    if W<=B:
                        M_by_B[B] += pa*ph*fhat[Y]*fhat[Y]
ok("full_key_spectral_identity",rhs==p_rec,(rhs,p_rec))

# Source-only masses for C=F_2^1 across N=kappa L coordinates.
N=kappa*L
T={}
for B in range(1,N+1):
    low=sum(Fraction(math.comb(N,w))*beta**(2*w) for w in range(1,B+1))
    high=sum(Fraction(math.comb(N,w))*beta**(2*w) for w in range(B+1,N+1))
    T[B]=(low,high)

tail_records=[]
for B in (1,2,3):
    low,high=T[B]
    delta_float=float(Delta)-math.sqrt(float(high)/2**kappa)
    if delta_float>0:
        lower=(delta_float**2)/(float(low)/2**kappa)
        actual=float(M_by_B[B])
        ok(f"tail_bound_B{B}",actual+1e-14>=lower,(actual,lower))
        tail_records.append({"B":B,"T_low":str(low),"T_high":str(high),
                             "actual_M_low":str(M_by_B[B]),
                             "delta":delta_float,"lower_bound":lower})
ok("B2_reference_actual", M_by_B[2]==Fraction(281,512), M_by_B[2])

S=beta**2
T_all=(1+S)**N-1
ok("product_spectrum",T_all==sum(Fraction(math.comb(N,w))*beta**(2*w) for w in range(1,N+1)))
ok("global_spectral_floor", T_all >= (2**kappa)*(Delta**2),(T_all,2**kappa*Delta**2))

# ----------------------------------------------------------------------
# 2. Exact one-copy mixed-advice operator-Fourier inequality.
# Binary c in F_2^2; V_c chosen independently from {I,X,Z,-I}.
# Advice states |0>, |+>, I/2.  All arithmetic is rational.
# Check Q(Y)=Tr(rho Vhat^T Vhat) >= |Tr(rho Vhat)|^2.
# 4^4 assignments * 3 states * 4 frequencies = 3072 checks.
# ----------------------------------------------------------------------
I=((Fraction(1),Fraction(0)),(Fraction(0),Fraction(1)))
X=((Fraction(0),Fraction(1)),(Fraction(1),Fraction(0)))
Z=((Fraction(1),Fraction(0)),(Fraction(0),Fraction(-1)))
nI=((Fraction(-1),Fraction(0)),(Fraction(0),Fraction(-1)))
ops=(I,X,Z,nI)
rho0=((Fraction(1),Fraction(0)),(Fraction(0),Fraction(0)))
rhop=((Fraction(1,2),Fraction(1,2)),(Fraction(1,2),Fraction(1,2)))
rhomix=((Fraction(1,2),Fraction(0)),(Fraction(0),Fraction(1,2)))
rhos=(("zero",rho0),("plus",rhop),("mixed",rhomix))
xs=vecs(2,2)
ys=xs

def madd(A,B):
    return tuple(tuple(A[i][j]+B[i][j] for j in range(2)) for i in range(2))
def mscale(a,A):
    return tuple(tuple(a*A[i][j] for j in range(2)) for i in range(2))
def mmul(A,B):
    return tuple(tuple(sum(A[i][k]*B[k][j] for k in range(2)) for j in range(2)) for i in range(2))
def mT(A):
    return tuple(tuple(A[j][i] for j in range(2)) for i in range(2))
def tr(A):
    return A[0][0]+A[1][1]
def trrho(rho,A):
    return tr(mmul(rho,A))

op_checks=0
minimum_slack=None
for assignment in product(range(4), repeat=4):
    V={xs[i]:ops[assignment[i]] for i in range(4)}
    for Y in ys:
        Vhat=((Fraction(0),Fraction(0)),(Fraction(0),Fraction(0)))
        for x in xs:
            sign=-1 if dot(Y,x,2) else 1
            Vhat=madd(Vhat,mscale(Fraction(sign,4),V[x]))
        for label,rho in rhos:
            scalar=trrho(rho,Vhat)
            Q=trrho(rho,mmul(mT(Vhat),Vhat))
            slack=Q-scalar*scalar
            ok(f"operator_fourier_{op_checks}",slack>=0,(assignment,Y,label,slack))
            if minimum_slack is None or slack<minimum_slack:
                minimum_slack=slack
            op_checks+=1
ok("operator_check_count",op_checks==3072,op_checks)

# ----------------------------------------------------------------------
# 3. Gamma mean-square identity for several q/kappa values.
# Direct numerical roots of unity check:
# E_a |prod_i (1+(-1)^a_i z_i)/2|^2 = 2^-kappa.
# ----------------------------------------------------------------------
gamma_records=[]
maxerr=0.0
for qv in (2,3,5,7):
    omega=complex(math.cos(2*math.pi/qv),math.sin(2*math.pi/qv))
    for kap in (1,2,3):
        for sig in product(range(qv),repeat=kap):
            acc=0.0
            for a in product((0,1),repeat=kap):
                g=1+0j
                for i in range(kap):
                    g *= (1 + ((-1)**a[i])*(omega**sig[i]))/2
                acc += abs(g)**2
            acc/=2**kap
            err=abs(acc-2**(-kap))
            maxerr=max(maxerr,err)
            ok(f"gamma_q{qv}_k{kap}_{sig}",err<1e-12,(acc,2**(-kap)))
        gamma_records.append({"q":qv,"kappa":kap})

# ----------------------------------------------------------------------
# 4. Two-temperature source tail and normalized-mass arithmetic.
# Use C=F_2^1, N=8, beta=1/3, beta'=1/2, B=3.
# ----------------------------------------------------------------------
N2=8; b=Fraction(1,3); bp=Fraction(1,2); B=3; kap=2
tail=sum(Fraction(math.comb(N2,w))*b**(2*w) for w in range(B+1,N2+1))
cert=(b/bp)**(2*(B+1))*((1+bp**2)**N2-1)
ok("two_temperature_full_key",tail<=cert,(tail,cert))
norm_tail=tail/Fraction(2**kap)
norm_low=sum(Fraction(math.comb(N2,w))*b**(2*w) for w in range(1,B+1))/Fraction(2**kap)

out={
    "run":102,
    "status":"PASS",
    "total_assertions":len(checks),
    "full_key_fixture":{
        "q":2,"m":1,"kappa":kappa,"L":L,"beta":str(beta),
        "p_recovery":str(p_rec),"baseline":str(baseline),"Delta":str(Delta),
        "T_all":str(T_all),
        "floor_rhs":str((2**kappa)*(Delta**2)),
        "tail_records":tail_records
    },
    "operator_fourier":{
        "assignments":4**4,
        "advice_states":[x[0] for x in rhos],
        "frequencies":4,
        "exact_checks":op_checks,
        "minimum_slack":str(minimum_slack)
    },
    "gamma_mean_square":{
        "records":gamma_records,
        "max_abs_error":maxerr
    },
    "two_temperature":{
        "N":N2,"kappa":kap,"B":B,"beta":str(b),"beta_prime":str(bp),
        "tail":str(tail),"certificate":str(cert),
        "normalized_low":str(norm_low),"normalized_tail":str(norm_tail)
    },
    "scope":[
        "Algebra/probability and finite operator inequalities only.",
        "The checker does not establish that an actual generic-NP source compiler has the required spectrum/extractor.",
        "No LWE/SIS/generic-group hardness is inferred from a passing checker."
    ]
}
print(json.dumps(out,indent=2,sort_keys=True))
