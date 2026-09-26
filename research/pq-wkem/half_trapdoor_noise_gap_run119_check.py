#!/usr/bin/env python3
from __future__ import annotations
import json, math, hashlib
from itertools import product

checks=[]
def ok(name, cond, detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    checks.append({"name":name,"detail":detail})

# ----------------------------------------------------------------------
# 1. Wee half-trapdoor offset algebra.
# Restricted sampler target: [D ; D M + Z].  For scalar M=mu I,
# B := A_bot - mu A_top and any returned K obeying
# A_top K=D, A_bot K=mu D+Z, we have B K=Z exactly.
# We exhaust small scalar/matrix fixtures (K=I) because the identity is
# purely algebraic; no security property is inferred.
# ----------------------------------------------------------------------
offset_cases=0
for q in (3,5,7,11):
    for n in (1,2):
        m=2
        for mu in range(q):
            # modest exhaustive public rows and source offsets
            vals=range(min(q,3))
            for atop_flat in product(vals, repeat=n*m):
                for z_flat in product(vals, repeat=n*m):
                    atop=[list(atop_flat[i*m:(i+1)*m]) for i in range(n)]
                    z=[list(z_flat[i*m:(i+1)*m]) for i in range(n)]
                    abot=[[ (mu*atop[i][j]+z[i][j])%q for j in range(m)] for i in range(n)]
                    B=[[ (abot[i][j]-mu*atop[i][j])%q for j in range(m)] for i in range(n)]
                    ok(f"offset_B_{offset_cases}", B==[[x%q for x in row] for row in z], (q,n,mu))
                    # K=I_m, hence BK=Z and sampler output itself is a public preimage.
                    ok(f"offset_preimage_{offset_cases}", B==z, (q,n,mu))
                    offset_cases += 1

# A nontrivial invertible-K control over 2x2 matrices.
def inv2(K,q):
    a,b=K[0]; c,d=K[1]
    det=(a*d-b*c)%q
    if det==0: return None
    invdet=pow(det,-1,q)
    return [[d*invdet%q, -b*invdet%q],[-c*invdet%q,a*invdet%q]]
def mm(A,B,q):
    return [[sum(A[i][k]*B[k][j] for k in range(len(B)))%q for j in range(len(B[0]))] for i in range(len(A))]
def madd(A,B,q):
    return [[(A[i][j]+B[i][j])%q for j in range(len(A[0]))] for i in range(len(A))]
def msub(A,B,q):
    return [[(A[i][j]-B[i][j])%q for j in range(len(A[0]))] for i in range(len(A))]
def smul(c,A,q):
    return [[c*x%q for x in row] for row in A]

nontrivial_cases=0
for q in (5,7):
    mats=[]
    for a,b,c,d in product(range(q), repeat=4):
        K=[[a,b],[c,d]]
        if inv2(K,q) is not None:
            mats.append(K)
    # deterministic subsample to keep runtime bounded
    for idx,K in enumerate(mats[::max(1,len(mats)//31)]):
        Ki=inv2(K,q)
        for mu in range(q):
            atop=[[1,(idx+2)%q],[(idx+3)%q,2%q]]
            D=mm(atop,K,q)
            Z=[[(idx+1)%q,3%q],[4%q,(idx+mu+1)%q]]
            target=madd(smul(mu,D,q),Z,q)
            abot=mm(target,Ki,q)
            B=msub(abot,smul(mu,atop,q),q)
            ok(f"nontrivial_sampler_top_{nontrivial_cases}",mm(atop,K,q)==D)
            ok(f"nontrivial_sampler_bottom_{nontrivial_cases}",mm(abot,K,q)==target)
            ok(f"nontrivial_offset_preimage_{nontrivial_cases}",mm(B,K,q)==Z,(q,mu,K))
            nontrivial_cases += 1

# ----------------------------------------------------------------------
# 2. Gaussian-only validity filter obstruction.
# Honest std = sigma_h.  Invalid public pseudowitness has std <= C*sigma_h
# for constant C.  Threshold t_lambda = sigma_h*sqrt(2 lambda ln 2)
# gives negligible honest rejection, but also negligible invalid rejection.
# We validate exact continuous-normal tails for representative lambda/C.
# ----------------------------------------------------------------------
gaussian_rows=[]
for C2 in (1.25,1.5,2.0,3.0,4.0):
    C=math.sqrt(C2)
    prev_h=prev_f=1.0
    for lam in (32,64,128,256):
        t=math.sqrt(2*lam*math.log(2.0))
        honest_fail=math.erfc(t/math.sqrt(2.0))
        false_fail=math.erfc(t/(math.sqrt(2.0)*C))
        false_accept=1.0-false_fail
        ok(f"gauss_h_decrease_{C2}_{lam}",honest_fail < prev_h)
        ok(f"gauss_f_decrease_{C2}_{lam}",false_fail < prev_f)
        ok(f"gauss_false_accept_{C2}_{lam}",false_accept > 0.5)
        # asymptotic exponent proxy: 2^{-lambda/C^2}; positive linear exponent
        ok(f"gauss_exponent_{C2}_{lam}",lam/C2 >= lam/4.0 - 1e-12)
        gaussian_rows.append({
            "C_squared":C2,"lambda":lam,"threshold_sigma_h":t,
            "honest_fail":honest_fail,"invalid_fail":false_fail,
            "invalid_accept":false_accept,"tail_exponent_proxy":lam/C2
        })
        prev_h,prev_f=honest_fail,false_fail

# Run-118 worst-case explicit affine upper solution has squared l2 <= B+2m <= 3B.
# Hence C^2<=3 whenever B=n+m and n,m>=1.
for n in range(1,17):
    for m in range(1,17):
        B=n+m
        C2=(B+2*m)/B
        ok(f"run118_constant_ratio_{n}_{m}",C2<=3.0+1e-12,(n,m,C2))

# ----------------------------------------------------------------------
# 3. Hair-Sahai advertised lp gap does not black-box transfer to l2.
# theta=1/2-1/p.  The paper allows epsilon < (p-2)/(4p)=theta/2
# (and epsilon<1/8).  Naive norm comparison loses M^theta, so epsilon-theta<0.
# ----------------------------------------------------------------------
norm_rows=[]
for p in (2.1,2.5,3,4,6,10,50):
    theta=0.5-1.0/p
    eps_cap=min((p-2.0)/(4.0*p),1.0/8.0)
    eps=0.999*eps_cap
    euclid_exp=eps-theta
    ok(f"norm_theta_{p}",theta>0)
    ok(f"norm_cap_half_{p}",eps_cap <= theta/2.0 + 1e-15,(p,eps_cap,theta))
    ok(f"norm_transfer_negative_{p}",euclid_exp<0,(p,eps,theta,euclid_exp))
    norm_rows.append({"p":p,"theta":theta,"epsilon_cap":eps_cap,"tested_epsilon":eps,"naive_l2_exponent":euclid_exp})
# p=infinity: theta=1/2, epsilon<1/8.
eps_inf=0.999/8.0
ok("norm_inf_transfer_negative",eps_inf-0.5<0)
norm_rows.append({"p":"inf","theta":0.5,"epsilon_cap":0.125,"tested_epsilon":eps_inf,"naive_l2_exponent":eps_inf-0.5})

# ----------------------------------------------------------------------
# 4. Parameter-ledger arithmetic for partial-trapdoor kappa-LWE reduction.
# The cited theorem requires chi0 > Omega(m^(3/2) max sigma'_i * chi).
# We only check monotone growth examples; this is not a hardness proof.
# ----------------------------------------------------------------------
param_rows=[]
for m in (64,128,256,512):
    for sigp in (2,4,8):
        ratio=(m**1.5)*sigp
        ok(f"param_growth_{m}_{sigp}",ratio>m)
        param_rows.append({"m":m,"max_sigma_prime":sigp,"chi0_over_chi_asymptotic_factor":ratio})

out={
  "run":119,
  "status":"PASS",
  "total_assertions":len(checks),
  "offset_half":{
    "identity_cases":offset_cases,
    "nontrivial_invertible_K_cases":nontrivial_cases,
    "claim":"For M=mu I, any sampler output K with A_top K=D and A_bot K=mu D+Z is an exact short preimage BK=Z for B=A_bot-mu A_top. Publishing K therefore defeats source-witness gating for a hash projected through B."
  },
  "gaussian_constant_gap":{
    "rows":gaussian_rows,
    "claim":"In an ideal zero-centered Gaussian threshold decoder, a constant standard-deviation factor cannot make honest rejection negligible while source-invalid rejection tends to one; both rejection probabilities tend to zero as the correctness threshold diverges in honest-sigma units."
  },
  "hair_sahai_norm_transfer":{
    "rows":norm_rows,
    "claim":"The advertised M^epsilon lp gap with epsilon<(p-2)/(4p) cannot be converted black-box to a polynomial l2 gap via generic norm comparison, whose dimension exponent is theta=1/2-1/p."
  },
  "partial_trapdoor_parameter_ledger":{
    "rows":param_rows,
    "claim":"Arithmetic record only for the m^(3/2)*max(sigma'_i) noise-loss factor in the cited integer kappa-LWE reduction."
  },
  "scope":[
    "Algebraic and continuous-Gaussian model checks only; no computational hardness is inferred.",
    "Wee's T_{1/2}-LWE and Albrecht-Lai-Lapiha-Woo kappa-LWE theorems are stated for PPT adversaries in the cited papers; QPT security is not silently imported.",
    "The straight-line shape of Wee's proof is a research lead for a possible QPT lift under QPT-LWE, not a completed quantum theorem here.",
    "Hair-Sahai worst-case NP-hardness is not average-case LWE/SIS hardness and their lp theorem alone does not supply an l2 gap.",
    "Stopping condition not met."
  ]
}
print(json.dumps(out,indent=2,sort_keys=True))
