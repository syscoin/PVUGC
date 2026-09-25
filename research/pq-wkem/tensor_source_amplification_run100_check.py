#!/usr/bin/env python3
from __future__ import annotations
from itertools import product
from fractions import Fraction
from collections import Counter
import json, math, hashlib, sys
from pathlib import Path

def span_code(q, gens):
    if not gens:
        return [()]
    n = len(gens[0])
    words = set()
    for coeff in product(range(q), repeat=len(gens)):
        w = tuple(sum(coeff[i]*gens[i][j] for i in range(len(gens))) % q for j in range(n))
        words.add(w)
    return sorted(words)

def wt(v):
    return sum(1 for x in v if x != 0)

def tensor_vec(a, b, q):
    return tuple((x*y) % q for x in a for y in b)

def tensor_gens(gens_a, gens_b, q):
    return [tensor_vec(a,b,q) for a in gens_a for b in gens_b]

def tensor_power_gens(gens, q, t):
    out = list(gens)
    for _ in range(t-1):
        out = tensor_gens(out, gens, q)
    return out

def fiber(v, n, t, axis, fixed):
    # Flattening order agrees with itertools.product(range(n), repeat=t).
    arr = {}
    for idx, val in zip(product(range(n), repeat=t), v):
        arr[idx] = val
    out = []
    for a in range(n):
        idx = []
        it = iter(fixed)
        for j in range(t):
            idx.append(a if j == axis else next(it))
        out.append(arr[tuple(idx)])
    return tuple(out)

def all_nonempty_fibers(v, n, t):
    ans = []
    for axis in range(t):
        for fixed in product(range(n), repeat=t-1):
            f = fiber(v,n,t,axis,fixed)
            if wt(f):
                ans.append((axis,fixed,f))
    return ans

def spectrum(code, beta):
    return sum(beta ** (2*wt(w)) for w in code if any(w))

def h2(x):
    if x <= 0.0 or x >= 1.0:
        return 0.0 if x in (0.0,1.0) else float("nan")
    return -x*math.log(x)-(1-x)*math.log(1-x)

def q_entropy_rate(q, beta):
    eta = (1.0-1.0/q)*(1.0-beta)
    return (h2(eta)+eta*math.log(q-1))/math.log(q)

checks = []
def ok(name, cond, detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    checks.append({"name":name,"ok":True,"detail":detail})

# Base code: binary [3,2,2] even-parity code.
q = 2
gens = [(1,1,0),(0,1,1)]
base = span_code(q, gens)
ok("base_size", len(base)==4, len(base))
ok("base_distance", min(wt(w) for w in base if any(w))==2)

tensor_records=[]
for t in (1,2,3):
    tg = tensor_power_gens(gens,q,t)
    code = span_code(q,tg)
    k_t = len(gens)**t
    n_t = 3**t
    d_t = min(wt(w) for w in code if any(w))
    expected_size = q**k_t
    expected_dist = 2**t
    ok(f"tensor_size_t{t}", len(code)==expected_size, (len(code),expected_size))
    ok(f"tensor_distance_t{t}", d_t==expected_dist, (d_t,expected_dist))
    counts = dict(sorted(Counter(wt(w) for w in code).items()))
    tensor_records.append({"t":t,"length":n_t,"dimension":k_t,
                           "distance":d_t,"weight_enumerator":counts})
    if t >= 2:
        bset = set(base)
        nonzero = 0
        sparse_fiber = 0
        for v in code:
            if not any(v):
                continue
            nonzero += 1
            fibs = all_nonempty_fibers(v,3,t)
            ok(f"fibers_exist_t{t}_{nonzero}", bool(fibs))
            for _,_,f in fibs:
                ok(f"fiber_in_base_t{t}_{nonzero}", f in bset, f)
            mfw = min(wt(f) for _,_,f in fibs)
            W = wt(v)
            # Exact integer form of mfw <= W^(1/t)
            ok(f"sparse_fiber_bound_t{t}_{nonzero}", mfw**t <= W, (mfw,W))
            if W <= 2**t:
                ok(f"source_threshold_t{t}_{nonzero}", mfw <= 2, (mfw,W))
                sparse_fiber += 1
        tensor_records[-1]["nonzero_words_checked"] = nonzero
        tensor_records[-1]["words_at_base_threshold_power"] = sparse_fiber

# Exact spectral sums and min-distance coarse bounds at beta=1/2.
beta = Fraction(1,2)
spectral_records=[]
for t in (1,2,3):
    code = span_code(q,tensor_power_gens(gens,q,t))
    S = spectrum(code,beta)
    k_t=2**t
    D_t=2**t
    coarse=(q**k_t-1)*beta**(2*D_t)
    ok(f"spectral_bound_t{t}", S <= coarse, (S,coarse))
    spectral_records.append({"t":t,"S_exact":f"{S.numerator}/{S.denominator}",
                             "S_float":float(S),
                             "distance_bound":f"{coarse.numerator}/{coarse.denominator}",
                             "distance_bound_float":float(coarse)})

# Fixed auxiliary tensor no-go at matched honest signal.
# Base honest source weight d=1 is a release benchmark.  Auxiliary honest vector has d_A=2.
# Choose beta_aux=1/2 so matched base beta_0 = beta_aux^d_A = 1/4.
A_rep_gens=[(1,1)]                 # delta_A=d_A=2
A_full_gens=[(1,0),(0,1)]         # delta_A=1, while choose honest a_h=(1,1), d_A=2
fixed_aux_records=[]
for label,ag in [("repetition",A_rep_gens),("full_space",A_full_gens)]:
    A=span_code(2,ag)
    delta=min(wt(a) for a in A if any(a))
    product_code=span_code(2,tensor_gens(gens,ag,2))
    S_prod=spectrum(product_code,Fraction(1,2))
    beta0=Fraction(1,4)
    S_base=spectrum(base,beta0)
    lower=spectrum(base,Fraction(1,2)**delta)
    ok(f"fixed_aux_subcode_{label}", S_prod >= lower, (S_prod,lower))
    ok(f"fixed_aux_matched_{label}", lower >= S_base, (lower,S_base))
    fixed_aux_records.append({
        "aux":label,"delta_A":delta,"honest_aux_weight":2,
        "product_S_beta_half":f"{S_prod.numerator}/{S_prod.denominator}",
        "subcode_lower":f"{lower.numerator}/{lower.denominator}",
        "matched_base_S":f"{S_base.numerator}/{S_base.denominator}"
    })

# Self-tensor benchmark can genuinely reduce spectral mass at same beta in this toy false code.
S1=spectrum(base,Fraction(1,2))
C2=span_code(2,tensor_power_gens(gens,2,2))
S2=spectrum(C2,Fraction(1,2))
ok("self_tensor_toy_spectral_drop", S2 < S1, (S2,S1))

# Run-98/99 parameter accounting in log domain:
# tau=lambda^{-c}; coarse log leakage exponent is
# ln(kappa*A)+k^t ln q-(2 gamma^t-1)c ln lambda.
lambda_bits=128
lnlam=lambda_bits*math.log(2)
qpar=65537
kappa=256
Aamp=256
param_rows=[]
for label,k,gamma in [("favorable_ratio",8,4),("unfavorable_ratio",16,4)]:
    prev=None
    for t in (1,2,3):
        log_bound = math.log(kappa*Aamp)+(k**t)*math.log(qpar)-(2*(gamma**t)-1)*lnlam
        param_rows.append({"case":label,"k":k,"gamma":gamma,"t":t,
                           "log_coarse_kappa_L_S":log_bound,
                           "bits_equiv":log_bound/math.log(2)})
        if prev is not None:
            # No monotonic theorem claimed; just ensure finite arithmetic.
            ok(f"finite_param_{label}_t{t}", math.isfinite(log_bound))
        prev=log_bound

# Run-99 exact Shannon necessary condition under tensoring.
# H^{⊗t} has active-column count n_act^t; dimension k^t.
tau=2.0**-20
capacity_rows=[]
for label,k,nact,d in [("rho_eq_1",1,100,100),("rho_eq_2",2,100,100)]:
    rho=k*d/nact
    for t in range(1,8):
        beta_t=tau**(1/(d**t))
        lhs=(k/nact)**t
        rhs=q_entropy_rate(65537,beta_t)
        capacity_rows.append({"case":label,"rho":rho,"t":t,"beta":beta_t,
                              "tensor_rate":lhs,"noise_entropy_rate":rhs,
                              "necessary_capacity_passes":lhs <= rhs,
                              "ratio":lhs/rhs})
# In the rho=2 synthetic row, exact necessary condition eventually fails.
r2=[r for r in capacity_rows if r["case"]=="rho_eq_2"]
ok("rho2_eventual_capacity_failure", any(not r["necessary_capacity_passes"] for r in r2), r2[-1])
r1=[r for r in capacity_rows if r["case"]=="rho_eq_1"]
ok("rho1_rows_pass_here", all(r["necessary_capacity_passes"] for r in r1))

out={
    "run":"100",
    "checker":"tensor_source_amplification_run100_check.py",
    "status":"PASS",
    "claims_checked":[
        "tensor dimension and minimum-distance powers on binary [3,2,2] code",
        "every nonempty tensor fiber is a base-code word",
        "sparse-fiber root-support bound on every enumerated tensor codeword",
        "low-weight tensor word exposes a base word within the root threshold",
        "exact tensor-code spectral sums and minimum-distance coarse bounds",
        "fixed statement-independent auxiliary tensor cannot beat matched-signal base spectral leakage",
        "self-tensor can reduce toy false spectral mass",
        "Run-98 coarse leakage exponent arithmetic",
        "Run-99 tensorized Shannon necessary-condition arithmetic"
    ],
    "tensor_records":tensor_records,
    "spectral_records":spectral_records,
    "fixed_aux_records":fixed_aux_records,
    "self_tensor":{"base_S":str(S1),"tensor2_S":str(S2)},
    "parameter_rows":param_rows,
    "capacity_rows":capacity_rows,
    "total_checks":len(checks)
}
print(json.dumps(out,sort_keys=True,indent=2))
