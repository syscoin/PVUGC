#!/usr/bin/env python3
import json, math, random
from fractions import Fraction

SEED = 800080001
rng = random.Random(SEED)

def tv(P,Q):
    keys=set(P)|set(Q)
    return sum(abs(P.get(k,Fraction(0))-Q.get(k,Fraction(0))) for k in keys)/2

def acceptance_gap(P,Q,q):
    # q[x] is the acceptance probability of an arbitrary algorithm on
    # classical input x.  A QPT algorithm receiving only a classical sample
    # also induces such a number for every x.
    keys=set(P)|set(Q)
    return abs(sum((P.get(k,0)-Q.get(k,0))*q[k] for k in keys))

def hybrid_counts(t,w):
    # Conservative counts from the visible proof skeleton:
    # first step: t layers, at most two outgoing edge encodings per width node;
    # second step: 2^t evaluation strings, 2t sub-hybrids each.
    n_extra = 2*t*w
    n_lwe = 2*t*(2**t)
    return n_extra,n_lwe

def required_bits(t,w,target_bits=128):
    a,l=hybrid_counts(t,w)
    n=a+l
    loss=math.ceil(math.log2(n))
    return {
        "t":t, "w":w,
        "extra_assumption_steps_upper_control":a,
        "standard_lwe_steps_upper_control":l,
        "total_steps_upper_control":n,
        "ceil_log2_hybrid_loss":loss,
        "per_step_bits_for_final_%d_bits"%target_bits: target_bits+loss
    }

# 1. Classical statistical distance == trace distance of diagonal states,
# and every bounded acceptance functional is dominated by TV.
distance_checks=0
max_gap_ratio=Fraction(0)
for _ in range(600):
    n=rng.randint(2,12)
    a=[rng.randint(0,20) for _ in range(n)]
    b=[rng.randint(0,20) for _ in range(n)]
    if sum(a)==0: a[0]=1
    if sum(b)==0: b[0]=1
    P={i:Fraction(a[i],sum(a)) for i in range(n)}
    Q={i:Fraction(b[i],sum(b)) for i in range(n)}
    d=tv(P,Q)
    # Diagonal density matrices have eigenvalues P_i-Q_i, so trace distance
    # is exactly 1/2 sum_i |P_i-Q_i| = TV. We check the arithmetic identity.
    diag_trace=Fraction(sum(abs(P[i]-Q[i]) for i in range(n)),2)
    assert d==diag_trace
    q={i:Fraction(rng.randint(0,1000),1000) for i in range(n)}
    g=acceptance_gap(P,Q,q)
    assert g <= d
    if d:
        max_gap_ratio=max(max_gap_ratio,g/d)
    distance_checks += 1

# 2. Exact telescoping / hybrid triangle inequality on synthetic acceptance
# probabilities. This is model-independent arithmetic; it does not establish
# that any cryptographic neighboring hybrids are QPT-indistinguishable.
hybrid_checks=0
for _ in range(1000):
    m=rng.randint(2,200)
    ps=[Fraction(rng.randint(0,1000000),1000000) for _ in range(m+1)]
    endpoint=abs(ps[-1]-ps[0])
    telescoped=sum(abs(ps[i+1]-ps[i]) for i in range(m))
    assert endpoint <= telescoped
    hybrid_checks += 1

# 3. Concrete loss ledger for the visible Tsabary proof skeleton.
loss_rows=[required_bits(t,w) for t,w in [
    (8,64),(16,128),(32,256),(64,512),(128,1024)
]]

# 4. Demonstrate why "negligible per step" alone is insufficient under an
# exponential number of hybrids. eps(lambda)=2^{-sqrt(lambda)} is negligible,
# but with t=lambda the log2 union bound is about lambda-sqrt(lambda).
# This numerical table only illustrates the exact exponent; the proof of
# negligibility/non-negligibility is mathematical, not experimental.
exp_loss=[]
for lam in [64,128,256,512,1024,2048,4096]:
    t=lam
    log2_steps=math.log2(2*t)+t
    log2_eps=-math.sqrt(lam)
    exp_loss.append({
        "lambda":lam,
        "log2_steps_for_2t2^t":log2_steps,
        "log2_per_step_eps_2^-sqrtlambda":log2_eps,
        "log2_union_bound":log2_steps+log2_eps
    })

# 5. In contrast, polynomially many hybrids preserve every negligible
# function. Use t=ceil(log2 lambda), for which 2t2^t is polynomial.
poly_loss=[]
for lam in [64,128,256,512,1024,2048,4096]:
    t=math.ceil(math.log2(lam))
    steps=2*t*(2**t)
    poly_loss.append({
        "lambda":lam,
        "t_ceil_log2lambda":t,
        "steps":steps,
        "steps_over_lambda_loglambda":steps/(lam*math.log2(lam))
    })

report={
    "seed":SEED,
    "scope":"arithmetic/model-boundary validation only; no cryptographic or QPT security inferred",
    "classical_tv_equals_diagonal_trace_distance_checks":distance_checks,
    "max_sampled_bounded_acceptance_gap_over_tv":float(max_gap_ratio),
    "hybrid_triangle_inequality_checks":hybrid_checks,
    "visible_skeleton_loss_rows":loss_rows,
    "exponential_hybrid_negligible_countercontrol":exp_loss,
    "polynomial_hybrid_control":poly_loss,
    "status":"PASS"
}
print(json.dumps(report, indent=2, sort_keys=True))
