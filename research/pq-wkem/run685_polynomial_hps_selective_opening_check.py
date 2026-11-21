#!/usr/bin/env python3
"""Exact finite checks for a polynomially correlated HPS-hashing-key family.
Research toy arithmetic only; no cryptographic-size/security claims.
"""
import itertools
import json
from collections import Counter

Q, MOD, G, A = 11, 23, 2, 3
H = pow(G, A, MOD)
R, T = 2, 6  # W=(g^R,h^T) is FALSE because R != T.
COUNTS = Counter()

def chk(b, category):
    assert b, category
    COUNTS[category] += 1

def evalpoly(coeff, x):
    return sum(c * pow(x, j, Q) for j, c in enumerate(coeff)) % Q

def inv(x):
    return pow(x % Q, -1, Q)

def lagrange(xs, target):
    coefficients = []
    for j, xj in enumerate(xs):
        numerator, denominator = 1, 1
        for k, xk in enumerate(xs):
            if j != k:
                numerator = numerator * (target - xk) % Q
                denominator = denominator * (xj - xk) % Q
        coefficients.append(numerator * inv(denominator) % Q)
    return coefficients

def poly_key(beta, theta):
    alpha = tuple((theta[j] - A * beta[j]) % Q for j in range(len(beta)))
    return alpha, beta

def mask(alpha, beta, x, r=R, t=T):
    al, be = evalpoly(alpha, x), evalpoly(beta, x)
    return pow(G, (r * al + A * t * be) % Q, MOD)

def projection(alpha, beta, x):
    return pow(G, (evalpoly(alpha, x) + A * evalpoly(beta, x)) % Q, MOD)

def exact_conditional_fiber(degree):
    theta = tuple((3 + 2 * j) % Q for j in range(degree + 1))
    xs = list(range(degree + 2))
    histogram = Counter()
    for beta in itertools.product(range(Q), repeat=degree + 1):
        alpha, beta = poly_key(beta, theta)
        masks = tuple(mask(alpha, beta, x) for x in xs)
        histogram[masks] += 1
        for x in xs:
            chk(projection(alpha, beta, x) == pow(G, evalpoly(theta, x), MOD), "projection_consistency")
        for x in xs[:-1]:
            for witness in range(Q):
                chk(mask(alpha, beta, x, witness, witness) == pow(projection(alpha, beta, x), witness, MOD), "true_projectivity")
        coeffs = lagrange(xs[:-1], xs[-1])
        reconstructed = 1
        for y, c in zip(masks[:-1], coeffs):
            reconstructed = reconstructed * pow(y, c, MOD) % MOD
        chk(reconstructed == masks[-1], "interpolation")
    # k=d+1 masks jointly uniform; the additional coordinate is determined.
    prefix = Counter({tuple(k[:-1]): v for k, v in histogram.items()})
    chk(len(prefix) == Q ** (degree + 1), "uniform_prefix_support")
    chk(set(prefix.values()) == {1}, "uniform_prefix_multiplicity")
    chk(len(histogram) == Q ** (degree + 1), "joint_support_size")
    return {"degree": degree, "distinct_public_slots": len(xs),
            "conditional_key_fiber_size": Q ** (degree + 1),
            "joint_mask_support": len(histogram),
            "full_independent_support": Q ** len(xs),
            "lagrange_coefficients": lagrange(xs[:-1], xs[-1])}

def actual_lawful_opening_attack():
    theta=(3,5)
    xs=(0,1,2)
    coeffs=lagrange(xs[:2], xs[2])
    tested=0
    for beta in itertools.product(range(Q), repeat=2):
        alpha,beta=poly_key(beta,theta)
        P=[projection(alpha,beta,x) for x in xs]
        B=[mask(alpha,beta,x) for x in xs]
        for mb0 in range(Q):
            for mb1 in range(Q):
                for mt in range(Q):
                    M0, M1, MT = (pow(G,k,MOD) for k in (mb0,mb1,mt))
                    # Lawfully open B0 and B1 through their TRUE alternate clauses.
                    true0=3; true1=7
                    ctrue0=M0*pow(P[0],true0,MOD)%MOD
                    ctrue1=M1*pow(P[1],true1,MOD)%MOD
                    open0=ctrue0*pow(pow(P[0],true0,MOD),-1,MOD)%MOD
                    open1=ctrue1*pow(pow(P[1],true1,MOD),-1,MOD)%MOD
                    false0=M0*B[0]%MOD
                    false1=M1*B[1]%MOD
                    target=MT*B[2]%MOD
                    known=[false0*pow(open0,-1,MOD)%MOD,false1*pow(open1,-1,MOD)%MOD]
                    predicted=pow(known[0],coeffs[0],MOD)*pow(known[1],coeffs[1],MOD)%MOD
                    recovered=target*pow(predicted,-1,MOD)%MOD
                    chk(recovered==MT,"lawful_opening_key_recovery")
                    tested+=1
    return tested

def negative_control_independent():
    # In the fresh-independent-key model, for every pair of known masks,
    # each target mask occurs equally often (one each in the ideal finite model).
    outcomes=Counter()
    for b0,b1,b2 in itertools.product(range(Q),repeat=3):
        outcomes[(pow(G,b0,MOD),pow(G,b1,MOD),pow(G,b2,MOD))]+=1
    chk(len(outcomes)==Q**3,"fresh_independent_support")
    chk(set(outcomes.values())=={1},"fresh_independent_uniform")
    return len(outcomes)

def check_pairwise_independence_of_unconditioned_slot_keys():
    # For degree one, two distinct (alpha,beta) slot keys are jointly uniform.
    outputs=Counter()
    for a0,a1,b0,b1 in itertools.product(range(Q),repeat=4):
        outputs[((a0,b0),((a0+a1)%Q,(b0+b1)%Q))]+=1
    chk(len(outputs)==Q**4,"raw_pairwise_key_support")
    chk(set(outputs.values())=={1},"raw_pairwise_key_uniform")
    return len(outputs)

if __name__=="__main__":
    result={
        "run":685,
        "toy_group":{"prime_order":Q,"modulus":MOD,"generator":G,"h":H,
                     "false_word_exponents":[R,T]},
        "conditional_fibers":[exact_conditional_fiber(1),exact_conditional_fiber(2)],
        "raw_pairwise_key_support":check_pairwise_independence_of_unconditioned_slot_keys(),
        "lawful_opening_recovery_cases":actual_lawful_opening_attack(),
        "fresh_independent_mask_triples":negative_control_independent(),
    }
    result["assertions_by_category"]=dict(sorted(COUNTS.items()))
    result["total_assertions"]=sum(COUNTS.values())
    result["limitations"]=["finite algebra only", "discrete-log group is not post-quantum",
                           "no generic-NP source compiler", "no arbitrary-QPT ORIGINAL extraction"]
    print(json.dumps(result,sort_keys=True,indent=2))
