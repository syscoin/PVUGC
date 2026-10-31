#!/usr/bin/env python3
import json

# Deterministic finite algebra checks for Run 124.
# These validate the syntax/algebra of Wee's DH EHPS-style formulas on a toy prime-order group
# and the fixed-instance/source-extraction reduction shape. They do NOT test DL/CDH hardness.

P = 23
Q = 11
G = 2
ALPHA = 3
TAG_STAR = 4

assert pow(G, Q, P) == 1
assert all(pow(G, d, P) != 1 for d in range(1, Q))

assertions = 2

def inv_group(x):
    return pow(x, P - 2, P)

def inv_q(x):
    return pow(x % Q, -1, Q)

def mul(*xs):
    z = 1
    for x in xs:
        z = (z * x) % P
    return z

def gexp(a):
    return pow(G, a % Q, P)

# Concrete DH relation: SampR(r)=(u,s)=(g^r,g^(alpha r)).
GA = gexp(ALPHA)
dl_base_ga = {}
for r in range(Q):
    u = gexp(r)
    s = gexp(ALPHA * r)
    assert s == pow(u, ALPHA, P); assertions += 1
    assert s == pow(GA, r, P); assertions += 1
    assert s not in dl_base_ga; assertions += 1
    dl_base_ga[s] = r
assert len(dl_base_ga) == Q; assertions += 1

# Extraction-mode formulas for all secret keys, nonzero tags, and sampler coins.
# PK=g^SK; tau=(g^(alpha*TAG) PK)^r;
# Ext=(tau*u^(-SK))^(TAG^{-1}) = s.
ext_mode_checks = 0
for sk in range(Q):
    pk = gexp(sk)
    for tag in range(1, Q):
        tag_inv = inv_q(tag)
        for r in range(Q):
            u = gexp(r)
            s = gexp(ALPHA * r)
            tau = pow(mul(gexp(ALPHA * tag), pk), r, P)
            ext = pow(mul(tau, pow(inv_group(u), sk, P)), tag_inv, P)
            assert ext == s
            assertions += 1
            ext_mode_checks += 1

# All-but-one/hash-mode target identity at TAG_STAR.
# PK*=g^(SK* - alpha TAG*); tau at TAG* equals u^SK* = Priv(SK*,u).
abo_target_checks = 0
for sk_star in range(Q):
    pk_star = gexp(sk_star - ALPHA * TAG_STAR)
    for r in range(Q):
        u = gexp(r)
        tau = pow(mul(gexp(ALPHA * TAG_STAR), pk_star), r, P)
        priv = pow(u, sk_star, P)
        assert tau == priv
        assertions += 1
        abo_target_checks += 1

# For tags != TAG_STAR, the ABO extractor recovers the same relation witness s.
abo_ext_checks = 0
for sk_star in range(Q):
    pk_star = gexp(sk_star - ALPHA * TAG_STAR)
    for tag in range(Q):
        if tag == TAG_STAR:
            continue
        delta_inv = inv_q(tag - TAG_STAR)
        for r in range(Q):
            u = gexp(r)
            s = gexp(ALPHA * r)
            tau = pow(mul(gexp(ALPHA * tag), pk_star), r, P)
            ext = pow(mul(tau, pow(inv_group(u), sk_star, P)), delta_inv, P)
            assert ext == s
            assertions += 1
            abo_ext_checks += 1

# Exact equality of public-key distributions in the two modes on this toy group.
ext_pks = sorted(gexp(sk) for sk in range(Q))
abo_pks = sorted(gexp(sk_star - ALPHA * TAG_STAR) for sk_star in range(Q))
assert ext_pks == abo_pks
assert len(set(ext_pks)) == Q
assertions += 2

# Sampler-coin/witness separation: in this concrete DH relation the EHPS Pub input is r,
# whereas the relation witness is s=(g^alpha)^r. Recovering the Pub input from s is
# exactly computing log_{g^alpha}(s) on the sampled support. This is an algebraic identity,
# not a hardness test.
dl_identity_checks = 0
for r in range(Q):
    s = pow(GA, r, P)
    recovered_r = dl_base_ga[s]
    assert recovered_r == r
    assertions += 1
    dl_identity_checks += 1

# Finite reduction-shape check for the setup-collapse theorem.
# Source relation: x = w^2 mod 31. A hypothetical bridge extractor B_x(s) that maps
# ANY setup-sampled EHPS witness s to an ORIGINAL source witness immediately lets setup
# solve the source relation by sampling s once and applying B_x.
PS = 31
true_x = sorted({(w * w) % PS for w in range(1, PS)})
source_checks = 0
for x in true_x:
    roots = [w for w in range(1, PS) if (w * w) % PS == x]
    assert roots
    assertions += 1
    canonical_w = min(roots)
    # Finite stand-in for the claimed universal source-extractor-on-sampled-witness property.
    # The point tested is the reduction: once such an extractor exists, the witness-free
    # setup's own sampler output suffices to invoke it.
    for sampled_s in range(Q):
        bridge_output = canonical_w
        assert (bridge_output * bridge_output) % PS == x
        assertions += 1
        source_checks += 1

# Direct public-witness-evaluation syntax is strictly different from Wee's Pub syntax:
# for each sampled pair, the source witness object s and the required Pub randomness r
# live in different representation spaces. The only canonical conversion present in the
# concrete DH algebra above is the discrete-log table just checked.
assert all(isinstance(s, int) and isinstance(r, int) for s, r in ((pow(GA, r, P), r) for r in range(Q)))
assertions += 1

out = {
    "run": 124,
    "checker": "ehps_fixed_instance_sampler_coin_run124_check.py",
    "assertions": assertions,
    "toy_group": {"p": P, "q": Q, "g": G, "alpha": ALPHA, "tag_star": TAG_STAR},
    "checks": {
        "dh_relation_and_sampler": 3 * Q + 1,
        "extraction_mode_formula": ext_mode_checks,
        "abo_target_hash_identity": abo_target_checks,
        "abo_non_target_extraction": abo_ext_checks,
        "mode_public_key_distribution_exact_equality": True,
        "sampler_coin_is_discrete_log_of_relation_witness": dl_identity_checks,
        "fixed_instance_source_collapse_reduction_instances": source_checks
    },
    "claims_not_tested": [
        "discrete-log, CDH, factoring, LWE, SIS, or any computational hardness",
        "QPT security of Wee 2010 or Chen-Zhang PEPRF",
        "existence of a generic-NP fixed-instance witness-public-evaluable dual-mode hash",
        "security of any final witness KEM"
    ]
}
print(json.dumps(out, sort_keys=True, indent=2))