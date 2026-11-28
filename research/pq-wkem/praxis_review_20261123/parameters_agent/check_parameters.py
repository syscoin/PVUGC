#!/usr/bin/env python3
"""Own exact arithmetic audit of selected public Praxis constants.

Source: Praxis Table 4 and praxis-lean Constants.lean at
60d3defeebd77caa0e57babe97991e672b948bb6.
No downloaded implementation is executed. This is not cryptanalysis or a
reproduction of the lattice estimator / Lean build / concrete timings.
"""
from fractions import Fraction
from math import isqrt, log, log2, pi, sqrt
import json

q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
N = 391693
g = 1736375024658487
theta = Fraction((1 << 20) - 1, 1 << 221)
beta = 243263909612554812554484966287587365620785086315305388991
d, k, ell = 64, 71, 6121
n, c0 = 4608, 5
D, K1, K2 = 3861007, 192, 12
L1, L2, LT = 151468814, 56828073, 2
L = L1+L2+LT
beta_kummer = 15455056031545522072329890326622223210121953105925913337013641664433101999706
assert (g-1)**8 < 2**405 <= g**8
assert Fraction(1, g**4) <= Fraction(1, 2**202) < theta < Fraction(1, 2**201)
assert theta < Fraction(1, g**3) < Fraction(1, g**2)
assert 24 * beta**4 < q**3
assert 2*beta < q
assert 2*(N+1)*(g+1)+1 < q
assert (q-1) % (2*d) == 0
assert (q-1) % n == 0 and n == 2**9*3**2
assert q % 4 == 1
# The binomial irreducibility criterion for X^n-c0 over F_q applies because
# n divides q-1. Here n has exactly the prime divisors 2 and 3; c0 is neither
# a square nor a cube. Primality of q is assumed from the paper/BN254 parameter,
# not independently certified by this arithmetic script.
kummer_power_tests = {str(p): pow(c0, (q-1)//p, q) for p in [2,3]}
assert all(v != 1 for v in kummer_power_tests.values())
assert beta_kummer == pow(c0, (q-1)//n, q)
assert pow(beta_kummer,n,q) == 1
assert all(pow(beta_kummer,n//p,q) != 1 for p in [2,3])
assert pow(beta_kummer,n//2,q) == q-1
assert n == (k+1)*d and ell*d-d < N <= ell*d
assert K1*K2 == n//2

# Exact rational evaluation of Definition B.1, using the public label counts
# in Constants.lean. No floating-point quantity is used in these assertions.
choose2 = lambda v: v*(v-1)//2
eps_f = Fraction(3*D+2*n+2*K1+67, q-D)
n_free = 2**254 - L - 3*2**101 - 1
assert 3*(L+3*2**101+1) <= q and n_free > 0
def E(u):
    n_cmp = u*L + u*(u+1)//2
    return ((choose2(L1)+choose2(L2)+choose2(LT)+L)*eps_f
        + n_cmp*(theta+eps_f)
        + (choose2(L+3*u)+L+3*u)*eps_f
        + (8*u+8)*eps_f
        + Fraction(2*L+4*u+2**102, n_free)
        + Fraction(4*u,2**126)+Fraction(1,2**128))
E2 = E(2)
Ecap_minus_E2 = E(2**101)-E2
generic_slack = 1-Fraction(1,2**100)-Ecap_minus_E2
assert E2 < Fraction(1,2**122)
assert generic_slack >= 0

root = next(pow(a, (q-1)//(2*d), q) for a in range(2, 100)
            if pow(pow(a, (q-1)//(2*d), q), d, q) == q-1)
assert pow(root, 2*d, q) == 1
roots = {pow(root, 2*j+1, q) for j in range(d)}
assert len(roots) == d and all(pow(r,d,q) == q-1 for r in roots)

# If an integer polynomial z of degree <64 is nonzero and coefficient bounded
# by beta, |Norm(z)| <= ||z||_2^64 <= (64 beta^2)^32. At the split prime q,
# vanishing at v distinct CRT roots implies q^v divides its nonzero norm.
norm_upper = (d * beta**2)**(d//2)
max_zeros_allowed_by_norm = max(v for v in range(d+1) if q**v <= norm_upper)
assert max_zeros_allowed_by_norm == 48

# A short nontrivial zero divisor exists; this alone is not a matrix-kernel
# solution. Cornacchia yields q = a^2+b^2. One of a +/- b*X^32 vanishes on
# 32 CRT roots. It need not annihilate a random 71-row column.
i = pow(root, d//2, q)
assert i*i % q == q-1
a, b = q, i
while b*b > q:
    a, b = b, a % b
other = isqrt(q-b*b)
assert other*other+b*b == q
zero_divisor = [b, other]
counts = [sum((b + sign*other*pow(r,32,q)) % q == 0 for r in roots)
          for sign in [1,-1]]
assert counts == [32,32]

# Heuristic GSA sanity check ONLY: no attack code or MATZOV cost model.
block = 242
delta = ((block/(2*pi*2.718281828459045)) *
         (pi*block)**(1/block))**(1/(2*(block-1)))
n_eff = d*k
log_det = n_eff*log2(q)
m_opt = sqrt(log_det / log2(delta))
short_l2_log = log_det/m_opt + m_opt*log2(delta)
gaussian_max_coordinate_log = short_l2_log - 0.5*log2(m_opt) + 0.5*log2(2*log(m_opt))

out = {
  "exact_checks_passed": True,
  "source_commit": "60d3defeebd77caa0e57babe97991e672b948bb6",
  "constants_blob": "494e9eac6cc1ddc94e1cddb92f8e8d69a57a7276",
  "q_exact": str(q),
  "beta_eta_exact": str(beta),
  "q_primality_independently_certified": False,
  "kummer_n_divides_q_minus_one": True,
  "kummer_n_prime_divisors": [2,3],
  "kummer_nonpower_residues": {p:str(v) for p,v in kummer_power_tests.items()},
  "kummer_irreducibility_criterion_checked_given_q_prime": True,
  "kummer_beta_exact_order": n,
  "E2_exact": str(E2),
  "E2_log2": log2(E2.numerator)-log2(E2.denominator),
  "Ecap_minus_E2_exact": str(Ecap_minus_E2),
  "Ecap_generic_slack_exact": str(generic_slack),
  "Ecap_generic_slack_log2": log2(generic_slack.numerator)-log2(generic_slack.denominator),
  "q_bits": log2(q), "g_bits": log2(g), "beta_bits": log2(beta),
  "coefficient_constraint_rows": k*d,
  "coefficient_output_dimension": ell*d,
  "ring_splits_into_distinct_linear_factors": len(roots),
  "norm_obstruction_max_zero_crt_slots": max_zeros_allowed_by_norm,
  "norm_obstruction_min_active_crt_slots": d-max_zeros_allowed_by_norm,
  "short_zero_divisor_coefficients": zero_divisor,
  "short_zero_divisor_log2_max_coefficient": log2(max(zero_divisor)),
  "short_zero_divisor_vanishing_slots": counts,
  "zero_divisor_is_not_msis_kernel_solution": True,
  "gsa_heuristic_only": {"block":block,"log2_delta":log2(delta),
    "optimal_dimension_approx":m_opt,
    "predicted_log2_max_coefficient_approx":gaussian_max_coordinate_log},
  "composite_budget_example_log2": log2(2**100+2**65*2**37),
  "paper_dlp_budget_quoted_log2": 103,
  "paper_msis_attack_estimate_quoted_log2": 103.5,
  "paper_reduction_estimate_quoted_log2": 108,
  "no_independent_msis_cost_certification": True,
}
print(json.dumps(out,indent=2,sort_keys=True))
