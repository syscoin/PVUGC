#!/usr/bin/env python3
from __future__ import annotations
from fractions import Fraction
from itertools import product
import json


def eval_poly(coeffs, x, p):
    acc = 0
    power = 1
    for c in coeffs:
        acc = (acc + c * power) % p
        power = (power * x) % p
    return acc


def low_degree_vectors(p, degree_lt):
    return {
        tuple(eval_poly(coeffs, x, p) for x in range(p))
        for coeffs in product(range(p), repeat=degree_lt)
    }


def prefix_extension_accepts(vec, p, degree_lt):
    # Determine whether the first degree_lt+1 evaluations lie on a polynomial
    # of degree < degree_lt. Brute-force coefficients; finite-check only.
    xs = range(degree_lt + 1)
    target = tuple(vec[x] for x in xs)
    for coeffs in product(range(p), repeat=degree_lt):
        if tuple(eval_poly(coeffs, x, p) for x in xs) == target:
            return True
    return False


def composition_lower_bound(p_recover, eps_tiny, eps_knowledge):
    # If the tiny extractor produces an accepted proof with probability at least
    # p_recover-eps_tiny, and an online/straight-line knowledge extractor has
    # extraction error at most eps_knowledge under a perfect simulation, then
    # original-witness output is at least the union-bound expression below.
    return max(Fraction(0), p_recover - eps_tiny - eps_knowledge)


def main():
    checks = 0
    qwise = []
    for p, q in [(3, 1), (5, 1), (5, 2), (7, 1)]:
        k = 2 * q
        assert k < p
        fam = low_degree_vectors(p, k)
        assert len(fam) == p ** k
        checks += 1

        # Full-table membership distinguishes the low-degree family from a
        # uniformly random function with exact advantage 1-p^(k-p).
        full_adv = Fraction(1) - Fraction(p ** k, p ** p)
        assert full_adv == Fraction(p ** p - p ** k, p ** p)
        checks += 1

        # Merely exposing k+1 = 2q+1 ordinary evaluations already distinguishes:
        # a degree < k polynomial always passes interpolation consistency,
        # while a uniform function passes with probability exactly 1/p.
        # We enumerate when the total function space is small enough.
        if p <= 5:
            total = p ** p
            accepted = 0
            for vec in product(range(p), repeat=p):
                if prefix_extension_accepts(vec, p, k):
                    accepted += 1
            assert accepted == total // p
            checks += 1
            prefix_adv = Fraction(p - 1, p)
        else:
            prefix_adv = Fraction(p - 1, p)

        qwise.append({
            "field_prime": p,
            "quantum_query_bound_q": q,
            "independence_degree": k,
            "family_size": len(fam),
            "all_function_count": p ** p,
            "full_description_membership_advantage": str(full_adv),
            "two_q_plus_one_evaluation_test_advantage": str(prefix_adv),
        })

    composition_cases = []
    for vals in [
        (Fraction(3, 4), Fraction(1, 16), Fraction(1, 32)),
        (Fraction(9, 10), Fraction(1, 100), Fraction(1, 1000)),
        (Fraction(1, 2), Fraction(1, 8), Fraction(1, 8)),
    ]:
        p, et, ek = vals
        lb = composition_lower_bound(p, et, ek)
        assert lb <= p
        assert lb >= 0
        checks += 2
        composition_cases.append({
            "key_recovery_success": str(p),
            "tiny_extractor_loss": str(et),
            "knowledge_extraction_error": str(ek),
            "original_witness_success_lower_bound": str(lb),
        })

    out = {
        "run": 204,
        "status": "finite algebra/probability checks only",
        "checks": checks,
        "qwise_description_exposure": qwise,
        "straight_line_composition_examples": composition_cases,
        "claims_not_tested": [
            "QROM theorem proofs",
            "Jin tiny-WE quantum security",
            "standard-model compilation of a QROM verifier",
            "practical WKEM security",
        ],
    }
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
