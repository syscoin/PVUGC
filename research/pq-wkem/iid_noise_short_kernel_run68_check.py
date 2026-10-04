#!/usr/bin/env python3
"""Deterministic Run-68 validation for the normalized short-kernel + iid-noise audit.

Standard-library only.  This validates finite algebra/probability identities used by
IID_NOISE_SHORT_KERNEL_RUN68.md.  It is not a cryptographic security proof.
"""

from __future__ import annotations

import cmath
import hashlib
import json
import math
import random
from fractions import Fraction
from typing import Dict, Iterable, List, Sequence, Tuple

SEED = 680067
RNG = random.Random(SEED)
TOL = 2e-11

Literal = int  # +(i+1) for z_i, -(i+1) for not z_i
Clause = Tuple[Literal, Literal, Literal]


def eval_lit(lit: Literal, a: Sequence[int]) -> int:
    idx = abs(lit) - 1
    v = int(a[idx])
    return v if lit > 0 else 1 - v


def eval_clause(c: Clause, a: Sequence[int]) -> bool:
    return any(eval_lit(lit, a) for lit in c)


def build_H(n: int, clauses: Sequence[Clause]) -> List[List[int]]:
    """Compiler from SHORT_KERNEL_LWE_BOUNDARY.md.

    Coordinate 0 is h. Then n variable pairs, followed by two slack pairs per clause.
    """
    m = len(clauses)
    N = n + 2 * m
    d = 1 + 2 * N
    rows: List[List[int]] = []

    def pair_coords(pair_idx: int) -> Tuple[int, int]:
        return 1 + 2 * pair_idx, 2 + 2 * pair_idx

    # pair equations u + ubar - h = 0
    for p in range(N):
        row = [0] * d
        u, ub = pair_coords(p)
        row[u] = 1
        row[ub] = 1
        row[0] = -1
        rows.append(row)

    # clause equations l1+l2+l3+s1+2s2-4h=0
    for j, clause in enumerate(clauses):
        row = [0] * d
        row[0] = -4
        for lit in clause:
            var = abs(lit) - 1
            u, ub = pair_coords(var)
            row[u if lit > 0 else ub] += 1
        s1_pair = n + 2 * j
        s2_pair = n + 2 * j + 1
        s1, _ = pair_coords(s1_pair)
        s2, _ = pair_coords(s2_pair)
        row[s1] += 1
        row[s2] += 2
        rows.append(row)
    return rows


def mat_vec(H: Sequence[Sequence[int]], x: Sequence[int]) -> List[int]:
    return [sum(a * b for a, b in zip(row, x)) for row in H]


def pseudo_vector(n: int, clauses: Sequence[Clause], a: Sequence[int]) -> Tuple[List[int], int, int]:
    """Exact kernel vector for *any* Boolean assignment.

    Returns (x, L, v) where L=n+2m+1 is the number of |coefficient|=1 entries
    and v is the number of violated clauses / number of +2 entries.
    """
    m = len(clauses)
    N = n + 2 * m
    d = 1 + 2 * N
    x = [0] * d
    x[0] = 1

    def set_pair(pair_idx: int, u: int) -> None:
        i = 1 + 2 * pair_idx
        x[i] = u
        x[i + 1] = 1 - u

    for i, bit in enumerate(a):
        set_pair(i, int(bit))

    v = 0
    for j, clause in enumerate(clauses):
        t = sum(eval_lit(lit, a) for lit in clause)
        if t == 3:
            s1, s2 = 1, 0
        elif t == 2:
            s1, s2 = 0, 1
        elif t == 1:
            s1, s2 = 1, 1
        elif t == 0:
            s1, s2 = 0, 2
            v += 1
        else:
            raise AssertionError(t)
        set_pair(n + 2 * j, s1)
        set_pair(n + 2 * j + 1, s2)

    L = N + 1
    return x, L, v


def random_formula(n: int, m: int) -> List[Clause]:
    clauses: List[Clause] = []
    for _ in range(m):
        lits = []
        for _ in range(3):
            var = RNG.randrange(n) + 1
            lits.append(var if RNG.randrange(2) else -var)
        clauses.append(tuple(lits))  # type: ignore[arg-type]
    return clauses


def phi(dist: Sequence[Fraction], t: int) -> complex:
    q = len(dist)
    return sum(float(p) * cmath.exp(2j * math.pi * t * x / q) for x, p in enumerate(dist))


def random_dist(q: int) -> List[Fraction]:
    weights = [RNG.randrange(1, 1000) for _ in range(q)]
    total = sum(weights)
    return [Fraction(w, total) for w in weights]


def convolve_cyclic(p: Sequence[float], d: Sequence[Fraction]) -> List[float]:
    q = len(p)
    out = [0.0] * q
    for i, pi in enumerate(p):
        if pi == 0.0:
            continue
        for j, dj in enumerate(d):
            out[(i + j) % q] += pi * float(dj)
    return out


def convolution_power(dist: Sequence[Fraction], L: int) -> List[float]:
    q = len(dist)
    p = [0.0] * q
    p[0] = 1.0
    base = list(dist)
    for _ in range(L):
        p = convolve_cyclic(p, base)
    return p


def tv_half_shift(p: Sequence[float]) -> float:
    q = len(p)
    assert q % 2 == 0
    return 0.5 * sum(abs(p[x] - p[(x - q // 2) % q]) for x in range(q))


def unit_character(q: int, t: int, z: int) -> complex:
    return cmath.exp(2j * math.pi * t * (z % q) / q)


def enumerate_support_expectation(
    q: int,
    H: Sequence[Sequence[int]],
    x: Sequence[int],
    dist_support: Sequence[Tuple[int, Fraction]],
    t: int,
    mu: int,
    y: Sequence[int],
) -> complex:
    """Exact-enough explicit complete-transcript enumeration for tiny support.

    c = H^T y + e + mu*(q/2)g.  Enumerate independent e support recursively.
    """
    d = len(x)
    base = [0] * d
    for r, yr in enumerate(y):
        for j in range(d):
            base[j] = (base[j] + H[r][j] * yr) % q
    base[0] = (base[0] + mu * (q // 2)) % q

    total = 0j

    def rec(pos: int, prob: Fraction, dot_noise: int) -> None:
        nonlocal total
        if pos == d:
            dot_base = sum(x[j] * base[j] for j in range(d))
            total += float(prob) * unit_character(q, t, dot_base + dot_noise)
            return
        for val, pr in dist_support:
            rec(pos + 1, prob * pr, dot_noise + x[pos] * val)

    rec(0, Fraction(1, 1), 0)
    return total


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def main() -> None:
    results: Dict[str, object] = {
        "schema": "pq-wkem-run68-validation-v1",
        "seed": SEED,
        "claims": {
            "cryptographic_security": False,
            "scope": "normalized short-kernel compiler with public iid additive Z_q noise",
        },
    }

    # 1) Universal arbitrary-assignment pseudovector theorem.
    pseudo_cases = 0
    total_violations = 0
    max_violation_ratio = 0.0
    for _ in range(500):
        n = RNG.randint(1, 9)
        m = RNG.randint(1, 14)
        clauses = random_formula(n, m)
        a = [RNG.randrange(2) for _ in range(n)]
        H = build_H(n, clauses)
        x, L, v = pseudo_vector(n, clauses, a)
        assert all(z == 0 for z in mat_vec(H, x))
        assert x[0] == 1
        v_truth = sum(not eval_clause(c, a) for c in clauses)
        assert v == v_truth
        unit_count = sum(abs(z) == 1 for z in x)
        double_count = sum(z == 2 for z in x)
        other = [z for z in x if abs(z) not in (0, 1, 2)]
        assert unit_count == L
        assert double_count == v
        assert not other
        assert sum(z == -1 for z in x) == v
        assert sum(z * z for z in x) == L + 4 * v
        assert v <= m <= (L - 1) // 2
        pseudo_cases += 1
        total_violations += v
        max_violation_ratio = max(max_violation_ratio, v / L)
    results["universal_pseudovector"] = {
        "cases": pseudo_cases,
        "total_violated_clauses": total_violations,
        "max_v_over_L": max_violation_ratio,
        "all_exact_kernel": True,
    }

    # 2) Positive-definite doubling inequality |phi(2t)| >= max(0,2|phi(t)|^2-1).
    inequalities = 0
    min_margin = float("inf")
    by_q: Dict[str, int] = {}
    for q in (8, 10, 12, 16, 24, 32, 64):
        c = 0
        for _ in range(140):
            d = random_dist(q)
            for t in range(1, q):
                r = abs(phi(d, t))
                lhs = abs(phi(d, 2 * t))
                rhs = max(0.0, 2.0 * r * r - 1.0)
                margin = lhs - rhs
                assert margin >= -TOL, (q, t, lhs, rhs)
                min_margin = min(min_margin, margin)
                inequalities += 1
                c += 1
        by_q[str(q)] = c
    results["doubling_inequality"] = {
        "checks": inequalities,
        "by_q": by_q,
        "min_numeric_margin": min_margin,
    }

    # 3) Sharp notch control: q=8, D uniform on +/-1.
    q = 8
    notch = [Fraction(0, 1)] * q
    notch[1] = Fraction(1, 2)
    notch[7] = Fraction(1, 2)
    p1 = phi(notch, 1)
    p2 = phi(notch, 2)
    assert abs(abs(p1) - 1 / math.sqrt(2)) < 1e-12
    assert abs(p2) < 1e-12
    assert abs(max(0.0, 2 * abs(p1) ** 2 - 1.0)) < 1e-12
    notch_tvs = {}
    for L in (1, 2, 4, 8, 16, 32):
        conv = convolution_power(notch, L)
        notch_tvs[str(L)] = tv_half_shift(conv)
    results["sharp_notch_control"] = {
        "q": 8,
        "abs_phi1": abs(p1),
        "abs_phi2": abs(p2),
        "honest_halfshift_tv_by_L": notch_tvs,
    }

    # 4) Honest half-shift TV -> odd harmonic lower bound.
    harmonic_cases = 0
    min_max_ratio = float("inf")
    max_tv_upper_slack = 0.0
    for q in (8, 10, 12, 16, 20):
        for _ in range(45):
            d = random_dist(q)
            L = RNG.randint(1, 20)
            conv = convolution_power(d, L)
            delta = tv_half_shift(conv)
            betas = [abs(phi(d, t)) ** L for t in range(1, q, 2)]
            s = sum(betas)
            mx = max(betas)
            assert delta <= s + 5e-11, (delta, s)
            assert mx + 5e-11 >= 2 * delta / q, (q, L, mx, delta)
            if delta > 1e-14:
                min_max_ratio = min(min_max_ratio, mx / (2 * delta / q))
            max_tv_upper_slack = max(max_tv_upper_slack, s - delta)
            harmonic_cases += 1
    results["honest_tv_to_odd_harmonic"] = {
        "cases": harmonic_cases,
        "min_ratio_maxbeta_over_2delta_over_q": min_max_ratio,
        "max_sum_beta_minus_tv": max_tv_upper_slack,
    }

    # 5) Explicit complete-transcript character identity on tiny true/false-style pseudovector fixture.
    # One variable, one clause (z OR z OR z), arbitrary assignment z=0 violates it.
    clauses = [(1, 1, 1)]
    H = build_H(1, clauses)
    x, L, v = pseudo_vector(1, clauses, [0])
    assert L == 4 and v == 1
    q = 8
    # Public 2-point noise, not the sharp notch: makes all relevant phases nonzero.
    support = [(0, Fraction(3, 5)), (1, Fraction(2, 5))]
    d = [Fraction(0, 1)] * q
    for z, pr in support:
        d[z] += pr
    y = [RNG.randrange(q) for _ in range(len(H))]
    t = 1
    ex0 = enumerate_support_expectation(q, H, x, support, t, 0, y)
    ex1 = enumerate_support_expectation(q, H, x, support, t, 1, y)
    # predicted product includes L-v +1 coefficients, v -1 coefficients, and v +2 coefficients.
    predicted = (phi(d, t) ** (L - v)) * (phi(d, -t) ** v) * (phi(d, 2 * t) ** v)
    assert abs(ex0 - predicted) < 2e-11, (ex0, predicted)
    assert abs(ex1 + predicted) < 2e-11, (ex1, predicted)
    results["complete_transcript_fixture"] = {
        "q": q,
        "L": L,
        "v": v,
        "support_size_per_coordinate": len(support),
        "enumerated_noise_vectors": len(support) ** len(x),
        "abs_expectation": abs(ex0),
        "abs_predicted": abs(predicted),
        "key_sign_flip_error": abs(ex1 + ex0),
    }

    # 6) Quantitative beta^5 theorem finite controls.
    beta5_cases = 0
    min_ratio_to_beta5 = float("inf")
    for _ in range(3000):
        # choose beta0/beta directly; theorem is analytic in these values
        beta = 10 ** (-RNG.uniform(0.03, 5.0))
        a = math.log(1.0 / beta)
        Lmin = max(2, math.ceil(8.0 * a))
        L = Lmin + RNG.randrange(0, 250)
        v = RNG.randrange(0, L // 2 + 1)
        r = beta ** (1.0 / L)
        twice_lb = max(0.0, 2.0 * r * r - 1.0)
        amp_lb = beta * (twice_lb ** v)
        target = beta ** 5
        # Small floating tolerance for values near one/tiny values.
        assert amp_lb + 1e-14 >= target * (1 - 2e-10), (beta, L, v, amp_lb, target)
        if target > 1e-250:
            min_ratio_to_beta5 = min(min_ratio_to_beta5, amp_lb / target)
        beta5_cases += 1
    results["beta5_bound"] = {
        "cases": beta5_cases,
        "min_ratio_amplitude_lower_bound_over_beta5": min_ratio_to_beta5,
        "condition_checked": "L >= 8 ln(1/beta), v <= L/2",
    }

    # 7) Distribution-level examples with rho*delta0+(1-rho)*uniform, where every nonzero phi=rho.
    # This family also gives a transparent comparison between exact pseudodecoder amplitude and theorem bound.
    mixture_examples = []
    for q, L, v, rho in [
        (8, 64, 20, 0.99),
        (16, 96, 30, 0.995),
        (32, 160, 50, 0.997),
        (64, 256, 80, 0.998),
    ]:
        uniform = Fraction(1, q)
        # Rational approximation to rho for deterministic exact-public distribution.
        rnum = int(round(rho * 1000000))
        rfrac = Fraction(rnum, 1000000)
        d = [(1 - rfrac) * uniform for _ in range(q)]
        d[0] += rfrac
        r1 = abs(phi(d, 1))
        r2 = abs(phi(d, 2))
        beta = r1 ** L
        amp = beta * (r2 ** v)
        condition = L >= 8 * math.log(1 / beta) if beta > 0 else False
        if condition:
            assert amp + 1e-14 >= beta ** 5 * (1 - 2e-10)
        conv = convolution_power(d, L)
        delta = tv_half_shift(conv)
        mixture_examples.append({
            "q": q,
            "L": L,
            "v": v,
            "rho_public": float(rfrac),
            "abs_phi1": r1,
            "abs_phi2": r2,
            "honest_beta": beta,
            "honest_tv": delta,
            "pseudo_character_amplitude": amp,
            "beta5": beta ** 5,
            "guaranteed_from_honest_tv": (2 * delta / q) ** 5,
            "beta5_condition": condition,
        })
    results["mixture_examples"] = mixture_examples

    # 8) A few random real formula + random public D cases: verify exact character magnitude product.
    # No transcript enumeration here; identity is direct from iid factorization and exact Hx=0.
    factor_cases = 0
    min_double_bound_margin = float("inf")
    for _ in range(400):
        n = RNG.randint(1, 7)
        m = RNG.randint(1, 10)
        clauses = random_formula(n, m)
        a_bits = [RNG.randrange(2) for _ in range(n)]
        x, L, v = pseudo_vector(n, clauses, a_bits)
        H = build_H(n, clauses)
        assert all(z == 0 for z in mat_vec(H, x))
        q = RNG.choice([8, 10, 12, 16, 20])
        d = random_dist(q)
        t = RNG.choice(list(range(1, q, 2)))
        r1 = abs(phi(d, t))
        r2 = abs(phi(d, 2 * t))
        actual_mag = 1.0
        for coeff in x:
            actual_mag *= abs(phi(d, coeff * t))
        formula_mag = (r1 ** L) * (r2 ** v)
        assert abs(actual_mag - formula_mag) <= 5e-11 * max(1.0, actual_mag, formula_mag)
        lb2 = max(0.0, 2 * r1 * r1 - 1)
        min_double_bound_margin = min(min_double_bound_margin, r2 - lb2)
        factor_cases += 1
    results["formula_factorization"] = {
        "cases": factor_cases,
        "min_doubling_margin": min_double_bound_margin,
    }

    # Canonical JSON output, with no timestamps, so reruns are byte-identical.
    text = json.dumps(results, sort_keys=True, indent=2, separators=(",", ": ")) + "\n"
    print(text, end="")


if __name__ == "__main__":
    main()
