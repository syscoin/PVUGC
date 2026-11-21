#!/usr/bin/env python3
"""Run 134 deterministic checker: gap-only syndrome-separation barrier.

Standard library only.  This validates finite coding/probability identities and an
asymptotic parameter ledger.  It does not establish cryptographic hardness.
"""
from __future__ import annotations

from collections import defaultdict
from fractions import Fraction
from itertools import product
import hashlib
import json
import math

ASSERTIONS = 0


def check(cond: bool, msg: str) -> None:
    global ASSERTIONS
    ASSERTIONS += 1
    if not cond:
        raise AssertionError(msg)


def weight(v):
    return sum(1 for x in v if x)


def add_scaled(row, coeff, q):
    return [(coeff * x) % q for x in row]


def lincomb(coeffs, H, q):
    m = len(H[0])
    out = [0] * m
    for a, row in zip(coeffs, H):
        for j in range(m):
            out[j] = (out[j] + a * row[j]) % q
    return tuple(out)


def min_distance(H, q):
    k = len(H)
    md = len(H[0]) + 1
    hist = defaultdict(int)
    for coeffs in product(range(q), repeat=k):
        if all(a == 0 for a in coeffs):
            continue
        w = weight(lincomb(coeffs, H, q))
        hist[w] += 1
        md = min(md, w)
    return md, dict(sorted(hist.items()))


def syndrome_dist(H, q, beta: Fraction):
    """Exact law of H E for iid q-symmetric E with character bias beta."""
    k = len(H)
    m = len(H[0])
    p0 = (Fraction(1) + (q - 1) * beta) / q
    pn = (Fraction(1) - beta) / q
    dist = {tuple([0] * k): Fraction(1)}
    for j in range(m):
        col = [H[i][j] for i in range(k)]
        nxt = defaultdict(Fraction)
        for s, ps in dist.items():
            nxt[s] += ps * p0
            for a in range(1, q):
                ns = tuple((s[i] + a * col[i]) % q for i in range(k))
                nxt[ns] += ps * pn
        dist = dict(nxt)
    check(sum(dist.values(), Fraction(0)) == 1, "distribution must normalize")
    return dist


def tv_uniform(dist, q, k):
    u = Fraction(1, q ** k)
    total = Fraction(0)
    for s in product(range(q), repeat=k):
        total += abs(dist.get(s, Fraction(0)) - u)
    return total / 2


def qsym_prob(x, q, gamma: Fraction):
    if x == 0:
        return (Fraction(1) + (q - 1) * gamma) / q
    return (Fraction(1) - gamma) / q


def product_qsym_dist(q, gammas):
    out = {}
    for s in product(range(q), repeat=len(gammas)):
        p = Fraction(1)
        for x, g in zip(s, gammas):
            p *= qsym_prob(x, q, g)
        out[s] = p
    return out


def entropy_qsym(q: int, beta: float) -> float:
    eta = (1.0 - 1.0 / q) * (1.0 - beta)
    if eta == 0.0:
        return 0.0
    h2 = -eta * math.log(eta) - (1.0 - eta) * math.log(1.0 - eta)
    return h2 + eta * math.log(q - 1)


def next_power_of_two(n: int) -> int:
    return 1 << (n - 1).bit_length()


def main():
    # Exact finite pair: same q,m,D,n_act; radically different dimensions.
    q = 7
    m = 6
    D = 3
    k_bad = m - D + 1
    xs = list(range(m))
    # Reed-Solomon evaluation generator (polynomials degree < k_bad).
    H_bad = [[pow(x, j, q) for x in xs] for j in range(k_bad)]
    # Direct sum of two length-D repetition codes.
    H_good = [
        [1, 1, 1, 0, 0, 0],
        [0, 0, 0, 1, 1, 1],
    ]

    md_bad, hist_bad = min_distance(H_bad, q)
    md_good, hist_good = min_distance(H_good, q)
    check(md_bad == D, "RS fixture must have exact distance D")
    check(md_good == D, "block repetition fixture must have exact distance D")
    check(len(H_bad) == 4 and len(H_good) == 2, "fixture dimensions")
    check(all(any(H_bad[i][j] != 0 for i in range(len(H_bad))) for j in range(m)), "bad active columns")
    check(all(any(H_good[i][j] != 0 for i in range(len(H_good))) for j in range(m)), "good active columns")

    beta = Fraction(1, 2)
    dist_bad = syndrome_dist(H_bad, q, beta)
    dist_good = syndrome_dist(H_good, q, beta)
    tv_bad = tv_uniform(dist_bad, q, len(H_bad))
    tv_good = tv_uniform(dist_good, q, len(H_good))

    gamma = beta ** D
    predicted_good = product_qsym_dist(q, [gamma, gamma])
    check(dist_good == predicted_good, "block sums must be independent q-symmetric with bias beta^D")
    one_tv = Fraction(q - 1, q) * gamma
    good_union_bound = len(H_good) * one_tv
    check(tv_good <= good_union_bound, "product-TV hybrid upper bound")

    # Every nonzero Fourier character is indexed by a nonzero codeword, hence <= beta^D.
    max_bad_char = Fraction(0)
    max_good_char = Fraction(0)
    for coeffs in product(range(q), repeat=len(H_bad)):
        if all(a == 0 for a in coeffs):
            continue
        max_bad_char = max(max_bad_char, beta ** weight(lincomb(coeffs, H_bad, q)))
    for coeffs in product(range(q), repeat=len(H_good)):
        if all(a == 0 for a in coeffs):
            continue
        max_good_char = max(max_good_char, beta ** weight(lincomb(coeffs, H_good, q)))
    check(max_bad_char == gamma, "bad max nontrivial character = beta^D")
    check(max_good_char == gamma, "good max nontrivial character = beta^D")

    # Entropy lower bound on TV for a higher-beta finite control.
    beta_hi = 0.8
    H_E = entropy_qsym(q, beta_hi)
    delta_entropy = k_bad * math.log(q) - m * H_E
    tv_entropy_lb = max(0.0, (delta_entropy - math.log(2.0)) / (k_bad * math.log(q)))
    dist_bad_hi = syndrome_dist(H_bad, q, Fraction(4, 5))
    tv_bad_hi = float(tv_uniform(dist_bad_hi, q, k_bad))
    check(tv_bad_hi + 1e-15 >= tv_entropy_lb, "Fannes-derived TV lower bound")

    # Asymptotic separation ledger.  lambda = 2^bits, d=lambda,
    # gap g=(log2 lambda)^2, D=d*g, m=2D, beta^d=1/lambda.
    ledger = []
    for bits in (8, 12, 16, 20):
        lam = 2 ** bits
        d = lam
        g = bits ** 2
        D_as = d * g
        m_as = 2 * D_as
        q_as = next_power_of_two(m_as + 1)  # prime-power field size >= m
        beta_as = math.exp(-math.log(lam) / d)
        k_bad_as = m_as - D_as + 1
        H_E_as = entropy_qsym(q_as, beta_as)
        delta_as = k_bad_as * math.log(q_as) - m_as * H_E_as
        bad_tv_lb = max(0.0, (delta_as - math.log(2.0)) / (k_bad_as * math.log(q_as)))
        good_log2_tv_ub = math.log2(2.0 * (1.0 - 1.0 / q_as)) + D_as * math.log2(beta_as)
        max_char_log2 = D_as * math.log2(beta_as)
        # Exact algebraic target: D/d=g and beta^D=lambda^-g=2^(-bits^3).
        check(D_as // d == g and D_as % d == 0, "gap ratio")
        check(abs(max_char_log2 + bits ** 3) < 1e-7, "max-character exponent identity")
        check(g > bits, "gap grows faster than log2(lambda) on ledger points")
        check(bad_tv_lb > 0.90, "high-rate bad family has constant/near-unit TV lower bound")
        check(good_log2_tv_ub < -500, "low-rate good family has negligible TV upper bound")
        ledger.append({
            "log2_lambda": bits,
            "d": d,
            "gap_ratio_D_over_d": g,
            "D": D_as,
            "m": m_as,
            "q_prime_power": q_as,
            "beta": beta_as,
            "max_nontrivial_character_log2": max_char_log2,
            "good_tv_upper_log2": good_log2_tv_ub,
            "bad_tv_lower": bad_tv_lb,
            "bad_rate": k_bad_as / m_as,
            "noise_entropy_rate": H_E_as / math.log(q_as),
        })

    result = {
        "run": 134,
        "theorem_scope": "gap-only false-syndrome separation; no hardness claim",
        "finite_fixture": {
            "q": q,
            "m": m,
            "D": D,
            "bad_code": {"type": "Reed-Solomon", "dimension": len(H_bad), "min_distance": md_bad, "weight_histogram": hist_bad},
            "good_code": {"type": "direct_sum_repetition", "dimension": len(H_good), "min_distance": md_good, "weight_histogram": hist_good},
            "beta": str(beta),
            "max_nontrivial_character": str(gamma),
            "tv_bad": str(tv_bad),
            "tv_bad_float": float(tv_bad),
            "tv_good": str(tv_good),
            "tv_good_float": float(tv_good),
            "good_tv_hybrid_upper": str(good_union_bound),
            "beta_hi_entropy_control": {
                "beta": beta_hi,
                "entropy_tv_lower_bound": tv_entropy_lb,
                "exact_bad_tv": tv_bad_hi,
            },
        },
        "asymptotic_ledger": ledger,
        "assertions": ASSERTIONS,
    }
    raw = json.dumps(result, sort_keys=True, indent=2) + "\n"
    print(raw, end="")


if __name__ == "__main__":
    main()
