#!/usr/bin/env python3
import cmath
import json
import math
import random
from collections import Counter

SEED = 202609221641
RNG = random.Random(SEED)


def fourier(counts, k):
    q = len(counts)
    tot = sum(counts)
    w = cmath.exp(2j * math.pi / q)
    return sum(c * (w ** (k * x)) for x, c in enumerate(counts)) / tot


def compositions(total, parts):
    if parts == 1:
        yield (total,)
        return
    for x in range(total + 1):
        for rest in compositions(total - x, parts - 1):
            yield (x,) + rest


def scalar_moment_census():
    out = []
    min_slack = 1e9
    checked = 0
    for q, M in [(5, 7), (7, 6)]:
        local_min = 1e9
        local_checked = 0
        worst = None
        for counts in compositions(M, q):
            p1 = fourier(counts, 1)
            p2 = fourier(counts, 2)
            a = abs(p1)
            bound = max(0.0, 2.0 * a * a - 1.0)
            slack = abs(p2) - bound
            if slack < local_min:
                local_min = slack
                worst = counts
            if slack < -2e-12:
                raise AssertionError((q, M, counts, a, abs(p2), bound, slack))
            local_checked += 1
        checked += local_checked
        min_slack = min(min_slack, local_min)
        out.append({
            "q": q,
            "denominator": M,
            "laws_checked": local_checked,
            "minimum_numeric_slack": local_min,
            "argmin_counts": list(worst),
        })
    return {"groups": out, "total_laws_checked": checked, "minimum_numeric_slack": min_slack}


def sharp_two_point_checks():
    rows = []
    for q in [5, 7, 11, 17, 31, 64, 127, 257]:
        counts = [0] * q
        counts[1] = 1
        counts[-1] = 1
        p1 = fourier(counts, 1)
        p2 = fourier(counts, 2)
        lhs = p2.real
        rhs = 2 * (p1.real ** 2) - 1
        err = abs(lhs - rhs) + abs(p1.imag) + abs(p2.imag)
        if err > 2e-11:
            raise AssertionError((q, p1, p2, rhs, err))
        rows.append({"q": q, "phi1": p1.real, "phi2": p2.real, "identity_error": err})
    return rows


def build_compiler(nvars, clauses):
    m = len(clauses)
    npairs = nvars + 2 * m
    ncoord = 1 + 2 * npairs
    pairs = [(1 + 2 * i, 2 + 2 * i) for i in range(npairs)]
    H = []
    for u, ub in pairs:
        row = [0] * ncoord
        row[0] = -1
        row[u] = 1
        row[ub] = 1
        H.append(row)
    for j, clause in enumerate(clauses):
        row = [0] * ncoord
        row[0] = -4
        for lit in clause:
            vi = abs(lit) - 1
            u, ub = pairs[vi]
            row[u if lit > 0 else ub] += 1
        row[pairs[nvars + 2 * j][0]] += 1
        row[pairs[nvars + 2 * j + 1][0]] += 2
        H.append(row)
    return H, pairs


def matvec(H, x):
    return [sum(a * b for a, b in zip(row, x)) for row in H]


def contradiction_false_vector(dummy_vars):
    nvars = 1 + dummy_vars
    clauses = [(1, 1, 1), (-1, -1, -1)]
    H, pairs = build_compiler(nvars, clauses)
    x = [0] * len(H[0])
    x[0] = 1
    for i in range(nvars):
        u, ub = pairs[i]
        x[u], x[ub] = 0, 1
    vals = [0, 2, 1, 0]
    for j, val in enumerate(vals):
        u, ub = pairs[nvars + j]
        x[u], x[ub] = val, 1 - val
    assert matvec(H, x) == [0] * len(H)
    abs_hist = Counter(abs(v) for v in x if v != 0)
    assert max(abs(v) for v in x) == 2
    assert abs_hist[2] == 1
    B = len(pairs) + 1
    assert abs_hist[1] == B
    return {
        "dummy_vars": dummy_vars,
        "pairs": len(pairs),
        "B_unit_honest_size": B,
        "coordinates": len(x),
        "false_nonzero_abs_histogram": {str(k): v for k, v in sorted(abs_hist.items())},
        "false_linfty": max(abs(v) for v in x),
    }


def padded_false_family():
    return [contradiction_false_vector(d) for d in [0, 1, 2, 4, 16, 64, 256, 1024]]


def asymptotic_tradeoff(beta=0.8):
    rows = []
    for B in [6, 7, 8, 10, 16, 32, 64, 128, 256, 1024, 4096, 16384]:
        a = beta ** (1.0 / B)
        ratio_lb = max(0.0, 2 * a * a - 1)
        false_bias_lb = beta * ratio_lb
        rows.append({
            "B": B,
            "per_coordinate_abs_phi1": a,
            "false_to_honest_bias_ratio_lower_bound": ratio_lb,
            "honest_bias": beta,
            "false_bias_lower_bound": false_bias_lb,
            "honest_character_success": (1 + beta) / 2,
            "false_character_success_lower_bound": (1 + false_bias_lb) / 2,
            "B_times_ratio_gap": B * (1 - ratio_lb),
            "asymptotic_limit_4_abs_log_beta": 4 * abs(math.log(beta)),
        })
    return rows


def finite_modulus_saturation():
    rows = []
    for q in [16, 32, 64, 128, 256, 512]:
        theta = 2 * math.pi / q
        a = math.cos(theta)
        b = math.cos(2 * theta)
        B = max(1, round(math.log(0.8) / math.log(a)))
        honest = a ** B
        false = honest * abs(b)
        lower = honest * max(0.0, 2*a*a - 1)
        if abs(false - lower) > 2e-12:
            raise AssertionError((q, B, honest, false, lower))
        rows.append({
            "q": q,
            "B": B,
            "phi1": a,
            "phi2": b,
            "honest_bias": honest,
            "false_bias": false,
            "ratio": abs(b),
            "bound_saturated": True,
        })
    return rows


def random_complex_laws():
    checked = 0
    min_slack = 1e9
    for q in [5, 7, 11, 17, 31]:
        for _ in range(2000):
            counts = [RNG.randrange(0, 50) for _ in range(q)]
            if not any(counts):
                counts[0] = 1
            p1 = fourier(counts, 1)
            p2 = fourier(counts, 2)
            a = abs(p1)
            slack = abs(p2) - max(0.0, 2*a*a - 1)
            if slack < -2e-11:
                raise AssertionError((q, counts, p1, p2, slack))
            min_slack = min(min_slack, slack)
            checked += 1
    return {"laws_checked": checked, "minimum_numeric_slack": min_slack}


def main():
    result = {
        "run": 36,
        "seed": SEED,
        "candidate": "iid/product additive noise intended to exploit the Run-35 infinity-norm 1-vs-2 source gap by keeping |phi(1)| large while suppressing |phi(2)|",
        "scalar_moment_census": scalar_moment_census(),
        "random_laws": random_complex_laws(),
        "sharp_two_point": sharp_two_point_checks(),
        "padded_false_family": padded_false_family(),
        "constant_honest_bias_tradeoff_beta_0_8": asymptotic_tradeoff(0.8),
        "finite_modulus_saturation": finite_modulus_saturation(),
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
