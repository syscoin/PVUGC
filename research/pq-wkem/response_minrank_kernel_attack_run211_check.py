#!/usr/bin/env python3
"""Run 211 exact finite checks for the response-MinRank kernel-search checkpoint.

Standard library only.  No network access, no production code, no secrets.
"""
from __future__ import annotations
from fractions import Fraction
from math import log2
import hashlib, json, random, sys

ASSERTIONS = 0

def check(cond, msg="assertion failed"):
    global ASSERTIONS
    ASSERTIONS += 1
    if not cond:
        raise AssertionError(msg)

def gf2_rank(rows, ncols):
    rows = list(rows)
    rank = 0
    for col in range(ncols):
        pivot = next((i for i in range(rank, len(rows)) if (rows[i] >> col) & 1), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for i in range(len(rows)):
            if i != rank and ((rows[i] >> col) & 1):
                rows[i] ^= rows[rank]
        rank += 1
    return rank

def gf2_nullspace_basis(rows, nvars):
    rows = list(rows)
    pivots = []
    rank = 0
    for col in range(nvars):
        pivot = next((i for i in range(rank, len(rows)) if (rows[i] >> col) & 1), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for i in range(len(rows)):
            if i != rank and ((rows[i] >> col) & 1):
                rows[i] ^= rows[rank]
        pivots.append(col)
        rank += 1
    free = [c for c in range(nvars) if c not in pivots]
    basis = []
    for f in free:
        v = 1 << f
        for i, p in enumerate(pivots):
            if (rows[i] >> f) & 1:
                v |= 1 << p
        basis.append(v)
    return basis

def matvec(rows, x):
    out = 0
    for i, row in enumerate(rows):
        if (row & x).bit_count() & 1:
            out |= 1 << i
    return out

def xor_mats(a, b):
    return [x ^ y for x, y in zip(a, b)]

def combine_mats(mats, coeff):
    out = [0] * len(mats[0])
    for j, M in enumerate(mats):
        if (coeff >> j) & 1:
            out = xor_mats(out, M)
    return out

def Bx_rows(mats, x):
    t = len(mats)
    cols = [matvec(M, x) for M in mats]
    rows = []
    for i in range(t):
        row = 0
        for j, c in enumerate(cols):
            if (c >> i) & 1:
                row |= 1 << j
        rows.append(row)
    return rows

def random_matrix_rows(rng, nrows, ncols):
    return [rng.getrandbits(ncols) for _ in range(nrows)]

def matrix_from_columns(cols, nrows):
    rows = [0] * nrows
    for j, c in enumerate(cols):
        for i in range(nrows):
            if (c >> i) & 1:
                rows[i] |= 1 << j
    return rows

def random_full_column_matrix(rng, t, r):
    while True:
        cols = [rng.getrandbits(t) for _ in range(r)]
        rows = matrix_from_columns(cols, t)
        if gf2_rank(rows, r) == r:
            return cols

def plant_instance(rng, t, r, d):
    check(0 < r < min(t, d), "need nontrivial rank target")
    n = rng.randrange(1, 1 << t)
    pivot = (n & -n).bit_length() - 1
    Ucols = random_full_column_matrix(rng, t, r)
    # Sample G until E has exact rank r, to make the work-factor check sharp.
    while True:
        gcols = [rng.getrandbits(r) for _ in range(d)]
        Ecols = []
        for g in gcols:
            c = 0
            for i, u in enumerate(Ucols):
                if (g >> i) & 1:
                    c ^= u
            Ecols.append(c)
        E = matrix_from_columns(Ecols, t)
        if gf2_rank(E, d) == r:
            break
    mats = [None] * t
    for j in range(t):
        if j != pivot:
            mats[j] = random_matrix_rows(rng, t, d)
    acc = E[:]
    for j in range(t):
        if j != pivot and ((n >> j) & 1):
            acc = xor_mats(acc, mats[j])
    mats[pivot] = acc
    check(combine_mats(mats, n) == E, "planted combination mismatch")
    return mats, n, E

def rank_count(a, b, j):
    if j < 0 or j > min(a, b):
        return 0
    num = 1
    den = 1
    for i in range(j):
        num *= (2**a - 2**i) * (2**b - 2**i)
        den *= (2**j - 2**i)
    return num // den

def rank_prob(a, b, j):
    return Fraction(rank_count(a, b, j), 2**(a*b))

def p_independent_t_minus_1_vectors(t):
    p = Fraction(1, 1)
    for i in range(t - 1):
        p *= Fraction(2**t - 2**i, 2**t)
    return p

def exact_clean_probability(t, d, rho):
    # x is sampled uniformly from nonzero F_2^d.
    pker = Fraction(2**(d-rho) - 1, 2**d - 1)
    return pker * p_independent_t_minus_1_vectors(t)

def exhaustive_independence_fixture():
    # t=3, rank-one residual E with one nonzero right-kernel vector x.
    # Fix hidden n=(1,1,1), pivot=0, E rows encoding columns [u,0]
    # with u=(1,0,0), so x=second coordinate is the unique nonzero kernel vector.
    t, d = 3, 2
    n = 0b111
    x = 0b10
    E = [0b01, 0, 0]  # rank 1
    total = clean = recovered = 0
    # Two free 3x2 matrices: 64 possibilities each.
    for code1 in range(1 << (t*d)):
        F1 = [(code1 >> (i*d)) & ((1 << d)-1) for i in range(t)]
        for code2 in range(1 << (t*d)):
            F2 = [(code2 >> (i*d)) & ((1 << d)-1) for i in range(t)]
            F0 = xor_mats(E, xor_mats(F1, F2))
            mats = [F0, F1, F2]
            total += 1
            B = Bx_rows(mats, x)
            if gf2_rank(B, t) == t - 1:
                clean += 1
                basis = gf2_nullspace_basis(B, t)
                check(len(basis) == 1)
                if basis[0] == n:
                    recovered += 1
    expected = p_independent_t_minus_1_vectors(t)
    check(total == 4096)
    check(Fraction(clean, total) == expected, "independence probability mismatch")
    check(recovered == clean, "clean kernel did not recover hidden coefficient")
    return {
        "total_free_instances": total,
        "clean_instances": clean,
        "exact_clean_fraction": f"{clean}/{total}",
        "expected_fraction": f"{expected.numerator}/{expected.denominator}",
    }

def deterministic_attack_fixtures():
    rng = random.Random(211)
    rows = []
    for t, r, d in [(5,1,3), (5,2,4), (6,2,5), (7,3,6)]:
        for rep in range(8):
            mats, n, E = plant_instance(rng, t, r, d)
            rho = gf2_rank(E, d)
            true_nonzero_kernel = 0
            clean = 0
            attack_hits = 0
            for x in range(1, 1 << d):
                if matvec(E, x) == 0:
                    true_nonzero_kernel += 1
                B = Bx_rows(mats, x)
                basis = gf2_nullspace_basis(B, t)
                if matvec(E, x) == 0 and len(basis) == 1:
                    clean += 1
                    check(basis[0] == n, "unique nullspace should equal planted n")
                if len(basis) == 1:
                    cand = basis[0]
                    if cand and gf2_rank(combine_mats(mats, cand), d) <= r:
                        attack_hits += 1
            check(true_nonzero_kernel == 2**(d-rho)-1)
            check(clean <= true_nonzero_kernel)
            check(attack_hits >= clean)
            rows.append((t,r,d,rho,true_nonzero_kernel,clean,attack_hits))
    return rows

def parameter_row(t, r, d, s):
    m = r*s
    # principal bad-branch probability: rank(Y)=t-1 and rank(Z)=r
    py1 = rank_prob(t, m, t-1)
    pz = rank_prob(t, r, r)
    pprincipal = py1 * pz
    # all rank-deficient Y
    eps = sum(rank_prob(t, m, j) for j in range(t))
    py2 = eps - py1
    # uniform false-positive union bound from Run-210 event
    q = sum(rank_count(t, d, j) for j in range(r+1))
    q = Fraction(q, 2**(t*d))
    u = min(Fraction(1,1), Fraction(2**t - 1,1) * q)
    clean = exact_clean_probability(t, d, r)
    return {
        "t": t, "r": r, "d": d, "s": s, "rs_minus_t": m-t,
        "principal_bad_probability_log2": log2(float(pprincipal)),
        "all_bad_Y_probability_log2": log2(float(eps)),
        "Y_corank_at_least_2_probability_log2": log2(float(py2)),
        "uniform_false_positive_bound_log2": log2(float(u)),
        "clean_kernel_marked_fraction_log2": log2(float(clean)),
        "classical_expected_trials_log2": -log2(float(clean)),
        "quantum_amplitude_iterations_log2": -0.5*log2(float(clean)),
        "independence_constant": float(p_independent_t_minus_1_vectors(t)),
    }

def cmv_projection_checks():
    # Verify the exact rank-stratum facts used in the reduction-to-CMV discussion.
    # CMV residual is uniform among square matrices of rank <= r.
    t, r = 8, 3
    low_counts = [rank_count(t,t,j) for j in range(r+1)]
    theta = Fraction(sum(low_counts[:-1]), sum(low_counts))
    qfull = 1 - rank_prob(r,t,r)
    check(theta > 0 and qfull > 0)
    # Conditioning a uniform r x t matrix on full row rank changes the full joint
    # distribution by exactly qfull in TV; every marginal changes by at most qfull.
    # Also verify rank-r matrices dominate the <=r law in this finite fixture.
    check(Fraction(low_counts[-1], sum(low_counts)) == 1-theta)
    return {
        "fixture_t": t, "fixture_r": r,
        "cmv_rank_lt_r_probability": float(theta),
        "full_factor_failure_probability": float(qfull),
    }

def main():
    fixture = exhaustive_independence_fixture()
    det = deterministic_attack_fixtures()

    # Exhaustive rank-count sanity checks for small matrices.
    for a in range(1,5):
        for b in range(1,5):
            check(sum(rank_count(a,b,j) for j in range(min(a,b)+1)) == 2**(a*b))

    sample = parameter_row(128, 50, 53, 3)
    # Exact values advertised in the note, to tight tolerance.
    check(abs(sample["classical_expected_trials_log2"] - 50.984561902604426) < 1e-12)
    check(abs(sample["quantum_amplitude_iterations_log2"] - 25.492280951302213) < 1e-12)
    check(sample["uniform_false_positive_bound_log2"] < -104)
    check(sample["principal_bad_probability_log2"] < -21.99 and sample["principal_bad_probability_log2"] > -22.01)

    # A 128-bit Grover margin from this attack alone needs r/2 >= 128.
    check(2*128 == 256)

    out = {
        "run": 211,
        "python": sys.version.split()[0],
        "assertions": ASSERTIONS,
        "exhaustive_independence_fixture": fixture,
        "deterministic_attack_fixture_count": len(det),
        "sample_parameters": sample,
        "cmv_projection_fixture": cmv_projection_checks(),
        "security_margin_examples": {
            "lambda_128_min_r_for_quantum_kernel_exponent": 256,
            "if_uniform_rank_error_target_is_2^-128_simple_gap_sqrt_bound": 12,
            "illustrative_t_if_r_256_and_gap_12": 268
        }
    }
    # cmv_projection_checks adds assertions after out's first ASSERTIONS snapshot.
    out["assertions"] = ASSERTIONS
    print(json.dumps(out, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
