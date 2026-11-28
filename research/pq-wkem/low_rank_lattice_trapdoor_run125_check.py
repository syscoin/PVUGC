#!/usr/bin/env python3
"""Run 125 deterministic validation: low-rank vs lattice-trapdoor interface.

Standard-library-only.  This validates finite combinatorics and parameter arithmetic;
it does NOT establish LWE/SIS/QPT hardness or properties of a concrete trapdoor sampler.
"""
from __future__ import annotations

import itertools
import json
import math
from math import comb

ASSERTIONS = 0


def check(cond: bool, msg: str = "") -> None:
    global ASSERTIONS
    ASSERTIONS += 1
    if not cond:
        raise AssertionError(msg or "check failed")


def inv_mod(a: int, p: int) -> int:
    return pow(a % p, p - 2, p)


def rank_mod(mat, p: int) -> int:
    a = [[x % p for x in row] for row in mat]
    if not a:
        return 0
    nr, nc = len(a), len(a[0])
    r = 0
    for c in range(nc):
        piv = None
        for i in range(r, nr):
            if a[i][c] % p:
                piv = i
                break
        if piv is None:
            continue
        a[r], a[piv] = a[piv], a[r]
        z = inv_mod(a[r][c], p)
        a[r] = [(z * x) % p for x in a[r]]
        for i in range(nr):
            if i != r and a[i][c] % p:
                f = a[i][c] % p
                a[i] = [(a[i][j] - f * a[r][j]) % p for j in range(nc)]
        r += 1
        if r == nr:
            break
    return r


def exact_rank_count_square(p: int, m: int, r: int) -> int:
    if r < 0 or r > m:
        return 0
    if r == 0:
        return 1
    num = 1
    den = 1
    for i in range(r):
        num *= (p**m - p**i) ** 2
        den *= (p**r - p**i)
    check(num % den == 0, "rank count must be integral")
    return num // den


def enumerate_rank_histogram(p: int, m: int):
    hist = [0] * (m + 1)
    for flat in itertools.product(range(p), repeat=m * m):
        mat = [flat[i*m:(i+1)*m] for i in range(m)]
        hist[rank_mod(mat, p)] += 1
    return hist


def frob2_int(mat) -> int:
    return sum(int(x) * int(x) for row in mat for x in row)


def identity(m: int):
    return [[1 if i == j else 0 for j in range(m)] for i in range(m)]


def ones(m: int):
    return [[1 for _ in range(m)] for _ in range(m)]


def hs_params(N: int):
    R = int(math.log2(N))
    check(2**R <= N < 2**(R+1))
    m = (N + 1) * (2 * N * R + 1) * comb(2 * R, R)
    entries = m * m
    dense_bits_lb = m**3  # p >= 2^m => each field entry requires >=m bits.
    ambient_neglog2_lb = m * m * (m - 2 * R)  # from Pr[rank<=R] <= p^{-m(m-2R)} and p>=2^m.
    return {
        "N": N,
        "R": R,
        "m": m,
        "matrix_entries": entries,
        "dense_bits_lower_bound": dense_bits_lb,
        "dense_decimal_TB_lower_bound": dense_bits_lb / 8 / 10**12,
        "ambient_lowrank_neglog2_upperbound": ambient_neglog2_lb,
    }


# 1. Exact finite-field rank-count formula against exhaustive enumeration.
rank_formula_cases = []
for p, m in [(2, 1), (2, 2), (2, 3), (3, 1), (3, 2)]:
    hist = enumerate_rank_histogram(p, m)
    check(sum(hist) == p ** (m*m))
    formulas = [exact_rank_count_square(p, m, r) for r in range(m+1)]
    check(hist == formulas, f"rank formula mismatch p={p},m={m}: {hist} != {formulas}")
    rank_formula_cases.append({"p": p, "m": m, "histogram": hist})

# 2. Safe factorization bound #rank<=R <= p^(2mR) for all exhaustive fixtures.
factorization_bound_cases = []
for p, m in [(2, 2), (2, 3), (3, 2)]:
    hist = enumerate_rank_histogram(p, m)
    for R in range(m + 1):
        low = sum(hist[:R+1])
        bound = p ** (2*m*R) if R > 0 else 1
        check(low <= bound, f"factorization bound failed p={p},m={m},R={R}")
        factorization_bound_cases.append({"p":p,"m":m,"R":R,"lowrank_count":low,"bound":bound})

# 3. Low rank is not implied by Euclidean/Frobenius shortness.
# For every m>=2: rank(I_m)=m, ||I_m||_F=sqrt(m), while rank(J_m)=1, ||J_m||_F=m.
rank_norm_cases = []
for m in range(2, 33):
    I = identity(m)
    J = ones(m)
    ri = rank_mod(I, 1000003)
    rj = rank_mod(J, 1000003)
    i2 = frob2_int(I)
    j2 = frob2_int(J)
    check(ri == m)
    check(rj == 1)
    check(i2 == m)
    check(j2 == m*m)
    check(i2 < j2)
    rank_norm_cases.append({"m":m,"rank_short":ri,"short_norm2":i2,"rank_long":rj,"long_norm2":j2})

# Stronger threshold control: for each R<m, diag with R+1 ones is rank R+1 and norm sqrt(R+1),
# while an (R+1)x(R+1) all-ones block is rank 1 and squared norm (R+1)^2.
threshold_counterexamples = []
p = 1000003
for m in range(3, 20):
    for R in range(1, m):
        D = [[0]*m for _ in range(m)]
        for i in range(R+1):
            D[i][i] = 1
        O = [[0]*m for _ in range(m)]
        for i in range(R+1):
            for j in range(R+1):
                O[i][j] = 1
        check(rank_mod(D,p) == R+1)
        check(rank_mod(O,p) == 1)
        check(frob2_int(D) == R+1)
        check(frob2_int(O) == (R+1)**2)
        check(frob2_int(D) <= frob2_int(O))
        threshold_counterexamples.append({"m":m,"R":R,"invalid_rank":R+1,"invalid_norm2":R+1,"valid_rank":1,"valid_norm2":(R+1)**2})

# 4. Min-entropy counting lemma controls on finite toy spaces.
# If max point mass <= 2^{-h}, event mass <= |E| 2^{-h}.
# We instantiate distributions explicitly on F_p^{m x m} and verify.
min_entropy_cases = []
for p,m,R in [(2,2,1),(2,3,1),(3,2,1)]:
    elems = []
    for flat in itertools.product(range(p), repeat=m*m):
        mat = [flat[i*m:(i+1)*m] for i in range(m)]
        elems.append(rank_mod(mat,p))
    M = len(elems)
    E = sum(r <= R for r in elems)
    # uniform distribution: Hinf=log2 M, exact event probability E/M.
    lhs_num, lhs_den = E, M
    rhs_num, rhs_den = E, M
    check(lhs_num * rhs_den <= rhs_num * lhs_den)
    # biased but bounded distribution: give first half weight 2, second half weight 1.
    weights = [2 if i < M//2 else 1 for i in range(M)]
    Z = sum(weights)
    maxw = max(weights)
    eventw = sum(w for w,r in zip(weights, elems) if r <= R)
    # P(E) <= |E| * max_x P(x) = E * maxw/Z.
    check(eventw * Z <= E * maxw * Z)  # cancels Z; deliberately integer form below too
    check(eventw <= E * maxw)
    min_entropy_cases.append({
        "p":p,"m":m,"R":R,"space":M,"event_size":E,
        "uniform_event_probability":E/M,
        "biased_event_weight":eventw,"biased_total_weight":Z,"max_point_weight":maxw,
    })

# 5. Hair-Sahai stated-parameter arithmetic from the exact formula recorded in the research branch.
hs_table = [hs_params(N) for N in (4,8,16,32)]
# Exact values used in the note, to catch accidental arithmetic drift.
expected = {
    4: (2, 510, 260100, 132651000, 131610600),
    8: (3, 8820, 77792400, 686128968000, 685662213600),
    16:(4,153510,23565320100,3617512288551000,3617323765990200),
    32:(5,2669436,7125888558096,19022103448969553856,19022032190083972896),
}
for row in hs_table:
    e = expected[row["N"]]
    check((row["R"],row["m"],row["matrix_entries"],row["dense_bits_lower_bound"],row["ambient_lowrank_neglog2_upperbound"]) == e)
    check(row["m"] > 2*row["R"])

# 6. Statement-derived-subspace caveat encoded as an algebraic sanity check.
# Ambient rarity does NOT imply rarity in a special subspace: diagonal rank-1 line span(E_11)
# consists entirely of rank<=1 matrices (except zero rank 0), despite low ambient density.
subspace_caveat = []
for p in (2,3,5,7):
    m=3
    line=[]
    for a in range(p):
        M=[[0]*m for _ in range(m)]
        M[0][0]=a
        line.append(rank_mod(M,p))
    check(all(r <= 1 for r in line))
    ambient_low = sum(exact_rank_count_square(p,m,r) for r in (0,1))
    check(ambient_low < p**(m*m))
    subspace_caveat.append({"p":p,"line_ranks":line,"ambient_rank_le_1_fraction":ambient_low/(p**(m*m))})

out = {
    "run": 125,
    "status": "PASS",
    "assertions": ASSERTIONS,
    "scope": "finite algebra/counting/parameter arithmetic only; no LWE/SIS/QPT hardness claim",
    "rank_formula_cases": rank_formula_cases,
    "factorization_bound_case_count": len(factorization_bound_cases),
    "rank_norm_case_count": len(rank_norm_cases),
    "threshold_counterexample_count": len(threshold_counterexamples),
    "min_entropy_cases": min_entropy_cases,
    "hair_sahai_parameter_table": hs_table,
    "statement_subspace_caveat": subspace_caveat,
    "conclusions_checked": [
        "exact square-matrix rank-count formula on exhaustive small fields",
        "safe ambient bound #rank<=R <= p^(2mR)",
        "Euclidean/Frobenius shortness does not enforce low rank",
        "event probability is bounded by event cardinality times max point mass",
        "naive dense Hair-Sahai matrix/lattice embedding has enormous exact stated-parameter dimensions",
        "ambient low-rank rarity alone does not imply rarity in a statement-derived subspace"
    ]
}
print(json.dumps(out, sort_keys=True, separators=(",",":")))