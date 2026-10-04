#!/usr/bin/env python3
"""Run 65 deterministic checker.

Validates exact algebraic claims for:
  * the affine-query three-accepting-preimage barrier;
  * the ideal high-order exclusion/moment block over F_2;
  * the forged-feature 3-sparse bypass when only affine/degree-1
    query features are tied to the real query;
  * finite parameter arithmetic for the *ideal trusted-feature* BSC
    diagnostic.  The parameter arithmetic is not a security proof for
    an implementable generic-NP capsule.

Standard library only.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import random
from pathlib import Path

SEED = 650065
RNG = random.Random(SEED)


def bits(n):
    return list(itertools.product((0, 1), repeat=n))


def proper_subsets(n):
    out = []
    for mask in range((1 << n) - 1):  # excludes full [n]
        out.append(tuple(i for i in range(n) if (mask >> i) & 1))
    return out


def monomial(x, S):
    v = 1
    for i in S:
        v &= x[i]
    return v


def feature(x):
    R = len(x)
    return tuple(monomial(x, S) for S in proper_subsets(R))


def xor_vec(*vs):
    if not vs:
        return ()
    out = [0] * len(vs[0])
    for v in vs:
        for i, a in enumerate(v):
            out[i] ^= a
    return tuple(out)


def mat_rank_f2(rows):
    rows = [sum((bit & 1) << j for j, bit in enumerate(row)) for row in rows]
    if not rows:
        return 0
    ncols = max((r.bit_length() for r in rows), default=0)
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


def solve_f2(A, b):
    """Return one solution and rank; raise if inconsistent."""
    m = len(A)
    n = len(A[0]) if m else 0
    aug = [sum((A[i][j] & 1) << j for j in range(n)) | ((b[i] & 1) << n) for i in range(m)]
    rank = 0
    pivots = []
    for col in range(n):
        pivot = next((i for i in range(rank, m) if (aug[i] >> col) & 1), None)
        if pivot is None:
            continue
        aug[rank], aug[pivot] = aug[pivot], aug[rank]
        for i in range(m):
            if i != rank and ((aug[i] >> col) & 1):
                aug[i] ^= aug[rank]
        pivots.append(col)
        rank += 1
    mask = (1 << n) - 1
    for i in range(rank, m):
        if (aug[i] & mask) == 0 and ((aug[i] >> n) & 1):
            raise ValueError("inconsistent")
    x = [0] * n
    for i, col in enumerate(pivots):
        x[col] = (aug[i] >> n) & 1
    return tuple(x), rank


def centered(v, q):
    v %= q
    if v > q // 2:
        v -= q
    return v


def affine_syndrome(qbits, c, cols, mod):
    out = list(c)
    for bit, col in zip(qbits, cols):
        if bit:
            out = [(x + y) % mod for x, y in zip(out, col)]
    return tuple(out)


def flip(q, *idxs):
    out = list(q)
    for i in idxs:
        out[i] ^= 1
    return tuple(out)


def affine_barrier_checks():
    mods = [2, 17, 257]
    total = 0
    exact = 0
    for mod in mods:
        for r in range(2, 7):
            for _ in range(80):
                m = 7
                c = tuple(RNG.randrange(mod) for _ in range(m))
                cols = [tuple(RNG.randrange(mod) for _ in range(m)) for _ in range(r)]
                qstar = tuple(RNG.randrange(2) for _ in range(r))
                i, j = RNG.sample(range(r), 2)
                a = flip(qstar, i)
                b = flip(qstar, j)
                cc = flip(qstar, i, j)
                sq = affine_syndrome(qstar, c, cols, mod)
                sa = affine_syndrome(a, c, cols, mod)
                sb = affine_syndrome(b, c, cols, mod)
                sc = affine_syndrome(cc, c, cols, mod)
                rhs = tuple((x + y - z) % mod for x, y, z in zip(sa, sb, sc))
                total += 1
                if sq == rhs:
                    exact += 1
                else:
                    raise AssertionError((mod, r, qstar, a, b, cc, sq, rhs))
    return {"tests": total, "exact_identities": exact}


def norm_barrier_checks():
    # Construct arbitrary integer accepting preimages and a random integer H;
    # define the reject syndrome by the affine-square identity.  Then the
    # three-preimage combination is exact and obeys the triangle bound.
    trials = 1000
    exact = 0
    norm_bound = 0
    support_bound = 0
    max_ratio = 0.0
    for _ in range(trials):
        m, n = 6, 24
        H = [[RNG.randint(-3, 3) for _ in range(n)] for _ in range(m)]
        zs = []
        for _k in range(3):
            z = [0] * n
            for idx in RNG.sample(range(n), RNG.randint(1, 5)):
                z[idx] = RNG.choice((-1, 1))
            zs.append(z)
        za, zb, zc = zs
        zstar = [x + y - z for x, y, z in zip(za, zb, zc)]
        def mul(z):
            return [sum(H[i][j] * z[j] for j in range(n)) for i in range(m)]
        sa, sb, sc, ss = mul(za), mul(zb), mul(zc), mul(zstar)
        rhs = [x + y - z for x, y, z in zip(sa, sb, sc)]
        if ss != rhs:
            raise AssertionError("linearity failure")
        exact += 1
        na = math.sqrt(sum(x*x for x in za))
        nb = math.sqrt(sum(x*x for x in zb))
        nc = math.sqrt(sum(x*x for x in zc))
        ns = math.sqrt(sum(x*x for x in zstar))
        if ns <= na + nb + nc + 1e-12:
            norm_bound += 1
        else:
            raise AssertionError("triangle bound")
        supp = lambda z: sum(x != 0 for x in z)
        if supp(zstar) <= supp(za) + supp(zb) + supp(zc):
            support_bound += 1
        else:
            raise AssertionError("support bound")
        denom = max(na, nb, nc)
        if denom:
            max_ratio = max(max_ratio, ns / denom)
    return {
        "trials": trials,
        "exact_linear_combinations": exact,
        "euclidean_triangle_bounds": norm_bound,
        "support_union_bounds": support_bound,
        "max_observed_reject_norm_over_max_accept_norm": max_ratio,
        "proved_upper_bound": 3.0,
    }


def ideal_high_order_checks():
    records = []
    total_accept = 0
    for R in range(2, 9):
        cube = bits(R)
        qstar = tuple(RNG.randrange(2) for _ in range(R))
        omega = [x for x in cube if x != qstar]
        subs = proper_subsets(R)
        A = [[monomial(x, S) for x in omega] for S in subs]
        rank = mat_rank_f2(A)
        if rank != len(omega):
            raise AssertionError((R, "rank", rank, len(omega)))
        rhs_bad = [monomial(qstar, S) for S in subs]
        sol_bad, rank2 = solve_f2(A, rhs_bad)
        if rank2 != len(omega) or any(v != 1 for v in sol_bad):
            raise AssertionError((R, "bad solution not all ones"))
        # Every accepted target has unique one-hot solution.
        for q in omega:
            rhs = [monomial(q, S) for S in subs]
            sol, _ = solve_f2(A, rhs)
            expected = tuple(1 if x == q else 0 for x in omega)
            if sol != expected:
                raise AssertionError((R, q, sol, expected))
            total_accept += 1
        records.append({
            "R": R,
            "columns": len(omega),
            "proper_monomials": len(subs),
            "rank": rank,
            "accepted_unique_weight": 1,
            "rejected_unique_weight": sum(sol_bad),
        })
    return {"records": records, "accepted_targets_checked": total_accept}


def feature_forgery_checks():
    records = []
    for R in range(3, 11):
        qstar = (0,) * R
        a = (1, 0) + (0,) * (R - 2)
        b = (0, 1) + (0,) * (R - 2)
        c = (1, 1) + (0,) * (R - 2)
        omega = [x for x in bits(R) if x != qstar]
        subs = proper_subsets(R)
        fa, fb, fc, fq = map(feature, (a, b, c, qstar))
        forged = xor_vec(fa, fb, fc)
        # constant + degree-1 features match qstar exactly
        low_idx = [idx for idx, S in enumerate(subs) if len(S) <= 1]
        if any(forged[i] != fq[i] for i in low_idx):
            raise AssertionError((R, "low features do not match"))
        # For R>=2, the x1*x2 feature differs and witnesses the forgery.
        s12 = (0, 1)
        idx12 = subs.index(s12)
        if forged[idx12] == fq[idx12]:
            raise AssertionError((R, "quadratic feature unexpectedly matches"))
        z = tuple(1 if x in (a, b, c) else 0 for x in omega)
        A = [[monomial(x, S) for x in omega] for S in subs]
        got = tuple(sum(A[i][j] * z[j] for j in range(len(omega))) & 1 for i in range(len(subs)))
        if got != forged or sum(z) != 3:
            raise AssertionError((R, "forged representation mismatch"))
        records.append({
            "R": R,
            "ideal_reject_weight": (1 << R) - 1,
            "forged_weight_if_degree_ge_2_features_are_free": 3,
            "degree_0_1_features_match_real_reject_query": True,
            "quadratic_feature_differs": True,
        })
    return {"records": records}



def nonlinear_feature_graph_check():
    graph = {(q1, q2, q1 & q2) for q1 in (0, 1) for q2 in (0, 1)}
    a = (0, 0, 0)
    b = (1, 0, 0)
    c = (0, 1, 0)
    closure = tuple(x ^ y ^ z for x, y, z in zip(a, b, c))
    if closure in graph:
        raise AssertionError("multiplication graph unexpectedly affine")
    return {
        "graph_size": len(graph),
        "three_graph_points": [a, b, c],
        "affine_closure_point": closure,
        "closure_point_in_graph": False,
    }

def ideal_bsc_parameter_diagnostic():
    # If the high-order feature vector were *trusted/bound*, a false assignment
    # has one block of weight M=2^R-1 instead of 1.  For the binary additive
    # capsule, with honest direct success h, rho^(B+1)=beta=2h-1.
    # The crude complete projective enumerator bound for a false statement with
    # at most 2^W proof assignments is
    #   S <= 2^W rho^(2(B+M-1)).
    # TV <= sqrt(S) (up to the extra d-coordinate noise factor <=1).
    # Solve for M giving sqrt(S) <= 2^-kappa.
    cases = []
    for B, W, kappa in [(128, 64, 64), (256, 128, 128), (512, 256, 128), (1024, 512, 128)]:
        h = 0.90
        beta = 2*h - 1
        rho = beta ** (1.0 / (B + 1))
        p = (1-rho)/2
        numerator = (W + 2*kappa) * math.log(2)
        M_req = math.ceil(numerator / (-2*math.log(rho)) - B + 1)
        R = math.ceil(math.log2(M_req + 1))
        M = (1 << R) - 1
        log2S = W + 2*(B+M-1)*math.log(rho, 2)
        tv_bound = 2 ** (0.5*log2S) if log2S > -1074 else 0.0
        cases.append({
            "B": B,
            "W": W,
            "kappa": kappa,
            "honest_direct_success": h,
            "rho": rho,
            "bit_error_p": p,
            "minimum_M_from_crude_bound": M_req,
            "chosen_R": R,
            "chosen_M_2powR_minus1": M,
            "log2_S_bound": log2S,
            "sqrt_S_tv_upper_bound": tv_bound,
        })
    return {
        "scope": "ideal trusted-feature diagnostic only; not an implementable generic-NP security claim",
        "cases": cases,
    }


def main():
    result = {
        "run": 65,
        "seed": SEED,
        "affine_query_three_point_identity": affine_barrier_checks(),
        "integer_preimage_norm_barrier": norm_barrier_checks(),
        "ideal_high_order_exclusion_block": ideal_high_order_checks(),
        "free_feature_forgery": feature_forgery_checks(),
        "nonlinear_feature_graph": nonlinear_feature_graph_check(),
        "ideal_trusted_feature_bsc_diagnostic": ideal_bsc_parameter_diagnostic(),
    }
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
