#!/usr/bin/env python3
"""Run 129 finite validation for the Hair--Sahai anchor-quotient barrier.

This checker implements the literal v1 weighted-table family for small prime fields
with p > max(2^N, 2NR), constructs the public source space by the paper's linear
constraints, and verifies the codimension-one public anchor decomposition on
satisfiable examples.  It is algebra validation only; it proves no LWE/SIS/QPT
hardness statement.
"""
from itertools import product
from math import comb
import hashlib, json

RUN = 129
SEED = None


def inv(a, p):
    a %= p
    assert a
    return pow(a, p - 2, p)


def rref(rows, p):
    rows = [[x % p for x in row] for row in rows]
    if not rows:
        return [], []
    m, n = len(rows), len(rows[0])
    A = [row[:] for row in rows]
    rr = 0
    pivots = []
    for c in range(n):
        j = next((i for i in range(rr, m) if A[i][c] % p), None)
        if j is None:
            continue
        A[rr], A[j] = A[j], A[rr]
        s = inv(A[rr][c], p)
        A[rr] = [(s * x) % p for x in A[rr]]
        for i in range(m):
            if i == rr or not A[i][c] % p:
                continue
            f = A[i][c] % p
            A[i] = [(x - f * y) % p for x, y in zip(A[i], A[rr])]
        pivots.append(c)
        rr += 1
        if rr == m:
            break
    return A[:rr], pivots


def rank(rows, p):
    return len(rref(rows, p)[0])


def span_basis(vectors, p):
    return rref(vectors, p)[0] if vectors else []


def nullspace(rows, p, ncols):
    if not rows:
        return [[1 if i == j else 0 for i in range(ncols)] for j in range(ncols)]
    R, piv = rref(rows, p)
    free = [j for j in range(ncols) if j not in piv]
    out = []
    for f in free:
        x = [0] * ncols
        x[f] = 1
        for i in range(len(piv) - 1, -1, -1):
            pc = piv[i]
            x[pc] = (-sum(R[i][j] * x[j] for j in free)) % p
        out.append(x)
    return out


def in_span(v, B, p):
    return rank(B + [v], p) == rank(B, p)


def alphas(R):
    return [a for a in product(range(R + 1), repeat=R) if sum(a) <= R]


def weights_and_encode(w, N, R, p):
    """Literal Hair--Sahai v1 eqs. (12)-(13), then stacked A(b), no zero padding."""
    v = [1] + list(w)
    out = []
    weight_values = []
    for t in range(2 * N * R + 1):
        ell = []
        for j in range(R):
            base = (pow(2, j, p) * t) % p
            ell.append(sum(pow(base, i, p) * v[i] for i in range(N + 1)) % p)
        for a in alphas(R):
            h = 1
            for x, e in zip(ell, a):
                h = (h * pow(x, e, p)) % p
            weight_values.append(h)
            for vi in v:
                for vj in v:
                    out.append((h * vi * vj) % p)
    return weight_values, out


def source_space(N, R, p, equations):
    assert p > max(2 ** N, 2 * N * R)
    words = list(product((0, 1), repeat=N))
    enc = []
    weights = []
    for w in words:
        hs, A = weights_and_encode(w, N, R, p)
        weights.append(hs)
        enc.append(A)
    hcount = len(weights[0])
    stride = (N + 1) ** 2
    constraints = []
    for eq in equations:
        for hidx in range(hcount):
            constraints.append([
                (weights[i][hidx] * eq(w)) % p for i, w in enumerate(words)
            ])
    coeff_basis = nullspace(constraints, p, len(words))
    mats = []
    for c in coeff_basis:
        mats.append([
            sum(ci * A[j] for ci, A in zip(c, enc)) % p
            for j in range(len(enc[0]))
        ])
    S = span_basis(mats, p)
    return words, enc, S, constraints


def analyze_case(name, N, R, p, equations):
    words, enc, S, constraints = source_space(N, R, p, equations)
    sats = [(w, A) for w, A in zip(words, enc) if all(eq(w) % p == 0 for eq in equations)]
    assert sats, "run129 satisfiable controls require at least one witness"

    # The first listed weight is alpha=(0,...,0) at t=0, hence h=1.
    # Its top-left table coordinate is exactly 1 on every assignment encoding.
    anchor = lambda M: M[0] % p
    assert all(anchor(A) == 1 for _, A in zip(words, enc))

    # Every satisfying A(w) lies in the source space S.
    for _, A in sats:
        assert in_span(A, S, p)

    # Public normalized representative U: any public source-basis vector with
    # nonzero anchor, scaled to anchor 1. Existence follows from satisfiability.
    idx = next(i for i, B in enumerate(S) if anchor(B) != 0)
    a = anchor(S[idx])
    U = [(inv(a, p) * x) % p for x in S[idx]]
    assert anchor(U) == 1

    # Public K = S cap ker(anchor).  The following basis construction is explicit.
    Kgens = []
    for B in S:
        ab = anchor(B)
        Kvec = [(x - ab * u) % p for x, u in zip(B, U)]
        assert anchor(Kvec) == 0
        if any(Kvec):
            Kgens.append(Kvec)
    K = span_basis(Kgens, p)
    assert len(K) == len(S) - 1
    assert all(anchor(k) == 0 for k in K)

    # Every honest witness encoding has the same public quotient class U + K.
    for _, A in sats:
        diff = [(x - u) % p for x, u in zip(A, U)]
        assert anchor(diff) == 0
        assert in_span(diff, K, p)

    # Exact honest-difference span D sits inside K. K may be strictly larger,
    # which exposes the ambient-pseudorepresentation over-collapse directly.
    A0 = sats[0][1]
    D = span_basis([
        [(x - y) % p for x, y in zip(A, A0)] for _, A in sats[1:]
    ], p)
    for d in D:
        assert in_span(d, K, p)

    # Quotient dual on S is one-dimensional: any linear invariant on S that
    # annihilates K is determined by its value on U, equivalently by anchor.
    # Finite check: append U to a K basis recovers S exactly.
    assert rank(K + [U], p) == len(S)
    assert all(in_span(B, K + [U], p) for B in S)

    # Witness classes all have quotient coordinate 1; this coordinate is public.
    qcoords = sorted({anchor(A) for _, A in sats})
    assert qcoords == [1]

    return {
        "name": name,
        "N": N,
        "R": R,
        "p": p,
        "source_dimension": len(S),
        "public_anchor_kernel_dimension": len(K),
        "honest_difference_dimension": len(D),
        "ambient_extra_kernel_dimension": len(K) - len(D),
        "satisfying_witnesses": len(sats),
        "quotient_dimension": len(S) - len(K),
        "honest_quotient_coordinate_set": qcoords,
        "public_normalized_representative_anchor": anchor(U),
        "constraint_rank": rank(constraints, p),
    }


def main():
    cases = [
        (
            "N2_and_zero",
            2, 1, 11,
            [lambda w: w[0] * w[1]],
        ),
        (
            "N3_and_gate",
            3, 1, 17,
            [lambda w: w[0] * w[1] - w[2]],
        ),
        (
            "N4_and_gate_plus_free_bit",
            4, 2, 19,
            [lambda w: w[0] * w[1] - w[2]],
        ),
        (
            "N4_linear_two_choice",
            4, 2, 19,
            [lambda w: w[0] + w[1] - 1],
        ),
        (
            "N4_hamming_weight_two",
            4, 2, 19,
            [lambda w: sum(w) - 2],
        ),
        (
            "N4_two_independent_choices",
            4, 2, 19,
            [lambda w: w[0] + w[1] - 1, lambda w: w[2] + w[3] - 1],
        ),
    ]
    reports = [analyze_case(*case) for case in cases]

    # The key theorem-level finite facts are common to every tested actual space.
    assert all(r["quotient_dimension"] == 1 for r in reports)
    assert all(r["honest_quotient_coordinate_set"] == [1] for r in reports)
    assert all(r["public_normalized_representative_anchor"] == 1 for r in reports)
    # At least one case must witness that the public K is strictly larger than
    # the actual honest-difference span, i.e. ambient pseudodirections exist.
    assert any(r["ambient_extra_kernel_dimension"] > 0 for r in reports)

    out = {
        "run": RUN,
        "scope": (
            "finite algebra validation of the public anchor-quotient theorem on "
            "literal Hair--Sahai v1 weighted-table spaces; no cryptographic hardness test"
        ),
        "primary_source": "Hair--Sahai arXiv:2609.18275v1, Sections 4.3-4.6",
        "cases": reports,
        "summary": {
            "cases": len(reports),
            "all_public_anchor_quotients_codim_one": True,
            "all_honest_quotient_coordinates_public_one": True,
            "cases_with_ambient_pseudodirections": sum(
                r["ambient_extra_kernel_dimension"] > 0 for r in reports
            ),
            "total_satisfying_witnesses_checked": sum(r["satisfying_witnesses"] for r in reports),
        },
    }
    print(json.dumps(out, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
