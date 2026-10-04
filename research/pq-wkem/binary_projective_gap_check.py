#!/usr/bin/env python3
"""Fresh finite-field controls for BINARY_PROJECTIVE_GAP.md.

Standard library only.  These are algebraic fixtures, not security parameters.
"""
from fractions import Fraction
import itertools
import json


def rref_gf2(A, b=None):
    M = [list(map(lambda x: x & 1, row)) + ([] if b is None else [b[i] & 1])
         for i, row in enumerate(A)]
    if not M:
        return M, []
    n = len(A[0])
    m = len(M)
    pivots = []
    r = 0
    for c in range(n):
        p = next((i for i in range(r, m) if M[i][c]), None)
        if p is None:
            continue
        M[r], M[p] = M[p], M[r]
        for i in range(m):
            if i != r and M[i][c]:
                M[i] = [x ^ y for x, y in zip(M[i], M[r])]
        pivots.append(c)
        r += 1
        if r == m:
            break
    return M, pivots


def solve_affine_all_gf2(A, b):
    R, pivots = rref_gf2(A, b)
    n = len(A[0])
    for row in R:
        if not any(row[:n]) and row[n]:
            return []
    free = [j for j in range(n) if j not in pivots]
    out = []
    for vals in itertools.product([0, 1], repeat=len(free)):
        x = [0] * n
        for j, v in zip(free, vals):
            x[j] = v
        for i, c in enumerate(pivots):
            s = R[i][n]
            for j in free:
                s ^= R[i][j] & x[j]
            x[c] = s
        out.append(tuple(x))
    return out


STATES = [(0, 0), (0, 1), (1, 0), (1, 1)]


def gate_matrix(kind):
    f = {"AND": lambda a, b: a & b, "OR": lambda a, b: a | b}[kind]
    return [
        [1, 1, 1, 1],
        [a for a, _ in STATES],
        [b for _, b in STATES],
        [f(a, b) for a, b in STATES],
    ]


def gate_controls():
    checks = 0
    for kind in ("AND", "OR"):
        f = {"AND": lambda a, b: a & b, "OR": lambda a, b: a | b}[kind]
        for a, b, o in itertools.product([0, 1], repeat=3):
            sols = solve_affine_all_gf2(gate_matrix(kind), [1, a, b, o])
            assert len(sols) == 1
            expected = 1 if o == f(a, b) else 3
            assert sum(sols[0]) == expected
            checks += 1
    return checks


def predicate_controls():
    checks = 0
    for table in itertools.product([0, 1], repeat=4):
        for x in STATES:
            A = [
                [1, 1, 1, 1],
                [a for a, _ in STATES],
                [b for _, b in STATES],
                list(table),
            ]
            sols = solve_affine_all_gf2(A, [1, x[0], x[1], 1])
            actual_accepts = table[STATES.index(x)] == 1
            if actual_accepts:
                e = [0] * 4
                e[STATES.index(x)] = 1
                assert tuple(e) in sols
            else:
                assert all(sum(q) >= 3 for q in sols)
            checks += 1
    return checks


def build_gap_or_csp(G):
    """Synthetic gap instance: half OR(x,x)->0, half OR(x,x)->1."""
    assert G % 2 == 0
    names = []
    for w in range(3):  # x, y0=0, y1=1
        for v in (0, 1):
            names.append(("w", w, v))
    for g in range(G):
        for a, b in STATES:
            names.append(("g", g, a, b))
    idx = {name: i for i, name in enumerate(names)}
    A, rhs = [], []

    def add(keys, r):
        row = [0] * len(names)
        for key in keys:
            row[idx[key]] ^= 1
        A.append(row)
        rhs.append(r)

    for w in range(3):
        add([("w", w, 0), ("w", w, 1)], 1)
    add([("w", 1, 1)], 0)
    add([("w", 2, 1)], 1)

    for g in range(G):
        outw = 1 if g < G // 2 else 2
        add([("g", g, a, b) for a, b in STATES], 1)
        add([("w", 0, 1)] + [("g", g, a, b) for a, b in STATES if a], 0)
        add([("w", 0, 1)] + [("g", g, a, b) for a, b in STATES if b], 0)
        add([("w", outw, 1)] +
            [("g", g, a, b) for a, b in STATES if (a | b)], 0)
    return A, rhs, names


def gap_csp_control():
    G = 4
    A, rhs, names = build_gap_or_csp(G)
    sols = solve_affine_all_gf2(A, rhs)
    B = 3 + G
    assert len(sols) == 2
    assert all(sum(x) == B + G for x in sols)  # nu=G/2 -> B+2nu
    return {"G": G, "variables": len(names), "solutions": len(sols),
            "B": B, "solution_weights": [sum(x) for x in sols]}


def projection_identity_control():
    # Exact rational enumeration of E_R[S_R].
    n = 5
    C = [[1, 1, 0, 0, 0]]
    J = [[0, 1, 1, 0, 1], [1, 0, 1, 1, 0]]

    def dot2(a, v):
        return sum(x * y for x, y in zip(a, v)) & 1

    candidates = [v for v in itertools.product([0, 1], repeat=n)
                  if v[-1] == 1 and all(dot2(row, v) == 0 for row in C)]
    weight = lambda v: Fraction(1, 2) ** sum(v)
    S_C = sum((weight(v) for v in candidates), Fraction(0))
    exact = [v for v in candidates if all(dot2(row, v) == 0 for row in J)]
    S_exact = sum((weight(v) for v in exact), Fraction(0))

    d = 2
    m = len(J)
    masses = []
    for bits in itertools.product([0, 1], repeat=d * m):
        R = [bits[i * m:(i + 1) * m] for i in range(d)]
        mass = Fraction(0)
        for v in candidates:
            y = [dot2(row, v) for row in J]
            survives = all(sum(R[i][j] * y[j] for j in range(m)) % 2 == 0
                           for i in range(d))
            if survives:
                mass += weight(v)
        masses.append(mass)
    observed = sum(masses, Fraction(0)) / len(masses)
    formula = S_exact + Fraction(1, 2 ** d) * (S_C - S_exact)
    assert observed == formula
    return {
        "projection_matrices": len(masses),
        "candidates": len(candidates),
        "exact_candidates": len(exact),
        "S_C": str(S_C),
        "S_exact": str(S_exact),
        "observed_mean": str(observed),
        "formula": str(formula),
    }


def channel_tables(target=0.9):
    beta = 2 * target - 1
    padded = []
    for pad in (0, 10, 50, 200, 1000, 5000):
        B = 5 + pad
        rho = beta ** (1 / (B + 1))
        padded.append({
            "B": B,
            "coordinate_error_p": (1 - rho) / 2,
            "honest_success": (1 + rho ** (B + 1)) / 2,
            "one_violation_false_success": (1 + rho ** (B + 3)) / 2,
        })

    gap = []
    for G in (4, 10, 50, 200, 1000, 5000):
        B = 3 + G
        rho = beta ** (1 / (B + 1))
        # Every assignment violates G/2 tests, so wt = B+G.
        gap.append({
            "G": G,
            "B": B,
            "coordinate_error_p": (1 - rho) / 2,
            "honest_success": target,
            "half_gap_false_success": (1 + rho ** (B + G + 1)) / 2,
        })
    return {"target_honest_success": target, "padded_false_family": padded,
            "synthetic_half_gap_family": gap}


def main():
    out = {
        "status": "PASS",
        "and_or_local_checks": gate_controls(),
        "two_input_predicate_checks": predicate_controls(),
        "gap_csp_control": gap_csp_control(),
        "projection_identity_control": projection_identity_control(),
        "channel_tables": channel_tables(),
        "scope": "fresh algebra/formula controls only; not cryptographic parameters",
    }
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
