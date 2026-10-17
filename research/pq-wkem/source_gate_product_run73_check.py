#!/usr/bin/env python3
import hashlib
import itertools
import json
import math
import random
from pathlib import Path

Q = 257
SEED = 730073001

def eye(n):
    return [[1 if i == j else 0 for j in range(n)] for i in range(n)]

def diag(vals):
    n = len(vals)
    return [[vals[i] if i == j else 0 for j in range(n)] for i in range(n)]

def mat_mul(A, B, q=Q):
    return [[sum(A[i][k] * B[k][j] for k in range(len(B))) % q
             for j in range(len(B[0]))] for i in range(len(A))]

def mat_vec(A, v, q=Q):
    return [sum(A[i][j] * v[j] for j in range(len(v))) % q
            for i in range(len(A))]

def mat_inv(A, q=Q):
    n = len(A)
    M = [[A[i][j] % q for j in range(n)] +
         [1 if i == j else 0 for j in range(n)] for i in range(n)]
    for c in range(n):
        piv = next((r for r in range(c, n) if M[r][c] % q), None)
        if piv is None:
            raise ValueError("singular")
        M[c], M[piv] = M[piv], M[c]
        inv = pow(M[c][c], -1, q)
        M[c] = [(x * inv) % q for x in M[c]]
        for r in range(n):
            if r != c and M[r][c] % q:
                f = M[r][c] % q
                M[r] = [(M[r][j] - f * M[c][j]) % q for j in range(2 * n)]
    return [row[n:] for row in M]

def rand_gl(n, rng, q=Q):
    while True:
        A = [[rng.randrange(q) for _ in range(n)] for _ in range(n)]
        try:
            return A, mat_inv(A, q)
        except ValueError:
            pass

# Literal is (variable_index, positive_bool).
def clause_sat(clause, w):
    return any((w[i] == 1 if positive else w[i] == 0)
               for i, positive in clause)

def formula_sat(formula, w):
    return all(clause_sat(c, w) for c in formula)

def violation_vec(formula, w):
    return [0 if clause_sat(c, w) else 1 for c in formula]

def compile_clause_product(formula, n):
    # Coordinate 0 is always 1. Clause coordinate c is multiplied by 0
    # exactly when this variable assignment satisfies clause c.
    out = []
    for i in range(n):
        pair = []
        for b in (0, 1):
            vals = [1]
            for clause in formula:
                sat_here = any(j == i and (b == 1 if positive else b == 0)
                               for j, positive in clause)
                vals.append(0 if sat_here else 1)
            pair.append(diag(vals))
        out.append(pair)
    return out

def raw_product(G, w, q=Q):
    P = eye(len(G[0][0]))
    for i, b in enumerate(w):
        P = mat_mul(P, G[i][b], q)
    return P

def setup_masked(formula, n, rng, q=Q):
    G = compile_clause_product(formula, n)
    d = len(formula) + 1
    S, Sinv = [], []
    for _ in range(n + 1):
        x, xi = rand_gl(d, rng, q)
        S.append(x)
        Sinv.append(xi)
    T = []
    for i in range(n):
        pair = []
        for b in (0, 1):
            pair.append(mat_mul(mat_mul(Sinv[i], G[i][b], q), S[i + 1], q))
        T.append(pair)
    # Fix target raw vector e0. Then s*=S0^{-1}e0, which under uniform
    # S0 in GL_d is uniform over nonzero vectors.
    z0 = [1] + [rng.randrange(1, q) for _ in range(d - 1)]
    z = mat_vec(Sinv[n], z0, q)
    target = mat_vec(Sinv[0], [1] + [0] * (d - 1), q)
    return G, T, z, target

def eval_masked(T, z, w, q=Q):
    P = eye(len(z))
    for i, b in enumerate(w):
        P = mat_mul(P, T[i][b], q)
    return mat_vec(P, z, q)

def centered(x, q=Q):
    x %= q
    return x if x <= q // 2 else x - q

def bits_of(vals, q=Q):
    ell = math.ceil(math.log2(q))
    out = []
    for x in vals:
        out.extend((x >> k) & 1 for k in range(ell))
    return out

def vals_of(bits, count, q=Q):
    ell = math.ceil(math.log2(q))
    out = []
    for i in range(count):
        v = sum(bits[i * ell + k] << k for k in range(ell))
        out.append(v % q)
    return out

def lwe_transport(parent, child, rng, q=Q, Delta=128, err=3):
    A, b = [], []
    for bit in bits_of(child, q):
        a = [rng.randrange(q) for _ in parent]
        e = rng.randint(-err, err)
        A.append(a)
        b.append((sum(ai * si for ai, si in zip(a, parent))
                  + Delta * bit + e) % q)
    return A, b

def lwe_decode(parent, A, b, child_len, q=Q, Delta=128):
    bits = []
    for a, bi in zip(A, b):
        r = (bi - sum(ai * si for ai, si in zip(a, parent))) % q
        d0 = abs(centered(r, q))
        d1 = abs(centered(r - Delta, q))
        bits.append(0 if d0 <= d1 else 1)
    return vals_of(bits, child_len, q)

def monomial_masks(num_vars, degree):
    out = [0]
    for k in range(1, degree + 1):
        for inds in itertools.combinations(range(num_vars), k):
            mask = 0
            for i in inds:
                mask |= 1 << i
            out.append(mask)
    return out

def feature(u, degree, q=Q):
    vals = []
    for mask in monomial_masks(len(u), degree):
        v = 1
        for i in range(len(u)):
            if (mask >> i) & 1:
                v = (v * u[i]) % q
        vals.append(v)
    return vals

def add_scaled(acc, v, c, q=Q):
    return [(a + c * b) % q for a, b in zip(acc, v)]

def run():
    rng = random.Random(SEED)
    report = {
        "seed": SEED,
        "q": Q,
        "claims": "finite algebra/correctness validation only; cryptographic claims require the written reductions/theorems",
    }

    # 1. Compiler identity and satisfying-witness common target.
    compiler_cases = 0
    satisfying_target_checks = 0
    formulas = [
        [((0, True), (1, True)), ((0, False), (1, True))],
        [((0, True),), ((0, False), (1, True))],
        [((0, True), (1, False)), ((1, True), (2, True)), ((0, False), (2, False))],
    ]
    for formula in formulas:
        n = 1 + max(i for c in formula for i, _ in c)
        G = compile_clause_product(formula, n)
        for w in itertools.product((0, 1), repeat=n):
            P = raw_product(G, w)
            got = [P[i][i] for i in range(len(P))]
            want = [1] + violation_vec(formula, w)
            assert got == want
            compiler_cases += 1
        for _ in range(40):
            _, T, z, target = setup_masked(formula, n, rng)
            for w in itertools.product((0, 1), repeat=n):
                if formula_sat(formula, w):
                    assert eval_masked(T, z, w) == target
                    satisfying_target_checks += 1

    # 2. Explicit false-statement affine recovery:
    # F0=(not x) AND (not y) AND (x OR y).
    F0 = [((0, False),), ((1, False),), ((0, True), (1, True))]
    all_w = list(itertools.product((0, 1), repeat=2))
    assert not any(formula_sat(F0, w) for w in all_w)
    affine_parent_recoveries = 0
    lwe_root_recoveries = 0
    for _ in range(500):
        G, T, z, target = setup_masked(F0, 2, rng)
        y10 = eval_masked(T, z, (1, 0))
        y01 = eval_masked(T, z, (0, 1))
        y11 = eval_masked(T, z, (1, 1))
        rec = [(a + b - c) % Q for a, b, c in zip(y10, y01, y11)]
        assert rec == target
        affine_parent_recoveries += 1

        child = [rng.randrange(Q) for _ in range(2)]
        A, b = lwe_transport(target, child, rng)
        got = lwe_decode(rec, A, b, 2)
        assert got == child
        lwe_root_recoveries += 1

    # 3. General clause-defect affine closure. Random hidden defect vectors
    # preserve D1 + D2 - (D1+D2)=0 under every linear embedding.
    defect_affine_checks = 0
    for dim in (2, 4, 9, 17):
        for _ in range(250):
            d1 = [rng.randrange(Q) for _ in range(dim)]
            d2 = [rng.randrange(Q) for _ in range(dim)]
            base = [rng.randrange(Q) for _ in range(dim)]
            v10 = [(base[i] + d1[i]) % Q for i in range(dim)]
            v01 = [(base[i] + d2[i]) % Q for i in range(dim)]
            v11 = [(base[i] + d1[i] + d2[i]) % Q for i in range(dim)]
            rec = [(v10[i] + v01[i] - v11[i]) % Q for i in range(dim)]
            assert rec == base
            defect_affine_checks += 1

    # 4. Low-degree feature repair barrier on
    # F_r=(AND_i not x_i) AND (OR_i x_i), which is unsatisfiable.
    # For every multilinear monomial of degree < r,
    # phi(0)=sum_{w!=0}(-1)^(|w|+1) phi((w,0)).
    low_degree_equalities = 0
    degree_r_separations = 0
    for r in range(2, 8):
        zero = [0] * (r + 1)  # r unit-clause defects plus final OR defect.
        for d in range(r):
            lhs = feature(zero, d)
            rhs = [0] * len(lhs)
            for w in itertools.product((0, 1), repeat=r):
                if not any(w):
                    continue
                u = list(w) + [0]  # all nonzero assignments satisfy final OR.
                coeff = 1 if (sum(w) % 2 == 1) else -1
                rhs = add_scaled(rhs, feature(u, d), coeff)
            assert rhs == lhs
            low_degree_equalities += len(lhs)

        lhs = feature(zero, r)
        rhs = [0] * len(lhs)
        for w in itertools.product((0, 1), repeat=r):
            if not any(w):
                continue
            u = list(w) + [0]
            coeff = 1 if (sum(w) % 2 == 1) else -1
            rhs = add_scaled(rhs, feature(u, r), coeff)
        assert rhs != lhs
        degree_r_separations += 1

    # 5. Exact distribution control: S^{-1}e0 for uniform GL_2(F_3)
    # is uniform over the eight nonzero vectors. Enumerate all 2x2 matrices.
    q3 = 3
    counts = {}
    gl_count = 0
    for a, b, c, d in itertools.product(range(q3), repeat=4):
        M = [[a, b], [c, d]]
        try:
            Mi = mat_inv(M, q3)
        except ValueError:
            continue
        gl_count += 1
        v = tuple(mat_vec(Mi, [1, 0], q3))
        counts[v] = counts.get(v, 0) + 1
    assert gl_count == 48
    assert len(counts) == 8
    assert set(counts.values()) == {6}

    report.update({
        "compiler_identity_cases": compiler_cases,
        "satisfying_witness_common_target_checks": satisfying_target_checks,
        "false_formula": "(not x) AND (not y) AND (x OR y)",
        "false_formula_witness_count": 0,
        "false_affine_parent_recoveries": affine_parent_recoveries,
        "false_lwe_root_recoveries": lwe_root_recoveries,
        "random_clause_defect_affine_checks": defect_affine_checks,
        "low_degree_feature_coordinate_equalities": low_degree_equalities,
        "degree_r_threshold_separations": degree_r_separations,
        "gl2_f3_count": gl_count,
        "gl2_f3_nonzero_target_counts": {str(k): v for k, v in sorted(counts.items())},
        "status": "PASS",
    })
    return report

if __name__ == "__main__":
    report = run()
    print(json.dumps(report, sort_keys=True, indent=2))
