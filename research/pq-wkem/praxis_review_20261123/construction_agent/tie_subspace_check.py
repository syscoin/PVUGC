"""Adversarial finite check of Praxis Eq.(5) on arbitrary rank-three row spaces.

No encryption or production parameter security is implemented here. Test the
linear solution space of passing tied stacks restricted to V, and compare it
to the independently enumerated honest weighted stacks in V. Dimensions N=3,4
and q=5,17. The sampled forms follow Forms(M) for d_R=2,k=1.
"""
import hashlib
import itertools
import json
import random
from pathlib import Path


def row_rank(matrix, q):
    a = [row[:] for row in matrix]
    r = 0
    for col in range(len(a[0]) if a else 0):
        p = next((i for i in range(r, len(a)) if a[i][col] % q), None)
        if p is None:
            continue
        a[r], a[p] = a[p], a[r]
        u = pow(a[r][col], -1, q)
        a[r] = [x * u % q for x in a[r]]
        for i in range(len(a)):
            if i != r and a[i][col]:
                k = a[i][col]
                a[i] = [(x - k * y) % q for x, y in zip(a[i], a[r])]
        r += 1
    return r


def check(q, c, ambient, seed):
    rng = random.Random(seed)
    n, dimension = 4, 3
    omega = pow(c, (q - 1) // n, q)
    assert pow(omega, 2, q) == q - 1
    pairs = [(i, j) for i in range(dimension) for j in range(i, dimension)]
    copies = [("U", i) for i in range(4)] + [("V", 0), ("V", 2)]
    width = 36
    zero = [0] * 4

    def mul(a, b):
        r = [0] * 4
        for i, x in enumerate(a):
            for j, y in enumerate(b):
                r[(i + j) % 4] += x * y * (c if i + j >= 4 else 1)
        return [x % q for x in r]

    def sub(a, s):
        return [x * pow(s, i, q) % q for i, x in enumerate(a)]

    # M is one row of elements of F_q[Y]/(Y^2+1).
    ell = (ambient - 1 + 1) // 2
    M = [[rng.randrange(q), rng.randrange(q)] for _ in range(ell + 1)]
    z = [[1, 0, M[0][0], M[0][1]]]
    for j in range(ell):
        a, b = M[j + 1]
        z.extend([[0, 0, a, b], [0, 0, -b % q, a]])
    z = z[:ambient]
    attempts = 0
    while True:
        attempts += 1
        basis = [[rng.randrange(q) for _ in range(ambient)] for _ in range(dimension)]
        projection = [[sum(basis[i][j] * z[j][k] for j in range(ambient)) % q
                       for k in range(4)] for i in range(dimension)]
        if row_rank(basis, q) == 3 and row_rank(projection, q) == 3:
            break
        if attempts > 1000:
            return {"q": q, "ambient": ambient, "seed": seed, "skipped_noninjective_M": True}

    def unpack(vec):
        out = []
        for copy in range(6):
            small = [[0] * dimension for _ in range(dimension)]
            for off, (i, j) in enumerate(pairs):
                small[i][j] = small[j][i] = vec[copy * 6 + off]
            out.append([[sum(basis[i][a] * small[i][j] * basis[j][b]
                             for i in range(dimension) for j in range(dimension)) % q
                         for b in range(ambient)] for a in range(ambient)])
        return out

    def aggregate(mats, kind):
        result = [[zero[:] for _ in range(ambient)] for _ in range(ambient)]
        for mat, (tag, deg) in zip(mats, copies):
            if tag == kind:
                for i in range(ambient):
                    for j in range(ambient):
                        result[i][j][deg] = mat[i][j]
        return result

    def matvec(mat, vec):
        result = []
        for i in range(ambient):
            row = [0] * 4
            for j in range(ambient):
                prod = mul(mat[i][j], vec[j])
                row = [(x + y) % q for x, y in zip(row, prod)]
            result.append(row)
        return result

    zm = [sub(v, -pow(omega, -1, q)) for v in z]
    z0 = [sub(v, -1) for v in z]
    zp = [sub(v, -omega) for v in z]

    def residual(vec, policy):
        mats = unpack(vec)
        result = []
        for mat in mats:
            result.extend(mat[i][i] - mat[0][i] for i in range(1, ambient))
            if policy == "false":
                result.extend([mat[0][1] + mat[0][2] - mat[0][0], mat[1][2] - mat[0][0]])
            elif policy == "product_zero":
                result.append(mat[1][2])
        wu, wv = aggregate(mats, "U"), aggregate(mats, "V")
        wu_sigma = [[sub(v, -omega) for v in row] for row in wu]
        for a, b in [(matvec(wu, z0), matvec(wv, zm)),
                     (matvec(wu, zp), matvec(wu_sigma, zm)),
                     (matvec(wv, zp), matvec(wu_sigma, z0))]:
            for v1, v2 in zip(a, b):
                result.extend(x - y for x, y in zip(v1, v2))
        return [x % q for x in result]

    candidates = []
    for coeff in itertools.product(range(q), repeat=3):
        w = [sum(coeff[i] * basis[i][j] for i in range(3)) % q for j in range(ambient)]
        if w[0] == 1 and all(x in (0, 1) for x in w):
            zz = [sum(w[i] * z[i][k] for i in range(ambient)) % q for k in range(4)]
            u = mul(zz, sub(zz, omega))
            v = mul(zz, sub(zz, pow(omega, 2, q)))
            assert v[1] == v[3] == 0
            vec = [((u if tag == "U" else v)[deg] * coeff[i] * coeff[j]) % q
                   for tag, deg in copies for i, j in pairs]
            candidates.append((w, vec))

    records = []
    for policy in ["none", "product_zero", "false"]:
        columns = [residual([int(i == j) for i in range(width)], policy) for j in range(width)]
        equations = list(map(list, zip(*columns)))
        passing_dim = width - row_rank(equations, q)
        honest = [vec for w, vec in candidates
                  if policy == "none" or policy == "product_zero" and w[1] * w[2] == 0]
        for vec in honest:
            assert not any(residual(vec, policy))
        honest_dim = row_rank(honest, q)
        assert passing_dim == honest_dim, (q, ambient, seed, policy, passing_dim, honest_dim)
        records.append({"policy": policy, "passing_dim": passing_dim, "honest_dim": honest_dim,
                        "honest_count": len(honest)})
    return {"q": q, "ambient": ambient, "seed": seed, "M": M, "basis": basis,
            "projection_rank": 3, "results": records}


if __name__ == "__main__":
    result = [check(q, c, ambient, seed)
              for q, c in [(5, 2), (17, 3)] for ambient in [4, 5] for seed in range(10)]
    out = {"scope": __doc__, "cases": result,
           "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    print(json.dumps(out, indent=2, sort_keys=True))
