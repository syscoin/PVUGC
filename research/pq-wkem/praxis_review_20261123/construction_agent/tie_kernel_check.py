"""Finite algebra check of Praxis Eq. (5), not its encryption/security.

Three coordinates w=(w0,w1,w2), n=4, six symmetric matrix copies.
All candidate stacks have rank <=3, so Lemma B.6 predicts their exact
span when the public form z is injective on this three-dimensional space.
This checks equations over small fields; it is not a production-parameter
test, GGM simulator, MSIS attack, or source-relation implementation.
"""
import hashlib
import itertools
import json
from pathlib import Path


def run(q, c, kernel=False):
    n = 4
    omega = pow(c, (q - 1) // n, q)
    assert pow(omega, 2, q) == q - 1
    pairs = [(i, j) for i in range(3) for j in range(i, 3)]
    copies = [("U", i) for i in range(4)] + [("V", 0), ("V", 2)]
    width = len(copies) * len(pairs)

    def plus(a, b):
        return [(x + y) % q for x, y in zip(a, b)]

    def neg(a):
        return [(-x) % q for x in a]

    def mul(a, b):
        out = [0] * 4
        for i, x in enumerate(a):
            for j, y in enumerate(b):
                out[(i + j) % 4] += x * y * (c if i + j >= 4 else 1)
        return [x % q for x in out]

    def sub(a, scale):
        return [v * pow(scale, k, q) % q for k, v in enumerate(a)]

    zero = [0] * 4
    # This is Forms(M) for d_R=2, k=1, M_10=0, M_11=1.
    # The kernel control deliberately identifies w1 and w2 instead.
    z = [[1, 0, 0, 0], [0, 0, 1, 0], [0, 0, 1, 0] if kernel else [0, 0, 0, 1]]

    def unpack(v):
        mats = []
        for k in range(6):
            m = [[0] * 3 for _ in range(3)]
            for off, (i, j) in enumerate(pairs):
                m[i][j] = m[j][i] = v[k * 6 + off]
            mats.append(m)
        return mats

    def aggregate(mats, kind):
        out = [[zero[:] for _ in range(3)] for _ in range(3)]
        for m, (tag, deg) in zip(mats, copies):
            if tag == kind:
                for i in range(3):
                    for j in range(3):
                        out[i][j][deg] = m[i][j]
        return out

    def matvec(m, v):
        return [list(map(lambda x: x % q, map(sum, zip(*(mul(m[i][j], v[j]) for j in range(3)))))) for i in range(3)]

    def residual(v, policy):
        mats = unpack(v)
        result = []
        for m in mats:
            result.extend([m[1][1] - m[0][1], m[2][2] - m[0][2]])
            if policy == "false_sum_and_product":
                result.extend([m[0][1] + m[0][2] - m[0][0], m[1][2] - m[0][0]])
            elif policy == "product_zero":
                result.append(m[1][2])
        wu, wv = aggregate(mats, "U"), aggregate(mats, "V")
        wm = [[sub(entry, -omega) for entry in row] for row in wu]
        zm = [sub(entry, -pow(omega, -1, q)) for entry in z]
        z0 = [sub(entry, -1) for entry in z]
        zp = [sub(entry, -omega) for entry in z]
        for a, b in [(matvec(wu, z0), matvec(wv, zm)),
                     (matvec(wu, zp), matvec(wm, zm)),
                     (matvec(wv, zp), matvec(wm, z0))]:
            for x, y in zip(a, b):
                result.extend((s - t) % q for s, t in zip(x, y))
        return [x % q for x in result]

    def rank(a):
        a = [row[:] for row in a]
        row = 0
        cols = len(a[0]) if a else 0
        for col in range(cols):
            pivot = next((i for i in range(row, len(a)) if a[i][col] % q), None)
            if pivot is None:
                continue
            a[row], a[pivot] = a[pivot], a[row]
            inv = pow(a[row][col], -1, q)
            a[row] = [v * inv % q for v in a[row]]
            for i in range(len(a)):
                if i != row and a[i][col]:
                    a[i] = [(x - a[i][col] * y) % q for x, y in zip(a[i], a[row])]
            row += 1
        return row

    def honest(w):
        zz = [sum(w[i] * z[i][j] for i in range(3)) % q for j in range(4)]
        u = mul(zz, sub(zz, pow(omega, 1, q)))
        v = mul(zz, sub(zz, pow(omega, 2, q)))
        assert v[1] == v[3] == 0
        return [((u if tag == "U" else v)[deg] * w[i] * w[j]) % q
                for tag, deg in copies for i, j in pairs]

    results = []
    for policy in ["none", "product_zero", "false_sum_and_product"]:
        units = [[int(i == j) for i in range(width)] for j in range(width)]
        equations = list(map(list, zip(*(residual(v, policy) for v in units))))
        dim = width - rank(equations)
        witnesses = [(1, a, b) for a, b in itertools.product([0, 1], repeat=2)
                     if policy == "none" or policy == "product_zero" and a * b == 0
                     or policy == "false_sum_and_product" and a + b == 1 and a * b == 1]
        hs = [honest(w) for w in witnesses]
        for v in hs:
            assert not any(residual(v, policy))
        hrank = rank(hs)
        if not kernel:
            assert dim == hrank, (q, policy, dim, hrank)
        results.append({"policy": policy, "witness_count": len(witnesses),
                        "passing_tied_stack_dimension": dim, "honest_stack_span_dimension": hrank,
                        "injective_lemma_applicable": not kernel})
    return {"q": q, "n": n, "c": c, "omega": omega,
            "z_has_kernel": kernel, "stack_coefficient_count": width, "results": results}


if __name__ == "__main__":
    data = {"scope": __doc__, "checks": [run(5, 2), run(17, 3), run(5, 2, True), run(17, 3, True)],
            "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    print(json.dumps(data, indent=2, sort_keys=True))
