import itertools, json, random
from collections import Counter


def eye(d):
    return [[1 if i == j else 0 for j in range(d)] for i in range(d)]


def transpose(A):
    return [list(row) for row in zip(*A)]


def matmul(A, B, q):
    return [[sum(A[i][k] * B[k][j] for k in range(len(B))) % q
             for j in range(len(B[0]))]
            for i in range(len(A))]


def matvec(A, x, q):
    return [sum(A[i][j] * x[j] for j in range(len(x))) % q
            for i in range(len(A))]


def vadd(a, b, q):
    return [(x + y) % q for x, y in zip(a, b)]


def vsub(a, b, q):
    return [(x - y) % q for x, y in zip(a, b)]


def inv_mod(a, q):
    return pow(a % q, -1, q)


def inverse(A, q):
    n = len(A)
    aug = [row[:] + e[:] for row, e in zip(A, eye(n))]
    r = 0
    for c in range(n):
        p = next((i for i in range(r, n) if aug[i][c] % q), None)
        if p is None:
            raise ValueError('singular')
        aug[r], aug[p] = aug[p], aug[r]
        s = inv_mod(aug[r][c], q)
        aug[r] = [(s * x) % q for x in aug[r]]
        for i in range(n):
            if i != r and aug[i][c] % q:
                t = aug[i][c] % q
                aug[i] = [(aug[i][j] - t * aug[r][j]) % q
                          for j in range(2 * n)]
        r += 1
    return [row[n:] for row in aug]


def det(A, q):
    A = [row[:] for row in A]
    n = len(A)
    out = 1
    for c in range(n):
        p = next((i for i in range(c, n) if A[i][c] % q), None)
        if p is None:
            return 0
        if p != c:
            A[c], A[p] = A[p], A[c]
            out = (-out) % q
        pivot = A[c][c] % q
        out = (out * pivot) % q
        s = inv_mod(pivot, q)
        for i in range(c + 1, n):
            if A[i][c] % q:
                t = A[i][c] * s % q
                for j in range(c, n):
                    A[i][j] = (A[i][j] - t * A[c][j]) % q
    return out % q


def block_rotation(d, q):
    assert d >= 2
    O = eye(d)
    O[0][0] = 0
    O[0][1] = -1 % q
    O[1][0] = 1
    O[1][1] = 0
    return O


def addmat(A, B, q):
    return [[(A[i][j] + B[i][j]) % q for j in range(len(A[0]))]
            for i in range(len(A))]


def Q(x, q):
    return sum(v * v for v in x) % q


def orthogonal_control():
    rows = []
    for q in (3, 5, 7, 11, 101):
        for d in (2, 4, 8):
            I = eye(d)
            O = block_rotation(d, q)
            assert matmul(transpose(O), O, q) == I
            A = addmat(I, O, q)
            got = det(A, q)
            want = pow(2, d - 1, q)
            assert got == want, (q, d, got, want)
            assert got != 0
            Ai = inverse(A, q)
            assert matmul(Ai, A, q) == I
            rows.append({"q": q, "d": d, "det_I_plus_O": got})
    return rows


def false_two_cycle_trials(q=101, d=8, trials=500, seed=2026092201):
    rng = random.Random(seed)
    I = eye(d)
    O = block_rotation(d, q)
    A = addmat(I, O, q)
    Ai = inverse(A, q)
    recovered = 0
    checked = 0
    while checked < trials:
        z = [rng.randrange(q) for _ in range(d)]
        k = Q(z, q)
        if k == 0:
            continue
        va = z
        vb = matvec(O, z, q)
        assert Q(va, q) == k == Q(vb, q)
        ra = [rng.randrange(q) for _ in range(d)]
        rb = [rng.randrange(q) for _ in range(d)]
        ya = vadd(va, vsub(ra, rb, q), q)
        yb = vadd(vb, vsub(rb, ra, q), q)
        Z = vadd(ya, yb, q)
        assert Z == matvec(A, z, q)
        z2 = matvec(Ai, Z, q)
        assert z2 == z
        k2 = Q(z2, q)
        assert k2 == k
        recovered += 1
        checked += 1
    return {"q": q, "d": d, "trials": trials, "exact_key_recoveries": recovered}


def fiber_control(q=3, d=2):
    O = block_rotation(d, q)
    all_vecs = list(itertools.product(range(q), repeat=d))
    total_seed_checks = 0
    example = None
    for zt in all_vecs:
        z = list(zt)
        va = z
        vb = matvec(O, z, q)
        Z = tuple(vadd(va, vb, q))
        counts = Counter()
        for rat in all_vecs:
            ra = list(rat)
            for rbt in all_vecs:
                rb = list(rbt)
                ya = tuple(vadd(va, vsub(ra, rb, q), q))
                yb = tuple(vadd(vb, vsub(rb, ra, q), q))
                counts[(ya, yb)] += 1
        want_support = q ** d
        want_mult = q ** d
        assert len(counts) == want_support
        assert set(counts.values()) == {want_mult}
        for ya, yb in counts:
            assert tuple(vadd(list(ya), list(yb), q)) == Z
        total_seed_checks += 1
        if example is None and Q(z, q) != 0:
            example = {
                "z": z, "k": Q(z, q), "orbit_sum": list(Z),
                "support_size": len(counts), "multiplicity": want_mult,
            }
    return {"q": q, "d": d, "seed_checks": total_seed_checks, "example": example}


def disjoint_support_control(q=5, d=4):
    I = eye(d)
    O = block_rotation(d, q)
    A = addmat(I, O, q)
    assert det(A, q) != 0
    supports = {}
    for k in range(1, q):
        S = []
        for zt in itertools.product(range(q), repeat=d):
            z = list(zt)
            if Q(z, q) == k:
                S.append(tuple(matvec(A, z, q)))
        supports[k] = set(S)
        assert len(supports[k]) == len(S)
    intersections = {}
    for k in range(1, q):
        for kp in range(k + 1, q):
            inter = supports[k] & supports[kp]
            assert not inter
            intersections[f"{k},{kp}"] = len(inter)
    return {
        "q": q, "d": d,
        "support_sizes": {str(k): len(v) for k, v in supports.items()},
        "pairwise_intersections": intersections,
        "pairwise_TV": 1.0,
    }


def general_linear_left_inverse_control(q=7, d=3, trials=200, seed=2026092202):
    rng = random.Random(seed)
    recovered = 0
    for _ in range(trials):
        while True:
            L1 = [[rng.randrange(q) for _ in range(d)] for _ in range(d)]
            L2 = [[rng.randrange(q) for _ in range(d)] for _ in range(d)]
            A = addmat(L1, L2, q)
            if det(A, q) != 0:
                break
        theta = [rng.randrange(q) for _ in range(d)]
        Z = vadd(matvec(L1, theta, q), matvec(L2, theta, q), q)
        theta2 = matvec(inverse(A, q), Z, q)
        assert theta2 == theta
        recovered += 1
    return {"q": q, "d": d, "trials": trials, "hidden_vectors_recovered": recovered}


out = {
    "status": "PASS",
    "orthogonal_blocks": orthogonal_control(),
    "false_two_cycle": false_two_cycle_trials(),
    "complete_transcript_fiber": fiber_control(),
    "key_support_separation": disjoint_support_control(),
    "general_linear_seed": general_linear_left_inverse_control(),
}
print(json.dumps(out, indent=2, sort_keys=True))
