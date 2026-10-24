#!/usr/bin/env python3
import hashlib
import itertools
import json
import random
from collections import Counter
from pathlib import Path

SEED = 0x62C0FFEE
rng = random.Random(SEED)


def inv(a, q):
    return pow(a % q, q - 2, q)


def dot(a, b, q):
    return sum(x*y for x, y in zip(a, b)) % q


def mat_vec(A, x, q):
    return [dot(row, x, q) for row in A]


def transpose(A):
    if not A:
        return []
    return [list(col) for col in zip(*A)]


def rref_solve(A, b, q):
    """Return one solution x to A x=b, or None. A may have zero rows."""
    m = len(A)
    n = len(A[0]) if m else 0
    aug = [[v % q for v in A[i]] + [b[i] % q] for i in range(m)]
    pivots = []
    r = 0
    for c in range(n):
        piv = next((i for i in range(r, m) if aug[i][c] % q), None)
        if piv is None:
            continue
        aug[r], aug[piv] = aug[piv], aug[r]
        s = inv(aug[r][c], q)
        aug[r] = [(v*s) % q for v in aug[r]]
        for i in range(m):
            if i != r and aug[i][c] % q:
                f = aug[i][c] % q
                aug[i] = [(aug[i][j] - f*aug[r][j]) % q for j in range(n+1)]
        pivots.append(c)
        r += 1
        if r == m:
            break
    for i in range(r, m):
        if all(aug[i][j] % q == 0 for j in range(n)) and aug[i][n] % q:
            return None
    x = [0] * n
    for i, c in enumerate(pivots):
        x[c] = aug[i][n] % q
    return x


def rank(A, q):
    if not A:
        return 0
    m, n = len(A), len(A[0])
    M = [[v % q for v in row] for row in A]
    r = 0
    for c in range(n):
        piv = next((i for i in range(r, m) if M[i][c] % q), None)
        if piv is None:
            continue
        M[r], M[piv] = M[piv], M[r]
        s = inv(M[r][c], q)
        M[r] = [(v*s) % q for v in M[r]]
        for i in range(m):
            if i != r and M[i][c] % q:
                f = M[i][c] % q
                M[i] = [(M[i][j] - f*M[r][j]) % q for j in range(n)]
        r += 1
        if r == m:
            break
    return r


def find_outside_image(A, q):
    """A is m x n. Find b not in column image, or None if surjective."""
    m = len(A)
    for b in itertools.product(range(q), repeat=m):
        if rref_solve(A, list(b), q) is None:
            return list(b)
    return None


def dual_separator(A, b, q):
    """Find v with A^T v=0 and b^T v=1, assuming b not in im(A)."""
    AT = transpose(A)
    M = AT + [list(b)]
    rhs = [0] * len(AT) + [1]
    return rref_solve(M, rhs, q)


def capsule_distribution(A, b, q, noise_support, K):
    """Exact Counter under uniform s and uniform list entries in noise_support."""
    m = len(A)
    n = len(A[0]) if m else len(noise_support[0][0])
    AT = transpose(A)
    ctr = Counter()
    for s in itertools.product(range(q), repeat=m):
        clean_c = mat_vec(AT, list(s), q)
        clean_d = dot(b, list(s), q)
        for e, e0 in noise_support:
            c = tuple((clean_c[j] + e[j]) % q for j in range(n))
            d = (clean_d + e0 + K) % q
            ctr[(c, d)] += 1
    return ctr


def random_matrix(m, n, q):
    return [[rng.randrange(q) for _ in range(n)] for _ in range(m)]


def random_noise_support(n, q, size):
    # Duplicates intentionally allowed: this represents arbitrary rational weights.
    return [([rng.randrange(q) for _ in range(n)], rng.randrange(q)) for _ in range(size)]


def test_false_distribution_identity():
    fixtures = 0
    dual_checks = 0
    distribution_checks = 0
    by_q = {2: 0, 3: 0, 5: 0}
    attempts = 0
    while fixtures < 180 and attempts < 10000:
        attempts += 1
        q = [2, 3, 5][fixtures % 3]
        m = rng.choice([2, 3])
        n = rng.choice([1, 2, 3])
        A = random_matrix(m, n, q)
        b = find_outside_image(A, q)
        if b is None:
            continue
        v = dual_separator(A, b, q)
        assert v is not None
        assert all(x % q == 0 for x in mat_vec(transpose(A), v, q))
        assert dot(b, v, q) == 1
        dual_checks += 1

        noise = random_noise_support(n, q, rng.choice([1, 2, 3, 5]))
        base = capsule_distribution(A, b, q, noise, 0)
        for K in range(1, q):
            assert capsule_distribution(A, b, q, noise, K) == base
            distribution_checks += 1
        fixtures += 1
        by_q[q] += 1
    assert fixtures == 180
    return {
        "fixtures": fixtures,
        "dual_separator_checks": dual_checks,
        "key_distribution_equalities": distribution_checks,
        "fixtures_by_field": by_q,
    }


def test_true_decoder_identity():
    fixtures = 0
    residual_checks = 0
    by_q = {2: 0, 3: 0, 5: 0}
    while fixtures < 180:
        q = [2, 3, 5][fixtures % 3]
        m = rng.choice([1, 2, 3])
        n = rng.choice([1, 2, 3])
        A = random_matrix(m, n, q)
        z0 = [rng.randrange(q) for _ in range(n)]
        b = mat_vec(A, z0, q)
        z = rref_solve(A, b, q)
        assert z is not None and mat_vec(A, z, q) == [x % q for x in b]
        noise = random_noise_support(n, q, 4)
        AT = transpose(A)
        # Exhaust all s for these small dimensions and all listed noise atoms/keys.
        for s in itertools.product(range(q), repeat=m):
            clean_c = mat_vec(AT, list(s), q)
            clean_d = dot(b, list(s), q)
            for e, e0 in noise:
                c = [(clean_c[j] + e[j]) % q for j in range(n)]
                for K in range(q):
                    d = (clean_d + e0 + K) % q
                    lhs = (d - dot(z, c, q)) % q
                    rhs = (K + e0 - dot(z, e, q)) % q
                    assert lhs == rhs
                    residual_checks += 1
        fixtures += 1
        by_q[q] += 1
    return {
        "fixtures": fixtures,
        "residual_identity_checks": residual_checks,
        "fixtures_by_field": by_q,
    }


def test_separable_vs_stacked():
    q = 5
    # Local relation 1: z=0. Local relation 2: z=1. No common z.
    A1, b1 = [[1]], [0]
    A2, b2 = [[1]], [1]
    z1, z2 = [0], [1]
    assert mat_vec(A1, z1, q) == b1
    assert mat_vec(A2, z2, q) == b2
    A = [[1], [1]]
    b = [0, 1]
    assert rref_solve(A, b, q) is None
    v = dual_separator(A, b, q)
    assert v is not None and mat_vec(transpose(A), v, q) == [0] and dot(b, v, q) == 1

    recovered = 0
    for _ in range(1000):
        K = rng.randrange(q)
        k1 = rng.randrange(q)
        k2 = (K - k1) % q
        s1 = rng.randrange(q)
        s2 = rng.randrange(q)
        c1, d1 = [s1], k1  # b1^T s1 = 0
        c2, d2 = [s2], (s2 + k2) % q
        r1 = (d1 - dot(z1, c1, q)) % q
        r2 = (d2 - dot(z2, c2, q)) % q
        assert (r1 + r2) % q == K
        recovered += 1

    # Weird correlated/no-uniform-looking noise represented with repeated atoms.
    noise = [([0], 0), ([1], 1), ([2], 4), ([2], 4), ([4], 3)]
    base = capsule_distribution(A, b, q, noise, 0)
    equalities = 0
    for K in range(1, q):
        assert capsule_distribution(A, b, q, noise, K) == base
        equalities += 1
    return {
        "separable_inconsistent_representation_key_recoveries": recovered,
        "stacked_common_solution_exists": False,
        "stacked_key_distribution_equalities": equalities,
        "dual_separator": v,
    }


def bits(x, k):
    return [(x >> i) & 1 for i in range(k)]


def test_run53_mod2_pseudolift():
    total = 0
    weights = {}
    for k in range(2, 7):
        B = 1 << k
        false_weight_expected = 2 * (B - 1)
        for t in range(B):
            tb = bits(t, k)
            total_weight = 0
            # Every block excludes its own index f.
            for f in range(B):
                coeff = {}
                if f != t:
                    coeff[t] = 1
                else:
                    for a in range(B):
                        if a != t:
                            coeff[a] = 1  # integral signed lift reduces to 1 mod 2
                # Support must use only allowed rows a != f.
                assert f not in coeff
                # normalization = 1 mod 2
                assert sum(coeff.values()) % 2 == 1
                # all block marginals equal the same excluded assignment t
                for i in range(k):
                    marg = sum(v * bits(a, k)[i] for a, v in coeff.items()) % 2
                    assert marg == tb[i]
                total_weight += sum(1 for v in coeff.values() if v % 2)
            assert total_weight == false_weight_expected
            total += 1
        weights[str(k)] = {
            "blocks": B,
            "false_pseudolift_weight": false_weight_expected,
            "hypothetical_all_one_hot_weight": B,
            "ratio": false_weight_expected / B,
        }
    return {
        "widths_checked": [2, 3, 4, 5, 6],
        "exact_false_pseudolifts_checked": total,
        "weights": weights,
        "global_boolean_witnesses": 0,
    }


def test_one_hot_affine_barrier():
    checks = 0
    witnesses = {}
    for r in range(3, 13):
        e1 = [0]*r; e2 = [0]*r; e3 = [0]*r
        e1[0]=1; e2[1]=1; e3[2]=1
        affine_closure_point = [(e1[i]+e2[i]+e3[i]) % 2 for i in range(r)]
        assert sum(affine_closure_point) == 3
        assert affine_closure_point not in [e1,e2,e3]
        # Any affine set containing e1,e2,e3 must contain e1+e2+e3.
        checks += 1
        witnesses[str(r)] = {"closure_point_weight": 3, "is_one_hot": False}
    return {
        "block_sizes_checked": list(range(3,13)),
        "affine_closure_counterexamples": checks,
        "witnesses": witnesses,
    }


def test_membership_controls():
    checks = 0
    solvable = 0
    unsolvable = 0
    for q in [2, 3, 5]:
        for _ in range(300):
            m = rng.choice([1, 2, 3, 4])
            n = rng.choice([1, 2, 3, 4])
            A = random_matrix(m, n, q)
            b = [rng.randrange(q) for _ in range(m)]
            sol = rref_solve(A, b, q)
            aug = [row + [b[i]] for i, row in enumerate(A)]
            membership = rank(A, q) == rank(aug, q)
            assert membership == (sol is not None)
            if sol is not None:
                assert mat_vec(A, sol, q) == [x % q for x in b]
                solvable += 1
            else:
                unsolvable += 1
            checks += 1
    return {"rank_membership_checks": checks, "solvable": solvable, "unsolvable": unsolvable}


def main():
    src = Path(__file__).read_bytes()
    out = {
        "run": 62,
        "seed": SEED,
        "checker_sha256": hashlib.sha256(src).hexdigest(),
        "false_distribution_identity": test_false_distribution_identity(),
        "true_decoder_identity": test_true_decoder_identity(),
        "separable_vs_stacked": test_separable_vs_stacked(),
        "run53_mod2_pseudolift": test_run53_mod2_pseudolift(),
        "one_hot_affine_barrier": test_one_hot_affine_barrier(),
        "linear_membership_controls": test_membership_controls(),
        "claims_scope": {
            "tests_validate": [
                "finite-field coupling and decoder identities",
                "exact small-instance key-conditioned distribution equality",
                "explicit separable-versus-stacked fixture",
                "Run-53 modulo-2 false pseudolifts",
                "one-hot affine-closure counterexamples",
                "Gaussian-elimination membership implementation",
            ],
            "tests_do_not_establish": [
                "generic-NP WKEM security",
                "LWE or SIS hardness",
                "arbitrary-QPT key-recovery extraction",
                "security of any nonlinear compiler",
            ],
        },
    }
    print(json.dumps(out, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
