#!/usr/bin/env python3
import hashlib, json, random
from collections import Counter
from itertools import product
from pathlib import Path

SEED = 330033


def is_prime(n):
    if n < 2:
        return False
    d = 2
    while d * d <= n:
        if n % d == 0:
            return False
        d += 1
    return True


def odd_primes_upto(n):
    return [p for p in range(3, n + 1, 2) if is_prime(p)]


def xor_bits(xs):
    out = 0
    for x in xs:
        out ^= x
    return out


def local_support(p, d, mu):
    Q = 4 * p
    Delta = 2 * p
    return {(d * z + Delta * mu) % Q for z in (0, 2)}


def transpose_matvec(H, y):
    out = [0] * len(H[0])
    for yi, row in zip(y, H):
        for k, a in enumerate(row):
            out[k] += yi * a
    return out


def matvec(H, x):
    return [sum(a * b for a, b in zip(row, x)) for row in H]


def compile_3cnf(n, clauses):
    # Columns: h, then two coordinates for each variable/slack pair.
    pairs = [("var", i) for i in range(n)]
    for j in range(len(clauses)):
        pairs += [("s1", j), ("s2", j)]
    cols = 1 + 2 * len(pairs)
    H = []
    for k in range(len(pairs)):
        row = [0] * cols
        row[0] = -1
        row[1 + 2 * k] = 1
        row[1 + 2 * k + 1] = 1
        H.append(row)
    for j, clause in enumerate(clauses):
        row = [0] * cols
        row[0] = -4
        for vi, neg in clause:
            base = 1 + 2 * vi
            row[base + (1 if neg else 0)] += 1
        s1 = n + 2 * j
        s2 = n + 2 * j + 1
        row[1 + 2 * s1] += 1
        row[1 + 2 * s2] += 2
        H.append(row)
    return H, pairs


def vec_from_pair_params(params):
    x = [1]
    for u in params:
        x += [u, 1 - u]
    return x


def pair_diffs(x, pair_count):
    return [x[1 + 2 * j] - x[1 + 2 * j + 1] for j in range(pair_count)]


def witness_params(n, clauses, assignment):
    params = list(assignment)
    for clause in clauses:
        t = sum((1 - assignment[i]) if neg else assignment[i] for i, neg in clause)
        if t == 0:
            raise ValueError("assignment does not satisfy clause")
        rem = 4 - t
        if rem == 1:
            s1, s2 = 1, 0
        elif rem == 2:
            s1, s2 = 0, 1
        elif rem == 3:
            s1, s2 = 1, 1
        else:
            raise AssertionError
        params += [s1, s2]
    return params


def make_capsule(H, j, p, bit, rng):
    Q = 4 * p
    Delta = 2 * p
    y = [rng.randrange(Q) for _ in H]
    z = rng.choice((0, 2))
    c = [v % Q for v in transpose_matvec(H, y)]
    c[1 + 2 * j] = (c[1 + 2 * j] + z) % Q
    c[1 + 2 * j + 1] = (c[1 + 2 * j + 1] - z) % Q
    c[0] = (c[0] + Delta * bit) % Q
    return c


def residual(x, c, Q):
    return sum(a * b for a, b in zip(x, c)) % Q


def decode_with_vector(x, c, j, p):
    Q = 4 * p
    d = x[1 + 2 * j] - x[1 + 2 * j + 1]
    r = residual(x, c, Q)
    s0 = local_support(p, d, 0)
    s1 = local_support(p, d, 1)
    if r in s0 and r not in s1:
        return 0
    if r in s1 and r not in s0:
        return 1
    return None


def toy_distribution(p, k, mu):
    # h,u,ubar with pair row u+ubar=h and d=u-ubar=k*h.
    # k=p is the complete-view hiding toy; k=1 is the leaking toy.
    Q = 4 * p
    Delta = 2 * p
    H = [[-1, 1, 1], [-k, 1, -1]]
    cnt = Counter()
    for y0 in range(Q):
        for y1 in range(Q):
            base = transpose_matvec(H, [y0, y1])
            for z in (0, 2):
                c = [v % Q for v in base]
                c[1] = (c[1] + z) % Q
                c[2] = (c[2] - z) % Q
                c[0] = (c[0] + Delta * mu) % Q
                cnt[tuple(c)] += 1
    return cnt


def run():
    rng = random.Random(SEED)
    result = {"seed": SEED}

    # 1. Exact scalar-support dichotomy.
    local_cases = 0
    same_cases = 0
    disjoint_cases = 0
    for p in (3, 5, 7, 11, 13):
        for d in range(-101, 102, 2):
            if d == 0:
                continue
            s0 = local_support(p, d, 0)
            s1 = local_support(p, d, 1)
            same = s0 == s1
            disjoint = s0.isdisjoint(s1)
            expect_same = (d % p == 0)
            assert same == expect_same
            assert same or disjoint
            local_cases += 1
            same_cases += int(same)
            disjoint_cases += int(disjoint)
    result["local_support_dichotomy"] = {
        "cases": local_cases,
        "identical_when_p_divides_d": same_cases,
        "disjoint_otherwise": disjoint_cases,
    }

    # 2. Bounded centered non-Boolean coefficients are caught by some odd prime.
    U = 64
    primes = odd_primes_upto(2 * U + 1)
    covered = 0
    for u in range(-U, U + 1):
        if u in (0, 1):
            continue
        d = abs(2 * u - 1)
        assert d > 1 and d % 2 == 1
        assert any(d % p == 0 for p in primes)
        covered += 1
    result["bounded_prime_coverage"] = {
        "U": U,
        "prime_count": len(primes),
        "nonboolean_u_values_checked": covered,
        "max_prime": primes[-1],
    }

    # 3. Full-capsule tiny enumeration: k=p gives identical distributions;
    #    k=1 gives disjoint supports.
    toy = []
    for p in (3, 5):
        h0 = toy_distribution(p, p, 0)
        h1 = toy_distribution(p, p, 1)
        l0 = toy_distribution(p, 1, 0)
        l1 = toy_distribution(p, 1, 1)
        assert h0 == h1
        assert not (set(l0) & set(l1))
        toy.append({
            "p": p,
            "hiding_support_size": len(h0),
            "hiding_total_mass_count": sum(h0.values()),
            "leaking_support_size_per_key": len(l0),
            "leaking_support_intersection": len(set(l0) & set(l1)),
        })
    result["full_capsule_toy_enumeration"] = toy

    # 4. True formula with two witnesses: both decode every component and same XOR key.
    true_clauses = [[(0, False), (0, True), (0, False)]]
    Ht, pt = compile_3cnf(1, true_clauses)
    true_vecs = []
    for a in (0, 1):
        x = vec_from_pair_params(witness_params(1, true_clauses, [a]))
        assert matvec(Ht, x) == [0] * len(Ht)
        assert all(abs(d) == 1 for d in pair_diffs(x, len(pt)))
        true_vecs.append(x)
    test_primes = (3, 5, 7, 11, 13)
    true_trials = 300
    true_component_decodes = 0
    for _ in range(true_trials):
        component_count = len(pt) * len(test_primes)
        K = rng.randrange(2)
        shares = [rng.randrange(2) for _ in range(component_count - 1)]
        shares.append(K ^ xor_bits(shares))
        caps = []
        idx = 0
        for j in range(len(pt)):
            for p in test_primes:
                caps.append((j, p, make_capsule(Ht, j, p, shares[idx], rng)))
                idx += 1
        for x in true_vecs:
            recovered = []
            for j, p, c in caps:
                b = decode_with_vector(x, c, j, p)
                assert b is not None
                recovered.append(b)
                true_component_decodes += 1
            assert xor_bits(recovered) == K
    result["true_two_witness_control"] = {
        "trials": true_trials,
        "witnesses_per_trial": 2,
        "components_per_trial": len(pt) * len(test_primes),
        "component_decodes": true_component_decodes,
        "key_failures": 0,
    }

    # 5. Explicit false contradiction: no Boolean kernel point, but two near-threshold
    #    exact pseudovectors cover all pairs with d=+-1 and splice all components.
    false_clauses = [[(0, False)] * 3, [(0, True)] * 3]
    Hf, pf = compile_3cnf(1, false_clauses)
    x0 = vec_from_pair_params([0, 0, 2, 1, 0])
    x1 = vec_from_pair_params([0, 2, 1, 1, 0])
    assert matvec(Hf, x0) == [0] * len(Hf)
    assert matvec(Hf, x1) == [0] * len(Hf)
    assert sum(v * v for v in x0) == 10
    assert sum(v * v for v in x1) == 10
    d0 = pair_diffs(x0, len(pf))
    d1 = pair_diffs(x1, len(pf))
    assert d0 == [-1, -1, 3, 1, -1]
    assert d1 == [-1, 3, 1, 1, -1]
    boolean_kernel_points = 0
    for params in product((0, 1), repeat=len(pf)):
        x = vec_from_pair_params(params)
        if matvec(Hf, x) == [0] * len(Hf):
            boolean_kernel_points += 1
    assert boolean_kernel_points == 0

    cover = []
    for j in range(len(pf)):
        if abs(d0[j]) == 1:
            cover.append(0)
        elif abs(d1[j]) == 1:
            cover.append(1)
        else:
            raise AssertionError("pair not covered")
    assert cover == [0, 0, 1, 0, 0]

    # A fixed pseudovector is genuinely erased on its bad pair at p=3.
    assert local_support(3, d0[2], 0) == local_support(3, d0[2], 1)
    assert local_support(3, d1[1], 0) == local_support(3, d1[1], 1)

    false_trials = 500
    false_component_decodes = 0
    for _ in range(false_trials):
        component_count = len(pf) * len(test_primes)
        K = rng.randrange(2)
        shares = [rng.randrange(2) for _ in range(component_count - 1)]
        shares.append(K ^ xor_bits(shares))
        recovered = []
        idx = 0
        for j in range(len(pf)):
            x = x0 if cover[j] == 0 else x1
            for p in test_primes:
                c = make_capsule(Hf, j, p, shares[idx], rng)
                b = decode_with_vector(x, c, j, p)
                assert b is not None
                recovered.append(b)
                false_component_decodes += 1
                idx += 1
        assert xor_bits(recovered) == K
    result["false_two_vector_splicing"] = {
        "formula": "(z OR z OR z) AND (!z OR !z OR !z)",
        "pair_count": len(pf),
        "boolean_kernel_points": boolean_kernel_points,
        "x0_pair_diffs": d0,
        "x1_pair_diffs": d1,
        "x0_norm_sq": sum(v * v for v in x0),
        "x1_norm_sq": sum(v * v for v in x1),
        "pair_cover_vector_index": cover,
        "trials": false_trials,
        "components_per_trial": len(pf) * len(test_primes),
        "component_decodes": false_component_decodes,
        "key_failures": 0,
        "fixed_x0_bad_pair_p3_is_identical_channel": True,
        "fixed_x1_bad_pair_p3_is_identical_channel": True,
    }

    src = Path(__file__).read_bytes()
    result["source_sha256"] = hashlib.sha256(src).hexdigest()
    return result


if __name__ == "__main__":
    out = run()
    text = json.dumps(out, sort_keys=True, indent=2) + "\n"
    print(text, end="")
