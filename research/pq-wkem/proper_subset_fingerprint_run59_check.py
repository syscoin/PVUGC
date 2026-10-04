#!/usr/bin/env python3
import json
import random
from itertools import product
from fractions import Fraction

SEED = 0x59C0FFEE
rng = random.Random(SEED)

def centered(x, q):
    x %= q
    return x - q if x > q // 2 else x

def decode_bit(x, q, phase):
    return 0 if abs(centered(x, q)) < abs(centered(x - phase, q)) else 1

def layers_diag(d):
    out = []
    for i in range(d - 1):
        a0 = [1] * d
        a1 = [1] * d
        a1[i] = -1
        a1[d - 1] = -1
        out.append((a0, a1))
    return out

def word_product_diag(d, word):
    p = [1] * d
    layers = layers_diag(d)
    for i, b in enumerate(word):
        a = layers[i][b]
        p = [x * y for x, y in zip(p, a)]
    return p

def target_diag(d):
    return [1] * (d - 1) + [-1]

def route_for_subset(d, subset):
    subset = set(subset)
    w = [0] * (d - 1)
    if d - 1 not in subset:
        return tuple(w)
    for j in range(d - 1):
        if j not in subset:
            w[j] = 1
            return tuple(w)
    raise ValueError("full target subset has no witness")

def restrict(v, subset):
    return [v[j] for j in subset]

def mat_zero(n):
    return [[0] * n for _ in range(n)]

def mat_eye(n, scale, q):
    out = mat_zero(n)
    for i in range(n):
        out[i][i] = scale % q
    return out

def mat_add(A, B, q):
    return [[(a + b) % q for a, b in zip(ar, br)] for ar, br in zip(A, B)]

def mat_sub(A, B, q):
    return [[(a - b) % q for a, b in zip(ar, br)] for ar, br in zip(A, B)]

def mat_scale(A, c, q):
    return [[(c * a) % q for a in row] for row in A]

def mat_right_diag(A, diag, q):
    return [[(row[j] * diag[j]) % q for j in range(len(diag))] for row in A]

def rand_mat(n, q):
    return [[rng.randrange(q) for _ in range(n)] for __ in range(n)]

def err_mat(n):
    return [[rng.choice((-1, 0, 1)) for _ in range(n)] for __ in range(n)]

def local_transport_trial(d, omitted, bit, q=257, phase=128):
    subset = [j for j in range(d) if j != omitted]
    s = len(subset)
    word = route_for_subset(d, subset)
    layers_full = layers_diag(d)
    layers = [([a0[j] for j in subset], [a1[j] for j in subset])
              for a0, a1 in layers_full]
    target = restrict(target_diag(d), subset)
    L = d - 1

    R = [None] * (L + 1)
    R[0] = rand_mat(s, q)
    for i in range(1, L):
        R[i] = rand_mat(s, q)
    R[L] = mat_add(mat_right_diag(R[0], target, q), mat_eye(s, phase * bit, q), q)

    C = {}
    E = {}
    for i in range(L):
        for b in (0, 1):
            e = err_mat(s)
            E[i, b] = [[x % q for x in row] for row in e]
            C[i, b] = mat_add(
                mat_sub(R[i + 1], mat_right_diag(R[i], layers[i][b], q), q),
                E[i, b], q)

    suffix = [[1] * s for _ in range(L + 1)]
    acc = [1] * s
    for i in range(L - 1, -1, -1):
        a = layers[i][word[i]]
        acc = [a[j] * acc[j] for j in range(s)]
        suffix[i] = list(acc)

    F = mat_zero(s)
    N = mat_zero(s)
    for i in range(L):
        b = word[i]
        F = mat_add(F, mat_right_diag(C[i, b], suffix[i + 1], q), q)
        N = mat_add(N, mat_right_diag(E[i, b], suffix[i + 1], q), q)

    formula = mat_add(
        mat_sub(R[L], mat_right_diag(R[0], suffix[0], q), q),
        N, q)
    local_match = suffix[0] == target
    decoded = decode_bit(F[0][0], q, phase)
    err = centered(F[0][0] - phase * bit, q)
    return local_match, F == formula, decoded == bit, abs(err)

def xor_bits(xs):
    out = 0
    for x in xs:
        out ^= x
    return out

def n_of_n_splice_trial(d, q=257, phase=128):
    key = rng.randrange(2)
    shares = [rng.randrange(2) for _ in range(d - 1)]
    shares.append(key ^ xor_bits(shares))
    got = []
    maxerr = 0
    for omitted in range(d):
        ok_match, ok_formula, ok_decode, err = local_transport_trial(
            d, omitted, shares[omitted], q=q, phase=phase)
        if not (ok_match and ok_formula and ok_decode):
            return False, err
        maxerr = max(maxerr, err)
        got.append(shares[omitted])  # decoder was checked against this share
    return xor_bits(got) == key, maxerr

def endpoint_fingerprint_exact_trial(q=257, n=3):
    # One dummy branch with A0=A1=I and public nonzero scalars alpha0 != alpha1.
    a0 = rng.randrange(1, q)
    a1 = rng.randrange(1, q)
    while a1 == a0:
        a1 = rng.randrange(1, q)
    R0 = rand_mat(n, q)
    R1 = rand_mat(n, q)
    C0 = mat_sub(R1, mat_scale(R0, a0, q), q)
    C1 = mat_sub(R1, mat_scale(R0, a1, q), q)
    inv = pow((a1 - a0) % q, -1, q)
    recovered = mat_scale(
        mat_sub(mat_scale(C0, a1, q), mat_scale(C1, a0, q), q),
        inv, q)
    return recovered == R1

def endpoint_fingerprint_short_noisy_trial(q=257, phase=128, n=3):
    # alpha0=1, alpha1=2 => 2*C0-C1 = R1 + 2*E0-E1.
    bit = rng.randrange(2)
    R0 = rand_mat(n, q)
    R1 = mat_eye(n, phase * bit, q)
    E0 = err_mat(n)
    E1 = err_mat(n)
    E0q = [[x % q for x in row] for row in E0]
    E1q = [[x % q for x in row] for row in E1]
    C0 = mat_add(mat_sub(R1, R0, q), E0q, q)
    C1 = mat_add(mat_sub(R1, mat_scale(R0, 2, q), q), E1q, q)
    public = mat_sub(mat_scale(C0, 2, q), C1, q)
    expected_noise = mat_sub(mat_scale(E0q, 2, q), E1q, q)
    formula = mat_add(R1, expected_noise, q)
    got = decode_bit(public[0][0], q, phase)
    err = abs(centered(public[0][0] - phase * bit, q))
    return public == formula and got == bit, err

def exhaustive_ternary_short_combo():
    hist = {}
    maxabs = 0
    for e0, e1 in product((-1,0,1), repeat=2):
        z = 2*e0 - e1
        hist[str(z)] = hist.get(str(z), 0) + 1
        maxabs = max(maxabs, abs(z))
    return hist, maxabs

def main():
    out = {
        "seed": SEED,
        "claim_scope": (
            "Finite algebra/implementation checks for the proper-subset signed-diagonal "
            "transport counterexample and scalar-fingerprint endpoint identities. "
            "Not a security proof for a surviving WKEM."
        )
    }

    proper = {}
    total_subsets = 0
    total_local_matches = 0
    for d in range(2, 13):
        full = (1 << d) - 1
        local = 0
        for mask in range(1 << d):
            if mask == full:
                continue
            subset = [j for j in range(d) if (mask >> j) & 1]
            w = route_for_subset(d, subset)
            p = word_product_diag(d, w)
            t = target_diag(d)
            assert all(p[j] == t[j] for j in subset)
            local += 1
        # no global word
        global_count = sum(word_product_diag(d, w) == target_diag(d)
                           for w in product((0,1), repeat=d-1))
        assert global_count == 0

        # leave-one-out family individually satisfiable but jointly has empty intersection
        loo_sets = []
        for omitted in range(d):
            S = [j for j in range(d) if j != omitted]
            matches = []
            for w in product((0,1), repeat=d-1):
                p = word_product_diag(d, w)
                if all(p[j] == target_diag(d)[j] for j in S):
                    matches.append(w)
            assert matches
            loo_sets.append(set(matches))
        joint = set.intersection(*loo_sets)
        assert not joint

        proper[str(d)] = {
            "proper_subsets_checked": local,
            "global_witness_count": global_count,
            "leave_one_out_component_count": d,
            "leave_one_out_joint_witness_count": len(joint),
        }
        total_subsets += local
        total_local_matches += local
    out["proper_subset_census"] = {
        "dimensions": proper,
        "total_proper_subsets_checked": total_subsets,
        "total_local_routes_verified": total_local_matches,
    }

    # Concrete noisy N-of-N leave-one-out transport.
    splice = {}
    total_trials = 0
    total_ok = 0
    global_maxerr = 0
    for d, trials in ((3,250),(4,250),(6,200),(8,150)):
        ok = 0
        mx = 0
        for _ in range(trials):
            success, err = n_of_n_splice_trial(d)
            ok += int(success)
            mx = max(mx, err)
        assert ok == trials
        splice[str(d)] = {
            "trials": trials,
            "false_global_key_recoveries": ok,
            "max_abs_centered_share_error": mx,
            "deterministic_per_share_bound": d-1,
        }
        total_trials += trials
        total_ok += ok
        global_maxerr = max(global_maxerr, mx)
    out["noisy_leave_one_out_n_of_n"] = {
        "q": 257,
        "phase": 128,
        "ternary_error": [-1,0,1],
        "dimensions": splice,
        "total_trials": total_trials,
        "total_false_global_key_recoveries": total_ok,
        "max_observed_abs_error": global_maxerr,
        "proof_note": (
            "Each local route is an actual witness for its restricted target, so its residual "
            "is the programmed share carrier plus a sum of L=d-1 signed ternary errors. "
            "The simulation checks the full matrix telescoping identity on every share."
        )
    }

    # Exact random-alpha endpoint recovery.
    exact_trials = 1200
    exact_ok = sum(endpoint_fingerprint_exact_trial() for _ in range(exact_trials))
    assert exact_ok == exact_trials

    # Exhaustive collision law for a single dummy branch over F_17^*.
    qsmall = 17
    pairs = 0
    collisions = 0
    for a0 in range(1, qsmall):
        for a1 in range(1, qsmall):
            pairs += 1
            collisions += int(a0 == a1)
    assert Fraction(collisions, pairs) == Fraction(1, qsmall-1)

    noisy_trials = 10000
    noisy_ok = 0
    noisy_max = 0
    for _ in range(noisy_trials):
        ok, err = endpoint_fingerprint_short_noisy_trial()
        noisy_ok += int(ok)
        noisy_max = max(noisy_max, err)
    assert noisy_ok == noisy_trials
    hist, exact_max = exhaustive_ternary_short_combo()
    assert exact_max == 3

    out["scalar_fingerprint_endpoint_collapse"] = {
        "random_distinct_alpha_exact_trials": exact_trials,
        "exact_endpoint_recoveries": exact_ok,
        "dummy_branch_collision_control": {
            "field": 17,
            "ordered_nonzero_alpha_pairs": pairs,
            "equal_pairs": collisions,
            "exact_collision_probability": f"{collisions}/{pairs}",
            "reduced_probability": f"1/{qsmall-1}",
        },
        "short_noisy_fixture": {
            "field": 257,
            "alpha0": 1,
            "alpha1": 2,
            "identity": "2*C0-C1 = R1 + 2*E0-E1",
            "trials": noisy_trials,
            "decoded_endpoint_bits": noisy_ok,
            "max_observed_abs_error": noisy_max,
            "deterministic_abs_error_bound": 3,
            "exact_two_error_histogram": hist,
        }
    }

    print(json.dumps(out, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
