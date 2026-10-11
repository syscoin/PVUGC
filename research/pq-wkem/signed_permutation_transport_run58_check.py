#!/usr/bin/env python3
"""
Run 58 checker: signed-permutation affine transport.

Standard-library-only deterministic validation of:
  * column-wise public routing evaluator,
  * explicit false target with no common witness path,
  * exact/noisy recovery identities,
  * symmetric-error marginal equivalence,
  * exhaustive d=2,L=2 census of false coordinatewise-reachable targets,
  * rigidity control for integral nonexpansive full-rank matrices.

These tests validate finite algebra/implementation only. They are not a
security proof for any surviving construction.
"""
from __future__ import annotations

import collections
import hashlib
import itertools
import json
import random
from typing import List, Tuple

Matrix = List[List[int]]
State = Tuple[int, int]  # (coordinate, sign)

SEED = 0x58A17E
RNG = random.Random(SEED)


def eye(d: int) -> Matrix:
    return [[1 if i == j else 0 for j in range(d)] for i in range(d)]


def matmul(A: Matrix, B: Matrix) -> Matrix:
    return [
        [sum(A[i][t] * B[t][j] for t in range(len(B))) for j in range(len(B[0]))]
        for i in range(len(A))
    ]


def matadd(A: Matrix, B: Matrix) -> Matrix:
    return [[A[i][j] + B[i][j] for j in range(len(A[0]))] for i in range(len(A))]


def matsub(A: Matrix, B: Matrix) -> Matrix:
    return [[A[i][j] - B[i][j] for j in range(len(A[0]))] for i in range(len(A))]


def modmat(A: Matrix, q: int) -> Matrix:
    return [[x % q for x in row] for row in A]


def matkey(A: Matrix):
    return tuple(tuple(row) for row in A)


def det_int(A: Matrix) -> int:
    n = len(A)
    if n == 1:
        return A[0][0]
    if n == 2:
        return A[0][0] * A[1][1] - A[0][1] * A[1][0]
    total = 0
    for j in range(n):
        M = [row[:j] + row[j + 1 :] for row in A[1:]]
        total += ((-1) ** j) * A[0][j] * det_int(M)
    return total


def all_signed_perms(d: int):
    out = []
    for perm in itertools.permutations(range(d)):
        for signs in itertools.product([-1, 1], repeat=d):
            M = [[0] * d for _ in range(d)]
            for j in range(d):
                M[perm[j]][j] = signs[j]
            out.append(M)
    return out


def rand_signed_perm(d: int) -> Matrix:
    perm = list(range(d))
    RNG.shuffle(perm)
    signs = [RNG.choice([-1, 1]) for _ in range(d)]
    M = [[0] * d for _ in range(d)]
    for j in range(d):
        M[perm[j]][j] = signs[j]
    return M


def signed_basis_image(A: Matrix, state: State) -> State:
    k, s = state
    nz = [(r, A[r][k]) for r in range(len(A)) if A[r][k] != 0]
    assert len(nz) == 1 and abs(nz[0][1]) == 1
    r, a = nz[0]
    return r, s * a


def path_product(A, word) -> Matrix:
    P = eye(len(A[0][0]))
    for i, b in enumerate(word):
        P = matmul(P, A[i][b])
    return P


def synth_column_route(A, T: Matrix, j: int):
    """Find b_i and signed basis v_{i+1} with v_i=A_{i,b_i}v_{i+1}.

    Starts from v_L=e_j and targets v_0=T e_j.  The layered state space has
    only 2d signed basis states.  Returns None if that column is unreachable.
    """
    L = len(A)
    target = signed_basis_image(T, (j, 1))
    cur = {(j, 1): []}
    for i in range(L - 1, -1, -1):
        nxt = {}
        for state, recs in cur.items():
            for b in (0, 1):
                prev = signed_basis_image(A[i][b], state)
                if prev not in nxt:
                    nxt[prev] = recs + [(i, b, state)]
        cur = nxt
    if target not in cur:
        return None
    bs = [None] * L
    vip1 = [None] * L
    for i, b, state in cur[target]:
        bs[i] = b
        vip1[i] = state
    return bs, vip1


def build_public_Q(A, T: Matrix):
    L, d = len(A), len(T)
    Q = [
        [[[0 for _ in range(d)] for _ in range(d)] for _b in range(2)]
        for _i in range(L)
    ]
    routes = []
    for j in range(d):
        route = synth_column_route(A, T, j)
        if route is None:
            return None, None
        bs, vip1 = route
        routes.append(bs)
        for i in range(L):
            k, s = vip1[i]
            Q[i][bs[i]][k][j] = s
    return Q, routes


def build_honest_Q(A, word):
    L, d = len(A), len(A[0][0])
    Q = [
        [[[0 for _ in range(d)] for _ in range(d)] for _b in range(2)]
        for _i in range(L)
    ]
    for i in range(L):
        U = eye(d)
        for h in range(i + 1, L):
            U = matmul(U, A[h][word[h]])
        Q[i][word[i]] = U
    return Q


def eval_Q(C, Q) -> Matrix:
    L, d = len(C), len(C[0][0])
    out = [[0] * d for _ in range(d)]
    for i in range(L):
        for b in (0, 1):
            out = matadd(out, matmul(C[i][b], Q[i][b]))
    return out


def zero_errors(L: int, d: int):
    return [
        [[[0] * d for _ in range(d)] for _b in range(2)]
        for _i in range(L)
    ]


def random_errors(L: int, d: int, alphabet=(-1, 0, 1)):
    return [
        [
            [[RNG.choice(alphabet) for _ in range(d)] for _ in range(d)]
            for _b in range(2)
        ]
        for _i in range(L)
    ]


def build_C(A, R, E=None):
    L, d = len(A), len(R[0])
    if E is None:
        E = zero_errors(L, d)
    C = []
    for i in range(L):
        layer = []
        for b in (0, 1):
            layer.append(matadd(matsub(R[i + 1], matmul(R[i], A[i][b])), E[i][b]))
        C.append(layer)
    return C


def random_matrix(d: int, q: int) -> Matrix:
    return [[RNG.randrange(q) for _ in range(d)] for _ in range(d)]


def centered(x: int, q: int) -> int:
    y = x % q
    return y - q if y > q // 2 else y


def count_q_column_nonzeros(Q, i: int, j: int):
    vals = []
    for b in (0, 1):
        for r in range(len(Q[i][b])):
            if Q[i][b][r][j] != 0:
                vals.append(Q[i][b][r][j])
    return vals


def exact_false_fixture():
    # Four common path products are X, -I, -X, I.  T is a 90-degree signed
    # rotation, absent from that set, but each target column is individually
    # reachable by a different branch word.
    A = [
        [
            [[0, 1], [1, 0]],
            [[0, -1], [-1, 0]],
        ],
        [
            [[1, 0], [0, 1]],
            [[0, -1], [-1, 0]],
        ],
    ]
    T = [[0, -1], [1, 0]]
    products = {
        word: path_product(A, word)
        for word in itertools.product((0, 1), repeat=2)
    }
    assert all(P != T for P in products.values())
    Q, routes = build_public_Q(A, T)
    assert Q is not None
    assert routes == [[0, 0], [1, 0]]
    return A, T, Q, routes, products


def ternary_sum_hist(signs):
    hist = collections.Counter()
    for xs in itertools.product((-1, 0, 1), repeat=len(signs)):
        hist[sum(s * x for s, x in zip(signs, xs))] += 1
    return dict(sorted(hist.items()))


def selected_signs_for_entry(Q, out_col: int):
    # For any output row, each layer contributes exactly one scalar error
    # into column out_col.  Record its +/- coefficient.
    signs = []
    for i in range(len(Q)):
        vals = count_q_column_nonzeros(Q, i, out_col)
        assert len(vals) == 1 and abs(vals[0]) == 1
        signs.append(vals[0])
    return signs


def run():
    result = {
        "run": 58,
        "seed": SEED,
        "claim_scope": (
            "finite algebra/implementation controls for signed-permutation affine "
            "transport; not a generic affine impossibility theorem and not a PQ "
            "security proof"
        ),
    }

    # 1. Explicit false instance: no common path, but column-wise public routing
    # recovers the exact endpoint carrier.
    A0, T0, Q0, routes0, products0 = exact_false_fixture()
    q = 65537
    false_exact = 0
    for _ in range(1000):
        R = [random_matrix(2, q) for _ in range(2)]
        S = random_matrix(2, q)
        R.append(modmat(matadd(matmul(R[0], T0), S), q))
        C = build_C(A0, R)
        got = modmat(eval_Q(C, Q0), q)
        assert got == modmat(S, q)
        false_exact += 1
    result["explicit_false_fixture"] = {
        "dimension": 2,
        "layers": 2,
        "common_path_exists": False,
        "column_routes": routes0,
        "path_products": {str(k): v for k, v in products0.items()},
        "target": T0,
        "exact_public_endpoint_recoveries": false_exact,
    }

    # 2. Random true instances.  Public routing must always exist, have exactly
    # one +/-1 per output column per layer, and recover an arbitrary endpoint
    # matrix exactly.
    true_trials = 600
    true_exact = 0
    inconsistent_route_sets = 0
    q = 65537
    for _ in range(true_trials):
        d, L = 4, 10
        A = [[rand_signed_perm(d), rand_signed_perm(d)] for _i in range(L)]
        witness = [RNG.randrange(2) for _i in range(L)]
        T = path_product(A, witness)
        Q, routes = build_public_Q(A, T)
        assert Q is not None
        if any(route != routes[0] for route in routes[1:]):
            inconsistent_route_sets += 1
        for i in range(L):
            for j in range(d):
                vals = count_q_column_nonzeros(Q, i, j)
                assert len(vals) == 1 and abs(vals[0]) == 1
        R = [random_matrix(d, q) for _i in range(L)]
        S = random_matrix(d, q)
        R.append(modmat(matadd(matmul(R[0], T), S), q))
        C = build_C(A, R)
        assert modmat(eval_Q(C, Q), q) == modmat(S, q)
        true_exact += 1
    result["random_true_instances"] = {
        "trials": true_trials,
        "dimension": 4,
        "layers": 10,
        "exact_public_endpoint_recoveries": true_exact,
        "trials_where_synthesized_column_routes_not_all_same_word": inconsistent_route_sets,
        "coefficient_alphabet": [-1, 0, 1],
        "nonzeros_per_output_column_per_layer": 1,
    }

    # 3. Exhaustive d=2,L=2 census: coordinatewise reachability can hold on a
    # genuinely false target, so the phenomenon is not isolated.
    sp2 = all_signed_perms(2)
    false_pairs = 0
    broken_false_pairs = 0
    programs_with_at_least_one_broken_false_target = 0
    for choices in itertools.product(range(len(sp2)), repeat=4):
        A = [
            [sp2[choices[0]], sp2[choices[1]]],
            [sp2[choices[2]], sp2[choices[3]]],
        ]
        path_products = {
            matkey(path_product(A, w))
            for w in itertools.product((0, 1), repeat=2)
        }
        local_broken = 0
        for T in sp2:
            if matkey(T) in path_products:
                continue
            false_pairs += 1
            Q, _routes = build_public_Q(A, T)
            if Q is not None:
                broken_false_pairs += 1
                local_broken += 1
        if local_broken:
            programs_with_at_least_one_broken_false_target += 1
    assert false_pairs == 19264
    assert broken_false_pairs == 3456
    assert programs_with_at_least_one_broken_false_target == 1088
    result["exhaustive_d2_l2_census"] = {
        "programs": len(sp2) ** 4,
        "false_program_target_pairs": false_pairs,
        "false_pairs_with_columnwise_public_evaluator": broken_false_pairs,
        "programs_with_at_least_one_such_false_target": programs_with_at_least_one_broken_false_target,
    }

    # 4. Noisy true instance: public and honest designated-coordinate
    # evaluators each use exactly L independent +/- unit coefficients. For iid
    # symmetric ternary noise their exact scalar marginal law is therefore the
    # same L-fold convolution.
    d, L = 4, 8
    A = [[rand_signed_perm(d), rand_signed_perm(d)] for _i in range(L)]
    witness = [RNG.randrange(2) for _i in range(L)]
    T = path_product(A, witness)
    Qpub, routes = build_public_Q(A, T)
    Qhon = build_honest_Q(A, witness)
    pub_signs = selected_signs_for_entry(Qpub, 0)
    hon_signs = selected_signs_for_entry(Qhon, 0)
    pub_hist = ternary_sum_hist(pub_signs)
    hon_hist = ternary_sum_hist(hon_signs)
    assert pub_hist == hon_hist
    assert sum(pub_hist.values()) == 3 ** L

    q = 257
    phase = q // 2
    noisy_true_trials = 5000
    pub_decodes = hon_decodes = 0
    max_pub_abs_noise = max_hon_abs_noise = 0
    for _ in range(noisy_true_trials):
        key = RNG.randrange(2)
        R = [random_matrix(d, q) for _i in range(L)]
        S = [[0] * d for _i in range(d)]
        S[0][0] = phase * key
        R.append(modmat(matadd(matmul(R[0], T), S), q))
        E = random_errors(L, d)
        C = build_C(A, R, E)
        pub = modmat(eval_Q(C, Qpub), q)[0][0]
        hon = modmat(eval_Q(C, Qhon), q)[0][0]
        pub_noise = centered(pub - phase * key, q)
        hon_noise = centered(hon - phase * key, q)
        max_pub_abs_noise = max(max_pub_abs_noise, abs(pub_noise))
        max_hon_abs_noise = max(max_hon_abs_noise, abs(hon_noise))
        pub_bit = 1 if abs(centered(pub - phase, q)) < abs(centered(pub, q)) else 0
        hon_bit = 1 if abs(centered(hon - phase, q)) < abs(centered(hon, q)) else 0
        pub_decodes += (pub_bit == key)
        hon_decodes += (hon_bit == key)
    assert pub_decodes == noisy_true_trials
    assert hon_decodes == noisy_true_trials
    assert max_pub_abs_noise <= L and max_hon_abs_noise <= L
    result["noisy_true_designated_coordinate"] = {
        "dimension": d,
        "layers": L,
        "ternary_noise_exact_histogram": pub_hist,
        "public_signs": pub_signs,
        "honest_signs": hon_signs,
        "histograms_identical": True,
        "trials": noisy_true_trials,
        "public_decodes": pub_decodes,
        "honest_decodes": hon_decodes,
        "deterministic_abs_noise_bound": L,
        "max_observed_public_abs_noise": max_pub_abs_noise,
        "max_observed_honest_abs_noise": max_hon_abs_noise,
    }

    # 5. Noisy false instance: setup programs the false target endpoint anyway
    # (as a generic statement-only setup must be able to do).  The public
    # coordinatewise evaluator decodes the scalar phase without a common path.
    A, T, Q, routes, _ = exact_false_fixture()
    q, phase = 257, 128
    false_noisy_trials = 5000
    recovered = 0
    max_abs_noise = 0
    for _ in range(false_noisy_trials):
        key = RNG.randrange(2)
        R = [random_matrix(2, q) for _i in range(2)]
        S = [[phase * key, 0], [0, phase * key]]
        R.append(modmat(matadd(matmul(R[0], T), S), q))
        E = random_errors(2, 2)
        C = build_C(A, R, E)
        pub = modmat(eval_Q(C, Q), q)[0][0]
        noise = centered(pub - phase * key, q)
        max_abs_noise = max(max_abs_noise, abs(noise))
        bit = 1 if abs(centered(pub - phase, q)) < abs(centered(pub, q)) else 0
        recovered += (bit == key)
    assert recovered == false_noisy_trials
    assert max_abs_noise <= 2
    result["noisy_false_fixture"] = {
        "common_path_exists": False,
        "trials": false_noisy_trials,
        "public_key_recoveries": recovered,
        "deterministic_abs_noise_bound": 2,
        "max_observed_abs_noise": max_abs_noise,
    }

    # 6. Rigidity control.  If an integer full-rank matrix has Euclidean
    # operator norm <=1 then every column has integer l2 norm <=1; hence each
    # is a signed basis vector and full rank forces a signed permutation.
    # Enumerate {-1,0,1} matrices for d=2,3 and check the equivalent column
    # consequence exactly.
    rigidity = {}
    for d in (2, 3):
        total = 0
        qualifying = 0
        signed_set = {matkey(M) for M in all_signed_perms(d)}
        for flat in itertools.product((-1, 0, 1), repeat=d * d):
            total += 1
            M = [list(flat[i * d : (i + 1) * d]) for i in range(d)]
            if det_int(M) == 0:
                continue
            col_norms = [sum(M[r][j] * M[r][j] for r in range(d)) for j in range(d)]
            if all(v <= 1 for v in col_norms):
                qualifying += 1
                assert matkey(M) in signed_set
        assert qualifying == len(signed_set)
        rigidity[str(d)] = {
            "enumerated_matrices": total,
            "full_rank_with_all_integer_column_norms_le_1": qualifying,
            "signed_permutations": len(signed_set),
        }
    result["integral_nonexpansive_rigidity_control"] = rigidity

    return result


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True, indent=2))
