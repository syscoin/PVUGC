#!/usr/bin/env python3
"""Run 70 deterministic checks: multiplicative telescoping and matrix-unit binder attacks.

Standard library only. The executable validates finite identities used in
MULTIPLICATIVE_MATRIX_BINDER_RUN70.md. Passing these tests is not a security
proof.
"""
from __future__ import annotations

import json
import random
from itertools import product
from typing import Dict, List, Sequence, Tuple

SEED = 0x70_2026_09_24
RNG = random.Random(SEED)

# Prime-order subgroup G <= F_607^* of order 101.
EXP_P = 101
FIELD_Q = 607
GEN = 64
assert pow(GEN, EXP_P, FIELD_Q) == 1 and GEN != 1
INV2 = pow(2, -1, EXP_P)


def bit(a: int, i: int) -> int:
    return (a >> i) & 1


def all_exclusions_public_attack(tables: Sequence[Dict[int, int]], k: int) -> int:
    """Public attack for the all-exclusions false family, fixed f=0^k."""
    f = 0
    out = 1
    for a, token in tables[f].items():
        d = a.bit_count()
        coeff = 1 if ((d + 1) % 2 == 0) else -1
        out = (out * pow(token, coeff % EXP_P, FIELD_Q)) % FIELD_Q
    for j in range(1, 1 << k):
        out = (out * tables[j][f]) % FIELD_Q
    return out


def all_exclusions_trial(k: int = 3) -> Tuple[int, int]:
    B = 1 << k
    x = [[RNG.randrange(EXP_P) for _ in range(2)] for _ in range(k)]
    sigma = [[RNG.randrange(EXP_P) for _ in range(k)] for _ in range(B - 1)]
    sigma.append([
        (-sum(sigma[j][i] for j in range(B - 1))) % EXP_P
        for i in range(k)
    ])
    r = [RNG.randrange(EXP_P) for _ in range(B)]
    key = pow(GEN, sum(r) % EXP_P, FIELD_Q)

    tables: List[Dict[int, int]] = []
    for j in range(B):
        row: Dict[int, int] = {}
        for a in range(B):
            if a == j:
                continue
            exponent = (
                r[j]
                + sum(sigma[j][i] * x[i][bit(a, i)] for i in range(k))
            ) % EXP_P
            row[a] = pow(GEN, exponent, FIELD_Q)
        tables.append(row)

    for a in range(B):
        assert a not in tables[a]
    return key, all_exclusions_public_attack(tables, k)


def odd_cycle_public_attack(tables: Sequence[Dict[Tuple[int, int], int]]) -> int:
    out = 1
    for row in tables:
        out = (out * pow(row[(0, 1)], INV2, FIELD_Q)) % FIELD_Q
        out = (out * pow(row[(1, 0)], INV2, FIELD_Q)) % FIELD_Q
    return out


def odd_cycle_trial(n: int = 5) -> Tuple[int, int]:
    assert n % 2 == 1
    x = [[RNG.randrange(EXP_P) for _ in range(2)] for _ in range(n)]
    r = [RNG.randrange(EXP_P) for _ in range(n)]
    key = pow(GEN, sum(r) % EXP_P, FIELD_Q)
    tables: List[Dict[Tuple[int, int], int]] = []
    for j in range(n):
        row: Dict[Tuple[int, int], int] = {}
        for a, b in ((0, 1), (1, 0)):
            exponent = (r[j] + x[j][a] - x[(j + 1) % n][b]) % EXP_P
            row[(a, b)] = pow(GEN, exponent, FIELD_Q)
        tables.append(row)
    return key, odd_cycle_public_attack(tables)


def has_odd_cycle_witness(n: int = 5) -> bool:
    for assignment in product((0, 1), repeat=n):
        if all(assignment[j] != assignment[(j + 1) % n] for j in range(n)):
            return True
    return False


def mat_mul(A, B, p):
    n, k, m = len(A), len(B), len(B[0])
    return [[sum(A[i][t] * B[t][j] for t in range(k)) % p for j in range(m)] for i in range(n)]


def row_mul(r, M, p):
    return [sum(r[t] * M[t][j] for t in range(len(r))) % p for j in range(len(M[0]))]


def dot(r, c, p):
    return sum(a * b for a, b in zip(r, c)) % p


def inv_mat(A, p):
    n = len(A)
    aug = [list(A[i]) + [1 if i == j else 0 for j in range(n)] for i in range(n)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if aug[r][col] % p), None)
        if pivot is None:
            raise ValueError("singular")
        aug[col], aug[pivot] = aug[pivot], aug[col]
        iv = pow(aug[col][col] % p, -1, p)
        aug[col] = [(x * iv) % p for x in aug[col]]
        for r in range(n):
            if r == col:
                continue
            f = aug[r][col] % p
            if f:
                aug[r] = [(aug[r][j] - f * aug[col][j]) % p for j in range(2 * n)]
    return [row[n:] for row in aug]


def rand_inv(d, p):
    while True:
        A = [[RNG.randrange(p) for _ in range(d)] for __ in range(d)]
        try:
            return A, inv_mat(A, p)
        except ValueError:
            pass


def matrix_unit(d, s, t):
    M = [[0] * d for _ in range(d)]
    M[s][t] = 1
    return M


def canonical_projective(v, p):
    for x in v:
        if x % p:
            iv = pow(x % p, -1, p)
            return tuple(y * iv % p for y in v)
    raise ValueError("zero projective vector")


def rank1_factor(M, p):
    d = len(M)
    for i in range(d):
        for j in range(d):
            if M[i][j] % p:
                c = [M[k][j] % p for k in range(d)]
                iv = pow(M[i][j] % p, -1, p)
                r = [M[i][l] * iv % p for l in range(d)]
                check = [[c[a] * r[b] % p for b in range(d)] for a in range(d)]
                assert check == [[x % p for x in row] for row in M]
                return c, r
    raise ValueError("zero matrix")


def outer(c, r, p):
    return [[a * b % p for b in r] for a in c]


def scalar_ratio(A, B, p):
    for i in range(len(A)):
        for j in range(len(A[0])):
            if B[i][j] % p:
                m = A[i][j] * pow(B[i][j] % p, -1, p) % p
                assert all((A[x][y] - m * B[x][y]) % p == 0 for x in range(len(A)) for y in range(len(A[0])))
                return m
    raise ValueError("zero denominator matrix")


def directed_path_exists(edges1, edges2, start, accept):
    mids = {t for s, t in edges1 if s == start}
    return any(s in mids and t == accept for s, t in edges2)


def public_matrix_unit_attack(public_layers, start_row, end_col_key, p):
    source_reps = []
    target_reps = []
    edge_data = []

    for arr in public_layers:
        creps = {}
        rreps = {}
        temp = []
        for M in arr:
            c, r = rank1_factor(M, p)
            cf, rf = canonical_projective(c, p), canonical_projective(r, p)
            creps.setdefault(cf, list(cf))
            rreps.setdefault(rf, list(rf))
            temp.append((M, cf, rf))
        source_reps.append(creps)
        target_reps.append(rreps)
        edge_data.append(temp)

    adjacency = {}

    def add_eq(u, v, constant):
        assert constant % p
        adjacency.setdefault(u, []).append((v, constant % p))
        adjacency.setdefault(v, []).append((u, constant % p))

    for layer, temp in enumerate(edge_data, start=1):
        for M, cf, rf in temp:
            C, R = list(cf), list(rf)
            m = scalar_ratio(outer(C, R, p), M, p)
            add_eq(("a", layer - 1, cf), ("b", layer, rf), m)

    same_state_matches = 0
    for layer in range(1, len(public_layers)):
        for rf in target_reps[layer - 1]:
            R = list(rf)
            matches = []
            for cf in source_reps[layer]:
                q = dot(R, list(cf), p)
                if q:
                    matches.append((cf, q))
            assert len(matches) <= 1
            if matches:
                same_state_matches += 1
                cf, q = matches[0]
                add_eq(("b", layer, rf), ("a", layer, cf), q)

    start_candidates = []
    for cf in source_reps[0]:
        val = dot(start_row, list(cf), p)
        if val:
            start_candidates.append((cf, val))
    assert len(start_candidates) == 1
    start_cf, a_start = start_candidates[0]

    accept_candidates = []
    for rf in target_reps[-1]:
        val = dot(list(rf), end_col_key, p)
        if val:
            accept_candidates.append((rf, val))
    assert len(accept_candidates) == 1
    accept_rf, endpoint_pairing = accept_candidates[0]

    start_id = ("a", 0, start_cf)
    accept_id = ("b", len(public_layers), accept_rf)
    values = {start_id: a_start}
    stack = [start_id]
    while stack:
        u = stack.pop()
        xu = values[u]
        for v, c in adjacency.get(u, []):
            xv = c * pow(xu, -1, p) % p
            if v in values:
                assert values[v] == xv
            else:
                values[v] = xv
                stack.append(v)

    assert accept_id in values
    b_accept = values[accept_id]
    Krec = endpoint_pairing * pow(b_accept, -1, p) % p
    return Krec, {
        "public_scale_vertices": len(adjacency),
        "same_state_matches": same_state_matches,
        "reached_scale_vertices": len(values),
    }


def matrix_unit_false_trial(p, d):
    assert d >= 2
    S, Sinv = [], []
    for _ in range(3):
        a, ai = rand_inv(d, p)
        S.append(a)
        Sinv.append(ai)

    edges1 = [(0, 0), (1, 0), (1, 1)]
    edges2 = [(1, 0)]
    assert not directed_path_exists(edges1, edges2, 0, 0)

    public_layers = []
    for layer, edges in ((1, edges1), (2, edges2)):
        arr = []
        for s, t in edges:
            M = mat_mul(mat_mul(Sinv[layer - 1], matrix_unit(d, s, t), p), S[layer], p)
            arr.append(M)
        RNG.shuffle(arr)
        public_layers.append(arr)

    K = RNG.randrange(1, p)
    start_row = list(S[0][0])
    end_col_key = [K * Sinv[2][i][0] % p for i in range(d)]
    Krec, stats = public_matrix_unit_attack(public_layers, start_row, end_col_key, p)
    return K, Krec, stats


def matrix_unit_true_trial(p, d):
    assert d >= 2
    S, Sinv = [], []
    for _ in range(3):
        a, ai = rand_inv(d, p)
        S.append(a)
        Sinv.append(ai)
    M1 = mat_mul(mat_mul(Sinv[0], matrix_unit(d, 0, 1), p), S[1], p)
    M2 = mat_mul(mat_mul(Sinv[1], matrix_unit(d, 1, 0), p), S[2], p)
    K = RNG.randrange(1, p)
    start_row = list(S[0][0])
    end_col_key = [K * Sinv[2][i][0] % p for i in range(d)]
    Pmat = mat_mul(M1, M2, p)
    scalar = dot(row_mul(start_row, Pmat, p), end_col_key, p)
    return K, scalar


def run():
    results = {
        "seed": SEED,
        "subgroup": {"exponent_order": EXP_P, "field_modulus": FIELD_Q, "generator": GEN},
    }

    ae_trials = 300
    ae_ok = 0
    for _ in range(ae_trials):
        K, Krec = all_exclusions_trial(3)
        ae_ok += (K == Krec)
    assert ae_ok == ae_trials
    results["all_exclusions"] = {
        "k": 3,
        "blocks": 8,
        "false_instances_verified": ae_trials,
        "public_key_recoveries": ae_ok,
        "uses_discrete_log": False,
    }

    assert not has_odd_cycle_witness(5)
    oc_trials = 300
    oc_ok = 0
    for _ in range(oc_trials):
        K, Krec = odd_cycle_trial(5)
        oc_ok += (K == Krec)
    assert oc_ok == oc_trials
    results["odd_cycle_fractional"] = {
        "cycle_length": 5,
        "source_witnesses": 0,
        "trials": oc_trials,
        "public_key_recoveries": oc_ok,
        "coefficient_half_mod_101": INV2,
        "uses_negative_token_power": False,
        "uses_discrete_log": False,
    }

    primes = [101, 103, 107]
    dims = [2, 3, 4]
    per_pair = 40
    mu_trials = 0
    mu_ok = 0
    total_reached = 0
    total_same_state = 0
    for p in primes:
        for d in dims:
            for _ in range(per_pair):
                K, Krec, stats = matrix_unit_false_trial(p, d)
                mu_trials += 1
                mu_ok += (K == Krec)
                total_reached += stats["reached_scale_vertices"]
                total_same_state += stats["same_state_matches"]
    assert mu_ok == mu_trials
    results["matrix_unit_false_complete_output"] = {
        "primes": primes,
        "dimensions": dims,
        "trials": mu_trials,
        "directed_accepting_paths": 0,
        "public_key_recoveries": mu_ok,
        "aggregate_reached_scale_vertices": total_reached,
        "aggregate_same_state_matches": total_same_state,
        "attack_uses_hidden_state_labels": False,
        "attack_uses_matrix_inverse_of_tokens": False,
    }

    true_trials = 180
    true_ok = 0
    for idx in range(true_trials):
        p = primes[idx % len(primes)]
        d = dims[idx % len(dims)]
        K, Krec = matrix_unit_true_trial(p, d)
        true_ok += (K == Krec)
    assert true_ok == true_trials
    results["matrix_unit_true_control"] = {
        "trials": true_trials,
        "valid_path_key_recoveries": true_ok,
    }

    results["claim_boundary"] = {
        "tests_prove_security": False,
        "commutative_result": "exact public algebraic attacks on two false families for the explicit multiplicative telescope",
        "matrix_result": "exact public alternating-gauge attack on the explicit transparent matrix-unit telescope",
        "not_claimed": [
            "generic impossibility for all noncommutative encodings",
            "LWE/SIS break",
            "completed witness KEM",
        ],
    }
    return results


if __name__ == "__main__":
    data = run()
    encoded = json.dumps(data, sort_keys=True, indent=2) + "\n"
    print(encoded, end="")
