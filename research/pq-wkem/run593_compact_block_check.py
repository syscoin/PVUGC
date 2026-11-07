#!/usr/bin/env python3
"""AADP compact-block diagnostic. Python 3 + NumPy; not a secure WE implementation.
All arithmetic is exact in F_257. Test vectors use a fixed PRNG, not secure coins.
"""
from __future__ import annotations
import hashlib
import itertools
import json
import random
import numpy as np

Q = 257
G = tuple(itertools.permutations(range(3)))
IDENTITY = G.index((0, 1, 2))
MUL = [[G.index(tuple(g[h[i]] for i in range(3))) for h in G] for g in G]
CHECKS = 0

def require(ok: bool, label: str) -> None:
    global CHECKS
    if not ok:
        raise AssertionError(label)
    CHECKS += 1

def ga_mul(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[int, ...]:
    out = [0] * 6
    for i in range(6):
        for j in range(6):
            out[MUL[i][j]] = (out[MUL[i][j]] + a[i] * b[j]) % Q
    return tuple(out)

def regular(a: tuple[int, ...]) -> np.ndarray:
    """Faithful left regular representation of F_257[S3]."""
    out = np.zeros((6, 6), dtype=np.int64)
    for i in range(6):
        for j in range(6):
            out[MUL[i][j], j] = (out[MUL[i][j], j] + a[i]) % Q
    return out

def mm(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return a @ b % Q

def rank(a: np.ndarray) -> int:
    a = a.copy() % Q
    row = 0
    for col in range(a.shape[1]):
        hits = np.flatnonzero(a[row:, col])
        if not len(hits):
            continue
        p = row + int(hits[0])
        a[[row, p]] = a[[p, row]]
        a[row] = a[row] * pow(int(a[row, col]), -1, Q) % Q
        for i in range(row + 1, a.shape[0]):
            a[i] = (a[i] - a[i, col] * a[row]) % Q
        row += 1
        if row == a.shape[0]:
            break
    return row

def inverse(a: np.ndarray) -> np.ndarray:
    n = len(a)
    w = np.concatenate((a.copy() % Q, np.eye(n, dtype=np.int64)), axis=1)
    for col in range(n):
        hits = np.flatnonzero(w[col:, col])
        if not len(hits):
            raise ValueError('singular')
        p = col + int(hits[0])
        w[[col, p]] = w[[p, col]]
        w[col] = w[col] * pow(int(w[col, col]), -1, Q) % Q
        for i in range(n):
            if i != col:
                w[i] = (w[i] - w[i, col] * w[col]) % Q
    return w[:, n:]

def det(a: np.ndarray) -> int:
    a = a.copy() % Q
    d = 1
    for col in range(len(a)):
        hits = np.flatnonzero(a[col:, col])
        if not len(hits):
            return 0
        p = col + int(hits[0])
        if p != col:
            a[[col, p]] = a[[p, col]]
            d = -d
        pivot = int(a[col, col])
        d = d * pivot % Q
        a[col] = a[col] * pow(pivot, -1, Q) % Q
        for i in range(col + 1, len(a)):
            a[i] = (a[i] - a[i, col] * a[col]) % Q
    return d

def gate(a: int, b: int, c: int, d: int, xi: np.ndarray) -> np.ndarray:
    h = len(xi)
    eye = np.eye(h, dtype=np.int64)
    z = np.zeros((h, h), dtype=np.int64)
    return np.block([[a*eye, c*eye, -xi, z],
                     [d*eye, b*eye, z, xi],
                     [z, z, b*eye, c*eye],
                     [z, z, d*eye, a*eye]]) % Q

def randmat(rng: random.Random, rows: int, cols: int) -> np.ndarray:
    return np.array([[rng.randrange(Q) for _ in range(cols)] for _ in range(rows)], dtype=np.int64)

def setup_boolean(m: int, block: int, seed: int) -> list[np.ndarray]:
    """Source X_i^2 = X_0 X_i, i=1..m. The original scalar AADP is block=1.
    block>1 replaces ONLY xi by noncommuting blocks; source coefficients stay central.
    """
    rng = random.Random(seed)
    size = 2 * block * m + 1
    out = [np.zeros((size, size), dtype=np.int64) for _ in range(m + 1)]
    for i in range(1, m + 1):
        left = randmat(rng, size, 4 * block)
        right = randmat(rng, 4 * block, size)
        for j in range(m + 1):
            # a=b=d=X_i, c=X_0: ab=cd is exactly X_i^2=X_0 X_i.
            a = b = d = int(j == i)
            c = int(j == 0)
            xi = randmat(rng, block, block)
            out[j] = (out[j] + mm(mm(left, gate(a, b, c, d, xi)), right)) % Q
    return out

def run() -> dict:
    rng = random.Random(593)
    algebra_pairs = 0
    quotient_message_cases = 0
    for _ in range(64):
        a = tuple(rng.randrange(Q) for _ in G)
        b = tuple(rng.randrange(Q) for _ in G)
        ab = ga_mul(a, b)
        require(sum(ab) % Q == sum(a)*sum(b) % Q, 'augmentation homomorphism')
        require(np.array_equal(regular(ab), mm(regular(a), regular(b))), 'regular representation')
        require(np.array_equal(np.ones(6, dtype=np.int64) @ regular(a) % Q,
                               np.full(6, sum(a) % Q, dtype=np.int64)), 'visible scalar quotient')
        algebra_pairs += 1
        for key in (0, 1, 17, 256):
            enc = list(a)
            enc[IDENTITY] = (enc[IDENTITY] + key) % Q
            require(sum(enc) % Q == (sum(a) + key) % Q, 'scalar message survives quotient')
            quotient_message_cases += 1
    u = tuple(int(i == G.index((1, 0, 2))) for i in range(6))
    v = tuple(int(i == G.index((0, 2, 1))) for i in range(6))
    require(ga_mul(u, v) != ga_mul(v, u), 'noncommuting group algebra')

    gate_tests = []
    for block in (1, 2, 3):
        for vals in ((0, 1, 0, 0), (1, 0, 0, 0), (2, 3, 1, 6),
                     (1, 1, 0, 0), (2, 3, 1, 5)):
            xi = randmat(rng, block, block)
            r = rank(gate(*vals, xi))
            expected = (2 if (vals[0]*vals[1]-vals[2]*vals[3]) % Q == 0 else 4) * block
            require(r == expected, 'block gate preserves source rank')
            gate_tests.append({'block': block, 'abcd': list(vals), 'rank': r})
        xi = np.eye(block, dtype=np.int64)
        require(rank(gate(0, 0, 0, 0, xi)) == 2*block, 'degenerate source with unit xi')

    # End-to-end algebra-valued ciphertext equality with scalar AADP under epsilon.
    m, dim, h = 2, 5, 6
    group_cipher = [np.zeros((dim*h, dim*h), dtype=np.int64) for _ in range(m+1)]
    scalar_cipher = [np.zeros((dim, dim), dtype=np.int64) for _ in range(m+1)]
    for i in range(1, m+1):
        la = np.array([[[rng.randrange(Q) for _ in G] for _ in range(4)] for _ in range(dim)], dtype=np.int64)
        ra = np.array([[[rng.randrange(Q) for _ in G] for _ in range(dim)] for _ in range(4)], dtype=np.int64)
        lr = np.block([[regular(tuple(map(int, la[row, col]))) for col in range(4)] for row in range(dim)])
        rr = np.block([[regular(tuple(map(int, ra[row, col]))) for col in range(dim)] for row in range(4)])
        ls, rs = la.sum(axis=2) % Q, ra.sum(axis=2) % Q
        for j in range(m+1):
            xa = tuple(rng.randrange(Q) for _ in G)
            vals = (int(j == i), int(j == i), int(j == 0), int(j == i))
            group_cipher[j] = (group_cipher[j] + mm(mm(lr, gate(*vals, regular(xa))), rr)) % Q
            scalar_cipher[j] = (scalar_cipher[j] + mm(mm(ls, gate(*vals, np.array([[sum(xa) % Q]], dtype=np.int64))), rs)) % Q
    for key in (0, 1, 73, 256):
        for j in range(m+1):
            gc, sc = group_cipher[j].copy(), scalar_cipher[j].copy()
            if j == 0:
                gc[-h:, -h:] = (gc[-h:, -h:] + key*np.eye(h, dtype=np.int64)) % Q
                sc[-1, -1] = (int(sc[-1, -1]) + key) % Q
            quotient = np.array([[int(gc[row*h:(row+1)*h, col*h].sum()) % Q
                                  for col in range(dim)] for row in range(dim)], dtype=np.int64)
            require(np.array_equal(quotient, sc), 'full ciphertext scalar quotient')

    correctness_cases = 0
    cofactor_zero_cases = 0
    for block in (1, 2):
        for seed in range(4):
            coeffs = setup_boolean(3, block, seed + 100)
            require(not np.array_equal(coeffs[0], sum(coeffs) % Q), 'different witness states')
            for w in itertools.product((0, 1), repeat=3):
                mat = coeffs[0].copy()
                for i, wi in enumerate(w, 1):
                    mat = (mat + wi*coeffs[i]) % Q
                require(det(mat) == 0, 'all Boolean source witnesses give zero determinant')
                require(rank(mat) <= len(mat)-1, 'rank ceiling')
                key = 73
                enc = mat.copy()
                enc[-1, -1] = (int(enc[-1, -1]) + key) % Q
                cofactor = det(enc[:-1, :-1])
                require(det(enc) == key*cofactor % Q, 'common key determinant identity')
                if cofactor:
                    require(det(enc)*pow(cofactor, -1, Q) % Q == key, 'unique root')
                else:
                    cofactor_zero_cases += 1
                correctness_cases += 1

    diagnostics = []
    for block in (1, 2):
        for seed in range(4):
            coeffs = setup_boolean(12, block, seed + 800)
            a, b, c = coeffs[1:4]
            ra = rank(a)
            if ra < len(a):
                diagnostics.append({'block': block, 'seed': seed + 800, 'size': len(a),
                                    'anchor_rank': ra, 'commutator_rank': None})
                continue
            ia = inverse(a)
            require(np.array_equal(mm(ia, a), np.eye(len(a), dtype=np.int64)), 'inverse')
            tb, tc = mm(ia, b), mm(ia, c)
            comm = (mm(tb, tc) - mm(tc, tb)) % Q
            diagnostics.append({'block': block, 'seed': seed + 800, 'size': len(a),
                                'anchor_rank': ra, 'commutator_rank': rank(comm)})

    m = 15000
    size_rows = []
    for block in (1, 2):
        n = 2*block*m+1
        size_rows.append({'gates': m, 'coefficient_count_assumed': m+1,
                          'block': block, 'matrix_size': n, 'bytes_per_field_element_assumed': 32,
                          'dense_bytes': (m+1)*n*n*32})
    return {'research_id': '593', 'status': 'PASS', 'field_prime': Q,
            'assertions_passed': CHECKS, 'group_algebra_dimension': 6,
            'regular_representation_entries': 36, 'algebra_pairs': algebra_pairs,
            'quotient_message_cases': quotient_message_cases, 'full_ciphertext_quotient_slices': 12, 'gate_tests': gate_tests,
            'witness_cases': correctness_cases, 'zero_cofactor_cases': cofactor_zero_cases,
            'normalized_commutator_diagnostics': diagnostics,
            'illustrative_dense_sizes_not_security_parameters': size_rows,
            'claims': {'generic_source_rank_bound': True, 'new_pq_security_proof': False,
                       'full_aadp_attack_implemented': False, 'production_modification': False}}

if __name__ == '__main__':
    print(json.dumps(run(), indent=2, sort_keys=True))
