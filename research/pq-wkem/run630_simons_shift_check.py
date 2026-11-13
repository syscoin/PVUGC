#!/usr/bin/env python3
"""Exact toy verification of a two-view shifted-permutation Simon falsifier.
Python standard library only; no cryptographic security claims. Seeded simulation.
"""
import json
import random

RNG = random.Random(63020261019)
checks = 0
fourier_cases = 0
pair_checks = 0
classical_checks = 0
quantum_trials = 0
quantum_success = 0


def check(cond):
    global checks
    checks += 1
    assert cond


def dot_parity(a, b):
    return (a & b).bit_count() % 2


def recover_K(samples, n):
    # All samples satisfy (y_low dot K) xor y_top = 0.
    rows = [((y & ((1 << n) - 1)) | (((y >> n) & 1) << n)) for y in samples]
    rank = 0
    for col in range(n):
        pivot = next((r for r in range(rank, len(rows)) if (rows[r] >> col) & 1), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for r in range(len(rows)):
            if r != rank and ((rows[r] >> col) & 1):
                rows[r] ^= rows[rank]
        rank += 1
    if rank < n:
        return None
    ans = 0
    for col in range(n):
        if (rows[col] >> n) & 1:
            ans |= 1 << col
    return ans


for n in range(2, 8):
    size = 1 << n
    for _ in range(8):
        P = list(range(size))
        RNG.shuffle(P)
        inverse = [0] * size
        for x, v in enumerate(P):
            inverse[v] = x
        K = RNG.randrange(size)
        h = size | K
        P0 = lambda z: P[z]
        P1 = lambda z: P[z ^ K]
        for x in range(size):
            for y in range(size):
                eq = P0(x) == P1(y)
                check(eq == ((x ^ y) == K))
                if eq:
                    pair_checks += 1
        for output in range(size):
            x0 = inverse[output]
            x1 = size | (x0 ^ K)
            check((x0 ^ x1) == h)
            seen = 0
            for fy in range(2 * size):
                signs = (-1 if dot_parity(fy, x0) else 1) + (-1 if dot_parity(fy, x1) else 1)
                # Exact Fourier probability equals signs**2 / 2**(n+2).
                probability_numerator = signs * signs
                if dot_parity(fy, h) == 0:
                    check(probability_numerator == 4)
                    seen += 1
                else:
                    check(probability_numerator == 0)
            check(seen == size)
            fourier_cases += 1

for n in range(4, 11):
    size = 1 << n
    for q0, q1 in ((1, 1), (2, 2), (2, 3), (3, 3)):
        A = list(range(q0))
        B = list(range(q1))
        D = {a ^ b for a in A for b in B}
        matches = sum(any((a ^ b) == K for a in A for b in B) for K in range(size))
        check(matches == len(D))
        check(matches <= q0 * q1)
        classical_checks += 1

for n in (4, 6, 8, 10):
    size = 1 << n
    for _ in range(100):
        K = RNG.randrange(size)
        h = size | K
        m = n + 10
        samples = []
        for __ in range(m):
            # Exactly uniform Simon Fourier sample from h-perpendicular subspace:
            lo = RNG.randrange(size)
            top = dot_parity(lo, K)
            y = lo | (top << n)
            check(dot_parity(y, h) == 0)
            samples.append(y)
        guess = recover_K(samples, n)
        quantum_trials += 1
        quantum_success += (guess == K)
        check(guess is None or guess == K)

report = {
    'run': 630,
    'model': 'ideal forward-only random permutation; coherent quantum queries',
    'check_count': checks,
    'pair_validity_cases': pair_checks,
    'exact_fourier_output_cases': fourier_cases,
    'classical_query_set_cases': classical_checks,
    'quantum_simon_trials': quantum_trials,
    'quantum_simon_success': quantum_success,
    'quantum_sample_count_per_trial': 'n+10',
    'mathematical_failure_bound': '2^(-10) for n+10 independent Simon samples',
    'cryptographic_security_established': False,
    'actual_np_wkem_constructed': False,
}
print(json.dumps(report, sort_keys=True, indent=2))
