#!/usr/bin/env python3
"""Run 681: exact finite public-orbit enumeration / binary-control separation.

This is a combinatorial interface checker, NOT a witness-KEM implementation,
not a cryptographic security test, and not an instantiation of CLZ.
"""
from hashlib import sha256
from math import asin, sin, sqrt
from itertools import product
import json

assertions = 0

def check(cond, why):
    global assertions
    assert cond, why
    assertions += 1


def pk_for(key, context):
    return sha256(b'run681/checking-key/' + context + key.to_bytes(2, 'big')).digest()


def accepts(candidate, public_key, context):
    return isinstance(candidate, int) and pk_for(candidate, context) == public_key


def unary_fixture(horizon, release_slots, key, context):
    """Opaque-table *functionality* fixture: C_t=t; public O_t offers key at
    release_slots. Does NOT implement or assume a cryptographically secure setup."""
    check(all(0 <= t <= horizon for t in release_slots), 'valid public slots')
    public_key = pk_for(key, context)
    public_step = lambda t: t + 1
    public_open = lambda t: key if t in release_slots else None
    state = 0
    valid_hits = []
    for i in range(horizon + 1):
        output = public_open(state)
        if accepts(output, public_key, context):
            valid_hits.append(i)
        if i < horizon:
            state = public_step(state)
    check(set(valid_hits) == set(release_slots), 'enumeration finds exact slots')
    check(all(public_open(t) == key for t in release_slots), 'common capability')
    check(len(valid_hits) > 0, 'at least one valid known schedule exists')
    # Show that changing branch/UTXO context can reject this credential.
    check(not accepts(key, pk_for(key, context + b'/other'), context), 'branch separation')
    return {
        'horizon': horizon, 'public_states_checked': horizon + 1,
        'released_slots': sorted(release_slots),
        'first_publicly_recovered_step': valid_hits[0],
        'unary_orbit_distinct_prefixes': horizon + 1,
        'credential_recovered_without_witness': True,
    }


def word_tree(n):
    """Two public transitions append a selected bit at each depth.
    The state is (depth, prefix). Public labels aren't security.
    """
    root = (0, ())
    def step(state, bit):
        depth, prefix = state
        check(depth < n and bit in (0, 1), 'binary public step well formed')
        return (depth + 1, prefix + (bit,))
    endpoints = set()
    for bits in product((0, 1), repeat=n):
        s = root
        for b in bits:
            s = step(s, b)
        endpoints.add(s)
        check(s == (n, bits), 'endpoint exactly records public input')
    check(len(endpoints) == 2**n, 'binary control has 2^n distinct prefixes')
    return {'bits': n, 'steps_per_witness': n, 'reachable_endpoints': len(endpoints)}


def grover_probability(n, successes, queries):
    theta = asin(sqrt(successes / n))
    return sin((2 * queries + 1) * theta)**2


def main():
    examples = [
        unary_fixture(12, {3, 7, 11}, 0x3b2a, b'claim/A/challenge'),
        unary_fixture(35, {23}, 0x71ef, b'claim/B/challenge'),
        unary_fixture(63, {1, 19, 52}, 0x1c17, b'claim/C/challenge'),
    ]
    trees = [word_tree(n) for n in range(1, 9)]
    check(all(t['reachable_endpoints'] > t['steps_per_witness'] for t in trees[2:]),
          'binary public-control options exceed unary horizon for n>=3')
    # Exhaustively verify elementary amplitude-amplification probability for
    # a tiny 8-state checker (one marked state), using a dense state vector.
    N = 8
    v = [1 / sqrt(N)] * N
    dense = []
    for q in range(4):
        prob = v[2]**2
        formula = grover_probability(N, 1, q)
        check(abs(prob - formula) < 1e-12, 'Grover analytic/dense agreement')
        dense.append(round(prob, 12))
        v[2] *= -1     # marked-state phase oracle
        avg = sum(v) / N
        v = [2 * avg - x for x in v]  # diffusion
    result = {
        'run': 681,
        'scope': 'exact finite public-orbit enumeration; not CLZ cryptanalysis',
        'unary_examples': examples,
        'binary_public_input_control': trees,
        'grover_dense_vs_formula_probabilities': dense,
        'assertions': assertions,
        'limitations': [
            'Toy public release fixture is not honest witness-free WKEM setup.',
            'No real ciphertext, iO, FHE, FE, or SLH-DSA evaluated.',
            'Only witness-independent public opening and enumerably many public unary iterates are ruled out.',
            'A witness-dependent protected output function is outside the theorem.',
        ]
    }
    print(json.dumps(result, sort_keys=True, indent=2))

if __name__ == '__main__':
    main()
