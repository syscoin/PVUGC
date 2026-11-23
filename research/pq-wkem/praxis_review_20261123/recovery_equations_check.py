#!/usr/bin/env python3
"""Check two algebraic identities used in this review; NOT a Praxis implementation.

1. Witness-dependent (xi,r,psi) combinations converge to the same kappa.
2. Given a relative discrete logarithm alpha, public alpha copies reveal K.

Tiny prime-order subgroups let us execute DLP exhaustively in (2). This does
not execute a quantum algorithm, attack BN254, instantiate the full ciphertext,
or contradict a classical security theorem at admissible parameters.
"""
import hashlib
import json
from pathlib import Path


def subgroup_generator(p, q):
    assert (p - 1) % q == 0
    for a in range(2, p):
        g = pow(a, (p - 1) // q, p)
        if g != 1 and pow(g, q, p) == 1:
            return g
    raise AssertionError('no generator')


def relative_dlog(base, target, p, q):
    cur = 1
    for a in range(q):
        if cur == target:
            return a
        cur = cur * base % p
    raise AssertionError('no logarithm')


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def pad(element):
    return hashlib.sha256(b'REVIEW-ONLY/key/' + element.to_bytes(2, 'big')).digest()


def run():
    q = 101
    kappa = 37
    confluence = []
    # Represent group elements by exponents solely for this identity check.
    for xi, r, psi in [(1, 3, 8), (2, 9, 7), (78, 4, 0), (100, 99, 65)]:
        lam = (xi * kappa + r * psi) % q
        recovered = pow(xi, -1, q) * (lam - r * psi) % q
        assert recovered == kappa
        confluence.append({'xi': xi, 'r': r, 'psi': psi, 'lambda': lam,
                           'recovered_kappa': recovered})

    # Distinct concrete cyclic groups stand in for G2 and GT, both order q.
    p2, pt = 607, 809
    g2, gt = subgroup_generator(p2, q), subgroup_generator(pt, q)
    capability = hashlib.sha256(b'REVIEW ONLY frozen cancellation bytes').digest()
    key_element = pow(gt, kappa, pt)
    masked = xor(capability, pad(key_element))
    cases = []
    for s, alpha in [(3, 17), (9, 48), (100, 100), (67, 1)]:
        S = pow(g2, s, p2)
        S_alpha = pow(S, alpha, p2)
        K_alpha = pow(key_element, alpha, pt)
        # Only these public values enter the recovery, with no witness.
        recovered_alpha = relative_dlog(S, S_alpha, p2, q)
        recovered_key = pow(K_alpha, pow(recovered_alpha, -1, q), pt)
        recovered_capability = xor(masked, pad(recovered_key))
        assert recovered_alpha == alpha
        assert recovered_key == key_element
        assert recovered_capability == capability
        cases.append({'S': S, 'S_alpha': S_alpha, 'K_alpha': K_alpha,
                      'recovered_alpha': recovered_alpha,
                      'recovered_key': recovered_key,
                      'same_capability': True})
    return {'scope': __doc__, 'group_order': q, 'G2_modulus': p2,
            'GT_modulus': pt, 'generators': [g2, gt],
            'confluence': confluence, 'dlp_conditional_recovery': cases,
            'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


if __name__ == '__main__':
    print(json.dumps(run(), indent=2, sort_keys=True))
