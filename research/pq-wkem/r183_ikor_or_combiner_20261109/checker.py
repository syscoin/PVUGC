#!/usr/bin/env python3
"""IKOR algebraic consistency checker, not a security experiment.

Enumerates exact uniform multi-pad public marginals, verifies the common
frozen capability under independent branch keys, and explicit unsafe domain
reuse. No actual witness-KEM, Bitcoin evidence, or QPT attack is implemented.
"""
from collections import Counter
import itertools
import json
import hashlib
from pathlib import Path

counts = Counter()

def check(cond, label):
    assert cond, label
    counts[label] += 1


def main():
    for bits in (1,2,3):
        domain = range(1 << bits)
        branches = 3
        for secret in domain:
            for keys in itertools.product(domain, repeat=branches):
                distribution = Counter()
                for pad_at_key in itertools.product(domain, repeat=branches):
                    masks = tuple(secret ^ z for z in pad_at_key)
                    distribution[masks] += 1
                    for j in range(branches):
                        check(masks[j] ^ pad_at_key[j] == secret, 'all_branches_same_capability')
                # Three independent quantum-accessible random-oracle domains,
                # evaluated only at their respective secret addresses, have
                # uniform independent outputs even conditioned on the keys.
                expected = 1  # each (D_1,D_2,D_3) once at fixed keys/secret
                check(len(distribution) == len(domain) ** branches,
                      'joint_marginal_full_support')
                check(all(v == expected for v in distribution.values()),
                      'joint_marginal_exact_uniformity')
    # Negatives: reusing the pad oracle as a public key-check tag immediately
    # exposes sigma; this is an explicit construction regression, not an attack
    # on the domain-separated proposed combiner.
    for bits in (1,2,3):
        for secret in range(1 << bits):
            for key in range(1 << bits):
                for pad in range(1 << bits):
                    public_cipher = secret ^ pad
                    public_ck_bad = pad
                    recovered = public_cipher ^ public_ck_bad
                    check(recovered == secret, 'public_check_reuse_leaks_secret')
    # A different branch's key does not generally open a target branch mask;
    # this is a functionality check of required branch-id domain separation.
    for bits in (2,3):
        for secret in range(1 << bits):
            for p1, p2 in itertools.product(range(1 << bits), repeat=2):
                D1 = secret ^ p1
                check((D1 ^ p2 == secret) == (p1 == p2),
                      'wrong_domain_pad_fails_except_collision')

    return {
        'candidate':'IKOR independent-key OR masked frozen native capability',
        'run':'R183_20261109',
        'assertions':sum(counts.values()),
        'groups':dict(sorted(counts.items())),
        'scope':'exact algebra/public marginal only, NOT security/real branch Build/Open',
        'not_implemented':[
            'hash-based ORIGINAL source branch-KEMs',
            'quantum extraction experiment',
            'native signature security',
            'real Bitcoin/Syscoin witness validation',
            'malicious-setup and active related-capsule security'
        ],
        'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    }

if __name__ == '__main__':
    print(json.dumps(main(),sort_keys=True,indent=2))
