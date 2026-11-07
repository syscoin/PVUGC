#!/usr/bin/env python3
"""Run 673: public signing-verification key refutes real-or-random seed secrecy.
This is an EXPLICITLY INSECURE 10-bit toy Lamport signature, not a WE construction.
No external libraries, remote requests, or hardness claims.
"""
from hashlib import shake_256, sha256
import json

N_BITS = 10
DOMAIN = 1 << N_BITS
LABEL_BYTES = 16
FIXED_MESSAGE = (1, 0, 1, 1)

def labels(seed):
    return [shake_256(b"Run673/Lamport" + seed.to_bytes(2,"big") +
                      bytes([index])).digest(LABEL_BYTES)
            for index in range(2 * len(FIXED_MESSAGE))]

def keygen_public(seed):
    return tuple(sha256(label).digest() for label in labels(seed))

def sign(seed, bits=FIXED_MESSAGE):
    parts = labels(seed)
    return tuple(parts[2*i + bit] for i,bit in enumerate(bits))

def verify(pk, bits, signature):
    return len(signature) == len(bits) and all(
        sha256(part).digest() == pk[2*i+bit]
        for i,(bit,part) in enumerate(zip(bits, signature))
    )

def public_checker(pk, candidate):
    return verify(pk, FIXED_MESSAGE, sign(candidate))

def main():
    checked = 0
    anchor_seed = 723
    pk = keygen_public(anchor_seed)
    assert public_checker(pk, anchor_seed)
    checked += 1
    accepted = [candidate for candidate in range(DOMAIN)
                if public_checker(pk, candidate)]
    checked += DOMAIN
    assert accepted == [anchor_seed]
    checked += 1
    assert DOMAIN-len(accepted) == DOMAIN-1
    checked += 1
    assert verify(pk, FIXED_MESSAGE, sign(anchor_seed))
    checked += 1
    for fake in [0, 1, 222, 723, 1023]:
        assert public_checker(pk, fake) == (fake == anchor_seed)
        checked += 1
    for relation in ["FALSE/nosolution", "TRUE/many-witnesses"]:
        for candidate in [anchor_seed, 0]:
            assert public_checker(pk, candidate) == (candidate == anchor_seed)
            checked += 1
    result = {
      "run": 673,
      "model": "toy deterministic Lamport OTS with 10-bit seed",
      "native_fixed_message_bits": "".join(map(str, FIXED_MESSAGE)),
      "domain_size": DOMAIN,
      "honest_seed": anchor_seed,
      "accepted_seed_count": len(accepted),
      "accepted_seed_candidates": accepted,
      "probability_check_accept_real": "1",
      "probability_check_accept_independent_uniform": f"{len(accepted)}/{DOMAIN}",
      "distinguishing_gap": f"{DOMAIN-len(accepted)}/{DOMAIN}",
      "assertions": checked,
      "note": "Public-key correlation only; not WE, PQ security, or practical signing."
    }
    print(json.dumps(result, sort_keys=True, indent=2))

if __name__ == "__main__":
    main()
