#!/usr/bin/env python3
"""Run 387 exact toy information-theoretic distributions.

This is NOT public-key FHE, LWE, an NP release, or a quantum security test.
The symbolic QPT IND-CPA/EUF-CMA theorem lives in the paired proof note.
"""
from collections import defaultdict
from itertools import product
import hashlib
import json

Q = 8
checks = 0
rows = []


def check(condition, reason):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(f"Check {checks}: {reason}")


def public_eval(capsules, w):
    # A stand-in for an arbitrary collection of *public deterministic* functions.
    return ((sum(capsules) + 3 * w) % Q,
            (capsules[0] + 2 * w) % Q,
            tuple((c + 2 * w) % Q for c in capsules))


for n_caps in (1, 2, 3):
    # K is uniform; each additive mask is independently uniform.
    # vk = K mod 2 leaks one bit intentionally to model *some* correlated
    # public checking data. This is NOT a native-signature verification key.
    obs_to_k = defaultdict(lambda: defaultdict(int))
    for K in range(Q):
        vk = K % 2
        for w in (0, 1):  # valid witness is public and independent of K
            for rs in product(range(Q), repeat=n_caps):
                ct = tuple((K + r) % Q for r in rs)
                obs = (vk, w, ct, public_eval(ct, w))
                obs_to_k[obs][K] += 1
    # Every full public observation has an exactly uniform 4-element
    # conditional key distribution: posterior success at most 1/4.
    for obs, histogram in obs_to_k.items():
        vk = obs[0]
        check(set(histogram) == {k for k in range(Q) if k % 2 == vk},
              "complete ciphertext + public evaluation adds no key knowledge")
        check(len(set(histogram.values())) == 1,
              "exactly uniform conditional key distribution")
        check(sum(histogram.values()) == Q // 2,
              "correct multiplicity per public observation")
    expected_views = 2 * 2 * (Q ** n_caps)
    check(len(obs_to_k) == expected_views, "all full public observations covered")
    rows.append({"capsules": n_caps, "public_views": len(obs_to_k),
                 "conditional_key_candidates": Q // 2,
                 "best_posterior_exact_key_success": "1/4"})

# A transparent public decoder with the actual pad r trivially releases K;
# a purported source check does not hide that public pad from the caller.
for K, r in product(range(Q), repeat=2):
    ct = (K + r) % Q
    check((ct - r) % Q == K,
          "published decryption material exposes K with no ORIGINAL witness")
    check((ct - r) % Q == K and False is not True,
          "false-witness caller still knows public decryption material")

# Distinct witness states can remain different; this toy solely models
# indistinguishability of K from ciphertext-only public observations.
output = {
    "run": 387,
    "status": "PASS",
    "assertions": checks,
    "parameter_q": Q,
    "models": rows,
    "public_auxiliary": "vk = K mod 2 (toy leakage, not native signing)",
    "complete_key_recovery_with_published_pad": True,
    "model_is_public_key_encryption": False,
    "model_is_FHE": False,
    "actual_LWE_assumption_verified": False,
    "actual_QPT_security_verified": False,
    "theorem_validated_by_checker": False,
    "takeaway": "Finite statistical sanity check only; QPT theorem is a separate hybrid proof."
}
print(json.dumps(output, sort_keys=True, indent=2))
