#!/usr/bin/env python3
from __future__ import annotations

from itertools import combinations, product
import json
import math
from fractions import Fraction

checks = 0
families = []
tightness = []

def ok(cond, msg=""):
    global checks
    checks += 1
    if not cond:
        raise AssertionError(msg)

def popcount(x: int) -> int:
    return x.bit_count()

def majority(bits, tie=None):
    ones = sum(bits)
    zeros = len(bits) - ones
    if ones > zeros:
        return 1
    if zeros > ones:
        return 0
    return tie

def ball_masks(k: int, t: int):
    out = []
    for w in range(t + 1):
        for idxs in combinations(range(k), w):
            m = 0
            for i in idxs:
                m |= 1 << i
            out.append(m)
    return out

# 1. Fixed-digest canonicalization theorem.
# For a common decoded center d, any two full valid opening strings r,e within
# Hamming distance t of d satisfy dist(r,e)<=2t.  If 4t<k, a pad p=K^k xor r
# lets every e recover K by majority(p xor e).
for k in (5, 7, 9, 11, 13):
    for t in range(0, 4):
        if 4 * t >= k:
            continue
        masks = ball_masks(k, t)
        # Translation invariance means d=0 is exhaustive for the relative geometry.
        for r in masks:
            for e in masks:
                dist = popcount(r ^ e)
                ok(dist <= 2 * t, (k, t, r, e, dist))
                for K in (0, 1):
                    keymask = ((1 << k) - 1) if K else 0
                    p = keymask ^ r
                    votes_mask = p ^ e
                    votes = [(votes_mask >> i) & 1 for i in range(k)]
                    got = majority(votes)
                    ok(got == K, (k, t, K, r, e, dist, got))
        families.append({
            "k": k,
            "t": t,
            "ball_size": len(masks),
            "max_pair_distance": 2*t,
            "majority_margin_lower_bound": k - 4*t,
        })

# Also exhaust every center for small k to independently check translation.
for k, t in ((5, 1), (7, 1)):
    masks = ball_masks(k, t)
    for d in range(1 << k):
        for mr in masks:
            r = d ^ mr
            for me in masks:
                e = d ^ me
                for K in (0, 1):
                    keymask = ((1 << k) - 1) if K else 0
                    p = keymask ^ r
                    votes = [((p ^ e) >> i) & 1 for i in range(k)]
                    ok(majority(votes) == K, (k, t, d, r, e, K))

# 2. Tightness controls: once 4t >= k there can be two radius-t strings whose
# distance reaches at least half the block length, so strict-majority decoding has
# no universal correctness guarantee.
for k in range(4, 15):
    for t in range(1, 5):
        if 4 * t < k or 2*t > k:
            continue
        # disjoint t-flip sets around d=0
        r = sum(1 << i for i in range(t))
        e = sum(1 << i for i in range(t, 2*t))
        dist = popcount(r ^ e)
        ok(dist == 2*t)
        keymask = 0
        p = keymask ^ r
        votes = [((p ^ e) >> i) & 1 for i in range(k)]
        got = majority(votes, tie="tie")
        # If 2t > k/2 the majority is wrong for K=0; at equality it ties.
        if 4*t > k:
            ok(got == 1, (k,t,dist,got))
            outcome = "wrong-majority"
        else:
            ok(got == "tie", (k,t,dist,got))
            outcome = "tie"
        tightness.append({"k":k,"t":t,"pair_distance":dist,"outcome":outcome})

# 3. Perfect one-time-pad control under a truly uniform r vector. For each K,
# p = r xor K^k is exactly uniform; enumerate small blocks and compare counts.
for k in range(1, 11):
    counts = []
    for K in (0, 1):
        freq = [0] * (1 << k)
        km = ((1 << k)-1) if K else 0
        for r in range(1 << k):
            freq[r ^ km] += 1
        counts.append(freq)
        ok(all(x == 1 for x in freq), (k,K))
    ok(counts[0] == counts[1], k)

# 4. Hybrid accounting is algebraic: if each of k coordinates has distinguishing
# advantage at most eps and setup-mode switching costs delta, the standard hybrid
# gives at most delta + k*eps. This checks arithmetic for representative rationals.
for k in (8,16,32,64,128,256):
    for eps_num in (1,2,3,7):
        den = 10_000_000
        delta_num = 11
        bound_num = delta_num + k*eps_num
        ok(Fraction(bound_num, den) == Fraction(delta_num, den) + k*Fraction(eps_num, den))

# 5. Full-valid-opening abstraction: a valid opening string is useful regardless of
# its origin. This explicitly records the source-gating boundary by confirming that
# any point in the binding ball decapsulates; no source predicate appears in Decap.
for k,t in ((9,1),(13,2)):
    if 4*t >= k:
        continue
    d = int("1010101010101"[:k], 2)
    masks = ball_masks(k,t)
    r = d ^ masks[-1]
    for e_mask in masks:
        e = d ^ e_mask
        for K in (0,1):
            km = ((1<<k)-1) if K else 0
            p = km ^ r
            got = majority([((p^e)>>i)&1 for i in range(k)])
            ok(got == K)

out = {
    "run": 121,
    "status": "PASS",
    "total_assertions": checks,
    "fixed_digest_majority": {
        "claim": "If every full valid encoding vector for one fixed digest is within Hamming radius t of one decoded center d, then pad p=K^k xor r from one honest opening vector r lets every full valid vector recover the same bit K by strict majority whenever 4t<k.",
        "families": families,
    },
    "tightness": {
        "claim": "When 4t>=k, two radius-t strings can be at distance at least k/2, so universal strict-majority correctness is no longer guaranteed.",
        "controls": tightness,
    },
    "pad_hiding_control": {
        "claim": "For truly uniform r in {0,1}^k, p=r xor K^k is exactly uniform and independent of K.",
        "enumerated_k_max": 10,
    },
    "security_scope": [
        "These are finite combinatorial/functionality checks, not a computational security proof.",
        "The VTDH paper's published pseudorandomness definition quantifies over PPT adversaries; a QPT lift of its concrete LWE instantiation is not established by this checker.",
        "The majority layer canonicalizes non-unique valid openings for a fixed digest but does not make an ORIGINAL NP witness capable of opening a setup-fixed digest.",
        "Any party that obtains any full valid opening vector in the binding ball recovers the key; source gating therefore remains a separate compiler/extraction obligation.",
    ],
}
print(json.dumps(out, indent=2, sort_keys=True))
