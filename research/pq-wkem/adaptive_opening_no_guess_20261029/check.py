#!/usr/bin/env python3
"""Offline exhaustive exact-transcript selective-opening checker.

This verifies finite classical distribution equalities, NOT QPT hardness,
actual SLH signatures, unrestricted NP security, or Bitcoin enforcement.
"""
import hashlib
import json
import random
from collections import Counter
from itertools import product
from pathlib import Path

Q = 3
A_ROWS = ((1, -1), (0, 1), (1, 0))  # p1=(1-x), p2=x, normalization=1
U = (0, 0, 1)
Z = (-1, -1, 1)


def check_rank_certificate():
    assert tuple(sum(Z[r] * A_ROWS[r][c] for r in range(3)) % Q
                 for c in range(2)) == (0, 0)
    assert sum(Z[r] * U[r] for r in range(3)) % Q == 1
    for x in (0, 1):
        assert not ((1-x) == 0 and x == 0)  # ORIGINAL x AND NOT x is false
    # Full ciphertext is uniform for each a, even when noises are fixed.
    histograms = []
    for a in (0, 1):
        hist = Counter()
        for s in product(range(Q), repeat=3):
            s0, s1, s2 = s
            c0 = (s0+s2+1) % Q
            c1 = (-s0+s1-1) % Q
            d = (s2+1+a) % Q
            hist[(c0, c1, d)] += 1
        assert len(hist) == Q**3 and set(hist.values()) == {1}
        histograms.append(hist)
    assert histograms[0] == histograms[1]
    return len(histograms[0])


def enc_actual(bit, coins):
    s0, s1, s2 = coins
    return ((s0+s2) % Q, (-s0+s1) % Q, (s2+bit) % Q)


def single_transcript(bits, coins, mask, pk):
    cs = tuple(enc_actual(bits[i], coins[i]) for i in range(3))
    first = (cs[0][0] + cs[1][2] + mask) % 3
    opened_first = (first, bits[first], *coins[first])
    remaining = [i for i in range(3) if i != first]
    second = remaining[(bits[first]+coins[first][0]+cs[2][2]+mask) % 2]
    opened_second = (second, bits[second], *coins[second])
    return (pk, "claim_A", cs, mask, opened_first, opened_second)


def exhaustive_single(k):
    pk = hashlib.sha256(bytes([k])).hexdigest()  # mock checking key only
    real, sim = Counter(), Counter()
    for bits in product(range(2), repeat=3):
        real_mask = k ^ bits[0] ^ bits[1] ^ bits[2]
        for raw in product(range(Q), repeat=9):
            coins = tuple(raw[3*i:3*i+3] for i in range(3))
            real[single_transcript(bits, coins, real_mask, pk)] += 1
            for independent_mask in (0, 1):
                sim[single_transcript(bits, coins, independent_mask, pk)] += 1
    assert set(real) == set(sim)
    assert all(sim[entry] == 2 * occurrences for entry, occurrences in real.items())
    return {"real_worlds": sum(real.values()), "sim_worlds": sum(sim.values()),
            "exact_transcripts": len(real), "probability_equality": True}


def enc_related(bit, coins):
    s0, s1 = coins
    return (s0, (2*s0) % Q, (s1+bit) % Q)


def related_transcript(bits, coins, masks, pk):
    # Both capsules use the *same* mock checking key, separate fresh share coins.
    cs = tuple(tuple(enc_related(bits[k][i], coins[k][i]) for i in range(2))
               for k in range(2))
    i = (cs[0][0][0]+cs[1][1][2]+masks[0]+masks[1]) % 2
    first = ("claim_A", i, bits[0][i], *coins[0][i])
    j = (bits[0][i]+coins[0][i][0]+cs[1][0][2]+masks[1]) % 2
    second = ("claim_B", j, bits[1][j], *coins[1][j])
    return (pk, cs, masks, first, second)


def exhaustive_two_capsules(k):
    pk = hashlib.sha256(bytes([k])).hexdigest()
    real, sim = Counter(), Counter()
    for raw_bits in product(range(2), repeat=4):
        bits = (raw_bits[:2], raw_bits[2:])
        real_masks = (k ^ bits[0][0] ^ bits[0][1], k ^ bits[1][0] ^ bits[1][1])
        for raw in product(range(Q), repeat=8):
            coins = tuple(tuple(raw[2*(2*c+i):2*(2*c+i)+2] for i in range(2))
                          for c in range(2))
            real[related_transcript(bits, coins, real_masks, pk)] += 1
            for masks in product(range(2), repeat=2):
                sim[related_transcript(bits, coins, masks, pk)] += 1
    assert set(real) == set(sim)
    assert all(sim[entry] == 4 * occurrences for entry, occurrences in real.items())
    return {"real_worlds": sum(real.values()), "sim_worlds": sum(sim.values()),
            "exact_transcripts": len(real), "probability_equality": True}


def enc_errors(bit, coins, errors, *, q, g):
    s0, s1, s2 = coins
    e0, e1, eps = errors
    return ((s0+s2+e0) % q, (-s0+s1+e1) % q,
            (s2+eps+g*bit) % q)


def change_hidden_opening(coins, old_bit, new_bit, *, q, g):
    # Public rank certificate Z=(-1,-1,1) is used to equivocate HIDDEN coins.
    delta = g*(old_bit-new_bit)
    return tuple((coins[i]+delta*Z[i]) % q for i in range(3))


def exhaustive_coin_equivocation():
    checks = 0
    for old, new in product(range(2), repeat=2):
        for coins in product(range(Q), repeat=3):
            for errors in product((-1, 0, 1), repeat=3):
                new_coins = change_hidden_opening(coins, old, new, q=Q, g=1)
                assert enc_errors(old, coins, errors, q=Q, g=1) == enc_errors(
                    new, new_coins, errors, q=Q, g=1)
                checks += 1
    assert checks == 4*(Q**3)*27
    return checks


def entire_mock_key_equivocation():
    rng = random.Random(0xA1D4)
    key = int.from_bytes(hashlib.sha256(b"native challenge secret / simulated ONLY").digest(), "big")
    q, g, width = 257, 7, 256
    checked = 0
    changed_digits = 0
    for claim, hidden in (("claim_A", 1), ("claim_B", 2)):
        shares = [rng.getrandbits(width) for _ in range(3)]
        mask = rng.getrandbits(width)  # independent simulator mask, not K-XOR-shares
        coins = [[tuple(rng.randrange(q) for _ in range(3)) for _ in range(width)]
                 for _ in range(3)]
        errors = [[tuple(rng.choice((-1, 0, 1)) for _ in range(3)) for _ in range(width)]
                  for _ in range(3)]
        public = [[enc_errors((shares[i] >> k)&1, coins[i][k], errors[i][k],
                              q=q, g=g) for k in range(width)] for i in range(3)]
        corrected_hidden = key ^ mask
        for i in range(3):
            if i != hidden:
                corrected_hidden ^= shares[i]
        updated_coins = [change_hidden_opening(coins[hidden][k],
                          (shares[hidden] >> k)&1, (corrected_hidden >> k)&1,
                          q=q, g=g) for k in range(width)]
        assert all(enc_errors((corrected_hidden >> k)&1, updated_coins[k],
                   errors[hidden][k], q=q, g=g) == public[hidden][k]
                   for k in range(width))
        assert (mask ^ corrected_hidden ^ shares[(hidden+1)%3] ^ shares[(hidden+2)%3]) == key
        # Only the unavailable unopened-share coins were changed.
        delta_bits = (corrected_hidden ^ shares[hidden]).bit_count()
        assert delta_bits > 0
        changed_digits += delta_bits
        checked += width
    return {"reconciled_hidden_digits": checked, "changed_hidden_digits": changed_digits, "capsules": 2,
            "native_key_bits": width, "status": "PASS"}


def main():
    rank_support = check_rank_certificate()
    equivocations = exhaustive_coin_equivocation()
    entire_key = entire_mock_key_equivocation()
    result = {
        "test": "adaptive_exact_selective_opening_no_guess",
        "source": "false ORIGINAL x AND NOT x, A=[(1,-1),(0,1),(1,0)], U=(0,0,1)",
        "q": Q,
        "fixed_noise_full_ciphertext_support": rank_support,
        "exact_coin_equivocations": equivocations,
        "whole_key_posthoc_equivocation": entire_key,
        "single_capsule": {str(k): exhaustive_single(k) for k in (0, 1)},
        "two_same_key_capsules": {str(k): exhaustive_two_capsules(k) for k in (0, 1)},
        "limitations": "finite exact classical distributions; mock pk; no native SLH, QPT hardness, arbitrary NP or Bitcoin check",
        "status": "PASS",
    }
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
