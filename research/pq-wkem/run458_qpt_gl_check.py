#!/usr/bin/env python3
"""Run 458: finite Walsh-list demonstration for re-runnable noisy-parity distinguishers.
Standard library only. This does NOT construct a protected release scheme or prove PQ security.
"""
import hashlib
import json
import random


def fwht(values):
    arr = list(values)
    half = 1
    while half < len(arr):
        for start in range(0, len(arr), 2 * half):
            for i in range(start, start + half):
                a, b = arr[i], arr[i + half]
                arr[i], arr[i + half] = a + b, a - b
        half *= 2
    return arr


def run_fixture(n, ell, seed, noise_quarters, honest=True):
    rng = random.Random(seed)
    k = rng.getrandbits(n)
    width = 1 << ell
    basis = [rng.getrandbits(n) for _ in range(ell)]
    rows = [0] * width
    for mask in range(1, width):
        bit = mask & -mask
        rows[mask] = rows[mask ^ bit] ^ basis[bit.bit_length() - 1]
    candidates = [0] * width
    query_count = 0
    correct_count = 0
    for coord in range(n):
        vals = [0] * width  # omit mask=0 to retain pairwise uniformity
        for mask in range(1, width):
            r = rows[mask] ^ (1 << coord)
            c = rng.getrandbits(1)
            parity = (r & k).bit_count() & 1
            noise = int(rng.randrange(4) < noise_quarters) if honest else rng.getrandbits(1)
            # Re-runnable synthetic distinguisher outputs b xor independent noise.
            out = c ^ parity ^ noise if honest else rng.getrandbits(1)
            prediction = c ^ out
            if honest:
                correct_count += int(prediction == parity)
            vals[mask] = 1 - 2 * prediction
            query_count += 1
        coeffs = fwht(vals)
        for a, val in enumerate(coeffs):
            if val < 0:
                candidates[a] |= (1 << coord)
    candidate_set = set(candidates)
    fullmask = (1 << n) - 1
    candidate_set.update(fullmask ^ value for value in candidates)
    commitment = hashlib.sha256(k.to_bytes((n + 7) // 8, 'big')).hexdigest()
    checked = [v for v in candidate_set if hashlib.sha256(v.to_bytes((n + 7) // 8, 'big')).hexdigest() == commitment]
    assert query_count == n * (width - 1)
    assert len(candidate_set) <= 2 * width
    assert len(checked) <= 1  # collision absent in these toy fixtures
    if honest:
        assert k in candidate_set
        assert checked == [k]
    else:
        assert k not in candidate_set
        assert checked == []
    return {
        "n": n, "ell": ell, "synthetic_distinguisher_correct_probability":
          "1-" + str(noise_quarters) + "/4" if honest else "1/2",
        "seed": seed, "quantum_advice": "none", "secret_in_list": k in candidate_set,
        "candidate_count": len(candidate_set), "public_commitment_matches": len(checked),
        "oracle_calls": query_count, "observed_predictor_success":
          round(correct_count / query_count, 6) if honest else None,
    }


def main():
    fixtures = [run_fixture(24, 10, 45801, 1),
                run_fixture(24, 10, 45802, 1),
                run_fixture(24, 12, 45803, 1),
                run_fixture(24, 10, 45804, 1, False)]
    assert all(item['secret_in_list'] for item in fixtures[:3])
    assert not fixtures[3]['secret_in_list']
    print(json.dumps({"run": 458, "test": "re-runnable measured predictor + pairwise-independent Walsh list",
                      "fixtures": fixtures, "status": "PASS", "security_claim": "NONE"},
                     sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
