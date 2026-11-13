#!/usr/bin/env python3
"""Finite demonstration of paired-query Fourier-prefix recovery of a hidden capability.

This tests the Goldreich--Levin inner-product reconstruction step, NOT a
witness encryption construction, any SHA/RO hardness, or quantum simulation.
The predictor is an explicitly simulated noisy oracle; the outer extractor
queries it repeatedly on the SAME public instance with independent coins.
"""
import hashlib
import json
import random
from math import ceil


def parity(x):
    return x.bit_count() & 1


class NoisyParityPredictor:
    def __init__(self, secret, flip_probability, seed):
        self.secret = secret
        self.flip_probability = flip_probability
        self.rng = random.Random(seed)
        self.calls = 0

    def __call__(self, r):
        self.calls += 1
        return parity(r & self.secret) ^ (self.rng.random() < self.flip_probability)


class NullPredictor:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.calls = 0

    def __call__(self, r):
        self.calls += 1
        return self.rng.randrange(2)


def prefix_energy(oracle, prefix, t, n, samples, rng):
    """Unbiased estimator for the prefix Fourier ENERGY of f(r)=E(-1)^A(r).

    E_prefix = sum_{suffix} hat(f)(prefix||suffix)^2
             = E_{a,a',b} f(a,b)f(a',b) (-1)^{prefix*(a xor a')}.
    Draw a,a' independently and use a COMMON b; separate oracle invocations.
    """
    acc = 0
    for _ in range(samples):
        a = rng.getrandbits(t)
        aprime = rng.getrandbits(t)
        b = rng.getrandbits(n - t)
        r = (a << (n - t)) | b
        rp = (aprime << (n - t)) | b
        obs1 = oracle(r)
        obs2 = oracle(rp)
        acc += 1 if (obs1 ^ obs2 ^ parity(prefix & (a ^ aprime))) == 0 else -1
    return acc / samples


def recover_heavy_fourier(oracle, n, min_correlation, samples, seed):
    """Polynomial-in-(n,1/min_correlation) coefficient listing.

    The min_correlation threshold is a promise for a relevant heavy Fourier
    coefficient. This implementation uses fixed samples rather than a
    confidence adaptive estimator; only finite tests are claimed.
    """
    rng = random.Random(seed)
    threshold = min_correlation * min_correlation / 2
    prefixes = [0]
    audit = []
    for t in range(1, n + 1):
        frontier = []
        for p in prefixes:
            for v in (p << 1, (p << 1) | 1):
                energy = prefix_energy(oracle, v, t, n, samples, rng)
                if energy > threshold:
                    frontier.append(v)
        prefixes = frontier
        audit.append(len(prefixes))
        if not prefixes:
            break
    return prefixes, audit


def empirical_prediction_advantage(oracle, secret, n, count, seed):
    rng = random.Random(seed)
    correct = 0
    for _ in range(count):
        r = rng.getrandbits(n)
        correct += (oracle(r) == parity(secret & r))
    return correct / count - 0.5


def exact_prefix_identity():
    """Check the Fourier-energy pair identity against arbitrary predictor means.

    For t prefix bits, E(u) = sum_{v} hat(f)(u||v)^2, with all
    probabilities and coefficients represented exactly as rationals.
    This is not a cryptographic or quantum simulation.
    """
    from fractions import Fraction
    n = 4
    means = [Fraction(v, 4) for v in (-3, 1, 4, -2, 0, 3, -1, 2,
                                        1, -4, 2, 3, 0, -1, 4, -2)]
    h = []
    for k in range(1 << n):
        h.append(sum(((-1) ** parity(k & r)) * means[r]
                     for r in range(1 << n)) / (1 << n))
    checks = 0
    for t in range(n + 1):
        suffix_bits = n - t
        for prefix in range(1 << t):
            energy = sum(h[(prefix << suffix_bits) | s] ** 2
                         for s in range(1 << suffix_bits))
            paired = sum(
                means[(a << suffix_bits) | b] *
                means[(ap << suffix_bits) | b] *
                ((-1) ** parity(prefix & (a ^ ap)))
                for a in range(1 << t) for ap in range(1 << t)
                for b in range(1 << suffix_bits)
            ) / (1 << (n + t))
            assert energy == paired, (t, prefix, energy, paired)
            checks += 1
    return checks


def run():
    n = 14
    rounds = 160
    flip = 0.14
    min_corr = 0.60
    cases = []
    counts = exact_prefix_identity()
    for fixture in range(5):
        secret = int.from_bytes(hashlib.sha256(f'R170:{fixture}'.encode()).digest()[:4], 'big') & ((1 << n) - 1)
        a = NoisyParityPredictor(secret, flip, 912_871 + fixture)
        found, sizes = recover_heavy_fourier(a, n, min_corr, rounds, 552_191 + fixture)
        assert secret in found, (fixture, secret, found)
        assert len(found) <= 4, (fixture, len(found))
        counts += 2
        adv = empirical_prediction_advantage(a, secret, n, 3000, 551_088 + fixture)
        assert 0.30 < adv < 0.42, (fixture, adv)
        counts += 1
        cases.append({'fixture': fixture, 'secret': secret, 'candidate_count': len(found),
                      'candidate_list': found, 'prefix_widths': sizes,
                      'measured_advantage': round(adv, 5), 'predictor_calls': a.calls})

    # Negative control: a public predictor independent of the hidden capability
    # does not carry a stable heavy Fourier coefficient at min_corr=0.60.
    null = NullPredictor(110481)
    bad, widths = recover_heavy_fourier(null, n, min_corr, rounds, 449781)
    assert not bad, bad
    counts += 1
    # Independent sampled genuine parities and independent random guesses:
    rng = random.Random(12613)
    null_guesses = [null(rng.getrandbits(n)) for _ in range(1000)]
    assert 350 < sum(null_guesses) < 650
    counts += 1

    out = {'test': 'paired-query Fourier-prefix / Goldreich-Levin reconstruction',
           'not_tested': 'a hash-only WKEM, QPT hardness, real source or Bitcoin PoW',
           'n': n, 'flip_probability': flip, 'min_correlation': min_corr,
           'samples_per_prefix': rounds, 'assertions': counts, 'positive': cases,
           'null': {'candidate_count': len(bad), 'prefix_widths': widths,
                    'predictor_calls': null.calls}}
    print(json.dumps(out, sort_keys=True, indent=2))


if __name__ == '__main__':
    run()
