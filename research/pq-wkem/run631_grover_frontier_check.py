#!/usr/bin/env python3
"""Exact finite checks of the bounded public-marking interface, not a WKEM."""
import json
from fractions import Fraction
from math import isqrt

checks = 0
cases = []

def require(x):
    global checks
    assert x
    checks += 1


def search(b, rho, good_states, good_coins, rounds):
    n = 1 << (b + rho)
    accept = lambda v: (v >> rho) < good_states and (v & ((1 << rho) - 1)) < good_coins
    marked = {i for i in range(n) if accept(i)}
    k = len(marked)
    require(k == good_states * good_coins)
    require(Fraction(k, n) == Fraction(good_states, 1 << b) * Fraction(good_coins, 1 << rho))
    # Work with exact rational amplitudes relative to a common 1/sqrt(n).
    # The common factor never changes, and all Grover reflections have rational coefficients.
    amps = [Fraction(1) for _ in range(n)]
    success = []
    for t in range(rounds + 1):
        prob = sum((a * a for i, a in enumerate(amps) if i in marked), Fraction(0)) / n
        total = sum((a * a for a in amps), Fraction(0)) / n
        require(total == 1)
        require(0 <= prob <= 1)
        success.append(prob)
        if t == rounds:
            break
        for i in marked:
            amps[i] = -amps[i]
        twice_avg = Fraction(2 * sum(amps), n)
        amps = [twice_avg - a for a in amps]
    require(success[0] == Fraction(k, n))
    return success


for b, rho, m, coins, steps in [(2, 0, 1, 1, 4), (4, 0, 1, 1, 5),
                                  (6, 0, 1, 1, 8), (8, 0, 1, 1, 14),
                                  (4, 2, 2, 3, 8), (6, 2, 2, 4, 9),
                                  (4, 2, 4, 4, 6)]:
    p = search(b, rho, m, coins, steps)
    cases.append(dict(b=b, random_bits=rho, distinct_good_states=m,
                      good_coins=coins, initial_rate=str(p[0]),
                      maximum_rate=str(max(p)),
                      best_round=p.index(max(p))))

# Adding independent unused padding doubles the full state space and the marked set;
# it does not change the success fraction or Grover's two-dimensional recurrence.
p0 = search(4, 0, 1, 1, 4)
pad = search(4, 2, 1, 4, 4)
require(p0 == pad)

# Orthogonal two-amplitude recurrence also matches full-vector Grover evolution.
for b, rho, m, coins, steps in [(4, 0, 1, 1, 4), (6, 2, 2, 3, 8)]:
    k = m * coins
    n = 1 << (b + rho)
    a, c = Fraction(1), Fraction(1)
    actual = search(b, rho, m, coins, steps)
    for t in range(steps + 1):
        require(Fraction(k, n) * a * a == actual[t])
        if t < steps:
            flipped_average = Fraction(2, n) * (-k * a + (n - k) * c)
            a, c = flipped_average + a, flipped_average - c

# Exact entropy bookkeeping: at 256 state bits, many good states decrease the Grover exponent.
query_bits = [dict(b=b, M_log2=m_log, exponent=(b - m_log) / 2)
              for b, m_log in [(128, 0), (256, 0), (256, 32), (256, 192)]]
for row in query_bits:
    require(row['exponent'] >= 0)

print(json.dumps({'result': 'PASS', 'checks': checks,
                  'model': 'public deterministic accepting predicate with enumerated finite state',
                  'cases': cases, 'irrelevant_padding_success_identical': True,
                  'quantum_search_exponents': query_bits,
                  'security_claim': 'exact finite search identities and a conditional generic search bound only'},
                 sort_keys=True, indent=2))
