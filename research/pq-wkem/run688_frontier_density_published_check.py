#!/usr/bin/env python3
"""Finite Grover-state check; not an implementation of cryptographic WKEM."""
import json, math
from fractions import Fraction
count = 0
cases = []
for b in (6, 8, 10):
    n = 1 << b
    for m in (1, 2, 4, 8, 16):
        good = {(5+37*j) % n for j in range(m)}
        assert len(good) == m
        theta = math.asin(math.sqrt(m/n))
        t = max(0, round(math.pi/(4*theta)-0.5))
        amps = [1/math.sqrt(n)]*n
        for _ in range(t):
            for j in good:
                amps[j] *= -1
            avg = math.fsum(amps)/n
            amps = [2*avg-a for a in amps]
        observed = math.fsum(amps[j]**2 for j in good)
        expected = math.sin((2*t+1)*theta)**2
        assert abs(observed-expected) < 1e-10
        assert abs(math.fsum(a*a for a in amps)-1) < 1e-10
        assert observed > .5
        count += 4
        cases.append([b,m,t,round(observed,9)])
assert Fraction(12*7, (1<<8)*(1<<3)) == Fraction(21,512)
assert len({(i%4)*37+5 for i in range(40)}) == 4
assert (256-32)//2 == 112 and (288-32)//2 == 128
count += 3
print(json.dumps({'run':688,'cases':len(cases),'assertions':count,'randomized_density':'21/512','colliding_witnesses':'40->4','query_exponents':{'b256_M2^32':112,'b288_M2^32':128},'minimum_success':min(x[3] for x in cases),'cryptographic_claim':False},sort_keys=True))
