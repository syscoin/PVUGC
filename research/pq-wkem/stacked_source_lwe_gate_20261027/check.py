#!/usr/bin/env python3
"""Offline exact finite checks for stacked-row SOURCE-LWE gate.
Not a security proof by exhaustive toy computation. Python 3 stdlib only.
"""
from itertools import product
from fractions import Fraction
from random import Random

checks = 0
q = 5
w = (1, 1, 0)
rows = list(product(range(q), repeat=3))
good = sum(1 for a, b in product(rows, repeat=2)
           if (a[0]+a[1]) % q == 0 and (b[0]+b[1]) % q == 0)
assert good == q**4
checks += 1
assert len(rows)**2 == q**6
checks += 1

# Arbitrarily source-chosen, publicly known extra rows (not challenge-secret dependent).
C = ((1,-1,0),(0,0,0))
rng = Random(12291)
for _ in range(1500):
    A = tuple(tuple(rng.randrange(q) for _ in range(3)) for _ in range(2))
    s = tuple(rng.randrange(q) for _ in range(2))
    t = tuple(rng.randrange(q) for _ in range(2))
    err = tuple(rng.choice((-1,0,1)) for _ in range(3))
    digit = rng.randrange(q)
    direct = tuple((sum(A[i][j]*s[i] for i in range(2))+
                    sum(C[i][j]*t[i] for i in range(2))+
                    err[j]+(digit if j==0 else 0))%q for j in range(3))
    y = tuple((sum(A[i][j]*s[i] for i in range(2))+err[j])%q
              for j in range(3))
    simulated = tuple((y[j]+sum(C[i][j]*t[i] for i in range(2))+
                       (digit if j==0 else 0))%q for j in range(3))
    assert direct == simulated
    checks += 1

# In the uniform-y branch, translation is a bijection for any public source rows,
# source-row secret t and fixed encoded digit: exact full conditional null law.
for Cx in [((1,-1,0),), ((1,0,0),), ((2,4,1),)]:
    for digit in range(q):
        for t in range(q):
            images = {tuple((y[j]+Cx[0][j]*t+(digit if j==0 else 0))%q
                      for j in range(3))
                      for y in product(range(q), repeat=3)}
            assert len(images)==q**3
            checks += 1

# Toy known-witness opening test, A uniform q^(d*n).
# For q=5,d=2,n=3, chance A(1,1,0)^T=0 is exactly q^(-d).
assert Fraction(good,q**6)==Fraction(1,q**2)
checks += 1

# Exhaustive toy public short-opening search: 4 anchored weight-2 candidates.
# For A uniform F_17^{1 x 5}, search succeeds if some a0+aj=0 mod 17.
q2=17
cnt=0
for a0 in range(q2):
    for others in product(range(q2), repeat=4):
        cnt += any((a0+v)%q2==0 for v in others)
total=q2**5
assert cnt == total-q2*(q2-1)**4
checks += 1
p=Fraction(cnt,total)
# If an extractor f returns short z independent of LWE y, then the test
# |z^T y|<=E (E=2, g=5) gives advantage p*(1-g/q) exactly.
adv=p*(1-Fraction(5,q2))
assert adv==Fraction(215820,1419857)
checks += 1

print('assertions_passed=',checks,sep='')
print('source_rows_tested=3')
print('exact_real_challenge_couplings=1500')
print('null_translation_bijections=75')
print('fixed_known_witness_kernel_probability=',Fraction(good,q**6),sep='')
print('public_short_open_search_probability=',p,sep='')
print('short_open_search_lwe_advantage=',adv,sep='')
print('status=finite_algebra_verified_not_QPT_security')
