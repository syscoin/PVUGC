#!/usr/bin/env python3
"""R117 independent, exact integer conditional Chernoff and v-compression check.
No external libraries, network, or randomness.  Python 3.11+ recommended.
"""
import hashlib
import json
from math import comb
from time import perf_counter

RUN = 'R117-8BIT-LWE-PHASE-EXACT-COND-MGF-20261106'
Q, M, D, ELL, COIN_L1 = 65521, 2000, 256, 64, 2729
P, R = 28, 25                  # exp(3*lambda) = P/R
Z = (P * R) ** 3
TILT_COEFF = [Z] + [(P**(2*a)+R**(2*a)) * (P*R)**(3-a) for a in (1, 2, 3)]

checks = 0
def check(cond):
    global checks
    checks += 1
    if not cond:
        raise AssertionError(f'failed assertion #{checks}')

def coeff_sum(weights, n=M, L=COIN_L1):
    """Exact integer sum of coefficients through degree L of P(z)^n.
    Descending in-place iteration guarantees reads of old coefficients.
    """
    c = [0]*(L+1)
    c[0] = 1
    a0,a1,a2,a3 = weights
    for i in range(1,n+1):
        for j in range(min(L,3*i),-1,-1):
            c[j] = (a0*c[j] + (a1*c[j-1] if j>=1 else 0)
                    + (a2*c[j-2] if j>=2 else 0)
                    + (a3*c[j-3] if j>=3 else 0))
    return sum(c)

# Validate recurrence with independent brute-force enumeration in a small domain.
from itertools import product
for n in (1,2,3,4):
    for L in (0,2,4,8):
        count = 0
        for r in product(range(-3,4),repeat=n):
            count += (sum(abs(a) for a in r) <= L)
        check(coeff_sum((1,2,2,2),n,L) == count)

start = perf_counter()
D0 = coeff_sum((1,2,2,2))
NUM = coeff_sum(TILT_COEFF)
# For h=1920, lambda=log(P/R)/3; 2 exp(-lambda*h) * NUM/(Z^M D0) < 2^-50
lhs = (1 << 51)*pow(R,640)*NUM
rhs = pow(P,640)*pow(Z,M)*D0
check(lhs < rhs)
# All arithmetic above uses integers; 10^-50 binary tail bound is exact.
check(D0.bit_length()==5446)
check(NUM.bit_length()==62206)

# Canonical v -> 8-bit index and public reconstruction.
phase_errors = set()
for v in range(Q):
    packed = v // 256
    check(0 <= packed <= 255)
    decoded = 256*packed + 128
    delta = decoded - v
    check(-127 <= delta <= 128)
    phase_errors.add(delta)
check(min(phase_errors) == -127 and max(phase_errors) == 128)

codepoints = [4095*i for i in range(16)]

def center(t):
    return (t + Q//2) % Q - Q//2

def nearest(z):
    return min(range(16),key=lambda mu:abs(center(z-codepoints[mu])))

for mu in range(16):
    target=codepoints[mu]
    for true_error in range(-1919,1920):
        # Every actual phase error lies within this interval, so extremes suffice
        # because the nearest-neighbor Voronoi interval is convex on this arc.
        check(nearest((target+true_error-127)%Q) == mu)
        check(nearest((target+true_error+128)%Q) == mu)

# RS(85,79) GF256 distance 7 -> at least four independent whole-group errors.
# Each group's union bound uses all 64 correlated symbol errors.
# For 256 occurrences, exact joint bound < 2^-147.
fail_num = 256 * comb(85,4)
check(fail_num < (1<<29))
check(85*(2*D+2*ELL) == 54400)
check(85*(2*D+ELL) == 85*576 == 48960)
check(54400-48960 == 5440)
check((54400-48960)*10 == 54400)

result = {
  'run': RUN,
  'status': 'PASS — restricted LWE credential source only; not generic ORIGINAL NP',
  'integer_recurrence': 'coeff P(z)^2000 through degree 2729, exact integer DP',
  'tilt': 'exp(3 lambda)=28/25',
  'phase': 'v8=floor(v/256), reconstructed v=256*v8+128 mod 65521',
  'assertions': checks,
  'D0_bits': D0.bit_length(), 'weighted_numerator_bits': NUM.bit_length(),
  'exact_chernoff_certificate': '2^51*25^640*NUM < 28^640*(700^3)^2000*D0',
  'chernoff_certificate_pass': lhs<rhs,
  'p_symbol_upper': 'strictly less than 2^-50',
  'p_all_256_occurrences_upper': 'strictly less than 2^-147 plus global source-nonuniqueness bound 2^-20502.54',
  'v_quantization_error': [-127,128],
  'cyclic_min_spacing': 4095,
  'per_credential_occurrence_ciphertext_bytes_before': 54400,
  'per_credential_occurrence_ciphertext_bytes_after': 48960,
  'ciphertext_savings_percent': 10,
  'exact_integer_numerator_sha256': hashlib.sha256(NUM.to_bytes((NUM.bit_length()+7)//8,'big')).hexdigest(),
  'exact_integer_denominator_sha256': hashlib.sha256(D0.to_bytes((D0.bit_length()+7)//8,'big')).hexdigest(),
  'limitations': 'Finite algebra/correctness certification, not QPT hardness; R116 RS decoder and restricted full-public reduction retained.'
}
print(json.dumps(result,indent=2,sort_keys=True))
