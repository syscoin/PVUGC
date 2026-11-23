#!/usr/bin/env python3
"""Symbolic noncommutative Barrington-style false-instance splice.
No original BTC/Syscoin evidence, FE, native signatures, or security theorem.
"""
import hashlib
import itertools
import json
import random

I = (0, 1, 2)
a = (1, 0, 2)     # transposition (0 1)
b = (0, 2, 1)     # transposition (1 2)

def mul(p, q):
    """Permutation composition p o q (right operand acts first)."""
    return tuple(p[q[i]] for i in range(3))

def inv(p):
    return tuple(p.index(i) for i in range(3))

def word_product(seq):
    z = I
    for g in seq:
        z = mul(z, g)
    return z

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def readout(perm):
    return hashlib.sha256(b'PVUGC-S3-screen-v1:' + bytes(perm)).digest()

def selector(j, bit):
    if j == 0: return a if bit == 1 else I
    if j == 1: return b if bit == 0 else I
    if j == 2: return inv(a) if bit == 1 else I
    if j == 3: return inv(b) if bit == 0 else I
    raise ValueError('invalid position')

r = random.Random(20261123)
perms = list(itertools.permutations(range(3)))
gauges = [r.choice(perms) for _ in range(5)]
# Public capsule M consists solely of permutation transitions, not private gauges.
M = [[mul(mul(inv(gauges[j]), selector(j, bit)), gauges[j+1])
      for bit in range(2)] for j in range(4)]

def evaluate(sequence):
    return word_product([M[j][sequence[j]] for j in range(4)])

commutator = word_product([a, b, inv(a), inv(b)])
reject0, reject1 = evaluate((0, 0, 0, 0)), evaluate((1, 1, 1, 1))
spoof = evaluate((1, 0, 1, 0))
assert commutator != I
assert reject0 == reject1 == mul(inv(gauges[0]), gauges[4])
assert spoof == mul(mul(inv(gauges[0]), commutator), gauges[4])
assert spoof != reject0
assert all(not (bool(bit) and (not bool(bit))) for bit in (0,1))
# The builder's S is not published. A synthetic capsule seals it under the
# accepting readout, as a proposed family would do; the adversary uses only M.
S = hashlib.sha256(b'PRIVATE fixture cancel capability; NOT real signature').digest()
D = xor_bytes(S, readout(spoof))
recovered = xor_bytes(D, readout(evaluate((1, 0, 1, 0))))
assert recovered == S
assert recovered != xor_bytes(D, readout(reject0))
print(json.dumps({
  'scope':'FALSE x AND NOT x group-program spoof; no original source, FE or native signature',
  'group':'S3',
  'true_original_witnesses':0,
  'commutator':list(commutator),
  'public_transitions':[[list(x) for x in p] for p in M],
  'two_consistent_readouts_equal':reject0 == reject1,
  'inconsistent_occurrence_assignment':[1,0,1,0],
  'inconsistent_product':list(spoof),
  'secret_recovered_with_public_transitions':recovered == S,
  'proof_scope':'symbolic telescoping with supplementary deterministic finite check',
},sort_keys=True,indent=2))
