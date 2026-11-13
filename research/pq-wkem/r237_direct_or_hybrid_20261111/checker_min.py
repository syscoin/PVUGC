#!/usr/bin/env python3
"""R237: exact finite algebra checks; NOT witness encryption or consensus validation."""
from itertools import product
from collections import Counter
import json

N = 8
base = Counter(tuple(0 ^ k for k in keys) for keys in product(range(N), repeat=3))
assert len(base) == N**3
for m in range(N):
    joint = Counter(tuple(m ^ k for k in keys) for keys in product(range(N), repeat=3))
    assert joint == base
    for keys in product(range(N), repeat=3):
        ct = tuple(m ^ k for k in keys)
        assert all(ct[j] ^ keys[j] == m for j in range(3))
        # Deliberately INVALID message-dependent secret-key correlation.
        k1 = keys[0]
        k2 = k1 ^ m
        assert (m ^ k1) ^ (m ^ k2) == m
for target in range(1, 256):
    vals = list(range(target + 1))  # toy valid digest <= target
    nforced = min(8 - ((vals[0] ^ v).bit_length()) for v in vals)
    assert nforced == 8 - target.bit_length()
print(json.dumps({"run":"R237_MIN","independent_joint_outputs":N**3,
                  "messages":N,"pow_targets_checked":255,
                  "status":"conditional algebra only; actual source-dependent Build/Open missing"},
                 sort_keys=True,indent=2))
