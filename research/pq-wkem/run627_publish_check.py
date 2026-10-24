"""Run 627: exhaustive S3 cycle-capsule compositional leakage falsifier."""
import itertools
import json
from collections import Counter

G = list(itertools.permutations(range(3)))
I = tuple(range(3))

def mul(a, b):
    return tuple(a[b[j]] for j in range(3))

def inv(a):
    return tuple(a.index(j) for j in range(3))

def laws(t, h):
    U = [I] * (t-1) + [h]
    law = Counter()
    for frames in itertools.product(G, repeat=t):
        edges = tuple(mul(mul(frames[j], U[j]), inv(frames[(j+1) % t])) for j in range(t))
        law[edges] += 1
    return law

checks = 0
cases = []
for t in [3, 4, 5]:
    L0, L1 = laws(t, I), laws(t, (1, 2, 0))
    assert not (set(L0) & set(L1)); checks += 1
    assert sum(L0.values()) == 6**t == sum(L1.values()); checks += 1
    for drop in range(t):
        for law in [L0, L1]:
            reduced = Counter()
            for e, count in law.items():
                reduced[e[:drop] + e[drop+1:]] += count
            assert len(reduced) == 6**(t-1); checks += 1
            assert set(reduced.values()) == {6}; checks += 1
    for edges in L0:
        product = I
        for e in edges:
            product = mul(product, e)
        assert product == I; checks += 1
    for edges in L1:
        product = I
        for e in edges:
            product = mul(product, e)
        assert product != I; checks += 1
    cases.append({'capsules': t, 'frames_per_world': 6**t, 'support_0':len(L0), 'support_1':len(L1), 'tv':'1', 'all_strict_subsets_identical':True})
print(json.dumps({'run':627, 'group':'S3', 'checks':checks, 'cases':cases, 'security_claim':False}, sort_keys=True, separators=(',', ':')))
