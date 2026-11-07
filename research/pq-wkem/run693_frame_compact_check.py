import collections
import itertools
import json
import random


def mul(p, q):
    return tuple(p[y] for y in q)


def inv(p):
    r = [0] * len(p)
    for x, y in enumerate(p):
        r[y] = x
    return tuple(r)


def gate(kind):
    return tuple(x ^ (4 if (x & 1 if kind == 0 else (x & 3) == 3) else 0) for x in range(8))


def aff(rng):
    while True:
        rows = [rng.randrange(8) for _ in range(3)]
        b = [0] * 3
        for a in rows:
            for j in (2, 1, 0):
                if a & (1 << j):
                    if b[j]:
                        a ^= b[j]
                    else:
                        b[j] = a
                        break
        if all(b):
            v = rng.randrange(8)
            return tuple(sum((((row & x).bit_count() & 1) << i) for i, row in enumerate(rows)) ^ v for x in range(8))


checks = 0
for p in itertools.permutations(range(8)):
    for bit in (0, 1):
        g = mul(p, mul(gate(bit), inv(p)))
        assert sum(g[x] == x for x in range(8)) == (4 if bit == 0 else 6)
        checks += 1

rng = random.Random(693)
for _ in range(128):
    a0, a1 = aff(rng), aff(rng)
    for bit in (0, 1):
        f = gate(bit)
        g1 = mul(a1, mul(f, inv(a0)))
        g2 = mul(a0, mul(f, inv(a1)))
        assert mul(g2, g1) == tuple(range(8))
        total = 0
        for u in range(8):
            for v in range(8):
                total += (g1[0] ^ g1[u] ^ g1[v] ^ g1[u ^ v]) != 0
        assert total == (0 if bit == 0 else 24)
        checks += 2

perms = list(itertools.permutations(range(4)))
hists = []
for f in (tuple(range(4)), (1, 0, 2, 3)):
    h = collections.Counter()
    for a in perms:
        for b in perms:
            g1 = mul(b, mul(f, inv(a)))
            g2 = mul(a, mul(f, inv(b)))
            assert mul(g2, g1) == tuple(range(4))
            checks += 1
            h[(g1, g2)] += 1
    hists.append(h)
assert hists[0] == hists[1]
assert len(hists[0]) == 24
assert set(hists[0].values()) == {24}
checks += 3
print(json.dumps({'run': 693, 'assertions_passed': checks,
                  'conjugation_exhaustive_cases': 80640,
                  'affine_gate_pairs': 256,
                  'ideal_uniform_frame_pairs_per_class': 576,
                  'ideal_full_joint_TV': 0,
                  'security_claim': 'finite algebra only; not concrete PQ WKEM'}, sort_keys=True, indent=2))
