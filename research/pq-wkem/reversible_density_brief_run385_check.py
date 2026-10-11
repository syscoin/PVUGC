#!/usr/bin/env python3
"""Run 385 exact finite reversible-density and coherent oracle check; no PQ claim."""
import json, math, random
checks = 0
for bits in range(4, 9):
    N = 1 << bits
    for guard in range(1, min(bits-1, 5)+1):
        for branch in range(3):
            p = list(range(N))
            random.Random(385000 + 100*bits + 7*guard + branch).shuffle(p)
            marked = {p[i] for i in range(N >> guard)}
            assert len(marked) == N >> guard
            checks += 1
            assert p[0] != p[1] and p[0] in marked and p[1] in marked
            checks += 1
            theta = math.asin(2**(-guard/2))
            for rounds in range(7):
                a = [1/math.sqrt(N)] * N
                for _ in range(rounds):
                    a = [-v if j in marked else v for j,v in enumerate(a)]
                    avg = sum(a)/N
                    a = [2*avg-v for v in a]
                got = sum(a[j]**2 for j in marked)
                expected = math.sin((2*rounds+1)*theta)**2
                assert abs(got-expected) < 5e-12
                checks += 1
print(json.dumps({"run":385,"status":"PASS","checks":checks,"widths":"4..8","context_permutations_per_case":3,"coherent_rounds":"0..6","finding":"bijection preserves free-input release density","qpt_security":False},sort_keys=True))
