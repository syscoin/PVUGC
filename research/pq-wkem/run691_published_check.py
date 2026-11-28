from fractions import Fraction
import json
rows = []
checks = 0
for n, h in ((5, 2), (7, 4), (9, 6)):
    leak = n - h
    tv = Fraction(0)
    for a in range(1 << n):
        for v in range(1 << leak):
            count0 = sum(((v | (r << leak)) & a).bit_count() % 2 == 0 for r in range(1 << h))
            tv += abs(Fraction(count0, 1 << h) - Fraction(1, 2)) / (1 << n) / (1 << leak)
            checks += 1
    assert tv == Fraction(1, 1 << (h + 1))
    rows.append({"n": n, "h": h, "tv": str(tv)})
print(json.dumps({"checks": checks, "rows": rows, "scope": "finite public-key leakage only"}, sort_keys=True))
