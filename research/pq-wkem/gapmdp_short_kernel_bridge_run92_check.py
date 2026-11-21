#!/usr/bin/env python3
import json, math, random, hashlib

SEED = 920092
rng = random.Random(SEED)


def ctr(a, p):
    a %= p
    if a > p // 2:
        a -= p
    return a


def vec_norm2_sq(v, p=None):
    if p is not None:
        v = [ctr(x, p) for x in v]
    return sum(x * x for x in v)


def wt(v, p=None):
    if p is not None:
        return sum(1 for x in v if x % p)
    return sum(1 for x in v if x)


def rank_mod(mat, p):
    a = [[x % p for x in row] for row in mat]
    if not a:
        return 0
    m, n = len(a), len(a[0])
    r = 0
    for c in range(n):
        piv = next((i for i in range(r, m) if a[i][c]), None)
        if piv is None:
            continue
        a[r], a[piv] = a[piv], a[r]
        inv = pow(a[r][c], -1, p)
        a[r] = [(x * inv) % p for x in a[r]]
        for i in range(m):
            if i != r and a[i][c]:
                f = a[i][c]
                a[i] = [(a[i][j] - f * a[r][j]) % p for j in range(n)]
        r += 1
        if r == m:
            break
    return r


def canonical_digits(a, B, L):
    ds = []
    x = a
    for _ in range(L):
        ds.append(x % B)
        x //= B
    if x:
        raise ValueError("not enough digits")
    return ds


report = {
    "run": 92,
    "seed": SEED,
    "claim_scope": "finite algebra and norm/interface checks only; no cryptographic security claim",
    "checks": {},
}

# 1. Core norm inequalities: wt(v) <= ||ctr(v)||_2^2 <= B^2 wt(v).
count = 0
for p in [5, 7, 11, 17, 31, 101]:
    for m in [3, 5, 8, 13]:
        for _ in range(300):
            v = [rng.randrange(p) for _ in range(m)]
            w = wt(v, p)
            n2 = vec_norm2_sq(v, p)
            B = max([abs(ctr(x, p)) for x in v] or [0])
            assert w <= n2
            assert n2 <= B * B * w
            count += 1
report["checks"]["centered_norm_support_bridge"] = {"cases": count, "failures": 0}

# 2. Gap criterion B^2 < gamma and ratio sqrt(gamma)/B.
criterion_cases = 0
passing = 0
min_passing_ratio = None
for B in [1, 2, 3, 4]:
    for gamma in [2, 4, 8, 16, 32, 64]:
        criterion_cases += 1
        ratio = math.sqrt(gamma) / B
        if B * B < gamma:
            passing += 1
            min_passing_ratio = ratio if min_passing_ratio is None else min(min_passing_ratio, ratio)
report["checks"]["gap_criterion"] = {
    "cases": criterion_cases,
    "B2_lt_gamma_cases": passing,
    "minimum_ratio_when_B2_lt_gamma": min_passing_ratio,
}

# 3. Any nonzero linear symbol encoder Enc(a)=a*r hits worst centered amplitude (p-1)/2.
linear_cases = 0
for p in [5, 7, 11, 17, 31, 101]:
    for L in [1, 2, 4, 7]:
        for _ in range(20):
            r = [rng.randrange(p) for _ in range(L)]
            if not any(r):
                r[0] = 1
            mx = 0
            for a in range(p):
                enc = [(a * x) % p for x in r]
                mx = max(mx, max(abs(ctr(x, p)) for x in enc))
            assert mx == (p - 1) // 2
            linear_cases += 1
report["checks"]["linear_encoder_amplitude"] = {"cases": linear_cases, "failures": 0}

# 4. Radix digit expansion: exact local kernel and full-span canonical set.
radix_records = []
for B, L, p in [(2, 4, 17), (2, 5, 37), (3, 3, 29), (4, 3, 67), (5, 3, 131)]:
    assert B ** (L - 1) < p
    row = [pow(B, j, p) for j in range(L)]
    g = [0] * L
    g[0], g[1] = B, -1
    assert sum(row[j] * g[j] for j in range(L)) % p == 0
    basis = []
    for j in range(L):
        ds = canonical_digits(B ** j, B, L)
        assert ds == [1 if i == j else 0 for i in range(L)]
        basis.append(ds)
    rk = rank_mod(basis, p)
    assert rk == L
    radix_records.append({
        "B": B,
        "L": L,
        "p": p,
        "kernel_support": wt(g),
        "kernel_l2_sq": sum(x * x for x in g),
        "canonical_span_rank": rk,
    })
report["checks"]["radix_linearization_barrier"] = radix_records

# 5. Worst-case raw-prime Hamming-to-Euclidean gap and bounded-symbol positive bridge.
raw_cases = 0
raw_gap_gt_one = 0
for p in [17, 31, 101, 257, 1009]:
    B = (p - 1) / 2
    for gamma in [4, 16, 64, 256]:
        raw_cases += 1
        if math.sqrt(gamma) / B > 1:
            raw_gap_gt_one += 1
bounded_cases = 0
for p in [17, 101, 1009, 65537]:
    for d in [4, 16, 64]:
        for gamma in [4, 16, 64]:
            yes_norm = math.sqrt(d)
            no_floor = math.sqrt(gamma * d)
            assert abs((no_floor / yes_norm) - math.sqrt(gamma)) < 1e-12
            bounded_cases += 1
report["checks"]["gap_tables"] = {
    "raw_prime_field_cases": raw_cases,
    "raw_cases_with_guaranteed_gap_gt_1": raw_gap_gt_one,
    "bounded_symbol_B1_cases": bounded_cases,
    "bounded_symbol_ratio_independent_of_p": True,
}

# 6. Exhaustive tiny supplied-short -> sparse implication.
small = 0
triggered = 0
for p in [5, 7, 11]:
    for m in [4, 5]:
        total = p ** m
        if total > 200000:
            continue
        for idx in range(total):
            x = idx
            v = []
            for _ in range(m):
                v.append(x % p)
                x //= p
            n2 = vec_norm2_sq(v, p)
            w = wt(v, p)
            for B, d in [(1, 2), (1, 3), (2, 1), (2, 2)]:
                if n2 <= B * B * d:
                    assert w <= B * B * d
                    triggered += 1
            small += 1
report["checks"]["exhaustive_short_implies_sparse"] = {
    "vectors": small,
    "triggered_threshold_checks": triggered,
    "failures": 0,
}

blob = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
report["report_sha256"] = hashlib.sha256(blob).hexdigest()
print(json.dumps(report, sort_keys=True, indent=2))
