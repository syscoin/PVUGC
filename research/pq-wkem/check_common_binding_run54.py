#!/usr/bin/env python3
"""Run 54 checker: hidden edge-pad common-binding attempt and complete-view cancellation.

Standard-library only.  This validates finite algebra and exact combinatorics for the
Run-53 8-clause false core.  It is not a PQ security proof.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import random
from collections import defaultdict
from pathlib import Path

SEED = 0x54C0FFEE
Q = 4093
MU = 2046
STRONG = 8
TRIALS = 500
rng = random.Random(SEED)

ASSIGNMENTS = list(itertools.product((0, 1), repeat=3))
AIDX = {a: i for i, a in enumerate(ASSIGNMENTS)}


def dot(a, b):
    return sum(x * y for x, y in zip(a, b))


def centered(x, q=Q):
    x %= q
    return x - q if x > q // 2 else x


def modvec(v, q=Q):
    return [x % q for x in v]


def addv(a, b, q=Q):
    return [(x + y) % q for x, y in zip(a, b)]


def q_block(f, p):
    rows = [a for a in ASSIGNMENTS if a != f]
    if p != f:
        return {a: int(a == p) for a in rows}
    return {
        a: (-1) ** (sum(int(x != y) for x, y in zip(a, f)) + 1)
        for a in rows
    }


# Common Run-53 source relation: p coordinates, then 7 allowed local rows per clause.
COORD_NAMES = [f"p{i}" for i in range(3)]
BLOCK_COORD = {}
for j, f in enumerate(ASSIGNMENTS):
    for a in ASSIGNMENTS:
        if a == f:
            continue
        BLOCK_COORD[(j, a)] = len(COORD_NAMES)
        COORD_NAMES.append(f"z{j}_{''.join(map(str, a))}")
N = len(COORD_NAMES)

B = []
DVEC = []
for j, f in enumerate(ASSIGNMENTS):
    row = [0] * N
    for a in ASSIGNMENTS:
        if a != f:
            row[BLOCK_COORD[(j, a)]] = 1
    B.append(row)
    DVEC.append(1)
for j, f in enumerate(ASSIGNMENTS):
    for i in range(3):
        row = [0] * N
        row[i] = -1
        for a in ASSIGNMENTS:
            if a != f and a[i]:
                row[BLOCK_COORD[(j, a)]] = 1
        B.append(row)
        DVEC.append(0)
R = len(B)


def matvec(M, v):
    return [dot(row, v) for row in M]


def bt_s(s):
    out = [0] * N
    for rr, sr in enumerate(s):
        if sr == 0:
            continue
        row = B[rr]
        for c, bc in enumerate(row):
            if bc:
                out[c] += bc * sr
    return out


def y_for(p):
    y = [0] * N
    y[:3] = list(p)
    for j, f in enumerate(ASSIGNMENTS):
        for a, coeff in q_block(f, p).items():
            y[BLOCK_COORD[(j, a)]] = coeff
    return y


def block_l1(y, j):
    f = ASSIGNMENTS[j]
    return sum(abs(y[BLOCK_COORD[(j, a)]]) for a in ASSIGNMENTS if a != f)


def block_l2sq(y, j):
    f = ASSIGNMENTS[j]
    return sum(y[BLOCK_COORD[(j, a)]] ** 2 for a in ASSIGNMENTS if a != f)


# 1. Exact source-relation / signed-pseudorepresentation checks.
source_checks = 0
for p in ASSIGNMENTS:
    y = y_for(p)
    assert matvec(B, y) == DVEC
    malformed = [j for j in range(8) if block_l2sq(y, j) != 1]
    assert malformed == [AIDX[p]]
    assert block_l2sq(y, AIDX[p]) == 7
    source_checks += 1 + 8

# 2. Count all locally-valid switching sequences p_j != excluded assignment j.
dp = {(p, 0): 1 for p in ASSIGNMENTS if p != ASSIGNMENTS[0]}
for j in range(1, 8):
    nxt = defaultdict(int)
    for (prev, mismatches), count in dp.items():
        for p in ASSIGNMENTS:
            if p == ASSIGNMENTS[j]:
                continue
            nxt[(p, mismatches + int(p != prev))] += count
    dp = nxt
mismatch_hist = defaultdict(int)
for (_, mismatches), count in dp.items():
    mismatch_hist[mismatches] += count
assert sum(mismatch_hist.values()) == 7 ** 8
assert mismatch_hist.get(0, 0) == 0

# 3. Exact finite-field edge-pad uniformity for every nonzero Boolean difference over F_5.
edge_uniform_checks = 0
for left in ASSIGNMENTS:
    for right in ASSIGNMENTS:
        if left == right:
            continue
        delta = [(right[i] - left[i]) % 5 for i in range(3)]
        counts = [0] * 5
        for r in itertools.product(range(5), repeat=3):
            counts[dot(r, delta) % 5] += 1
        assert counts == [25] * 5
        edge_uniform_checks += 1

# 4. Random semantic telescoping identities.
semantic_checks = 0
for _ in range(1000):
    pads = [[rng.randrange(Q) for _ in range(3)] for _ in range(7)]
    p = rng.choice(ASSIGNMENTS)
    common = [p] * 8
    total = 0
    for e in range(7):
        delta = [common[e + 1][i] - common[e][i] for i in range(3)]
        total += dot(pads[e], delta)
    assert total % Q == 0

    seq = []
    for j in range(8):
        allowed = [a for a in ASSIGNMENTS if a != ASSIGNMENTS[j]]
        seq.append(rng.choice(allowed))
    # Local validity and at least one mismatch are structural on this false core.
    assert all(seq[j] != ASSIGNMENTS[j] for j in range(8))
    assert any(seq[e] != seq[e + 1] for e in range(7))
    explicit = 0
    for e in range(7):
        delta = [seq[e + 1][i] - seq[e][i] for i in range(3)]
        explicit += dot(pads[e], delta)
    # Same expression obtained by component incidence offsets h_j.
    hs = []
    zero = [0, 0, 0]
    for j in range(8):
        incoming = pads[j - 1] if j > 0 else zero
        outgoing = pads[j] if j < 7 else zero
        hs.append([(outgoing[i] - incoming[i]) % Q for i in range(3)])
    by_component = -sum(dot(seq[j], hs[j]) for j in range(8))
    assert (by_component - explicit) % Q == 0
    semantic_checks += 2

# 5. Complete native capsule: public summation cancels hidden edge pads before witness use.
def noise_vector(target_j):
    e = []
    for c in range(N):
        scale = 1
        # Target block coordinates receive stronger ternary noise.
        for a in ASSIGNMENTS:
            if a != ASSIGNMENTS[target_j] and BLOCK_COORD[(target_j, a)] == c:
                scale = STRONG
                break
        e.append(scale * rng.choice((-1, 0, 1)))
    return e


def decode_bit(residue):
    # Compare circular distance to 0 and MU.
    r = residue % Q
    d0 = min(r, Q - r)
    d1raw = (r - MU) % Q
    d1 = min(d1raw, Q - d1raw)
    return int(d1 < d0)

capsule_trials = 0
false_recoveries = 0
max_observed_abs_aggregate_noise = 0
for _ in range(TRIALS):
    K = rng.randrange(2)
    pads = [[rng.randrange(Q) for _ in range(3)] for _ in range(7)]
    hs = []
    for j in range(8):
        incoming = pads[j - 1] if j > 0 else [0, 0, 0]
        outgoing = pads[j] if j < 7 else [0, 0, 0]
        hs.append([(outgoing[i] - incoming[i]) % Q for i in range(3)])
    assert all(sum(hs[j][i] for j in range(8)) % Q == 0 for i in range(3))

    avecs = []
    bvals = []
    enoises = []
    e0s = []
    secrets = []
    for j in range(8):
        s = [rng.randrange(Q) for _ in range(R)]
        e = noise_vector(j)
        e0 = rng.choice((-1, 0, 1))
        base = bt_s(s)
        hfull = hs[j] + [0] * (N - 3)
        a = [(base[c] + e[c] + hfull[c]) % Q for c in range(N)]
        b = (dot(DVEC, s) + e0 + (MU * K if j == 0 else 0)) % Q
        avecs.append(a)
        bvals.append(b)
        enoises.append(e)
        e0s.append(e0)
        secrets.append(s)

    # Complete-view aggregate is edge-pad free.
    Aagg = [sum(a[c] for a in avecs) % Q for c in range(N)]
    bagg = sum(bvals) % Q
    Sagg = [sum(s[r] for s in secrets) % Q for r in range(R)]
    Eagg = [sum(e[c] for e in enoises) for c in range(N)]
    expected_A = [(bt_s(Sagg)[c] + Eagg[c]) % Q for c in range(N)]
    assert Aagg == expected_A
    expected_b = (dot(DVEC, Sagg) + sum(e0s) + MU * K) % Q
    assert bagg == expected_b

    # Any exact signed false representation can now evaluate the aggregate capsule.
    p = rng.choice(ASSIGNMENTS)
    y = y_for(p)
    assert matvec(B, y) == DVEC
    residual = (bagg - dot(y, Aagg)) % Q
    integer_noise = sum(e0s) - dot(y, Eagg)
    assert residual == (MU * K + integer_noise) % Q
    max_observed_abs_aggregate_noise = max(max_observed_abs_aggregate_noise, abs(integer_noise))
    if decode_bit(residual) == K:
        false_recoveries += 1
    capsule_trials += 1

# Deterministic all-error bound for the above 8-block false core.
# Across all 8 components and a false representation: 14 strong-weight nonzeros;
# at most 106+8*3 = 130 unit-weight nonzeros (including e0 terms).
false_noise_bound = 14 * STRONG + 130
honest_noise_bound = 8 * STRONG + (64 + 8 * 3)
assert false_noise_bound == 242
assert honest_noise_bound == 152
assert false_noise_bound < Q // 4
assert false_recoveries == TRIALS

# 6. Public linear witness re-encoding does not hide the linear functional: signed-permutation check.
# For y_enc[k] = sign[k] y[perm[k]], choose a_enc[k] = sign[k] c[perm[k]].
reencoding_checks = 0
for _ in range(200):
    y = y_for(rng.choice(ASSIGNMENTS))
    c = [rng.randrange(-50, 51) for _ in range(N)]
    perm = list(range(N))
    rng.shuffle(perm)
    signs = [rng.choice((-1, 1)) for _ in range(N)]
    yenc = [signs[k] * y[perm[k]] for k in range(N)]
    aenc = [signs[k] * c[perm[k]] for k in range(N)]
    assert dot(yenc, aenc) == dot(y, c)
    # Public pullback reconstructs c exactly.
    pulled = [0] * N
    for k in range(N):
        pulled[perm[k]] += signs[k] * aenc[k]
    assert pulled == c
    reencoding_checks += 2

# 7. Exact target-only diagnostic: one strong coefficient per honest block versus +6 for one malformed block.
def ternary_counts(n):
    counts = [1]
    offset = 0
    for _ in range(n):
        new = [0] * (len(counts) + 2)
        for i, c in enumerate(counts):
            new[i] += c
            new[i + 1] += c
            new[i + 2] += c
        counts = new
        offset += 1
    return counts, offset


def min_threshold(n, target_num, target_den):
    counts, off = ternary_counts(n)
    den = 3 ** n
    acc = counts[off]
    if acc * target_den >= target_num * den:
        return 0, acc, den
    for t in range(1, n + 1):
        acc += counts[off - t] + counts[off + t]
        if acc * target_den >= target_num * den:
            return t, acc, den
    return n, den, den


def mass_abs_le(n, t):
    counts, off = ternary_counts(n)
    den = 3 ** n
    num = sum(c for i, c in enumerate(counts) if abs(i - off) <= t)
    return num, den

# Honest target success >= 1-2^-20; compare exact false success for m+6 coefficients.
target_num = (1 << 20) - 1
target_den = 1 << 20
diagnostic = []
for m in (8, 16, 32, 64, 128, 256, 512):
    t, hnum, hden = min_threshold(m, target_num, target_den)
    fnum, fden = mass_abs_le(m + 6, t)
    diagnostic.append({
        "m": m,
        "threshold": t,
        "honest_success": hnum / hden,
        "false_success": fnum / fden,
        "honest_failure": 1.0 - (hnum / hden),
        "false_failure": 1.0 - (fnum / fden),
    })

script_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
result = {
    "run": 54,
    "seed": SEED,
    "field_q": Q,
    "phase_mu": MU,
    "strong_noise_scale": STRONG,
    "relation": {
        "rows": R,
        "columns": N,
        "source_checks": source_checks,
    },
    "switching_sequences": {
        "total": sum(mismatch_hist.values()),
        "zero_mismatch": mismatch_hist.get(0, 0),
        "mismatch_histogram": {str(k): mismatch_hist[k] for k in sorted(mismatch_hist)},
    },
    "semantic_edge_pad": {
        "exact_nonzero_boolean_difference_uniformity_checks_F5": edge_uniform_checks,
        "random_telescoping_and_incidence_checks": semantic_checks,
    },
    "complete_view": {
        "capsule_trials": capsule_trials,
        "false_key_recoveries": false_recoveries,
        "max_observed_abs_aggregate_noise": max_observed_abs_aggregate_noise,
        "deterministic_false_noise_bound": false_noise_bound,
        "deterministic_honest_noise_bound": honest_noise_bound,
        "quarter_modulus_floor": Q // 4,
        "public_linear_reencoding_checks": reencoding_checks,
    },
    "target_only_exact_diagnostic_honest_ge_1_minus_2^-20": diagnostic,
    "checker_sha256": script_sha256,
    "scope": "Finite algebra/combinatorics and an explicit bounded-noise candidate break only; not a PQ security proof or generic impossibility theorem.",
}
print(json.dumps(result, indent=2, sort_keys=True))
