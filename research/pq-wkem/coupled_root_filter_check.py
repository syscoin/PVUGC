#!/usr/bin/env python3
import collections
import hashlib
import json
import random
from itertools import product

SEED = 2026092214
PRIMES = (5, 7, 11, 13)
TRIALS_PER_PRIME = 250

# Variable order:
# h, z, zbar, a, abar, b, bbar, c, cbar, d, dbar
PAIRS = ((1,2),(3,4),(5,6),(7,8),(9,10))
NVAR = 11


def build_false_H():
    rows = []
    for u, ub in PAIRS:
        r = [0] * NVAR
        r[0] = -1
        r[u] = 1
        r[ub] = 1
        rows.append(r)
    # (z OR z OR z): 3z + a + 2b = 4h
    r = [0] * NVAR
    r[0], r[1], r[3], r[5] = -4, 3, 1, 2
    rows.append(r)
    # (!z OR !z OR !z): -3z + c + 2d = h
    r = [0] * NVAR
    r[0], r[1], r[7], r[9] = -1, -3, 1, 2
    rows.append(r)
    return rows


def build_true_H():
    rows = []
    for u, ub in PAIRS:
        r = [0] * NVAR
        r[0] = -1
        r[u] = 1
        r[ub] = 1
        rows.append(r)
    # two identical positive clauses, with separate slack pairs
    r = [0] * NVAR
    r[0], r[1], r[3], r[5] = -4, 3, 1, 2
    rows.append(r)
    r = [0] * NVAR
    r[0], r[1], r[7], r[9] = -4, 3, 1, 2
    rows.append(r)
    return rows


H_FALSE = build_false_H()
H_TRUE = build_true_H()

# Exact integer kernel pseudovectors from Run 33.
X0 = [1, 0, 1, 0, 1, 2, -1, 1, 0, 0, 1]
X1_OLD = [1, 0, 1, 2, -1, 1, 0, 1, 0, 0, 1]
# True witness for two positive clauses.
W_TRUE = [1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1]


def matvec(H, x, mod=None):
    out = [sum(a*b for a, b in zip(row, x)) for row in H]
    if mod is not None:
        out = [v % mod for v in out]
    return out


def dot(x, y, mod=None):
    v = sum(a*b for a, b in zip(x, y))
    return v % mod if mod is not None else v


def pair_diff(x, pair, mod=None):
    v = x[pair[0]] - x[pair[1]]
    return v % mod if mod is not None else v


def ht_y(H, y, Q):
    out = [0] * NVAR
    for i, row in enumerate(H):
        yi = y[i] % Q
        for j, a in enumerate(row):
            out[j] = (out[j] + a * yi) % Q
    return out


def inv(a, p):
    return pow(a % p, -1, p)


def root_direction(pair, alpha, t, p):
    # e_t(x) = d_j(x) - alpha*h(x) + p*t*h(x).
    w = [0] * NVAR
    w[pair[0]] = 1
    w[pair[1]] = -1
    w[0] = -alpha + p*t
    return w


def components(p):
    out = []
    for j, pair in enumerate(PAIRS):
        for alpha in range(p):
            if alpha in (1, p-1):
                continue
            for t in (0, 1):
                out.append((j, alpha, t, root_direction(pair, alpha, t, p)))
    return out


def support(p, e, q):
    Q = p*p
    return frozenset((z*e + p*q) % Q for z in range(p))


def exhaustive_local_channel(p):
    Q = p*p
    stats = {
        "p": p,
        "unit_e_cases": 0,
        "unit_e_partition_cases": 0,
        "nonzero_p_multiple_cases": 0,
        "nonzero_p_multiple_hidden_cases": 0,
        "zero_e_cases": 0,
        "zero_e_exposes_q_cases": 0,
    }
    for e in range(Q):
        supports = [support(p, e, q) for q in range(p)]
        if e % p != 0:
            stats["unit_e_cases"] += 1
            union = set()
            disjoint = True
            for s in supports:
                if union.intersection(s):
                    disjoint = False
                union.update(s)
            if disjoint and len(union) == Q:
                stats["unit_e_partition_cases"] += 1
        elif e == 0:
            stats["zero_e_cases"] += 1
            if len(set(supports)) == p and all(len(s) == 1 for s in supports):
                stats["zero_e_exposes_q_cases"] += 1
        else:
            stats["nonzero_p_multiple_cases"] += 1
            if len(set(supports)) == 1:
                stats["nonzero_p_multiple_hidden_cases"] += 1
    return stats


def exhaustive_pad_coupling(p, m=3):
    # One coordinate is enough: T_m = -sum_{i<m} T_i.
    equal_cases = equal_exact = unequal_cases = unequal_uniform = 0
    for xs in product(range(p), repeat=m):
        counts = [0] * p
        for prefix in product(range(p), repeat=m-1):
            last = (-sum(prefix)) % p
            ts = prefix + (last,)
            phase = sum(x*t for x, t in zip(xs, ts)) % p
            counts[phase] += 1
        if len(set(xs)) == 1:
            equal_cases += 1
            if counts[0] == p**(m-1) and sum(counts[1:]) == 0:
                equal_exact += 1
        else:
            unequal_cases += 1
            if len(set(counts)) == 1:
                unequal_uniform += 1
    return {
        "p": p,
        "m": m,
        "equal_character_cases": equal_cases,
        "equal_character_exact": equal_exact,
        "unequal_character_cases": unequal_cases,
        "unequal_character_uniform": unequal_uniform,
    }


def no_boolean_false_witness():
    hits = []
    for z, a, b, c, d in product((0,1), repeat=5):
        x = [1, z, 1-z, a, 1-a, b, 1-b, c, 1-c, d, 1-d]
        if all(v == 0 for v in matvec(H_FALSE, x)):
            hits.append((z,a,b,c,d))
    return hits


def homogeneous_lift_direction(p):
    # h=z=c=d=0, choose 2*b=-1 and a=-2*b=1 mod p.
    b = (-inv(2, p)) % p
    u = [0, 0, 0, 1, (-1) % p, b, (-b) % p, 0, 0, 0, 0]
    assert all(v == 0 for v in matvec(H_FALSE, u, p))
    assert pair_diff(u, PAIRS[2], p) == p-1
    return u


def adjusted_lift(p):
    Q = p*p
    u = homogeneous_lift_direction(p)
    x = [(a + p*b) % Q for a, b in zip(X0, u)]
    assert all(v == 0 for v in matvec(H_FALSE, x, Q))
    return x


def setup(H, p, K, rng):
    Q = p*p
    comps = components(p)
    C = len(comps)

    shares = [rng.randrange(p) for _ in range(C-1)]
    shares.append((K - sum(shares)) % p)

    pads = [[rng.randrange(p) for _ in range(NVAR)] for _ in range(C-1)]
    pads.append([(-sum(pads[c][j] for c in range(C-1))) % p for j in range(NVAR)])

    capsules = []
    for idx, (_, _, _, w) in enumerate(comps):
        y = [rng.randrange(Q) for _ in range(len(H))]
        z = rng.randrange(p)
        base = ht_y(H, y, Q)
        c = [
            (base[j] + z*w[j] + (p*shares[idx] if j == 0 else 0) + p*pads[idx][j]) % Q
            for j in range(NVAR)
        ]
        capsules.append(c)
    return comps, capsules, shares, pads


def decode_masked_share(x, capsule, w, p):
    """Return q=s*h+<x,T> when the local radix channel is decodable."""
    Q = p*p
    r = dot(x, capsule, Q)
    e = dot(x, w, Q)
    if e % p != 0:
        z = (r % p) * inv(e, p) % p
        rem = (r - z*e) % Q
        assert rem % p == 0
        return (rem // p) % p, "unit"
    if e == 0:
        assert r % p == 0
        return (r // p) % p, "zero"
    return None, "hidden"


def test_true_and_false(rng):
    out = {}
    for p in PRIMES:
        Q = p*p
        comps = components(p)
        xbase = [v % Q for v in X0]
        xadj = adjusted_lift(p)
        xold = [v % Q for v in X1_OLD]

        # Identity checks for the unique bad root alpha=3 on pair b.
        bad0 = root_direction(PAIRS[2], 3, 0, p)
        bad1 = root_direction(PAIRS[2], 3, 1, p)
        lift_identity = {
            "base_t0_e": dot(xbase, bad0, Q),
            "base_t1_e": dot(xbase, bad1, Q),
            "adjusted_t0_e": dot(xadj, bad0, Q),
            "adjusted_t1_e": dot(xadj, bad1, Q),
            "same_mod_p": all((a-b) % p == 0 for a,b in zip(xbase,xadj)),
            "adjusted_kernel_mod_p2": all(v == 0 for v in matvec(H_FALSE, xadj, Q)),
        }

        true_final = false_final = 0
        true_local = false_local = 0
        false_kind_counts = collections.Counter()

        for _ in range(TRIALS_PER_PRIME):
            K = rng.randrange(p)
            # Honest true-instance decode.
            comps_t, caps_t, _, _ = setup(H_TRUE, p, K, rng)
            qs = []
            for comp, cap in zip(comps_t, caps_t):
                q, kind = decode_masked_share([v % Q for v in W_TRUE], cap, comp[3], p)
                assert q is not None
                true_local += 1
                qs.append(q)
            if sum(qs) % p == K:
                true_final += 1

            # False-instance p-adic lift splice.
            comps_f, caps_f, _, _ = setup(H_FALSE, p, K, rng)
            qs = []
            for comp, cap in zip(comps_f, caps_f):
                j, alpha, t, w = comp
                x = xadj if (j == 2 and alpha == 3 and t == 1) else xbase
                q, kind = decode_masked_share(x, cap, w, p)
                assert q is not None
                false_kind_counts[kind] += 1
                false_local += 1
                qs.append(q)
            if sum(qs) % p == K:
                false_final += 1

        # Control: the Run-33 two-vector splice is no longer pad-consistent.
        old_splice_trials = p * 200
        old_splice_errors = collections.Counter()
        for _ in range(old_splice_trials):
            K = rng.randrange(p)
            comps_f, caps_f, _, _ = setup(H_FALSE, p, K, rng)
            qs = []
            for comp, cap in zip(comps_f, caps_f):
                j, alpha, t, w = comp
                x = xold if (j == 2 and alpha == 3 and t == 1) else xbase
                q, _ = decode_masked_share(x, cap, w, p)
                assert q is not None
                qs.append(q)
            recovered = sum(qs) % p
            old_splice_errors[(recovered - K) % p] += 1

        out[str(p)] = {
            "components": len(comps),
            "residues_per_capsule": NVAR,
            "lift_identity": lift_identity,
            "true_trials": TRIALS_PER_PRIME,
            "true_local_decodes": true_local,
            "true_final_recoveries": true_final,
            "false_trials": TRIALS_PER_PRIME,
            "false_local_decodes": false_local,
            "false_final_recoveries": false_final,
            "false_decode_kinds": dict(false_kind_counts),
            "old_run33_splice_control_trials": old_splice_trials,
            "old_run33_splice_error_histogram": {str(k): old_splice_errors[k] for k in range(p)},
        }
    return out


def main():
    assert matvec(H_FALSE, X0) == [0] * len(H_FALSE)
    assert matvec(H_FALSE, X1_OLD) == [0] * len(H_FALSE)
    assert matvec(H_TRUE, W_TRUE) == [0] * len(H_TRUE)

    rng = random.Random(SEED)
    result = {
        "run": 34,
        "seed": SEED,
        "construction": "p-adically coupled affine-root share filter over Z_(p^2)",
        "local_channel_exhaustive": [exhaustive_local_channel(p) for p in (3,5,7)],
        "pad_coupling_exhaustive": [exhaustive_pad_coupling(p) for p in (3,5)],
        "false_boolean_witnesses": no_boolean_false_witness(),
        "false_base_pair_differences": [pair_diff(X0, pair) for pair in PAIRS],
        "old_splice_pair_differences": [pair_diff(X1_OLD, pair) for pair in PAIRS],
        "experiments": test_true_and_false(rng),
    }
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
