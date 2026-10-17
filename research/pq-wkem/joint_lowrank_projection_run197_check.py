#!/usr/bin/env python3
"""Run 197 finite controls for the shared-factor full-matrix projection law.

Standard library only. Exhaustive fixtures validate finite identities; they are not
cryptographic security experiments and do not establish the general theorem.
"""
from collections import Counter
from fractions import Fraction
from itertools import product
import json


def parity(x):
    return x.bit_count() & 1


def rank_rows(rows, ncols):
    rows = list(rows)
    r = 0
    for c in range(ncols - 1, -1, -1):
        pivot = next((i for i in range(r, len(rows)) if (rows[i] >> c) & 1), None)
        if pivot is None:
            continue
        rows[r], rows[pivot] = rows[pivot], rows[r]
        for i in range(len(rows)):
            if i != r and ((rows[i] >> c) & 1):
                rows[i] ^= rows[r]
        r += 1
        if r == len(rows):
            break
    return r


def p_full(rows, cols):
    """Probability a uniform rows x cols binary matrix has full row rank."""
    if cols < rows:
        return Fraction(0, 1)
    out = Fraction(1, 1)
    for j in range(rows):
        out *= Fraction((1 << cols) - (1 << j), 1 << cols)
    return out


def matrix_rows_from_bits(bits, rows, cols):
    mask = (1 << cols) - 1
    return [(bits >> (i * cols)) & mask for i in range(rows)]


def abt(A, B, t, m):
    """Return t x t matrix A B^T as one row-major bit integer."""
    out = 0
    for p in range(t):
        for q in range(t):
            out |= parity(A[p] & B[q]) << (p * t + q)
    return out


def product_hist(t, m):
    hist = Counter()
    for abits in range(1 << (t * m)):
        A = matrix_rows_from_bits(abits, t, m)
        for bbits in range(1 << (t * m)):
            B = matrix_rows_from_bits(bbits, t, m)
            hist[abt(A, B, t, m)] += 1
    return hist


def tv_to_uniform(hist, space_size):
    total = sum(hist.values())
    return sum(abs(Fraction(hist.get(x, 0), total) - Fraction(1, space_size))
               for x in range(space_size)) / 2


def full_rank_prob(hist, t):
    total = sum(hist.values())
    count = 0
    for x, multiplicity in hist.items():
        rows = matrix_rows_from_bits(x, t, t)
        if rank_rows(rows, t) == t:
            count += multiplicity
    return Fraction(count, total)


def product_controls():
    cases = []
    # Small enough for exact enumeration, broad enough to cross m<t, m=t, m>t.
    for t, ms in [(2, range(0, 6)), (3, range(1, 4))]:
        p_t = p_full(t, t)
        for m in ms:
            hist = product_hist(t, m)
            tv = tv_to_uniform(hist, 1 << (t * t))
            q_full = full_rank_prob(hist, t)
            p_tm = p_full(t, m)
            predicted_full = p_t * p_tm
            assert q_full == predicted_full
            lower = p_t * (1 - p_tm)
            upper = 1 - p_tm
            assert lower <= tv <= upper
            if m >= t:
                s = m - t
                failure = 1 - p_tm
                assert failure >= Fraction(1, 1 << (s + 1))
                assert failure < Fraction(1, 1 << s) if s > 0 else failure < 1
            else:
                assert q_full == 0
                assert lower == p_t
            cases.append({
                't': t,
                'm': m,
                'tv': str(tv),
                'full_rank_product': str(q_full),
                'full_rank_uniform': str(p_t),
                'rank_event_advantage': str(abs(q_full - p_t)),
                'p_B_full': str(p_tm),
                'tv_lower': str(lower),
                'tv_upper': str(upper),
            })
    return cases


def bilinear(u, M_rows, v):
    # u is a-bit vector; rows of M are b-bit vectors.
    x = 0
    for i, row in enumerate(M_rows):
        if (u >> i) & 1:
            x ^= row
    return parity(x & v)


def direct_cmv_hist(t, a, b, M_rows, r):
    """Enumerate C[p,q]=sum_l u_lp^T M v_lq for tiny fixtures."""
    hist = Counter()
    ublock_bits = t * a * r
    vblock_bits = t * b * r
    for ubits in range(1 << ublock_bits):
        us = []
        off = 0
        for l in range(r):
            row = []
            for p in range(t):
                row.append((ubits >> off) & ((1 << a) - 1))
                off += a
            us.append(row)
        for vbits in range(1 << vblock_bits):
            vs = []
            off = 0
            for l in range(r):
                row = []
                for q in range(t):
                    row.append((vbits >> off) & ((1 << b) - 1))
                    off += b
                vs.append(row)
            C = 0
            for p in range(t):
                for q in range(t):
                    bit = 0
                    for l in range(r):
                        bit ^= bilinear(us[l][p], M_rows, vs[l][q])
                    C |= bit << (p * t + q)
            hist[C] += 1
    return hist


def bridge_controls():
    # Two exact source matrices: rank 1 and rank 2 over F2.
    fixtures = [
        ('rho1_r1', [0b11, 0b00], 1, 1),
        ('rho1_r2', [0b11, 0b00], 1, 2),
        ('rho2_r1', [0b01, 0b10], 2, 1),
    ]
    out = []
    for name, M, rho, r in fixtures:
        assert rank_rows(M, 2) == rho
        direct = direct_cmv_hist(t=2, a=2, b=2, M_rows=M, r=r)
        product_law = product_hist(t=2, m=r * rho)
        direct_total = sum(direct.values())
        product_total = sum(product_law.values())
        keys = set(direct) | set(product_law)
        assert all(direct.get(x, 0) * product_total == product_law.get(x, 0) * direct_total for x in keys)
        out.append({
            'fixture': name,
            'rho': rho,
            'r': r,
            'm_equals_r_rho': r * rho,
            'histogram_matches_ABt_exactly': True,
            'tv_to_uniform': str(tv_to_uniform(direct, 16)),
        })
    return out


def coarse_parameter_obstruction(lam, R, r, t):
    # Run 82 guarantees a public member with rho <= R+2. If even the *largest*
    # allowed rho has m-t too small, every such member is within the attack region.
    s_max = r * (R + 2) - t
    if s_max < 0:
        classification = 'constant-rank-event-attack-guaranteed'
    elif s_max < lam - 3:
        classification = 'rank-event-advantage-exceeds-2^-lambda-by-coarse-constant-factor-bound'
    else:
        classification = 'not-ruled-out-by-this-coarse-necessary-condition'
    return {'lambda': lam, 'R': R, 'r': r, 't': t,
            'r_times_Rplus2_minus_t': s_max, 'classification': classification}


def main():
    result = {
        'run': 197,
        'status': 'PASS',
        'scope': 'exact shared-factor full-t-by-t public projection law and rank-event distinguisher controls; not full WKEM security',
        'product_law_cases': product_controls(),
        'direct_cmv_bridge_cases': bridge_controls(),
        'illustrative_necessary_condition_rows': [
            coarse_parameter_obstruction(128, 8, 8, 20),
            coarse_parameter_obstruction(128, 16, 8, 20),
            coarse_parameter_obstruction(128, 16, 10, 22),
        ],
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
