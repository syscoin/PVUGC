#!/usr/bin/env python3
"""Exact finite controls for conditional-image mixing, not a KEM implementation.
Python 3.10+, standard library. All enumerations are small validation oracles.
"""
from collections import Counter
from fractions import Fraction
from itertools import product, combinations
import json


def rank(vectors):
    pivots = {}
    for value in vectors:
        while value:
            k = value.bit_length() - 1
            if k in pivots:
                value ^= pivots[k]
            else:
                pivots[k] = value
                break
    return len(pivots)


def xor_all(values):
    out = 0
    for value in values:
        out ^= value
    return out


def walsh(values):
    out = list(values)
    step = 1
    while step < len(out):
        for start in range(0, len(out), 2 * step):
            for i in range(start, start + step):
                a, b = out[i], out[i + step]
                out[i], out[i + step] = a + b, a - b
        step *= 2
    return out


def image_bits(basis, us, vs):
    result = 0
    for j, cols in enumerate(basis):
        bit = 0
        for u, v in zip(us, vs):
            mv = xor_all(col for i, col in enumerate(cols) if (v >> i) & 1)
            bit ^= (u & mv).bit_count() & 1
        result |= bit << j
    return result


def conditional_controls():
    # Column-packed 2 x 2 binary matrix bases; the middle basis is a field code.
    fixtures = [('identity', [(1, 2)]),
                ('field_code', [(1, 2), (2, 3)]),
                ('full_space', [(1, 0), (2, 0), (0, 1), (0, 2)])]
    rows = []
    conditional_cases = 0
    for name, basis in fixtures:
        d = len(basis)
        mats = [tuple(xor_all(basis[j][i] for j in range(d) if (a >> j) & 1)
                      for i in range(2)) for a in range(1, 1 << d)]
        distance = min(map(rank, mats))
        for r in range(4):
            aggregate = Counter()
            bad = 0
            tuples = list(product(range(4), repeat=r))
            for vs in tuples:
                counts = Counter(image_bits(basis, us, vs) for us in tuples)
                # Each conditional distribution is exactly uniform on a linear image.
                assert len(set(counts.values())) == 1
                image = set(counts)
                assert 0 in image
                assert all((a ^ b) in image for a in image for b in image)
                kernel_exists = any(all(xor_all(col for i, col in enumerate(mat)
                                                       if (v >> i) & 1) == 0
                                             for v in vs) for mat in mats)
                assert kernel_exists == (len(image) < (1 << d))
                bad += rank(vs) <= 2 - distance
                if rank(vs) > 2 - distance:
                    assert len(image) == (1 << d)
                aggregate.update(counts)
                conditional_cases += 1
            total = len(tuples) ** 2
            tv = sum(abs(Fraction(aggregate[y], total) - Fraction(1, 1 << d))
                     for y in range(1 << d)) / 2
            bound = Fraction(bad, len(tuples))
            assert tv <= bound
            rows.append({'source': name, 'r': r, 'minimum_rank': distance,
                         'tv': str(tv), 'kernel_rank_failure_bound': str(bound)})
    return conditional_cases, rows


class Field:
    def __init__(self, h, poly):
        self.h, self.q, self.poly = h, 1 << h, poly
        self.mul = [[self.multiply(a, b) for b in range(self.q)] for a in range(self.q)]

    def multiply(self, a, b):
        z = 0
        while b:
            if b & 1:
                z ^= a
            b >>= 1
            a <<= 1
            if a & self.q:
                a ^= self.poly
        return z

    def power(self, a, e):
        z = 1
        for _ in range(e):
            z = self.mul[z][a]
        return z

    def order(self, a):
        z = 1
        for e in range(1, self.q):
            z = self.mul[z][a]
            if z == 1:
                return e
        raise ValueError('invalid field element')


def weighted_basis(n, R, field):
    assert field.q > 2 * n * R
    gamma = next(a for a in range(2, field.q) if field.order(a) > n)
    indices = [sum(1 << i for i in c) for degree in (1, 2)
               for c in combinations(range(n), degree)]
    aa = [a for a in product(range(R + 1), repeat=R) if sum(a) <= R]
    generators = [[0] * (n + 1) for _ in indices]
    rows = (2 * n * R + 1) * len(aa) * (n + 1)
    for word in range(1 << n):
        v = [1] + [(word >> i) & 1 for i in range(n)]
        cols = [0] * (n + 1)
        row_index = 0
        for tau in range(2 * n * R + 1):
            forms = [xor_all(field.power(field.mul[field.power(gamma, j)][tau], i)
                             for i in range(n + 1) if v[i]) for j in range(R)]
            for alpha in aa:
                weight = 1
                for value, exponent in zip(forms, alpha):
                    weight = field.mul[weight][field.power(value, exponent)]
                for vi in v:
                    if vi:
                        for j, vj in enumerate(v):
                            if vj:
                                cols[j] ^= weight << (field.h * row_index)
                    row_index += 1
        assert row_index == rows
        for mask, gen in zip(indices, generators):
            if word & mask == mask:
                for j in range(n + 1):
                    gen[j] ^= cols[j]
    # Independence of complete matrices, not of their columns.
    flat = [sum(col << (j * rows * field.h) for j, col in enumerate(gen))
            for gen in generators]
    assert rank(flat) == len(generators)
    return generators, rows * field.h, gamma


def rank_failure_probability(v, r, cutoff):
    # Exact rank counts: Gaussian(v,j) times number of full-row-rank j x r matrices.
    total = 0
    for j in range(min(cutoff, v, r) + 1):
        numerator = denominator = 1
        for i in range(j):
            numerator *= ((1 << v) - (1 << i)) * ((1 << r) - (1 << i))
            denominator *= (1 << j) - (1 << i)
        assert numerator % denominator == 0
        total += numerator // denominator
    return Fraction(total, 1 << (v * r))


def actual_table_controls(n, R, h, poly):
    basis, rows, gamma = weighted_basis(n, R, Field(h, poly))
    d, v = len(basis), n + 1
    ranks = [0] * (1 << d)
    current = [0] * v
    previous = 0
    for number in range(1, 1 << d):
        gray = number ^ (number >> 1)
        k = (gray ^ previous).bit_length() - 1
        current = [a ^ b for a, b in zip(current, basis[k])]
        ranks[gray] = rank(current)
        previous = gray
    hist = Counter(ranks[1:])
    assert hist == ({3: 155, 5: 868} if n == 4 else {4: 651, 6: 32116})
    minimum = min(hist)
    laws = []
    for r in range(1, 7):
        scale = 1 << (r * v)
        # Exact inverse Fourier law for the entire one-block quotient projection.
        density_numerators = walsh([1 << (r * (v - k)) for k in ranks])
        denominator = (1 << d) * scale
        assert min(density_numerators) >= 0
        assert sum(density_numerators) == denominator
        tv = Fraction(sum(abs(x - scale) for x in density_numerators), 2 * denominator)
        a, b = Fraction(1, 1 << (r * minimum)), Fraction(1, 1 << (r * v))
        closed = (Fraction(217, 256) * (5 * a - 4 * b) if n == 4
                  else Fraction(217, 512) * (21 * a - 20 * b))
        assert tv == closed
        bound = rank_failure_probability(v, r, v - minimum)
        assert tv <= bound
        if r > v - minimum:
            coarse = Fraction(4 * (v - minimum + 1),
                              1 << (minimum * (r - (v - minimum))))
            assert bound <= coarse
        laws.append({'r': r, 'tv': str(tv), 'tv_float': float(tv),
                     'rank_failure_bound': str(bound)})
    return {'n': n, 'R': R, 'field_bits': h, 'gamma': gamma,
            'binary_rows': rows, 'image_dimension': d,
            'nonzero_rank_spectrum': dict(sorted(hist.items())), 'laws': laws}


def main():
    count, controls = conditional_controls()
    actual = [actual_table_controls(4, 1, 4, 0b10011),
              actual_table_controls(5, 2, 5, 0b100101)]
    print(json.dumps({'run': 196, 'status': 'PASS',
                      'scope': 'conditional-image theorem controls and exact finite one-block marginals; not full-capsule security',
                      'conditional_images_checked': count,
                      'generic_controls': controls,
                      'literal_table_projections': actual}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
