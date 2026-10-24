"""Exact finite algebra tests. Neither candidate sampling nor tests prove hiding."""
from __future__ import annotations

from collections import Counter
from itertools import product
from pathlib import Path
import random
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from moment_compiler import (MomentCompiler, canonical_moments, evaluate,
                             flatten, monomials, rank)
from constraint_quotient import (ConstraintQuotient, bilinear_polynomial,
        canonical_span, constraint_rows, contraction, dot,
        normalized_dual, project_in_normalized_basis)


def all_subspaces(p: int, dimension: int):
    vectors = tuple(product(range(p), repeat=dimension))
    spaces = {()}
    frontier = {()}
    for _ in range(dimension):
        next_frontier = set()
        for basis in frontier:
            for v in vectors:
                span = canonical_span(basis + (v,), dimension, p)
                if span not in spaces:
                    spaces.add(span)
                    next_frontier.add(span)
        frontier = next_frontier
    return sorted(spaces, key=lambda a: (len(a), a))


class QuotientTests(unittest.TestCase):
    def test_all_small_cosets(self):
        spaces = offsets = 0
        for p in (2, 3):
            for dimension in (1, 2, 3):
                vectors = tuple(product(range(p), repeat=dimension))
                for subspace in all_subspaces(p, dimension):
                    q = ConstraintQuotient.build(p, dimension, subspace)
                    self.assertEqual(len(q.subspace) + len(q.dual_basis), dimension)
                    masks = tuple(product(range(p), repeat=len(q.subspace)))
                    for offset in vectors:
                        quotient = q.project(offset)
                        actual = Counter(q.add_mask(offset, u) for u in masks)
                        simulated = Counter(q.simulate(quotient, u) for u in masks)
                        self.assertEqual(actual, simulated)
                        for c in actual:
                            self.assertEqual(q.project(c), quotient)
                        offsets += 1
                    spaces += 1
        self.assertEqual((spaces, offsets), (59, 968))

    def test_nonlinear_precursor_and_auxiliary_input(self):
        p = 3
        q = ConstraintQuotient.build(p, 3, [(1, 1, 0)])
        actual, simulated = Counter(), Counter()
        # K and rho can be correlated with the precursor and public auxiliary
        # data. Only the fresh masking coefficient is independent uniform.
        for key, rho, mask in product(range(p), repeat=3):
            precursor = ((key + rho * rho) % p, key * rho % p, rho)
            aux = (rho, (key + rho) % p)
            actual[(key, aux, q.add_mask(precursor, (mask,)))] += 1
            simulated[(key, aux, q.simulate(q.project(precursor), (mask,)))] += 1
        self.assertEqual(actual, simulated)

    def test_mask_independence_is_necessary(self):
        p = 3
        q = ConstraintQuotient.build(p, 2, [(1, 0)])
        true_recoveries = simulated_recoveries = 0
        for key, disclosed_mask, fresh_mask in product(range(p), repeat=3):
            precursor = (key, 0)
            actual = q.add_mask(precursor, (disclosed_mask,))
            simulation = q.simulate(q.project(precursor), (fresh_mask,))
            true_recoveries += (actual[0] - disclosed_mask) % p == key
            simulated_recoveries += (simulation[0] - disclosed_mask) % p == key
        self.assertEqual(true_recoveries, 27)
        self.assertEqual(simulated_recoveries, 9)

    def test_moment_dual_basis_and_witness_evaluation(self):
        checked = 0
        for p in (2, 3, 5):
            for n in (2, 3):
                for degree in (2, 3, 4):
                    polynomials = ({1: 1, 2: 1, 0: -1},)  # x0+x1=1
                    c = MomentCompiler.build(n, degree, p, polynomials)
                    rows = constraint_rows(n, degree, p, polynomials)
                    q = ConstraintQuotient.build(p, len(c.origin), rows)
                    self.assertEqual(canonical_span(normalized_dual(c), len(c.origin), p),
                                     canonical_span(q.dual_basis, len(c.origin), p))
                    coeffs = tuple((7 * j + 2) % p for j in range(len(c.origin)))
                    y = project_in_normalized_basis(c, coeffs)
                    for bits in product((0, 1), repeat=n):
                        if any(evaluate(poly, bits, p) for poly in polynomials):
                            continue
                        sigma = c.lift(bits)
                        evaluated = dot(canonical_moments(bits, degree), coeffs, p)
                        self.assertEqual(evaluated, (y[0] + dot(sigma, y[1:], p)) % p)
                    checked += 1
        self.assertEqual(checked, 18)
        with self.assertRaises(ValueError):
            MomentCompiler.build(1, 3, 5, ({1: 1}, {1: 1, 0: -1}))

    def test_bilinear_moment_identity(self):
        rng = random.Random(910)
        count = 0
        for p, n, degree in product((2, 3, 5), (2, 3), (2, 3, 4)):
            for _ in range(5):
                mu = tuple(rng.randrange(p) for _ in monomials(n, degree))
                left = tuple(rng.randrange(p) for _ in monomials(n, degree - 1))
                right = tuple(rng.randrange(p) for _ in monomials(n, 1))
                f = bilinear_polynomial(n, degree, p, left, right)
                self.assertEqual(dot(mu, f, p),
                                 contraction(flatten(mu, n, degree, p), left, right, p))
                count += 1
        self.assertEqual(count, 90)

    def test_matrix_polynomial_equals_rank_projection(self):
        rng = random.Random(911)
        configurations = witnesses = 0
        for p in (2, 3, 5):
            for n, degree in ((2, 2), (3, 3)):
                polynomials = ({1: 1, 2: 1, 0: -1},)
                c = MomentCompiler.build(n, degree, p, polynomials)
                rows = constraint_rows(n, degree, p, polynomials)
                quotient = ConstraintQuotient.build(p, len(c.origin), rows)
                dual = normalized_dual(c)
                source_matrices = [flatten(mu, n, degree, p) for mu in dual]
                for t, r in ((2, 1), (3, 1), (3, 2)):
                    lefts = [[[rng.randrange(p) for _ in monomials(n, degree - 1)]
                              for _ in range(t)] for _ in range(r)]
                    rights = [[[rng.randrange(p) for _ in monomials(n, 1)]
                               for _ in range(t)] for _ in range(r)]
                    code = [[rng.randrange(p) for _ in range(t)] for _ in range(t)]
                    polys = [[None for _ in range(t)] for _ in range(t)]
                    for a, b in product(range(t), repeat=2):
                        coef = [code[a][b]] + [0] * (len(c.origin) - 1)
                        for h in range(r):
                            f = bilinear_polynomial(n, degree, p, lefts[h][a], rights[h][b])
                            coef = [(u + v) % p for u, v in zip(coef, f)]
                        mask = tuple(rng.randrange(p) for _ in quotient.subspace)
                        polys[a][b] = quotient.add_mask(coef, mask)
                        projections = project_in_normalized_basis(c, polys[a][b])
                        expected = []
                        for index, matrix in enumerate(source_matrices):
                            value = sum(contraction(matrix, lefts[h][a], rights[h][b], p)
                                        for h in range(r))
                            value += code[a][b] if index == 0 else 0
                            expected.append(value % p)
                        self.assertEqual(projections, tuple(expected))
                    for bits in product((0, 1), repeat=n):
                        if any(evaluate(poly, bits, p) for poly in polynomials):
                            continue
                        mu = canonical_moments(bits, degree)
                        error = [[(dot(mu, polys[a][b], p) - code[a][b]) % p
                                  for b in range(t)] for a in range(t)]
                        self.assertLessEqual(rank(error, t, p), r)
                        witnesses += 1
                    configurations += 1
        self.assertEqual((configurations, witnesses), (18, 54))

    def test_shapes_and_fields_rejected(self):
        with self.assertRaises(ValueError):
            ConstraintQuotient.build(4, 2, [])
        with self.assertRaises(ValueError):
            ConstraintQuotient.build(3, 2, [(1,)])
        q = ConstraintQuotient.build(3, 2, [(1, 0)])
        with self.assertRaises(ValueError):
            q.project((1,))
        with self.assertRaises(ValueError):
            q.simulate((), (1,))
        with self.assertRaises(ValueError):
            q.simulate((0,), ())
        with self.assertRaises(ValueError):
            constraint_rows(2, 1, 3, ())


if __name__ == '__main__':
    unittest.main(verbosity=2)
