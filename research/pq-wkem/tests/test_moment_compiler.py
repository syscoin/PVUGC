"""Exact small-field semantic checks. Passing is NOT a WKEM security claim."""
from __future__ import annotations

import itertools
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from moment_compiler import (MomentCompiler, canonical_moments, evaluate,
                             extract_moments, flatten, monomials, rank)


class MomentCompilerTests(unittest.TestCase):
    def test_affine_lift_and_multiple_witnesses(self):
        # w1 + w2 = 1, w1*w2 = 0; w2 + w3 = 1, w2*w3 = 0.
        for p in (2, 3, 5, 7, 257):
            polys = ({1: 1, 2: 1, 0: -1}, {3: 1},
                     {2: 1, 4: 1, 0: -1}, {6: 1})
            for degree in (2, 3, 4):
                comp = MomentCompiler.build(3, degree, p, polys)
                good = []
                for witness in itertools.product((0, 1), repeat=3):
                    if any(evaluate(poly, witness, p) for poly in polys):
                        with self.assertRaises(ValueError):
                            comp.lift(witness)
                        continue
                    good.append(witness)
                    coefficients = comp.lift(witness)
                    self.assertTrue(all(c in (0, 1) for c in coefficients))
                    self.assertEqual(rank(comp.matrix(coefficients), 4, p), 1)
                    self.assertEqual(comp.extract(coefficients), ((1, witness),))
                self.assertEqual(len(good), 2)

    def test_all_small_field_moment_vectors(self):
        # Exact enumeration, not random rank-gap sampling. Repeated on purpose
        # independently of the preceding archive's NumPy implementation.
        configs = ((3, 3, 2), (3, 3, 3), (2, 3, 5), (3, 4, 2), (3, 5, 3))
        for n, degree, p in configs:
            count = applicable = 0
            for mu in itertools.product(range(p), repeat=len(monomials(n, degree))):
                count += 1
                d = rank(flatten(mu, n, degree, p), n + 1, p)
                if 0 < d < degree:
                    atoms = extract_moments(mu, n, degree, p)
                    self.assertGreater(len(atoms), 0)
                    self.assertLessEqual(len(atoms), 1 << (d - 1))
                    applicable += 1
            self.assertEqual(count, p ** len(monomials(n, degree)))
            self.assertGreater(applicable, 0)

    def test_every_small_constrained_coefficient_vector(self):
        for p in (2, 3, 5):
            polys = ({1: 1, 2: 1, 0: -1}, {3: 1},
                     {2: 1, 4: 1, 0: -1}, {6: 1})
            comp = MomentCompiler.build(3, 3, p, polys)
            self.assertLessEqual(len(comp.directions), 3)
            for coefficients in itertools.product(range(p), repeat=len(comp.directions)):
                d = rank(comp.matrix(coefficients), 4, p)
                if 0 < d < comp.degree:
                    for _, witness in comp.extract(coefficients):
                        self.assertTrue(all(evaluate(poly, witness, p) == 0 for poly in polys))

    def test_boundary_rank_is_not_accepted(self):
        # Over F5, Boolean x+y cannot equal 3. The cubic affine slice nevertheless
        # contains mu=(1,4,4,3), and its rank is exactly D=3 (outside the theorem).
        comp = MomentCompiler.build(2, 3, 5, ({1: 1, 2: 1, 0: -3},))
        self.assertEqual(comp.origin, (1, 4, 4, 3))
        self.assertEqual(comp.directions, ())
        self.assertEqual(rank(comp.matrix(()), 3, 5), 3)
        with self.assertRaises(ValueError):
            comp.extract(())
        self.assertFalse(any(evaluate({1: 1, 2: 1, 0: -3}, w, 5) == 0
                             for w in itertools.product((0, 1), repeat=2)))

    def test_nonzero_homogeneous_normalization_is_not_assumed(self):
        # Equal weights on two Boolean atoms cancel mu_empty over F2.
        a = canonical_moments((0, 0, 0), 3)
        b = canonical_moments((1, 0, 0), 3)
        mu = tuple(x ^ y for x, y in zip(a, b))
        self.assertEqual(mu[0], 0)
        self.assertEqual(rank(flatten(mu, 3, 3, 2), 4, 2), 2)
        atoms = extract_moments(mu, 3, 3, 2)
        self.assertEqual(set(atoms), {(1, (0, 0, 0)), (1, (1, 0, 0))})

    def test_malformed_and_inconsistent_inputs(self):
        with self.assertRaises(ValueError):
            MomentCompiler.build(2, 3, 4, ())
        with self.assertRaises(ValueError):
            MomentCompiler.build(3, 3, 5, ({7: 1},))
        with self.assertRaises(ValueError):
            MomentCompiler.build(1, 3, 5, ({0: 1},))
        with self.assertRaises(ValueError):
            extract_moments((0, 0, 0, 0), 2, 3, 5)
        with self.assertRaises(ValueError):
            extract_moments((1, 0, 0, 0), 2, 3, 5, ({0: 1},))
        with self.assertRaises(ValueError):
            canonical_moments((0, 2), 3)


if __name__ == '__main__':
    unittest.main(verbosity=2)
