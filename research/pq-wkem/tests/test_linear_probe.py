"""Exact checks of fixed-probe laws, not general cryptographic security tests."""
from __future__ import annotations

from collections import Counter
from fractions import Fraction
from itertools import product
from pathlib import Path
import random
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from constraint_quotient import contraction, normalized_dual
from linear_probe import (analyze_fixed_probe, extract_from_low_rank_probe,
                          key_functional, tensor_combination)
from moment_compiler import MomentCompiler, evaluate, flatten, rank


def matrix(flat, rows, cols):
    return [list(flat[i*cols:(i+1)*cols]) for i in range(rows)]


def projection_outcomes(c, t):
    source = [flatten(mu, c.n, c.degree, c.p) for mu in normalized_dual(c)]
    a, b = len(source[0]), len(source[0][0])
    for left in product(range(c.p), repeat=t*a):
        lm = matrix(left, t, a)
        for right in product(range(c.p), repeat=b*t):
            rm = matrix(right, b, t)
            rights = [[rm[i][j] for i in range(b)] for j in range(t)]
            yield tuple(contraction(s, lm[i], rights[j], c.p)
                        for s in source for i in range(t) for j in range(t))


def walsh_hadamard(counts):
    a = list(counts)
    step = 1
    while step < len(a):
        for start in range(0, len(a), 2*step):
            for j in range(start, start+step):
                x, y = a[j], a[j+step]
                a[j], a[j+step] = x+y, x-y
        step *= 2
    return a


class LinearProbeTests(unittest.TestCase):
    def test_all_binary_matrix_modes(self):
        c = MomentCompiler.build(1, 2, 2, ())
        t = 2
        counts = [0] * 256
        for outcome in projection_outcomes(c, t):
            counts[sum(v << j for j, v in enumerate(outcome))] += 1
        total = sum(counts)
        self.assertEqual(total, 256)
        transformed = walsh_hadamard(counts)
        extracted = 0
        for word in range(256):
            bits = tuple((word >> j) & 1 for j in range(8))
            tests = (matrix(bits[:4], 2, 2), matrix(bits[4:], 2, 2))
            info = analyze_fixed_probe(c, tests, 1, ([[1,0],[0,1]],))
            self.assertEqual(Fraction(transformed[word], total), info.character_bias)
            if any(bits[:4]) and info.tensor_rank < c.degree:
                atoms = extract_from_low_rank_probe(c, tests)
                self.assertTrue(atoms)
                self.assertTrue(all(w in ((0,), (1,)) for _, w in atoms))
                extracted += 1
        self.assertGreater(extracted, 0)
        # Exhaustively combine two independent factor pairs and compare all modes.
        convolution = [0] * 256
        for x, cx in enumerate(counts):
            for y, cy in enumerate(counts):
                convolution[x ^ y] += cx*cy
        twice = walsh_hadamard(convolution)
        for word in range(256):
            bits = tuple((word >> j) & 1 for j in range(8))
            tests = (matrix(bits[:4], 2, 2), matrix(bits[4:], 2, 2))
            info = analyze_fixed_probe(c, tests, 2, ([[1,0],[0,1]],))
            self.assertEqual(Fraction(twice[word], total**2), info.character_bias)

    def test_odd_field_character_counts(self):
        c = MomentCompiler.build(1, 2, 3, ())
        outcomes = list(projection_outcomes(c, 2))
        self.assertEqual(len(outcomes), 6561)
        rng = random.Random(912)
        for _ in range(24):
            coeffs = tuple(rng.randrange(3) for _ in range(8))
            tests = (matrix(coeffs[:4], 2, 2), matrix(coeffs[4:], 2, 2))
            info = analyze_fixed_probe(c, tests, 1, ([[1,0],[0,1]],))
            counts = Counter(sum(a*b for a,b in zip(coeffs, out)) % 3
                             for out in outcomes)
            self.assertEqual(counts[1], counts[2])
            self.assertEqual(Fraction(counts[0]-counts[1],len(outcomes)),
                             info.character_bias)
            self.assertEqual(Fraction(counts[0],len(outcomes)), info.zero_noise_probability)

    def test_correctness_compatible_output_width(self):
        c = MomentCompiler.build(1, 2, 2, ())
        outcomes = [sum(v << j for j,v in enumerate(out))
                    for out in projection_outcomes(c, 3)]
        self.assertEqual(len(outcomes), 4096)
        rng = random.Random(913)
        generators = ([[1,0,0],[0,1,0],[0,0,1]],)
        for _ in range(64):
            word = rng.randrange(1<<18)
            bits = tuple((word>>j)&1 for j in range(18))
            tests = (matrix(bits[:9],3,3),matrix(bits[9:],3,3))
            info = analyze_fixed_probe(c, tests, 1, generators)
            numerator = sum(1 if (out & word).bit_count()%2==0 else -1
                            for out in outcomes)
            self.assertEqual(Fraction(numerator,len(outcomes)), info.character_bias)

    def test_false_instance_strict_boundary(self):
        # No Boolean (x,y) sums to 3 over F5, but the cubic affine slice exists.
        c = MomentCompiler.build(2, 3, 5, ({0:-3,1:1,2:1},))
        self.assertEqual(c.origin,(1,4,4,3))
        self.assertFalse(c.directions)
        tests = ([[1]],)
        info = analyze_fixed_probe(c, tests, 1, ([[1]],))
        self.assertEqual(info.tensor_rank,3)
        self.assertEqual(info.character_bias,Fraction(1,125))
        with self.assertRaises(ValueError):
            extract_from_low_rank_probe(c,tests)
        source = flatten(c.origin,c.n,c.degree,c.p)
        counts = Counter()
        # All 5^(4+3) factor pairs, exactly; no simulated exponent oracle.
        for left in product(range(5),repeat=4):
            for right in product(range(5),repeat=3):
                counts[contraction(source,left,right,5)]+=1
        self.assertEqual(sum(counts.values()),78125)
        self.assertEqual([counts[j] for j in range(1,5)], [15500]*4)
        self.assertEqual(counts[0],16125)
        self.assertEqual(Fraction(counts[0]-counts[1],78125),info.character_bias)

    def test_small_linear_bias_does_not_imply_hiding(self):
        # H=L R, L:4x2 and R:2x4. All output matrices have rank <=2.
        # Every fixed nontrivial character nevertheless has bias <=1/4.
        # The scalable theorem is in the note; this is its finite exact check.
        counts = [0] * (1 << 16)
        for lrows in product(range(4), repeat=4):
            for rcols in product(range(4), repeat=4):
                word = sum(((a & b).bit_count() & 1) << (4*i+j)
                           for i,a in enumerate(lrows) for j,b in enumerate(rcols))
                counts[word] += 1
        transformed = walsh_hadamard(counts)
        total = sum(counts)
        self.assertEqual(total, 65536)
        self.assertEqual(max(transformed[1:]), total // 4)

        def binary_rank(word):
            basis = {}
            for i in range(4):
                row = (word >> (4*i)) & 15
                while row:
                    pivot = row.bit_length()-1
                    if pivot in basis:
                        row ^= basis[pivot]
                    else:
                        basis[pivot] = row
                        break
            return len(basis)

        uniform_low_rank = 0
        for word in range(1 << 16):
            rk = binary_rank(word)
            self.assertEqual(Fraction(transformed[word],total),Fraction(1,2**(2*rk)))
            uniform_low_rank += rk <= 2
            if counts[word]:
                self.assertLessEqual(rk,2)
        self.assertEqual(uniform_low_rank,7576)

    def test_target_nonzero_and_input_checks(self):
        c=MomentCompiler.build(1,2,2,())
        with self.assertRaises(ValueError):
            extract_from_low_rank_probe(c, ([[0]],[[0]]))
        with self.assertRaises(ValueError):
            tensor_combination(c, ([[1]],))
        with self.assertRaises(ValueError):
            analyze_fixed_probe(c, ([[1]],[[0]]),0,([[1]],))
        self.assertEqual(key_functional([[0,1],[0,0]], ([[1,0],[0,1]],),2),(0,))


if __name__=='__main__':
    unittest.main(verbosity=2)
