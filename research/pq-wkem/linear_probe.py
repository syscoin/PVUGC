"""Exact fixed-character analysis and low-rank-probe extraction.

This is not a proof about arbitrary key-recovery algorithms. The character law
requires test coefficients chosen independently of the fresh masking factors.
The algebraic low-rank extractor itself works for any supplied coefficients.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Sequence

from moment_compiler import MomentCompiler, flatten, rank
from constraint_quotient import dot, normalized_dual


Matrix = Sequence[Sequence[int]]


def matrix_shape(matrix: Matrix) -> tuple[int, int]:
    rows = len(matrix)
    cols = len(matrix[0]) if rows else 0
    if any(len(row) != cols for row in matrix):
        raise ValueError("Ragged matrix")
    return rows, cols


def key_functional(test0: Matrix, code_generators: Sequence[Matrix],
                   p: int) -> tuple[int, ...]:
    shape = matrix_shape(test0)
    if any(matrix_shape(g) != shape for g in code_generators):
        raise ValueError("Code/test shape mismatch")
    flat_test = [x for row in test0 for x in row]
    return tuple(dot(flat_test, [x for row in g for x in row], p)
                 for g in code_generators)


def tensor_combination(compiler: MomentCompiler, tests: Sequence[Matrix]
                       ) -> tuple[tuple[int, ...], ...]:
    dual = normalized_dual(compiler)
    if len(tests) != len(dual) or not tests:
        raise ValueError("Incorrect test count")
    t, width = matrix_shape(tests[0])
    if t <= 0 or width != t or any(matrix_shape(z) != (t, t) for z in tests):
        raise ValueError("Tests must be nonempty square matrices of equal shape")
    sources = [flatten(mu, compiler.n, compiler.degree, compiler.p) for mu in dual]
    a, b = matrix_shape(sources[0])
    out = [[0] * (t * b) for _ in range(t * a)]
    for z, source in zip(tests, sources):
        for i in range(t):
            for j in range(t):
                coefficient = int(z[i][j]) % compiler.p
                if coefficient:
                    for row in range(a):
                        for col in range(b):
                            out[i*a+row][j*b+col] = (
                                out[i*a+row][j*b+col] + coefficient * source[row][col]
                            ) % compiler.p
    return tuple(tuple(row) for row in out)


@dataclass(frozen=True)
class ProbeAnalysis:
    tensor_rank: int
    character_bias: Fraction
    zero_noise_probability: Fraction
    key_functional: tuple[int, ...]


def analyze_fixed_probe(compiler: MomentCompiler, tests: Sequence[Matrix],
                        factors: int, code_generators: Sequence[Matrix]
                        ) -> ProbeAnalysis:
    if factors < 1:
        raise ValueError("Require at least one factor pair")
    d = tensor_combination(compiler, tests)
    rk = rank(d, len(d[0]), compiler.p)
    bias = Fraction(1, compiler.p ** (factors * rk))
    pzero = Fraction(1, compiler.p) + Fraction(compiler.p - 1, compiler.p) * bias
    return ProbeAnalysis(rk, bias, pzero,
                         key_functional(tests[0], code_generators, compiler.p))


def extract_from_low_rank_probe(compiler: MomentCompiler,
                                tests: Sequence[Matrix]
                                ) -> tuple[tuple[int, tuple[int, ...]], ...]:
    d = tensor_combination(compiler, tests)
    if rank(d, len(d[0]), compiler.p) >= compiler.degree:
        raise ValueError("Probe rank does not meet the strict extraction threshold")
    t = len(tests[0])
    cell = next(((i,j) for i in range(t) for j in range(t)
                 if tests[0][i][j] % compiler.p), None)
    if cell is None:
        raise ValueError("The target test is zero")
    i, j = cell
    scale = pow(int(tests[0][i][j]) % compiler.p, -1, compiler.p)
    coefficients = [(scale * z[i][j]) % compiler.p for z in tests[1:]]
    return compiler.extract(coefficients)
