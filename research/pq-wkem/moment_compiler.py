"""Exact Boolean-moment compiler and witness extractor over small prime fields.

Research reference only: this module has NO encryption or key-release API.
It proves/checks semantics of a submitted low-rank matrix, not WKEM security.
Only Python's standard library is required. Inputs and arithmetic are public.
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from math import isqrt
from typing import Mapping, Sequence


Polynomial = Mapping[int, int]  # squarefree monomial bit mask -> field coefficient


def check_prime(p: int) -> None:
    """Small-field validation, deliberately not a cryptographic parameter oracle."""
    if not isinstance(p, int) or p < 2 or p > 65537:
        raise ValueError("Reference accepts prime fields 2 <= p <= 65537 only")
    if any(p % d == 0 for d in range(2, isqrt(p) + 1)):
        raise ValueError("p must be prime")


def monomials(n: int, degree: int) -> tuple[int, ...]:
    if n < 0 or degree < 0:
        raise ValueError("Negative dimension or degree")
    return tuple(sum(1 << j for j in c)
                 for d in range(min(n, degree) + 1)
                 for c in combinations(range(n), d))


def rref(matrix: Sequence[Sequence[int]], columns: int, p: int
         ) -> tuple[list[list[int]], tuple[int, ...]]:
    if columns < 0 or any(len(row) != columns for row in matrix):
        raise ValueError("Ragged matrix")
    a = [[int(v) % p for v in row] for row in matrix]
    pivots: list[int] = []
    row = 0
    for col in range(columns):
        pivot = next((i for i in range(row, len(a)) if a[i][col]), None)
        if pivot is None:
            continue
        a[row], a[pivot] = a[pivot], a[row]
        scale = pow(a[row][col], -1, p)
        a[row] = [(scale * v) % p for v in a[row]]
        for i in range(len(a)):
            if i != row and a[i][col]:
                scale = a[i][col]
                a[i] = [(x - scale * y) % p for x, y in zip(a[i], a[row])]
        pivots.append(col)
        row += 1
        if row == len(a):
            break
    return a, tuple(pivots)


def rank(matrix: Sequence[Sequence[int]], columns: int, p: int) -> int:
    return len(rref(matrix, columns, p)[1])


def solve_affine(a: Sequence[Sequence[int]], b: Sequence[int], variables: int,
                 p: int) -> tuple[tuple[int, ...], tuple[tuple[int, ...], ...],
                                   tuple[int, ...]]:
    if len(a) != len(b) or any(len(row) != variables for row in a):
        raise ValueError("Linear-system shape mismatch")
    reduced, pivots = rref([list(row) + [rhs] for row, rhs in zip(a, b)],
                          variables + 1, p)
    if variables in pivots:
        raise ValueError("Inconsistent affine system")
    free = tuple(j for j in range(variables) if j not in pivots)
    origin = [0] * variables
    for i, col in enumerate(pivots):
        origin[col] = reduced[i][-1]
    directions = []
    for col in free:
        v = [0] * variables
        v[col] = 1
        for i, pivot in enumerate(pivots):
            v[pivot] = -reduced[i][col] % p
        directions.append(tuple(v))
    return tuple(origin), tuple(directions), free


def evaluate(poly: Polynomial, bits: Sequence[int], p: int) -> int:
    word = sum(int(bit) << i for i, bit in enumerate(bits))
    return sum(co for mask, co in poly.items() if word & mask == mask) % p


def validate_polynomials(n: int, polynomials: Sequence[Polynomial]) -> None:
    for poly in polynomials:
        for mask in poly:
            if not isinstance(mask, int) or mask < 0 or mask >= 1 << n:
                raise ValueError("Monomial uses an invalid wire index")
            if mask.bit_count() > 2:
                raise ValueError("Compiler input must have degree at most two")


def canonical_moments(bits: Sequence[int], degree: int) -> tuple[int, ...]:
    if any(bit not in (0, 1) for bit in bits):
        raise ValueError("Witness wires must be Boolean")
    word = sum(int(bit) << i for i, bit in enumerate(bits))
    return tuple(int(word & mask == mask) for mask in monomials(len(bits), degree))


def flatten(mu: Sequence[int], n: int, degree: int, p: int
            ) -> tuple[tuple[int, ...], ...]:
    indices = monomials(n, degree)
    if len(mu) != len(indices):
        raise ValueError("Incorrect number of moment coordinates")
    loc = {mask: j for j, mask in enumerate(indices)}
    cols = (0,) + tuple(1 << j for j in range(n))
    return tuple(tuple(int(mu[loc[row | col]]) % p for col in cols)
                 for row in monomials(n, degree - 1))


@dataclass(frozen=True)
class MomentCompiler:
    n: int
    degree: int
    p: int
    polynomials: tuple[tuple[tuple[int, int], ...], ...]
    origin: tuple[int, ...]
    directions: tuple[tuple[int, ...], ...]
    free_coordinates: tuple[int, ...]

    @classmethod
    def build(cls, n: int, degree: int, p: int,
              polynomials: Sequence[Polynomial]) -> "MomentCompiler":
        check_prime(p)
        if n < 0 or degree < 2:
            raise ValueError("Require n >= 0 and degree >= 2")
        validate_polynomials(n, polynomials)
        indices = monomials(n, degree)
        loc = {mask: j for j, mask in enumerate(indices)}
        equations = []
        for poly in polynomials:
            for multiplier in monomials(n, degree - 2):
                row = [0] * len(indices)
                for term, coefficient in poly.items():
                    j = loc[multiplier | term]
                    row[j] = (row[j] + coefficient) % p
                equations.append(row)
        rhs = [0] * len(equations)
        equations.append([1] + [0] * (len(indices) - 1))
        rhs.append(1)
        origin, directions, free = solve_affine(equations, rhs, len(indices), p)
        polys = tuple(tuple(sorted((mask, coefficient % p)
                                   for mask, coefficient in poly.items()))
                      for poly in polynomials)
        return cls(n, degree, p, polys, origin, directions, free)

    def moments(self, coefficients: Sequence[int]) -> tuple[int, ...]:
        if len(coefficients) != len(self.directions):
            raise ValueError("Incorrect affine coefficient count")
        out = list(self.origin)
        for c, direction in zip(coefficients, self.directions):
            for i, value in enumerate(direction):
                out[i] = (out[i] + int(c) * value) % self.p
        return tuple(out)

    def matrix(self, coefficients: Sequence[int]) -> tuple[tuple[int, ...], ...]:
        return flatten(self.moments(coefficients), self.n, self.degree, self.p)

    def lift(self, bits: Sequence[int]) -> tuple[int, ...]:
        if len(bits) != self.n or any(bit not in (0, 1) for bit in bits):
            raise ValueError("Incorrect Boolean witness shape")
        if any(evaluate(dict(poly), bits, self.p) for poly in self.polynomials):
            raise ValueError("Witness violates the relation")
        mu = canonical_moments(bits, self.degree)
        coefficients = tuple(mu[i] for i in self.free_coordinates)
        if self.moments(coefficients) != mu:
            raise ArithmeticError("Internal affine-lift consistency failure")
        return coefficients

    def extract(self, coefficients: Sequence[int]
                ) -> tuple[tuple[int, tuple[int, ...]], ...]:
        return extract_moments(self.moments(coefficients), self.n, self.degree,
                               self.p, [dict(poly) for poly in self.polynomials])


def extract_moments(mu: Sequence[int], n: int, degree: int, p: int,
                    polynomials: Sequence[Polynomial] = ()
                    ) -> tuple[tuple[int, tuple[int, ...]], ...]:
    """Return weighted satisfying atoms for an admissible 0 < rank < degree input.

    The caller must not infer that arbitrary recovered keys supply such an input.
    All structural conditions and the reconstructed witness are checked explicitly.
    """
    check_prime(p)
    if n < 0 or degree < 2:
        raise ValueError("Invalid degree or dimension")
    validate_polynomials(n, polynomials)
    indices = monomials(n, degree)
    if len(mu) != len(indices):
        raise ValueError("Incorrect moment count")
    mu = tuple(int(x) % p for x in mu)
    loc = {mask: j for j, mask in enumerate(indices)}
    for poly in polynomials:
        for multiplier in monomials(n, degree - 2):
            if sum(c * mu[loc[term | multiplier]]
                   for term, c in poly.items()) % p:
                raise ValueError("Moment vector violates a localizing equation")
    matrix = flatten(mu, n, degree, p)
    d = rank(matrix, n + 1, p)
    if not 0 < d < degree:
        raise ValueError("Extractor requires nonzero rank strictly below degree")
    if not any(row[0] for row in matrix):
        raise ArithmeticError("Constant coordinate vanished despite the theorem")
    basis = [0]
    for col in range(1, n + 1):
        if len(basis) == d:
            break
        trial = basis + [col]
        if rank([[row[j] for j in trial] for row in matrix], len(trial), p) > len(basis):
            basis.append(col)
    c = [[row[j] for j in basis] for row in matrix]
    coordinate_columns = []
    for col in range(n + 1):
        coordinates, directions, _ = solve_affine(c, [row[col] for row in matrix], d, p)
        if directions:
            raise ArithmeticError("Selected columns are not independent")
        coordinate_columns.append(coordinates)
    selected = [j - 1 for j in basis[1:]]
    weights = []
    for mask in range(1 << (d - 1)):
        original_mask = sum(1 << selected[j] for j in range(d - 1) if mask >> j & 1)
        weights.append(mu[loc[original_mask]])
    for bit in range(d - 1):
        for mask in range(1 << (d - 1)):
            if not mask >> bit & 1:
                weights[mask] = (weights[mask] - weights[mask | (1 << bit)]) % p
    atoms = []
    for mask, weight in enumerate(weights):
        if weight == 0:
            continue
        values = tuple((column[0] + sum(column[j + 1] for j in range(d - 1)
                                      if mask >> j & 1)) % p
                       for column in coordinate_columns)
        if values[0] != 1 or any(value not in (0, 1) for value in values):
            raise ArithmeticError("An extracted atom is not a normalized Boolean point")
        witness = values[1:]
        if any(evaluate(poly, witness, p) for poly in polynomials):
            raise ArithmeticError("An extracted atom fails the input relation")
        atoms.append((weight, witness))
    reconstruction = [0] * len(indices)
    for weight, witness in atoms:
        for j, value in enumerate(canonical_moments(witness, degree)):
            reconstruction[j] = (reconstruction[j] + weight * value) % p
    if not atoms or tuple(reconstruction) != mu:
        raise ArithmeticError("Extracted atoms do not reconstruct the submitted moments")
    return tuple(atoms)
