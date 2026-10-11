"""Public constraint-quotient normal forms; research algebra, NOT encryption.

All matrices/polynomials are public, over the small prime fields supported by
moment_compiler.py. No hardness assumption, KEM API, or security level is given.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from moment_compiler import (MomentCompiler, Polynomial, check_prime,
                             monomials, rref, solve_affine,
                             validate_polynomials)


def dot(a: Sequence[int], b: Sequence[int], p: int) -> int:
    if len(a) != len(b):
        raise ValueError("Vector shape mismatch")
    return sum(x * y for x, y in zip(a, b)) % p


def lincomb(coefficients: Sequence[int], vectors: Sequence[Sequence[int]],
            dimension: int, p: int) -> tuple[int, ...]:
    if len(coefficients) != len(vectors):
        raise ValueError("Coefficient count mismatch")
    if any(len(v) != dimension for v in vectors):
        raise ValueError("Vector shape mismatch")
    return tuple(sum(c * v[j] for c, v in zip(coefficients, vectors)) % p
                 for j in range(dimension))


def canonical_span(vectors: Sequence[Sequence[int]], dimension: int,
                   p: int) -> tuple[tuple[int, ...], ...]:
    check_prime(p)
    rows, pivots = rref(vectors, dimension, p)
    return tuple(tuple(row) for row in rows[:len(pivots)])


@dataclass(frozen=True)
class ConstraintQuotient:
    """pi has kernel equal to the public masking subspace, not its complement."""
    p: int
    dimension: int
    subspace: tuple[tuple[int, ...], ...]
    dual_basis: tuple[tuple[int, ...], ...]

    @classmethod
    def build(cls, p: int, dimension: int,
              generators: Sequence[Sequence[int]]) -> "ConstraintQuotient":
        check_prime(p)
        if dimension < 0:
            raise ValueError("Negative dimension")
        subspace = canonical_span(generators, dimension, p)
        _, dual, _ = solve_affine(subspace, [0] * len(subspace), dimension, p)
        return cls(p, dimension, subspace, dual)

    def project(self, vector: Sequence[int]) -> tuple[int, ...]:
        if len(vector) != self.dimension:
            raise ValueError("Vector shape mismatch")
        return tuple(dot(mu, vector, self.p) for mu in self.dual_basis)

    def section(self, quotient: Sequence[int]) -> tuple[int, ...]:
        if len(quotient) != len(self.dual_basis):
            raise ValueError("Quotient shape mismatch")
        origin, _, _ = solve_affine(self.dual_basis, quotient,
                                    self.dimension, self.p)
        return origin

    def add_mask(self, vector: Sequence[int], coefficients: Sequence[int]
                 ) -> tuple[int, ...]:
        if len(vector) != self.dimension:
            raise ValueError("Vector shape mismatch")
        noise = lincomb(coefficients, self.subspace, self.dimension, self.p)
        return tuple((x + y) % self.p for x, y in zip(vector, noise))

    def simulate(self, quotient: Sequence[int], coefficients: Sequence[int]
                 ) -> tuple[int, ...]:
        return self.add_mask(self.section(quotient), coefficients)


def constraint_rows(n: int, degree: int, p: int,
                    polynomials: Sequence[Polynomial]
                    ) -> tuple[tuple[int, ...], ...]:
    """Span of localizing polynomials only; do NOT add mu_empty=1 here."""
    check_prime(p)
    if n < 0 or degree < 2:
        raise ValueError("Require n>=0 and degree>=2")
    validate_polynomials(n, polynomials)
    indices = monomials(n, degree)
    loc = {mask: j for j, mask in enumerate(indices)}
    rows = []
    for poly in polynomials:
        for multiplier in monomials(n, degree - 2):
            row = [0] * len(indices)
            for mask, coefficient in poly.items():
                row[loc[mask | multiplier]] += coefficient
            rows.append([x % p for x in row])
    return canonical_span(rows, len(indices), p)


def normalized_dual(compiler: MomentCompiler) -> tuple[tuple[int, ...], ...]:
    """A basis of U^perp when the compiler's mu_empty=1 slice is nonempty."""
    return (compiler.origin,) + compiler.directions


def project_in_normalized_basis(compiler: MomentCompiler,
                                coefficients: Sequence[int]
                                ) -> tuple[int, ...]:
    return tuple(dot(mu, coefficients, compiler.p)
                 for mu in normalized_dual(compiler))


def bilinear_polynomial(n: int, degree: int, p: int,
                        left: Sequence[int], right: Sequence[int]
                        ) -> tuple[int, ...]:
    """Squarefree product: left degree <=D-1; right degree <=1."""
    left_masks, right_masks = monomials(n, degree - 1), monomials(n, 1)
    if len(left) != len(left_masks) or len(right) != len(right_masks):
        raise ValueError("Factor shape mismatch")
    indices = monomials(n, degree)
    loc = {mask: j for j, mask in enumerate(indices)}
    out = [0] * len(indices)
    for mask_a, a in zip(left_masks, left):
        for mask_b, b in zip(right_masks, right):
            out[loc[mask_a | mask_b]] += a * b
    return tuple(x % p for x in out)


def contraction(matrix: Sequence[Sequence[int]], left: Sequence[int],
                right: Sequence[int], p: int) -> int:
    if len(matrix) != len(left) or any(len(row) != len(right) for row in matrix):
        raise ValueError("Contraction shape mismatch")
    return sum(a * x * b for a, row in zip(left, matrix)
               for x, b in zip(row, right)) % p
