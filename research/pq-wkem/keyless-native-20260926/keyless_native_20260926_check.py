#!/usr/bin/env python3
"""Finite algebra/authorization checks, not a signature or WKEM implementation.

No network, Bitcoin transaction, imported historical checker, or cryptographic
security experiment. All arithmetic fixtures are deliberately tiny and public.
"""
from __future__ import annotations

from collections import Counter
from fractions import Fraction
from hashlib import sha256
from itertools import product
import json
from pathlib import Path
import random

CHECKS = 0


def check(condition: bool, description: str) -> None:
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError(description)


def rank(matrix: list[list[int]], p: int) -> int:
    a = [[x % p for x in row] for row in matrix]
    if not a:
        return 0
    r = 0
    for c in range(len(a[0])):
        pivot = next((i for i in range(r, len(a)) if a[i][c]), None)
        if pivot is None:
            continue
        a[r], a[pivot] = a[pivot], a[r]
        inv = pow(a[r][c], -1, p)
        a[r] = [x * inv % p for x in a[r]]
        for i in range(len(a)):
            if i != r and a[i][c]:
                t = a[i][c]
                a[i] = [(x - t*y) % p for x, y in zip(a[i], a[r])]
        r += 1
        if r == len(a):
            break
    return r


def affine_solve(rows: list[list[int]], rhs: list[int], p: int):
    """Public Gaussian elimination; returns origin and nullspace basis or None."""
    cols = len(rows[0])
    a = [[v % p for v in row] + [b % p] for row, b in zip(rows, rhs)]
    pivots = []
    r = 0
    for c in range(cols):
        pivot = next((i for i in range(r, len(a)) if a[i][c]), None)
        if pivot is None:
            continue
        a[r], a[pivot] = a[pivot], a[r]
        inv = pow(a[r][c], -1, p)
        a[r] = [v * inv % p for v in a[r]]
        for i in range(len(a)):
            if i != r and a[i][c]:
                t = a[i][c]
                a[i] = [(x - t*y) % p for x, y in zip(a[i], a[r])]
        pivots.append(c)
        r += 1
    if any(not any(row[:cols]) and row[-1] for row in a):
        return None
    origin = [0] * cols
    for i, c in enumerate(pivots):
        origin[c] = a[i][-1]
    basis = []
    for free in (c for c in range(cols) if c not in pivots):
        v = [0] * cols
        v[free] = 1
        for i, c in enumerate(pivots):
            v[c] = -a[i][free] % p
        basis.append(v)
    return origin, basis


def compile_relation(n: int, equations: list[list[tuple[int, int, int]]], p: int):
    """Equations sum(coefficient*x_i*x_j)=0, with x_0=1 and Boolean x_i."""
    positions = [(i, j) for i in range(n+1) for j in range(i, n+1)]
    ix = {pair: i for i, pair in enumerate(positions)}
    rows, rhs = [], []

    def add(terms, target=0):
        row = [0] * len(positions)
        for coef, i, j in terms:
            row[ix[min(i, j), max(i, j)]] += coef
        rows.append([x % p for x in row])
        rhs.append(target % p)

    add([(1, 0, 0)], 1)
    for i in range(1, n+1):
        add([(1, i, i), (-1, 0, i)])
    for equation in equations:
        add(equation)
    return positions, rows, rhs, affine_solve(rows, rhs, p)


def unpack(v, positions, n):
    matrix = [[0]*(n+1) for _ in range(n+1)]
    for x, (i, j) in zip(v, positions):
        matrix[i][j] = matrix[j][i] = x
    return matrix


def source_accepts(bits, equations, p):
    x = (1,) + tuple(bits)
    return all(sum(coef*x[i]*x[j] for coef, i, j in eq) % p == 0
               for eq in equations)


def outer(v, p):
    return [[x*y % p for y in v] for x in v]


def matmul(a, b, p):
    return [[sum(x*y for x, y in zip(row, col)) % p
             for col in zip(*b)] for row in a]


def pad_rank(matrix, r):
    z = r-1
    n = len(matrix)
    out = [[0]*(n+z) for _ in range(n+z)]
    for i in range(z):
        out[i][i] = 1
    for i in range(n):
        out[i+z][z:] = matrix[i][:]
    return out


def main():
    fixtures = [
        ("one_bit", 1, []),
        ("all_three_bits", 3, []),
        ("and_true", 3, [[(1, 1, 2), (-1, 0, 3)], [(1, 0, 3), (-1, 0, 0)]]),
        ("and_false", 3, [[(1, 1, 2), (-1, 0, 3)], [(1, 0, 3)]]),
        ("xor_true", 3, [[(1, 0, 1), (1, 0, 2), (-2, 1, 2), (-1, 0, 3)],
                         [(1, 0, 3), (-1, 0, 0)]]),
        ("boolean_false_affine_nonempty", 2,
         [[(1, 0, 1)], [(1, 1, 2), (-1, 0, 0)]]),
        ("linear_contradiction", 1, [[(1, 0, 1)], [(1, 0, 1), (-1, 0, 0)]]),
    ]
    results = []
    total_matrices = 0
    total_witnesses = 0
    for p in (2, 3, 5):
        for name, n, equations in fixtures:
            positions, rows, rhs, affine = compile_relation(n, equations, p)
            expected = {bits for bits in product((0, 1), repeat=n)
                        if source_accepts(bits, equations, p)}
            total_witnesses += len(expected)
            recovered = set()
            census = Counter()
            if affine is None:
                check(not expected, "inconsistent linear system cannot have source witness")
                # A fixed no-instance in an exact rank-one signature relation.
                check(rank([[1, 0], [0, 1]], p) > 1, "canonical false instance")
                count, dimension = 0, None
            else:
                origin, basis = affine
                dimension = len(basis)
                count = p**dimension
                for coefficients in product(range(p), repeat=dimension):
                    vector = [(origin[i] + sum(c*b[i] for c, b in zip(coefficients, basis))) % p
                              for i in range(len(origin))]
                    check(all(sum(x*y for x, y in zip(row, vector)) % p == b
                              for row, b in zip(rows, rhs)), "public affine basis is correct")
                    matrix = unpack(vector, positions, n)
                    matrix_rank = rank(matrix, p)
                    census[matrix_rank] += 1
                    if matrix_rank <= 1:
                        bits = tuple(matrix[0][1:])
                        check(all(x in (0, 1) for x in bits), "rank-one source is Boolean")
                        check(source_accepts(bits, equations, p), "rank-one extracts original source")
                        check(matrix == outer((1,)+bits, p), "no alternate rank-one matrix for this witness")
                        recovered.add(bits)
                for bits in expected:
                    matrix = outer((1,)+bits, p)
                    vector = [matrix[i][j] for i, j in positions]
                    check(all(sum(x*y for x, y in zip(row, vector)) % p == b
                              for row, b in zip(rows, rhs)), "every valid witness is represented")
                    check(rank(matrix, p) == 1, "honest exact rank")
                    # Exact fixed-first-columns factorization used in the
                    # *uncompressed* syndrome-MinRank relation, not stock Mirath.
                    for r in (1, 2, 4):
                        padded = pad_rank(matrix, r)
                        s = [row[:r] for row in padded]
                        cprime = [[0]*n for _ in range(r-1)] + [list(bits)]
                        support = [[int(i == j) for j in range(r)] + cprime[i]
                                   for i in range(r)]
                        check(matmul(s, support, p) == padded, "S[I|Cprime] factorization")
                        check(rank(s, p) == r, "first r columns span padded matrix")
                        check(rank(padded, p) == r, "rank padding for honest witness")
            check(recovered == expected, "exact all-witness/source-extraction set equality")
            total_matrices += count
            results.append({"name": name, "p": p, "n": n, "affine_dimension": dimension,
                            "affine_matrices": count, "source_witnesses": len(expected),
                            "rank_census": dict(sorted(census.items()))})

    rng = random.Random(20260926)
    padding_trials = 0
    for p in (2, 3, 5, 11):
        for n in (1, 2, 3, 4):
            for _ in range(25):
                a = [[rng.randrange(p) for _ in range(n)] for _ in range(n)]
                for r in (1, 2, 4):
                    check(rank(pad_rank(a, r), p) == r-1+rank(a, p), "padding identity for arbitrary matrices")
                    padding_trials += 1

    image_maps = 0
    for domain in range(1, 6):
        for codomain in range(1, 5):
            for mapping in product(range(codomain), repeat=domain):
                fibers = Counter(mapping)
                predicted = sum((Fraction(size, domain)**2 for size in fibers.values()), Fraction())
                measured = Fraction(sum(mapping[k] == mapping[u]
                                        for k in range(domain) for u in range(domain)), domain**2)
                check(measured == predicted, "public-image challenge collision formula")
                image_maps += 1
    # These public images validate a candidate; they do not recover it.
    image_examples = {"injective_256": "255/256", "balanced_two_to_one_256": "127/128"}
    check(1-Fraction(1,256) == Fraction(255,256), "injective challenge advantage")
    check(1-Fraction(2,256) == Fraction(127,128), "two-to-one challenge advantage")

    # Tiny classical Schnorr correctness fixture: not Bitcoin or PQ cryptography.
    p, q, g = 1019, 509, 4
    check(pow(g, q, p) == 1 and g != 1, "toy subgroup")
    signature_checks = 0
    for secret in range(1, 51):
        pk = pow(g, secret, p)
        for message in (b"whole UTXO: intended outputs", b"whole UTXO: different outputs"):
            nonce = (17*secret + message[-1]) % (q-1) + 1
            commitment = pow(g, nonce, p)
            encoded = f"{commitment}:{pk}:".encode() + message
            challenge = int.from_bytes(sha256(encoded).digest(), "big") % q
            response = (nonce + challenge*secret) % q
            check(pow(g, response, p) == commitment*pow(pk, challenge, p) % p,
                  "same private key authorizes either message")
            signature_checks += 1

    summary = {"identifier": "INTERACTIVE_KEYLESS_20260926", "assertions": CHECKS,
               "compiler_fixture_count": len(results), "affine_matrices_enumerated": total_matrices,
               "valid_witness_instances": total_witnesses, "fixtures": results,
               "rank_padding_trials": padding_trials, "public_image_maps": image_maps,
               "public_image_distinguishing_advantages": image_examples,
               "toy_signature_checks": signature_checks,
               "scope": "Exact finite algebra and authorization only; no implemented witness KEM, MinRank proof system, Bitcoin integration, or QPT security theorem.",
               "checker_sha256": sha256(Path(__file__).read_bytes()).hexdigest()}
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
