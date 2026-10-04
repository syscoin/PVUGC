#!/usr/bin/env python3
"""Run-25 checker for the nonlinear masked-carrier coefficient candidate.

Standard library only.  This validates finite algebra identities/theorems; it is
not cryptographic security evidence.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

SEED = 0x51574B454D25


def subsets_upto(n: int, d: int) -> List[int]:
    out: List[int] = []
    for k in range(d + 1):
        for comb in itertools.combinations(range(n), k):
            mask = 0
            for i in comb:
                mask |= 1 << i
            out.append(mask)
    return out


@dataclass
class BoolPolySpace:
    n: int
    degree: int
    q: int

    def __post_init__(self) -> None:
        self.basis = subsets_upto(self.n, self.degree)
        self.index = {m: i for i, m in enumerate(self.basis)}

    @property
    def dim(self) -> int:
        return len(self.basis)

    def zero(self) -> List[int]:
        return [0] * self.dim

    def mono(self, mask: int, c: int = 1) -> List[int]:
        v = self.zero()
        if mask in self.index:
            v[self.index[mask]] = c % self.q
        return v

    def add(self, a: Sequence[int], b: Sequence[int]) -> List[int]:
        return [(x + y) % self.q for x, y in zip(a, b)]

    def sub(self, a: Sequence[int], b: Sequence[int]) -> List[int]:
        return [(x - y) % self.q for x, y in zip(a, b)]

    def scale(self, c: int, a: Sequence[int]) -> List[int]:
        return [(c * x) % self.q for x in a]

    def mul(self, a: Sequence[int], b: Sequence[int]) -> List[int]:
        """Boolean multilinear product, truncated only above self.degree."""
        out = self.zero()
        for i, ai in enumerate(a):
            if not ai:
                continue
            mi = self.basis[i]
            for j, bj in enumerate(b):
                if not bj:
                    continue
                m = mi | self.basis[j]  # x_i^2 = x_i on Boolean domain
                k = self.index.get(m)
                if k is not None:
                    out[k] = (out[k] + ai * bj) % self.q
        return out

    def power(self, a: Sequence[int], d: int) -> List[int]:
        out = self.mono(0)
        for _ in range(d):
            out = self.mul(out, a)
        return out

    def dot(self, functional: Sequence[int], poly: Sequence[int]) -> int:
        return sum(x * y for x, y in zip(functional, poly)) % self.q

    def evaluate(self, poly: Sequence[int], bits: Sequence[int]) -> int:
        total = 0
        for coeff, mask in zip(poly, self.basis):
            if not coeff:
                continue
            val = 1
            for i in range(self.n):
                if (mask >> i) & 1:
                    val *= bits[i]
            total = (total + coeff * val) % self.q
        return total


def falling(a: int, t: int, q: int) -> int:
    z = 1
    for j in range(t):
        z = (z * (a - j)) % q
    return z


def formal_hamming_lambda(space: BoolPolySpace, r: int) -> List[int]:
    """lambda(x_T)=(r)_|T|/(n)_|T|, the formal weight-r moment functional."""
    vals: List[int] = []
    for mask in space.basis:
        t = mask.bit_count()
        den = falling(space.n, t, space.q)
        if den == 0:
            raise ValueError("denominator vanished; choose q > n")
        vals.append(falling(r, t, space.q) * pow(den, -1, space.q) % space.q)
    return vals


def hamming_constraint(space: BoolPolySpace, r: int) -> List[int]:
    g = space.scale(-r, space.mono(0))
    for i in range(space.n):
        g = space.add(g, space.mono(1 << i))
    return g


def mask_generators(space: BoolPolySpace, r: int, multiplier_degree: int) -> List[List[int]]:
    g = hamming_constraint(space, r)
    return [space.mul(space.mono(mask), g) for mask in subsets_upto(space.n, multiplier_degree)]


def random_lincomb(gens: Sequence[Sequence[int]], q: int, rng: random.Random) -> List[int]:
    if not gens:
        raise ValueError("empty generator set")
    out = [0] * len(gens[0])
    for g in gens:
        c = rng.randrange(q)
        if c:
            out = [(x + c * y) % q for x, y in zip(out, g)]
    return out


def random_poly(space: BoolPolySpace, max_degree: int, rng: random.Random) -> List[int]:
    out = space.zero()
    for mask in subsets_upto(space.n, max_degree):
        out[space.index[mask]] = rng.randrange(space.q)
    return out


def rref(rows: Sequence[Sequence[int]], q: int) -> Tuple[List[List[int]], List[int]]:
    A = [list(r) for r in rows]
    if not A:
        return [], []
    m, n = len(A), len(A[0])
    pivots: List[int] = []
    rr = 0
    for c in range(n):
        pivot = next((i for i in range(rr, m) if A[i][c] % q), None)
        if pivot is None:
            continue
        A[rr], A[pivot] = A[pivot], A[rr]
        inv = pow(A[rr][c] % q, -1, q)
        A[rr] = [(x * inv) % q for x in A[rr]]
        for i in range(m):
            if i != rr and A[i][c] % q:
                f = A[i][c] % q
                A[i] = [(A[i][j] - f * A[rr][j]) % q for j in range(n)]
        pivots.append(c)
        rr += 1
        if rr == m:
            break
    return A, pivots


def row_basis(rows: Sequence[Sequence[int]], q: int) -> List[List[int]]:
    A, pivots = rref(rows, q)
    return A[: len(pivots)]


def nullspace(rows: Sequence[Sequence[int]], q: int, width: int) -> List[List[int]]:
    if not rows:
        return [[1 if i == j else 0 for i in range(width)] for j in range(width)]
    A, pivots = rref(rows, q)
    free = [j for j in range(width) if j not in pivots]
    out: List[List[int]] = []
    for f in free:
        x = [0] * width
        x[f] = 1
        for i, p in enumerate(pivots):
            x[p] = (-A[i][f]) % q
        out.append(x)
    return out


def public_decoder(noise_span: Sequence[Sequence[int]], one: Sequence[int], q: int) -> List[int] | None:
    basis = row_basis(noise_span, q)
    for l in nullspace(basis, q, len(one)):
        d = sum(x * y for x, y in zip(l, one)) % q
        if d:
            inv = pow(d, -1, q)
            return [(inv * x) % q for x in l]
    return None


def no_boolean_solution_hamming(n: int, r: int) -> bool:
    return all(sum(bits) != r for bits in itertools.product((0, 1), repeat=n))


def run() -> dict:
    rng = random.Random(SEED)
    result: dict = {
        "classification": "finite algebra validation only; not a cryptographic proof by testing",
        "seed": SEED,
    }

    # 1. Honest same-key completeness on a true relation sum x_i = 2.
    q, n, L, r = 101, 4, 4, 2
    S = BoolPolySpace(n, L, q)
    M0 = mask_generators(S, r, 1)
    M1 = mask_generators(S, r, 3)
    witnesses = [bits for bits in itertools.product((0, 1), repeat=n) if sum(bits) == r]
    completeness_setups = 200
    decodes = 0
    for _ in range(completeness_setups):
        h = random_poly(S, 2, rng)
        m0 = random_lincomb(M0, q, rng)
        m1 = random_lincomb(M1, q, rng)
        k = rng.randrange(q)
        U = S.add(h, m0)
        B = S.add(S.scale(k, S.mono(0)), S.add(S.scale(-1, S.mul(h, h)), m1))
        for w in witnesses:
            got = (S.evaluate(B, w) + S.evaluate(U, w) ** 2) % q
            assert got == k
            decodes += 1
    result["true_same_key"] = {
        "field": q,
        "n": n,
        "witness_count": len(witnesses),
        "setups": completeness_setups,
        "successful_decodes": decodes,
    }

    # 2. False Hamming/knapsack instance: formal pseudo-functional exactly recovers k.
    q, n, L, r = 101, 8, 4, 9
    assert no_boolean_solution_hamming(n, r)
    S = BoolPolySpace(n, L, q)
    lam = formal_hamming_lambda(S, r)
    assert S.dot(lam, S.mono(0)) == 1
    M0 = mask_generators(S, r, 1)  # masks of degree <=2
    M1 = mask_generators(S, r, 3)  # masks of degree <=4
    assert all(S.dot(lam, g) == 0 for g in M1)

    trials = 500
    recovered = 0
    for _ in range(trials):
        h = random_poly(S, 2, rng)
        m0 = random_lincomb(M0, q, rng)
        m1 = random_lincomb(M1, q, rng)
        k = rng.randrange(q)
        U = S.add(h, m0)
        B = S.add(S.scale(k, S.mono(0)), S.add(S.scale(-1, S.mul(h, h)), m1))
        D = S.add(B, S.mul(U, U))
        assert S.dot(lam, D) == k
        recovered += 1
    result["false_quadratic_formal_decoder"] = {
        "field": q,
        "n": n,
        "published_degree": L,
        "feature_dimension": S.dim,
        "mask0_generators": len(M0),
        "mask1_generators": len(M1),
        "trials": trials,
        "exact_key_recoveries": recovered,
        "boolean_witnesses": 0,
    }

    # 3. Same attack found by public Gaussian elimination from the complete output closure.
    gauss_trials = 80
    gauss_ok = 0
    noise_ranks: List[int] = []
    for _ in range(gauss_trials):
        h = random_poly(S, 2, rng)
        m0 = random_lincomb(M0, q, rng)
        m1 = random_lincomb(M1, q, rng)
        k = rng.randrange(q)
        U = S.add(h, m0)
        B = S.add(S.scale(k, S.mono(0)), S.add(S.scale(-1, S.mul(h, h)), m1))
        noise = list(M1)
        noise.extend(S.mul(U, m) for m in M0)
        noise.extend(S.mul(a, b) for a in M0 for b in M0)
        rb = row_basis(noise, q)
        noise_ranks.append(len(rb))
        lstar = public_decoder(rb, S.mono(0), q)
        assert lstar is not None
        D = S.add(B, S.mul(U, U))
        assert S.dot(lstar, D) == k
        gauss_ok += 1
    result["public_gaussian_closure_decoder"] = {
        "trials": gauss_trials,
        "exact_key_recoveries": gauss_ok,
        "noise_rank_min": min(noise_ranks),
        "noise_rank_max": max(noise_ranks),
        "ambient_dimension": S.dim,
    }

    # 4. General pointwise powers: B=k-h^d+m1, D=B+U^d.
    power_configs = [
        # (n, L, h/m0 degree, power, trials)
        (8, 4, 2, 2, 150),
        (9, 6, 2, 3, 150),
        (8, 6, 1, 5, 150),
    ]
    power_rows = []
    for n, L, e, d, count in power_configs:
        q, r = 101, n + 1
        Sx = BoolPolySpace(n, L, q)
        lamx = formal_hamming_lambda(Sx, r)
        M0x = mask_generators(Sx, r, max(0, e - 1))
        M1x = mask_generators(Sx, r, L - 1)
        ok = 0
        for _ in range(count):
            h = random_poly(Sx, e, rng)
            m0 = random_lincomb(M0x, q, rng)
            m1 = random_lincomb(M1x, q, rng)
            k = rng.randrange(q)
            U = Sx.add(h, m0)
            B = Sx.add(Sx.scale(k, Sx.mono(0)), Sx.add(Sx.scale(-1, Sx.power(h, d)), m1))
            D = Sx.add(B, Sx.power(U, d))
            assert Sx.dot(lamx, D) == k
            ok += 1
        power_rows.append({
            "n": n,
            "degree_bound": L,
            "power": d,
            "feature_dimension": Sx.dim,
            "trials": count,
            "exact_key_recoveries": ok,
        })
    result["higher_degree_pointwise_controls"] = power_rows

    # 5. Exhaustive tiny false distribution: supports for two keys are disjoint.
    q, n, L, r = 5, 3, 2, 4
    assert no_boolean_solution_hamming(n, r)
    St = BoolPolySpace(n, L, q)
    gt = hamming_constraint(St, r)
    M0t = [gt]
    M1t = mask_generators(St, r, 1)
    lamt = formal_hamming_lambda(St, r)
    supports = {0: set(), 1: set()}
    randomness_points = 0
    for vals in itertools.product(range(q), repeat=2 + len(M1t)):
        h0, a, *bs = vals
        randomness_points += 1
        h = St.scale(h0, St.mono(0))
        m0 = St.scale(a, gt)
        m1 = St.zero()
        for c, mg in zip(bs, M1t):
            m1 = St.add(m1, St.scale(c, mg))
        U = St.add(h, m0)
        for k in (0, 1):
            B = St.add(St.scale(k, St.mono(0)), St.add(St.scale(-1, St.mul(h, h)), m1))
            assert St.dot(lamt, St.add(B, St.mul(U, U))) == k
            supports[k].add(tuple(U + B))
    overlap = len(supports[0].intersection(supports[1]))
    assert overlap == 0
    result["exhaustive_tiny_false_distribution"] = {
        "field": q,
        "n": n,
        "degree_bound": L,
        "randomness_points_per_key": randomness_points,
        "support_key0": len(supports[0]),
        "support_key1": len(supports[1]),
        "support_overlap": overlap,
        "pairwise_statistical_distance": 1.0,
    }

    # 6. Recurrence itself over several parameter sets.
    rec = []
    for q, n, L in [(101, 8, 4), (103, 10, 5), (107, 12, 6)]:
        r = n + 1
        Sr = BoolPolySpace(n, L, q)
        lamr = formal_hamming_lambda(Sr, r)
        gens = mask_generators(Sr, r, L - 1)
        zeros = sum(1 for g in gens if Sr.dot(lamr, g) == 0)
        assert zeros == len(gens)
        rec.append({"field": q, "n": n, "degree_bound": L, "tested_multiples": len(gens), "annihilated": zeros})
    result["formal_moment_recurrence"] = rec

    return result


def main() -> None:
    result = run()
    out = Path(__file__).with_name("quadratic-mask-closure-run25.json")
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
