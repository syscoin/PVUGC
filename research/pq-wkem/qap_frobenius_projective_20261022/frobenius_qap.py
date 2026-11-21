"""Research-only Frobenius quotient QAP and four-by-four rank gadget.

Exact finite-field arithmetic. This is NOT a secure KEM implementation.
The field table backend deliberately limits demonstration fields to 256 elements.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import random
import numpy as np


def _rem(a: int, b: int) -> int:
    while a and a.bit_length() >= b.bit_length():
        a ^= b << (a.bit_length() - b.bit_length())
    return a


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, _rem(a, b)
    return a


def _rawmul(a: int, b: int, mod: int, degree: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a >> degree:
            a ^= mod
    return r


class Field:
    """GF(2^degree), polynomial basis; reject reducible moduli."""
    def __init__(self, degree: int, modulus: int):
        if not 1 < degree <= 8 or modulus.bit_length() != degree + 1:
            raise ValueError("demonstration backend requires degree 2..8")
        x = 2
        p = x
        for i in range(1, degree + 1):
            p = _rawmul(p, p, modulus, degree)
            if i <= degree // 2 and _gcd(p ^ x, modulus) != 1:
                raise ValueError("reducible field modulus")
        if p != x:
            raise ValueError("reducible field modulus")
        self.degree, self.modulus, self.q = degree, modulus, 1 << degree
        self.table = np.array([
            [_rawmul(a, b, modulus, degree) for b in range(self.q)]
            for a in range(self.q)], dtype=np.uint16)
        self.inverses = [0] + [self.power(a, self.q - 2) for a in range(1, self.q)]
        self.roots = [self.power(a, self.q // 2) for a in range(self.q)]

    def mul(self, a: int, b: int) -> int:
        return int(self.table[int(a), int(b)])

    def power(self, a: int, n: int) -> int:
        r = 1
        while n:
            if n & 1:
                r = self.mul(r, a)
            a = self.mul(a, a)
            n >>= 1
        return r

    def inverse(self, a: int) -> int:
        if not a:
            raise ZeroDivisionError("zero has no inverse")
        return self.inverses[int(a)]

    def dot(self, a, b) -> int:
        v = self.table[np.asarray(a, dtype=np.uint16), np.asarray(b, dtype=np.uint16)]
        return int(np.bitwise_xor.reduce(v, initial=np.uint16(0)))

    def mm(self, a, b):
        a = np.asarray(a, dtype=np.uint16)
        b = np.asarray(b, dtype=np.uint16)
        if a.ndim != 2 or b.ndim != 2 or a.shape[1] != b.shape[0]:
            raise ValueError("incompatible matrices")
        out = np.zeros((a.shape[0], b.shape[1]), dtype=np.uint16)
        for k in range(a.shape[1]):
            out ^= self.table[a[:, k, None], b[None, k, :]]
        return out

    def reduce(self, mat):
        a = np.asarray(mat, dtype=np.uint16).copy()
        row = 0
        pivots = []
        determinant = 1
        for c in range(a.shape[1]):
            found = np.flatnonzero(a[row:, c])
            if not len(found):
                continue
            i = row + int(found[0])
            a[[row, i]] = a[[i, row]]
            pivot = int(a[row, c])
            determinant = self.mul(determinant, pivot)
            a[row] = self.table[self.inverse(pivot), a[row]]
            factors = a[:, c].copy()
            factors[row] = 0
            a ^= self.table[factors[:, None], a[row][None, :]]
            pivots.append(c)
            row += 1
            if row == a.shape[0]:
                break
        return a, pivots, determinant

    def rank(self, mat) -> int:
        return len(self.reduce(mat)[1])

    def determinant(self, mat) -> int:
        a = np.asarray(mat)
        if a.ndim != 2 or a.shape[0] != a.shape[1]:
            raise ValueError("determinant requires a square matrix")
        _, piv, d = self.reduce(a)
        return d if len(piv) == len(a) else 0

    def invmat(self, mat):
        a = np.asarray(mat, dtype=np.uint16)
        n = len(a)
        out, piv, _ = self.reduce(np.concatenate((a, np.eye(n, dtype=np.uint16)), axis=1))
        if piv[:n] != list(range(n)):
            raise ValueError("singular public pivot")
        return out[:, n:]


def trim(p):
    p = [int(x) for x in p]
    while len(p) > 1 and not p[-1]:
        p.pop()
    return p or [0]


def padd(a, b):
    c = [0] * max(len(a), len(b))
    for i, x in enumerate(a):
        c[i] ^= int(x)
    for i, x in enumerate(b):
        c[i] ^= int(x)
    return trim(c)


def pscale(f: Field, a, b):
    return trim([f.mul(x, b) for x in a])


def pmul(f: Field, a, b):
    c = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            c[i + j] ^= f.mul(x, y)
    return trim(c)


def pdiv(f: Field, a, b):
    a, b = trim(a), trim(b)
    if b == [0]:
        raise ZeroDivisionError("zero polynomial divisor")
    quotient = [0] * max(1, len(a) - len(b) + 1)
    while a != [0] and len(a) >= len(b):
        shift = len(a) - len(b)
        scale = f.mul(a[-1], f.inverse(b[-1]))
        quotient[shift] = scale
        a = padd(a, [0] * shift + pscale(f, b, scale))
    return trim(quotient), a


def peval(f: Field, p, x):
    a = 0
    for b in reversed(p):
        a = f.mul(a, x) ^ int(b)
    return a


def pgcd(f: Field, a, b):
    a, b = trim(a), trim(b)
    while b != [0]:
        a, b = b, pdiv(f, a, b)[1]
    return pscale(f, a, f.inverse(a[-1]))


@dataclass
class Compiled:
    field: Field
    source: tuple
    polys: tuple
    vanishing: list
    gate_nodes: tuple
    eval_nodes: tuple
    forms: np.ndarray
    base: int
    rows: int

    def evaluate_forms(self, y):
        y = list(y)
        if len(y) != self.forms.shape[1]:
            raise ValueError("incorrect SOURCE length")
        return [tuple(self.field.dot(y, forms[:, s]) for s in range(5)) for forms in self.forms]

    def residuals(self, y):
        f = self.field
        return [f.mul(a, b) ^ f.mul(c, d) ^ f.mul(s, s)
                for a, b, c, d, s in self.evaluate_forms(y)]

    def encode(self, original):
        z = [1] + list(original)
        if len(z) != self.base:
            raise ValueError("incorrect ORIGINAL assignment length")
        f = self.field
        values = []
        for columns in self.polys:
            p = [0]
            for col, value in zip(columns, z):
                p = padd(p, pscale(f, col, value))
            values.append(p)
        quotient, remainder = pdiv(f, padd(pmul(f, values[0], values[1]), values[2]), self.vanishing)
        if remainder != [0]:
            raise ValueError("not an accepted ORIGINAL assignment")
        quotient += [0] * (self.rows - 1 - len(quotient))
        return z + [f.roots[h] for h in quotient]

    def extract(self, y):
        if not any(y) or any(self.residuals(y)) or not y[0]:
            raise ValueError("not an accepted nonzero homogeneous SOURCE")
        normalized = [self.field.mul(x, self.field.inverse(y[0])) for x in y]
        original = normalized[1:self.base]
        if self.encode(original) != normalized:
            raise AssertionError("unique Frobenius lift failed")
        return original


def compile_qap(f: Field, A, B, C) -> Compiled:
    A, B, C = (np.asarray(x, dtype=np.uint16) for x in (A, B, C))
    if A.ndim != 2 or A.shape != B.shape or A.shape != C.shape:
        raise ValueError("SOURCE matrices must have equal two-dimensional shapes")
    m, base = A.shape
    L = 2 * m - 1
    if m < 2 or m + L > f.q:
        raise ValueError("need m>=2 and enough distinct field nodes")
    if max(int(A.max()), int(B.max()), int(C.max())) >= f.q:
        raise ValueError("SOURCE coefficient outside field")
    # Explicit sufficient projective-safety prerequisite, not a silent assumption.
    for j in range(1, base):
        e = np.zeros(base, dtype=np.uint16)
        e[j] = 1
        if not any(np.array_equal(a, e) and np.array_equal(b, e) and np.array_equal(c, e)
                   for a, b, c in zip(A, B, C)):
            raise ValueError("every free wire requires an explicit Booleanity row")
    gate_nodes = tuple(range(m))
    eval_nodes = tuple(range(m, m + L))
    lagrange = []
    Z = [1]
    for node in gate_nodes:
        Z = pmul(f, Z, [node, 1])
    for i, node in enumerate(gate_nodes):
        poly, den = [1], 1
        for j, other in enumerate(gate_nodes):
            if i != j:
                poly = pmul(f, poly, [other, 1])
                den = f.mul(den, node ^ other)
        lagrange.append(pscale(f, poly, f.inverse(den)))
    polys = []
    for mat in (A, B, C):
        columns = []
        for j in range(base):
            col = [0]
            for i in range(m):
                col = padd(col, pscale(f, lagrange[i], int(mat[i, j])))
            columns.append(col)
        polys.append(columns)
    forms = np.zeros((L, base + m - 1, 5), dtype=np.uint16)
    for i, e in enumerate(eval_nodes):
        for j in range(base):
            for slot in range(3):
                forms[i, j, slot] = peval(f, polys[slot][j], e)
        forms[i, 0, 3] = 1
        for j in range(m - 1):
            forms[i, base + j, 4] = f.roots[f.mul(peval(f, Z, e), f.power(e, j))]
    return Compiled(f, (A, B, C), tuple(polys), Z, gate_nodes, eval_nodes, forms, base, m)


def gate(a: int, b: int, c: int, d: int, s: int):
    return np.array([[0, a, d, s], [a, 0, s, c], [d, s, 0, b], [s, c, b, 0]], dtype=np.uint16)


def random_matrix(f: Field, rng: random.Random, rows: int, cols: int):
    return np.array([[rng.randrange(f.q) for _ in range(cols)] for _ in range(rows)], dtype=np.uint16)


def setup(comp: Compiled, key: int, seed: int):
    """Deterministic research setup; outer factors are independent, NOT transposes."""
    f = comp.field
    L, k, _ = comp.forms.shape
    N = 2 * L + 1
    rng = random.Random(seed)
    public = np.zeros((k, N, N), dtype=np.uint16)
    factors = []
    for forms in comp.forms:
        left, right = random_matrix(f, rng, N, 4), random_matrix(f, rng, 4, N)
        factors.append((left, right))
        for j, values in enumerate(forms):
            public[j] ^= f.mm(f.mm(left, gate(*map(int, values))), right)
    public[0] ^= f.table[key, np.eye(N, dtype=np.uint16)]
    return public, factors


def evaluate(f: Field, public, y):
    out = np.zeros_like(public[0])
    for a, v in zip(public, y):
        out ^= f.table[int(v), a]
    return out


def berlekamp_massey(f: Field, seq):
    C, B, length, shift, previous = [1], [1], 0, 1, 1
    for i, value in enumerate(seq):
        discrepancy = int(value)
        for j in range(1, length + 1):
            if j < len(C):
                discrepancy ^= f.mul(C[j], seq[i - j])
        if not discrepancy:
            shift += 1
            continue
        old = C[:]
        scale = f.mul(discrepancy, f.inverse(previous))
        if len(C) < len(B) + shift:
            C += [0] * (len(B) + shift - len(C))
        for j, v in enumerate(B):
            C[j + shift] ^= f.mul(scale, v)
        if 2 * length <= i:
            length = i + 1 - length
            B, previous, shift = old, discrepancy, 1
        else:
            shift += 1
    C += [0] * (length + 1 - len(C))
    return trim(C[:length + 1][::-1])


def field_roots(f: Field, poly, rng: random.Random):
    """Frobenius gcd + randomized trace splitting; no enumeration of field keys."""
    poly = trim(poly)
    if len(poly) <= 1:
        return []
    poly = pscale(f, poly, f.inverse(poly[-1]))
    xq = pdiv(f, [0, 1], poly)[1]
    for _ in range(f.degree):
        xq = pdiv(f, pmul(f, xq, xq), poly)[1]
    split = pgcd(f, poly, padd(xq, [0, 1]))

    def recurse(g):
        if len(g) == 1:
            return []
        if len(g) == 2:
            return [f.mul(g[0], f.inverse(g[1]))]
        for _ in range(512):
            z, trace = [0, rng.randrange(f.q)], [0]
            for _ in range(f.degree):
                trace = padd(trace, z)
                z = pdiv(f, pmul(f, z, z), g)[1]
            a = pgcd(f, g, trace)
            if 1 < len(a) < len(g):
                b, rem = pdiv(f, g, a)
                if rem != [0]:
                    raise AssertionError("nondividing gcd")
                return recurse(a) + recurse(b)
        raise RuntimeError("bounded trace splitter did not finish")
    return sorted(recurse(split))


def candidates(f: Field, matrix, seed: int, attempts: int = 4):
    rng = random.Random(seed)
    n = len(matrix)
    found = set()
    for _ in range(attempts):
        u = [rng.randrange(f.q) for _ in range(n)]
        v = np.array([[rng.randrange(f.q)] for _ in range(n)], dtype=np.uint16)
        seq = []
        for j in range(2 * n):
            seq.append(f.dot(u, v[:, 0]))
            if j != 2 * n - 1:
                v = f.mm(matrix, v)
        found.update(field_roots(f, berlekamp_massey(f, seq), rng))
    return sorted(found)


def tag(context: bytes, key: int) -> str:
    return hashlib.sha3_256(context + b'\x00' + int(key).to_bytes(2, 'big')).hexdigest()


def pencil_diagnostic(f: Field, public, key: int, indices):
    """Internal regression for two old attack templates, not a security proof."""
    def comm(a, b):
        return f.mm(a, b) ^ f.mm(b, a)
    a, c, d = indices
    n = len(public[0])
    try:
        Q = f.invmat(public[a])
    except ValueError:
        return dict(indices=list(indices), pivot_invertible=False)
    A, B, T = f.mm(Q, public[c]), f.mm(Q, public[d]), f.mm(Q, public[0])
    H = comm(A, B)
    H = f.mm(H, H)
    results = {}
    for label, F0, F1 in (
        ('commutator', comm(T, A), comm(Q, A)),
        ('squared_commutator', comm(H, T), comm(H, Q))):
        results[label] = dict(denominator_rank=f.rank(F1),
                              key_pencil_rank=f.rank(F0 ^ f.table[key, F1]), N=n)
    return dict(indices=list(indices), pivot_invertible=True, results=results)
