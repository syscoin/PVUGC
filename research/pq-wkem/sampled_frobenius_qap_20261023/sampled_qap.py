"""Random off-domain compression of the Frobenius quotient-QAP SOURCE.

Provides full source construction, deterministic reproduction of honest sampling,
and an exact bound on the sampled compiler's projective soundness error.

SECURITY SCOPE: compiler soundness/correctness only, not full-ciphertext WKEM hiding.
"""
from __future__ import annotations
# Exact predecessor dependency; refuse silently substituted algebra.
from pathlib import Path
import hashlib, sys
PREVIOUS = Path(__file__).resolve().parents[1] / 'qap_frobenius_projective_20261022' / 'frobenius_qap.py'
EXPECTED_PREVIOUS_SHA256 = '6da9e9519c1f9b21d00b736679ba498cb56a7518e9610abc7934ec3aacf66d9a'
if not PREVIOUS.exists() or hashlib.sha256(PREVIOUS.read_bytes()).hexdigest() != EXPECTED_PREVIOUS_SHA256:
    raise RuntimeError('missing or modified exact prior Frobenius-QAP dependency')
sys.path.insert(0, str(PREVIOUS.parent))
import random
import numpy as np

from frobenius_qap import (
    Compiled, Field, pmul, padd, pscale, peval, pdiv, compile_qap,
)


def lagrange(f: Field, nodes):
    basis = []
    for i, point in enumerate(nodes):
        numerator, denominator = [1], 1
        for j, other in enumerate(nodes):
            if i != j:
                numerator = pmul(f, numerator, [int(other), 1])
                denominator = f.mul(denominator, int(point) ^ int(other))
        basis.append(pscale(f, numerator, f.inverse(denominator)))
    return basis


def compile_sampled(f: Field, A, B, C, r: int, rng: random.Random):
    """Use m-1 deterministic and r independently sampled off-domain nodes.

    All m-1 base nodes are fixed and publicly regenerable; only r tail nodes
    require setup randomness. This leaves the adversary no hidden node secret.

    The SOURCE contains k=n+m homogeneous coordinates, and every accepted witness
    has the unique square-root quotient. For false instances this compiler is
    projectively sound except for the explicitly bounded probability over nodes.
    """
    A, B, C = (np.asarray(M, dtype=np.uint16) for M in (A, B, C))
    if A.ndim != 2 or A.shape != B.shape or A.shape != C.shape:
        raise ValueError('incompatible R1CS')
    m, base = A.shape
    if not 1 <= r <= m or m < 2 or m + (m - 1 + r) > f.q:
        raise ValueError('insufficient field or invalid extra evaluation count')
    if max(int(A.max()), int(B.max()), int(C.max())) >= f.q:
        raise ValueError('SOURCE field mismatch')
    for j in range(1, base):
        target = np.zeros(base, dtype=np.uint16)
        target[j] = 1
        if not any(np.array_equal(a, target) and np.array_equal(b, target)
                   and np.array_equal(c, target) for a, b, c in zip(A, B, C)):
            raise ValueError('missing explicit Booleanity row')
    gate_nodes = tuple(range(m))
    L = m - 1 + r
    base_nodes = tuple(range(m, 2*m-1))
    # Independent uniform draws with rejection, rather than enumerating GF(q).
    # random.Random is ONLY the reproducible fixture RNG; real setup needs CSPRNG.
    sampled_nodes = []
    seen = set(range(2*m-1))
    while len(sampled_nodes) < r:
        e = rng.getrandbits(f.degree)
        if e in seen:
            continue
        seen.add(e)
        sampled_nodes.append(e)
    eval_nodes = base_nodes + tuple(sampled_nodes)
    bases = lagrange(f, gate_nodes)
    Z = [1]
    for t in gate_nodes:
        Z = pmul(f, Z, [t, 1])
    polys = []
    for mat in (A, B, C):
        columns = []
        for j in range(base):
            p = [0]
            for i in range(m):
                p = padd(p, pscale(f, bases[i], int(mat[i, j])))
            columns.append(p)
        polys.append(columns)
    forms = np.zeros((L, base + m - 1, 5), dtype=np.uint16)
    for i, e in enumerate(eval_nodes):
        for j in range(base):
            for s in range(3):
                forms[i, j, s] = peval(f, polys[s][j], e)
        forms[i, 0, 3] = 1
        for j in range(m - 1):
            forms[i, base + j, 4] = f.roots[f.mul(peval(f, Z, e), f.power(e, j))]
    return Compiled(f, (A, B, C), tuple(polys), Z, gate_nodes, eval_nodes, forms, base, m)


def uniquely_interpolate_quotient(comp: Compiled, z):
    """Reconstruct the only possible H for fixed nonzero homogeneous original z.

    Uses ONLY first m-1 publicly sampled constraints. Valid on any z, even an
    invalid original source. This defines the object for the union-bound proof.
    """
    f = comp.field
    z = list(map(int, z))
    if len(z) != comp.base:
        raise ValueError('incorrect SOURCE length')
    value_polys = []
    for columns in comp.polys:
        p = [0]
        for col, s in zip(columns, z):
            p = padd(p, pscale(f, col, s))
        value_polys.append(p)
    numerator = padd(pmul(f, value_polys[0], value_polys[1]),
                     pscale(f, value_polys[2], z[0]))
    points = comp.eval_nodes[:comp.rows - 1]
    bases = lagrange(f, points)
    quotient = [0]
    for e, basis in zip(points, bases):
        value = f.mul(peval(f, numerator, e), f.inverse(peval(f, comp.vanishing, e)))
        quotient = padd(quotient, pscale(f, basis, value))
    quotient = quotient + [0] * (comp.rows - 1 - len(quotient))
    return list(z) + [f.roots[v] for v in quotient]


def integer_union_bound_exponent(n: int, m: int, r: int, kappa: int):
    """Conservative proved log2 upper bound, elementary integer-only powers.

    If q=2^kappa, q-2m+2-r >= 2^(kappa-1), then:
      epsilon < 2^(kappa*n+1 + r*(ceil(log2(m-1))-(kappa-1))).
    We use bit_length(D-1) for ceil(log2(D)) exactly, treating D>0.
    """
    q, D = 1 << kappa, m-1
    if n < 0 or m < 2 or r < 1 or q-2*m+2-r < q//2:
        raise ValueError('conservative bound prerequisites not satisfied')
    return kappa*n + 1 + r*((D-1).bit_length()-(kappa-1))


def exact_union_bound(n: int, m: int, r: int, q: int):
    """Exact rational upper bound on an honestly sampled compiler's failure.

    Uses the largest denominator-losing step for every extra node; it is a
    rational bound, not an estimate from tests and not a ciphertext-security bound.
    """
    from fractions import Fraction
    if m < 2 or not 1 <= r <= m or q < 2*m-1+r:
        raise ValueError('invalid sampling parameters')
    # Every invalid-source F_z has the m-1 fixed off-domain roots already.
    # Deg(F_z)<=2m-2, leaving at most m-1 OTHER roots.
    D = m-1
    lines = (pow(q,n+1)-1)//(q-1)
    bad = Fraction(lines,1)
    for j in range(1,r+1):
        bad *= Fraction(D, q-2*m+2-j)
    return min(Fraction(1),bad)


def residual_interpolant(comp: Compiled, z):
    """Direct m-row residual polynomial, for the exact source-soundness identity.

    For fixed base nodes E0(T)=prod(T-e) and unique H_z:
       A_z B_z + z0 C_z + Z H_z = E0 * P_z,
       P_z(t_i) = ORIGINAL_RESIDUAL_i(z) / E0(t_i).
    P_z has degree <=m-1. The r random tail tests are exactly P_z(e)=0.
    """
    f=comp.field
    z=list(map(int,z))
    if len(z)!=comp.base:
        raise ValueError('incorrect SOURCE length')
    base_nodes=comp.eval_nodes[:comp.rows-1]
    E=[1]
    for node in base_nodes:
        E=pmul(f,E,[int(node),1])
    m=comp.rows
    rows=[]
    A,B,C=comp.source
    for i,t in enumerate(comp.gate_nodes):
        resid=f.mul(f.dot(A[i],z),f.dot(B[i],z)) ^ f.mul(z[0],f.dot(C[i],z))
        rows.append(f.mul(resid,f.inverse(peval(f,E,t))))
    b=lagrange(f,comp.gate_nodes)
    P=[0]
    for value,p in zip(rows,b):
        P=padd(P,pscale(f,p,value))
    return P


def certified_extra_checks(comp: Compiled,z):
    """Equivalent tail verification after interpolation; no hidden witnesses."""
    f=comp.field
    y=uniquely_interpolate_quotient(comp,z)
    P=residual_interpolant(comp,z)
    return all(peval(f,P,e)==0 for e in comp.eval_nodes[comp.rows-1:]) == (not any(comp.residuals(y)))
