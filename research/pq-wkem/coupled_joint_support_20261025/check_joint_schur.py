#!/usr/bin/env python3
"""Finite-field proof checks for the current research carrier.

This is a supplied-secret algebra checker, not a key-recovery implementation.
It never factors a polynomial, searches keys, signs, or accesses a network.
The parent arithmetic and public-coordinate normalization are pinned verbatim.
"""
from __future__ import annotations
import hashlib
import itertools
import json
import random
from pathlib import Path
import quotient_recurrence_check as p
import canonical_release_check as canon

CHECKS = 0

def check(condition, description):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError(description)


def dot(a, b):
    result = 0
    for x, y in zip(a, b):
        result ^= p.E[x][y]
    return result


def outer(a, b):
    return [[p.E[x][y] for y in b] for x in a]


def split_gate(g):
    """Private-data verification of the exact Schur identity at pi != 0."""
    c, a, s = g[0]
    b, pi, zero = g[1]
    check(zero == 0 and g[2] == [s, 0, pi], 'exact published gate shape')
    check(pi != 0, 'invertible middle pivot')
    ai, bi = p.E[a][p.INV[pi]], p.E[b][p.INV[pi]]
    one = p.mscale(pi, outer([ai, 1, 0], [bi, 1, 0]))
    supported = p.madd(g, one)
    check(supported[1] == [0, 0, 0], 'middle row eliminated')
    check(all(row[1] == 0 for row in supported), 'middle column eliminated')
    check(p.rank(one) == 1, 'Schur contribution rank one')
    check(p.madd(supported, one) == g, 'Schur identity exact')
    check(supported[0][0] == c ^ p.E[a][bi], 'Schur residual formula')
    return supported, one


def source(kind):
    if kind == 'false':
        # Complete Boolean source: x^2=x, x=0, x=1, followed by two tautologies.
        return ([[0,1],[0,1],[0,1],[1,0],[0,0]],
                [[0,1],[1,0],[1,0],[1,0],[0,0]],
                [[0,1],[0,0],[1,0],[1,0],[0,0]])
    if kind == 'true':
        # u,v Boolean and uv=0, followed by two tautologies.
        return ([[0,1,0],[0,0,1],[0,1,0],[1,0,0],[0,0,0]],
                [[0,1,0],[0,0,1],[0,0,1],[1,0,0],[0,0,0]],
                [[0,1,0],[0,0,1],[0,0,0],[1,0,0],[0,0,0]])
    raise ValueError(kind)


def interpolation_weights(e, m):
    weights = []
    for j in range(m):
        numerator, denominator = 1, 1
        for t in range(m):
            if t != j:
                numerator = p.F[numerator][e ^ t]
                denominator = p.F[denominator][j ^ t]
        weights.append(p.F[numerator][p.INVF[denominator]])
    return weights


def source_values(matrices, e, y):
    m = len(matrices[0])
    weights = interpolation_weights(e, m)
    return tuple(dot(weights, [dot(row, y) for row in mat]) for mat in matrices)


def build_fixture(kind, seed, L):
    matrices = source(kind)
    m, n = len(matrices[0]), len(matrices[0][0]) - 1
    h, N = 4, 2 * L + 4
    nodes = list(range(m, m + L))
    check(nodes[-1] < 16, 'distinct off-domain nodes in base field')
    rng = random.Random(seed)
    key = rng.randrange(256)  # Supplied to assertions, not recovered.
    C0, Q0, Q1 = (p.zeros(N, N) for _ in range(3))
    retained = []
    witnesses = []
    for w in itertools.product(range(16), repeat=n):
        y = [1, *w]
        residuals = [p.E[dot(a,y)][dot(b,y)] ^ dot(c,y)
                     for a,b,c in zip(*matrices)]
        if not any(residuals):
            witnesses.append(w)
    check(len(witnesses) == (0 if kind == 'false' else 3), 'complete ORIGINAL source census')
    for e in nodes:
        aa, bb, cc = source_values(matrices, e, [1] + [0] * n)
        sp, sq, sr, st = p.sl2(rng)
        A = p.E[sp][aa] ^ p.E[sq][bb]
        B = p.E[sr][aa] ^ p.E[st][bb]
        # Frobenius Boolean correction at w=0 is the square of the constant form.
        C = cc ^ p.E[p.F[sp][sr]][p.E[aa][aa]] ^ p.E[p.F[sq][st]][p.E[bb][bb]]
        mu, orientation = rng.randrange(16,256), rng.randrange(2)
        pi = 1 ^ p.E[mu][A if orientation == 0 else B]
        check(pi != 0, 'subfield pivot separation at fixed y0')
        As = A if orientation == 0 else A ^ p.E[mu][C]
        Bs = B ^ p.E[mu][C] if orientation == 0 else B
        g = [[C,As,0],[Bs,pi,0],[0,0,pi]]
        check(p.E[C][pi] ^ p.E[As][Bs] == p.E[aa][bb] ^ cc,
              'pivot and SL2 preserve base residual')
        U = [[rng.randrange(256) for _ in range(3)] for _ in range(N)]
        V = [[rng.randrange(256) for _ in range(N)] for _ in range(3)]
        Z = 1
        for t in range(m):
            Z = p.F[Z][e ^ t]
        a, xi = p.fpow(Z,8), p.fpow(e,8)
        J = [[0,0,1],[0,0,0],[1,0,0]]
        q = p.mm(p.mm(U,J),V)
        Q0 = p.madd(Q0,p.mscale(a,q))
        Q1 = p.madd(Q1,p.mscale(p.E[a][xi],q))
        C0 = p.madd(C0,p.mm(p.mm(U,g),V))
        retained.append((g,U,V))
    C0 = p.madd(C0,p.mscale(key,p.ident(N)))
    check(p.rank(Q0) == 2*L, 'full quotient support in test fixture')
    P, Q, _ = canon.normalize_quotient(Q0,Q1,[p.fpow(e,8) for e in nodes])
    W = p.mm(P,Q)
    C = p.mm(p.mm(P,C0),Q)
    remaining = p.zeros(N,N)
    supported_sum = p.zeros(N,N)
    for e,(g,U,V) in enumerate(retained):
        supported, one = split_gate(g)
        Up, Vq = p.mm(P,U), p.mm(V,Q)
        H = p.mm(p.mm(Up,supported),Vq)
        R = p.mm(p.mm(Up,one),Vq)
        check(p.rank(R)==1,'global per-node remainder rank one')
        local={2*e,2*e+1}
        check(all(not H[i][j] for i in range(N) for j in range(N)
                  if i not in local or j not in local), 'Schur residual has only its public node block')
        remaining=p.madd(remaining,R)
        supported_sum=p.madd(supported_sum,H)
    check(p.madd(p.madd(supported_sum,remaining),p.mscale(key,W))==C,
          'full constant slice identity, including key metric')
    a_count=L//2
    row_ids=list(range(2*a_count))+list(range(2*L,N))
    col_ids=list(range(2*a_count,2*L))+list(range(2*L,N))
    Wcut=p.submatrix(W,row_ids,col_ids)
    Rcut=p.submatrix(remaining,row_ids,col_ids)
    Ccut=p.submatrix(C,row_ids,col_ids)
    check(p.submatrix(supported_sum,row_ids,col_ids)==p.zeros(len(row_ids),len(col_ids)),
          'separated public node blocks eliminate the supported term')
    check(p.rank(Rcut)<=L,'projected private remainder rank at most L')
    check(p.madd(Ccut,p.mscale(key,Wcut))==Rcut,'supplied-key projected identity')
    check(p.rank(Wcut)>=L+1,'key metric survives projection in this fixture')
    # Intentionally do NOT construct a key-recovery polynomial, factor it, or select keys.
    return dict(kind=kind,seed=seed,L=L,N=N,h=h,original_witness_count=len(witnesses),
                projection_shape=[len(row_ids),len(col_ids)],
                metric_rank=p.rank(Wcut),remainder_rank=p.rank(Rcut),
                full_supplied_key_rank=p.rank(p.madd(C,p.mscale(key,W))),
                full_acceptance_threshold=2*L,
                key_recovery_executed=False)


def main():
    sub4=[a for a in range(16) if p.fpow(a,4)==a]
    check(len(sub4)==4,'GF4 subfield for exact gate census')
    count=0
    for c,a,b,s in itertools.product(sub4, repeat=4):
        for pi in sub4[1:]:
            split_gate([[c,a,s],[b,pi,0],[s,0,pi]])
            count+=1
    runs=[build_fixture(kind,seed,L) for kind in ('false','true')
          for seed,L in ((1471,9),(20393,10),(44221,9))]
    result=dict(status='STRUCTURAL_SECURITY_CORRECTION_NOT_CONSTRUCTION_ADVANCE',
                exact_gate_census=count,fixture_runs=runs,assertions=CHECKS,
                pinned_helper_assertions=p.COUNT,canonical_helper_assertions=canon.TALLY,
                factorization_executed=False,production_or_network_access=False,
                source_hashes={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                               for name in ('check_joint_schur.py','quotient_recurrence_check.py','canonical_release_check.py')})
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__':main()
