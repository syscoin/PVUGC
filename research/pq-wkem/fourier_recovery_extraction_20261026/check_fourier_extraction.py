#!/usr/bin/env python3
"""Finite, offline checks of a code-access Fourier recovery extractor.

This is a mathematical validation program, not a cryptographic attack program.
It enumerates tiny locally generated SOURCE/noise examples and simulates small
controlled reflection circuits. No network or repository access is performed.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from collections import defaultdict
from fractions import Fraction as F
from pathlib import Path
import random
import numpy as np

COUNTS: dict[str, int] = defaultdict(int)

def check(ok: bool, group: str, why: str) -> None:
    if not ok:
        raise AssertionError(f"{group}: {why}")
    COUNTS[group] += 1

def parity(x: int) -> int:
    return x.bit_count() & 1

def kernel(rows: list[int], n: int) -> list[int]:
    a = list(rows)
    pivots: list[int] = []
    k = 0
    for col in range(n):
        j = next((j for j in range(k, len(a)) if (a[j] >> col) & 1), None)
        if j is None:
            continue
        a[k], a[j] = a[j], a[k]
        for j in range(len(a)):
            if j != k and ((a[j] >> col) & 1):
                a[j] ^= a[k]
        pivots.append(col)
        k += 1
    basis = []
    for c in range(n):
        if c in pivots:
            continue
        v = 1 << c
        for j, p in enumerate(pivots):
            if parity(a[j] & v):
                v ^= 1 << p
        check(all(parity(v & r) == 0 for r in rows), "kernel", "invalid basis")
        basis.append(v)
    return basis

class Source:
    def __init__(self, variables, inputs, affine, gates, pins):
        self.variables = tuple(variables)
        self.inputs = tuple(inputs)
        self.affine = tuple(affine)
        self.gates = tuple(gates)
        self.pins = tuple(pins)
        self.wires = {name: (1 + 2*i, 2 + 2*i) for i, name in enumerate(variables)}
        self.starts = [1 + 2*len(variables) + 4*i for i in range(len(gates))]
        self.n = 1 + 2*len(variables) + 4*len(gates)
        rows = []
        for p, q in self.wires.values():
            rows.append(1 ^ (1 << p) ^ (1 << q))
        for ins, out, epsilon in affine:
            row = (1 << self.wires[out][1]) ^ epsilon
            for name in ins:
                row ^= 1 << self.wires[name][1]
            rows.append(row)
        self.assignments = []
        for st, (a, b, out, kind) in zip(self.starts, gates):
            ass = [(i, j, (i & j) ^ (kind == 'NAND')) for i in (0, 1) for j in (0, 1)]
            self.assignments.append(ass)
            rows.append(1 ^ sum(1 << (st+i) for i in range(4)))
            for pos, name in enumerate((a, b, out)):
                for val in (0, 1):
                    row = 1 << self.wires[name][val]
                    for idx, assignment in enumerate(ass):
                        if assignment[pos] == val:
                            row ^= 1 << (st+idx)
                    rows.append(row)
        for name, val in pins:
            rows.append((1 << self.wires[name][1]) ^ val)
        self.rows = rows
        self.R = kernel(rows, self.n)
        self.d = len(self.R)
        self.size = 1 << self.d
        self.g = len(gates)
        self.rho = F(2, 3) ** self.g
        self.b = self.project(1)
        self.S = []
        self.witnesses = {}
        for a in range(self.size):
            v = self.lift(a)
            if v & 1 and all(((v >> st) & 15).bit_count() == 1 for st in self.starts):
                vals = {name: (v >> pair[1]) & 1 for name, pair in self.wires.items()}
                check(self.original_accepts(vals), "source", "support failed ORIGINAL relation")
                self.S.append(a)
                self.witnesses[a] = tuple(vals[name] for name in self.inputs)
        expected = []
        for vals in itertools.product((0, 1), repeat=len(self.variables)):
            state = dict(zip(self.variables, vals))
            if self.original_accepts(state):
                expected.append(tuple(state[name] for name in self.inputs))
        check(sorted(self.witnesses.values()) == sorted(expected), "source", "witness correspondence")
        check(len(self.S) <= 2 ** len(inputs), "source", "input-bit witness bound")
        self.P0 = self.distribution(0)
        self.P1 = self.distribution(1)

    def original_accepts(self, v):
        for ins, out, epsilon in self.affine:
            x = epsilon
            for a in ins:
                x ^= v[a]
            if x != v[out]:
                return False
        for a, b, out, kind in self.gates:
            if ((v[a] & v[b]) ^ (kind == 'NAND')) != v[out]:
                return False
        return all(v[name] == bit for name, bit in self.pins)

    def project(self, e):
        return sum(parity(e & r) << i for i, r in enumerate(self.R))

    def lift(self, a):
        v = 0
        for i, row in enumerate(self.R):
            if (a >> i) & 1:
                v ^= row
        return v

    def distribution(self, x):
        hist = [F(0) for _ in range(self.size)]
        choices = [[(0, 2)] + [(1 << (st+i), 1) for i in range(4)] for st in self.starts]
        for selected in itertools.product(*choices):
            e, wt = x, 1
            for e0, w in selected:
                e ^= e0
                wt *= w
            hist[self.project(e)] += F(wt, 6 ** self.g)
        check(sum(hist) == 1, "law", "distribution normalization")
        return hist

def fourier(f):
    n = len(f)
    return [sum((-1)**parity(a & y)*f[y]
                for y in range(n)) / n for a in range(n)]

def test_support(s):
    for a in range(s.size):
        c0 = sum(s.P0[y] * (-1)**parity(a & y) for y in range(s.size))
        c1 = sum(s.P1[y] * (-1)**parity(a & y) for y in range(s.size))
        expect = -2*s.rho if a in s.S else F(0)
        check(c1-c0 == expect, "fourier_support", "difference support identity")
        check(parity(a & s.b) == (s.lift(a) & 1), "fourier_support", "constant bit")
    if not s.S:
        check(s.P0 == s.P1, "false_secrecy", "false whole distribution")
    for a in s.S:
        p_correct = sum(s.P0[y] for y in range(s.size) if parity(a & y) == 0)
        check(p_correct == (1+s.rho)/2, "honest_channel", "witness bias")

def test_scalar_acceptance(s, rng):
    if not s.S:
        return
    if s.size <= 8:
        funcs = [[F((code >> y) & 1) for y in range(s.size)] for code in range(1 << s.size)]
    else:
        funcs = [[F(rng.randrange(9),8) for _ in range(s.size)] for _ in range(80)]
    for f in funcs:
        fh = fourier(f)
        gap = sum((s.P1[y]-s.P0[y])*f[y] for y in range(s.size))
        weight = 4*sum(fh[a]**2 for a in s.S)
        check(gap == -2*s.rho*sum(fh[a] for a in s.S), "acceptance", "gap Fourier identity")
        check(weight >= gap**2/(len(s.S)*s.rho**2), "acceptance", "extraction lower bound")
        check(weight <= 1, "acceptance", "probability feasibility")

def test_quantum_reflection(s, rng):
    """Matrix simulation of U_y^* (I-2 Pi) U_y, not a quantum hardware run."""
    if not s.S:
        return []
    dim = 4
    proj = np.diag([1., 1., 0., 0.]).astype(complex)
    Z = np.eye(dim) - 2*proj
    reports = []
    for trial in range(12):
        # One mixed advice/workspace state, possibly purified by an untouched reference.
        a = rng.normal(size=(dim,dim)) + 1j*rng.normal(size=(dim,dim))
        state = a @ a.conj().T
        state /= np.trace(state)
        Bs, fs = [], []
        for y in range(s.size):
            mat = rng.normal(size=(dim,dim)) + 1j*rng.normal(size=(dim,dim))
            U, _ = np.linalg.qr(mat)
            B = U.conj().T @ Z @ U
            Bs.append(B)
            fs.append(float(np.trace(state @ U.conj().T @ proj @ U).real))
        fh = [sum((-1)**parity(a & y)*fs[y] for y in range(s.size))/s.size for a in range(s.size)]
        probs = []
        for a in range(s.size):
            Bhat = sum(((-1)**parity(a & y))*Bs[y] for y in range(s.size))/s.size
            prob = float(np.trace(state @ Bhat.conj().T @ Bhat).real)
            probs.append(prob)
            if a != 0:
                check(prob+1e-12 >= 4*fh[a]**2, "quantum_reflection", "one-copy bound")
        check(abs(sum(probs)-1) < 1e-11, "quantum_reflection", "unitary normalization")
        p_ext = sum(probs[a] for a in s.S)
        gap = sum(float(s.P1[y]-s.P0[y])*fs[y] for y in range(s.size))
        lower = gap**2/(len(s.S)*float(s.rho)**2)
        check(p_ext+1e-12 >= lower, "quantum_reflection", "QPT extraction inequality")
        if trial == 0:
            reports.append({"gap": round(gap,10), "extraction_probability": round(p_ext,10),
                            "proved_lower_bound": round(lower,10)})
    return reports

def test_whole_view_hybrid(s):
    """Exact two-column hybrid with actual helper, pad, and a correlated public check.

    The 1-bit check is deliberately insecure. This illustrates why native/ideal
    success is SUBTRACTED; it is not asserted to instantiate a PQ checking key.
    """
    L = 2
    total_gap = F(0)
    expected_square = F(0)
    extracted_weight = F(0)
    # A probability-valued acceptance circuit, with both checking-key and full
    # helper/pad/capsule dependence. It is a finite algebra test, not a KEM.
    def f(K, X, q0, q1):
        W = X[0] ^ X[1]
        T = K ^ X[0]  # H=[1,0], helper F=[1,1]; HX is uniform given W.
        check_tag = K
        code = q0 + 3*q1 + 5*W + 7*T + 11*check_tag
        return F((code*code+code+3) % 9, 8)
    for j in range(L):
        for K, x0, x1 in itertools.product((0,1), repeat=3):
            X = (x0,x1)
            other = 1-j
            Pother = s.P0 if other < j else (s.P1 if X[other] else s.P0)
            for qo, pq in enumerate(Pother):
                if not pq:
                    continue
                fs = [f(K,X,y,qo) if j == 0 else f(K,X,qo,y) for y in range(s.size)]
                ptarget = s.P1 if X[j] else s.P0
                gap = sum((ptarget[y]-s.P0[y])*fs[y] for y in range(s.size))
                fh = fourier(fs)
                weight = 4*sum(fh[a]**2 for a in s.S)
                check(weight >= gap**2/(len(s.S)*s.rho**2), "full_view", "conditioned extraction")
                pr = pq/F(8*L)
                total_gap += pr*gap
                expected_square += pr*gap**2
                extracted_weight += pr*weight
    check(expected_square >= total_gap**2, "full_view", "Jensen over hybrid context")
    check(extracted_weight >= total_gap**2/(len(s.S)*s.rho**2), "full_view", "averaged extraction")
    # Independently enumerate endpoint games, verifying telescoping.
    rates = []
    for mode in ("real","ideal_columns"):
        p = F(0)
        for K, x0, x1 in itertools.product((0,1), repeat=3):
            X=(x0,x1)
            laws=[s.P1 if mode=="real" and x else s.P0 for x in X]
            for q0, q1 in itertools.product(range(s.size), repeat=2):
                p += laws[0][q0]*laws[1][q1]*f(K,X,q0,q1)/8
        rates.append(p)
    check(total_gap == (rates[0]-rates[1])/L, "full_view", "hybrid telescoping")
    return {"real_acceptance":str(rates[0]), "independent_column_acceptance":str(rates[1]),
            "mean_hybrid_gap":str(total_gap), "mean_extraction_weight_lower":str(extracted_weight)}

def main():
    rng = random.Random(20261026)
    qrng = np.random.default_rng(20261026)
    # First two reproduce the published mixed-affine one-gate relation.
    variables=['a','b','t','z','r']
    affine=[(('a','b'),'t',0),(('z','t'),'r',0)]
    gates=[('a','b','z','NAND')]
    fixtures = [
        ('published_true', Source(variables,['a','b'],affine,gates,[('r',0)])),
        ('published_false', Source(variables,['a','b'],affine,gates,[('r',0),('a',0),('b',0)])),
        ('unique_true', Source(['a','b','z'],['a','b'],[],[('a','b','z','AND')],[('z',1)])),
        ('two_gate_true', Source(['a','b','z','o'],['a','b'],[],
                                 [('a','b','z','AND'),('z','a','o','NAND')],[('o',1)])),
        ('two_gate_false', Source(['a','b','z','o'],['a','b'],[],
                                  [('a','b','z','AND'),('z','a','o','NAND')],
                                  [('a',1),('b',1),('o',1)])),
    ]
    result=[]
    for name,s in fixtures:
        test_support(s)
        test_scalar_acceptance(s,rng)
        qs=test_quantum_reflection(s,qrng)
        result.append({"name":name,"source_coordinates":s.n,"quotient_dimension":s.d,
                       "nonlinear_gates":s.g,"witnesses":len(s.S),"rho":str(s.rho),
                       "fourier_mass_D":str(len(s.S)*s.rho**2),"quantum_examples":qs})
    full=test_whole_view_hybrid(fixtures[0][1])
    # Exact independent pad check for the chosen rank-one helper/hash.
    for K,W in itertools.product((0,1),repeat=2):
        hist=[0,0]
        for x0,x1 in itertools.product((0,1),repeat=2):
            if x0^x1 == W:
                hist[K^x0]+=1
        check(hist==[1,1],"helper_pad","conditional exact uniformity")
    # No artificial padding is proposed. These are algebraic sufficient bounds only.
    for t in range(1,13):
        for g in range(t, t+5):
            check(F(2)**t*F(4,9)**g <= 1,"parameter_bound","g>=t sufficient")
    out={"status":"PASS","scope":"finite algebra and small matrix simulation only; not a practical security parameter set",
         "assertions":sum(COUNTS.values()),"groups":dict(sorted(COUNTS.items())),"fixtures":result,
         "whole_view_hybrid":full,"source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=='__main__':
    main()
