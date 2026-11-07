#!/usr/bin/env python3
import json, random, hashlib, sys
from itertools import product
from math import comb

SEED = 500050
Q = 65537  # Fermat prime; > 2^16 for divisor controls through n=10.
RNG = random.Random(SEED)


def inv(a, q=Q):
    return pow(a % q, -1, q)


def monomials(n, D):
    out = []
    cur = [0] * n
    def rec(i, rem):
        if i == n:
            out.append(tuple(cur)); return
        for e in range(rem + 1):
            cur[i] = e
            rec(i + 1, rem - e)
        cur[i] = 0
    rec(0, D)
    return out


def pclean(p, q=Q):
    return {m: v % q for m, v in p.items() if v % q}


def padd(a, b, q=Q):
    c = dict(a)
    for m, v in b.items():
        c[m] = (c.get(m, 0) + v) % q
        if c[m] == 0:
            del c[m]
    return c


def pscale(a, s, q=Q):
    return pclean({m: (v * s) % q for m, v in a.items()}, q)


def pmul(a, b, q=Q):
    if not a or not b: return {}
    n = len(next(iter(a)))
    c = {}
    for ma, va in a.items():
        for mb, vb in b.items():
            m = tuple(ma[i] + mb[i] for i in range(n))
            c[m] = (c.get(m, 0) + va * vb) % q
    return pclean(c, q)


def pconst(n, c, q=Q):
    return {(0,) * n: c % q} if c % q else {}


def pvar(n, i):
    e = [0] * n; e[i] = 1
    return {tuple(e): 1}


def pdeg(p):
    return max((sum(m) for m in p), default=0)


def peval(p, a, q=Q):
    s = 0
    for m, v in p.items():
        t = v
        for i, e in enumerate(m):
            if e:
                t = (t * pow(a[i] % q, e, q)) % q
        s = (s + t) % q
    return s


def bool_constraints(n, q=Q):
    gs = []
    for i in range(n):
        x = pvar(n, i)
        gs.append(padd(pmul(x, x, q), pscale(x, -1, q), q))
    return gs


def clause_poly(n, clause, q=Q):
    # clause entries: (variable index, positive_literal bool).
    out = pconst(n, 1, q)
    one = pconst(n, 1, q)
    for i, positive in clause:
        x = pvar(n, i)
        false_factor = padd(one, pscale(x, -1, q), q) if positive else x
        out = pmul(out, false_factor, q)
    return out


def clause_sat(assignment, clause):
    return any((assignment[i] == 1) if positive else (assignment[i] == 0)
               for i, positive in clause)


def formula_sat(n, clauses):
    for a in product((0, 1), repeat=n):
        if all(clause_sat(a, c) for c in clauses):
            return True, a
    return False, None


def poly_vector(p, idx, q=Q):
    v = [0] * len(idx)
    for m, c in p.items():
        if m not in idx:
            raise ValueError("polynomial exceeds ambient degree")
        v[idx[m]] = c % q
    return v


def rref(rows, q=Q):
    if not rows:
        return [], []
    a = [[x % q for x in row] for row in rows]
    R = 0; pivots = []
    C = len(a[0])
    for c in range(C):
        piv = next((i for i in range(R, len(a)) if a[i][c] % q), None)
        if piv is None:
            continue
        a[R], a[piv] = a[piv], a[R]
        z = inv(a[R][c], q)
        a[R] = [(x * z) % q for x in a[R]]
        for i in range(len(a)):
            if i != R and a[i][c] % q:
                f = a[i][c] % q
                a[i] = [(a[i][j] - f * a[R][j]) % q for j in range(C)]
        pivots.append(c)
        R += 1
        if R == len(a):
            break
    return a[:R], pivots


def rank(rows, q=Q):
    return len(rref(rows, q)[1]) if rows else 0


def nullspace(rows, width, q=Q):
    if not rows:
        return [[1 if i == j else 0 for i in range(width)] for j in range(width)]
    rr, piv = rref(rows, q)
    free = [j for j in range(width) if j not in piv]
    basis = []
    for f in free:
        x = [0] * width; x[f] = 1
        for ri in range(len(piv)-1, -1, -1):
            pc = piv[ri]
            s = sum(rr[ri][j] * x[j] for j in free) % q
            x[pc] = (-s) % q
        basis.append(x)
    return basis


def dot(a, b, q=Q):
    return sum((x * y) % q for x, y in zip(a, b)) % q


def truncated_ideal(n, gs, D, q=Q):
    mons = monomials(n, D); idx = {m: i for i, m in enumerate(mons)}
    rows = []
    labels = []
    for j, g in enumerate(gs):
        dg = pdeg(g)
        if dg > D:
            continue
        for m in monomials(n, D - dg):
            h = pmul({m: 1}, g, q)
            rows.append(poly_vector(h, idx, q))
            labels.append((j, m))
    rr, piv = rref(rows, q)
    return mons, idx, rr, piv, rows, labels


def in_span(rows, v, q=Q):
    return rank(rows, q) == rank(rows + [v], q)


def min_degree(n, gs, f, max_D, q=Q):
    lo = max([pdeg(f)] + [pdeg(g) for g in gs])
    for D in range(lo, max_D + 1):
        mons, idx, rr, piv, rows, labels = truncated_ideal(n, gs, D, q)
        fv = poly_vector(f, idx, q)
        if in_span(rows, fv, q):
            return D
    return None


def separator_for_shift(rows, shift, q=Q):
    ns = nullspace(rows, len(shift), q)
    for lam in ns:
        d = dot(lam, shift, q)
        if d:
            z = inv(d, q)
            return [(z * x) % q for x in lam]
    return None


def random_span_element(rows, rng, q=Q):
    if not rows:
        return [0] * 0
    out = [0] * len(rows[0])
    for row in rows:
        c = rng.randrange(q)
        if c:
            out = [(x + c*y) % q for x, y in zip(out, row)]
    return out


def divisor_poly(n, q=Q):
    r = pconst(n, 1, q)
    for i in range(n):
        r = padd(r, pscale(pvar(n, i), 1 << i, q), q)
    return r


def inverse_divisor_multilinear_coeffs(n, q=Q):
    vals = [0] * (1 << n)
    for mask in range(1 << n):
        rv = 1 + sum((1 << i) for i in range(n) if (mask >> i) & 1)
        vals[mask] = inv(rv, q)
    coeff = vals[:]
    for i in range(n):
        for mask in range(1 << n):
            if (mask >> i) & 1:
                coeff[mask] = (coeff[mask] - coeff[mask ^ (1 << i)]) % q
    return coeff


def coeffs_to_poly(n, coeff, q=Q):
    p = {}
    for mask, c in enumerate(coeff):
        if c % q:
            e = tuple(1 if (mask >> i) & 1 else 0 for i in range(n))
            p[e] = c % q
    return p


def multilinear_reduce(p, q=Q):
    out = {}
    for m, c in p.items():
        mm = tuple(1 if e else 0 for e in m)
        out[mm] = (out.get(mm, 0) + c) % q
    return pclean(out, q)


def random_3clause(n, rng):
    inds = rng.sample(range(n), 3)
    return [(i, bool(rng.getrandbits(1))) for i in inds]


def collect_unsat_4var_formulas(count, rng):
    out = []
    attempts = 0
    while len(out) < count and attempts < 200000:
        attempts += 1
        clauses = [random_3clause(4, rng) for _ in range(14)]
        sat, _ = formula_sat(4, clauses)
        if not sat:
            out.append(clauses)
    if len(out) != count:
        raise RuntimeError("failed to collect deterministic unsat formulas")
    return out, attempts


def full_assignment_blocking_3cnf():
    # For each assignment a, include the unique width-3 clause false at a.
    clauses = []
    for a in product((0, 1), repeat=3):
        clause = []
        for i, bit in enumerate(a):
            # Literal false at bit: x if bit=0, not x if bit=1.
            clause.append((i, bit == 0))
        clauses.append(clause)
    return clauses


def true_relation_controls(rng, trials=400):
    # Boolean x,y plus x+y-1=0.  D=2 full truncated ideal masks.
    n = 2; q = Q
    x, y = pvar(n,0), pvar(n,1)
    g = padd(padd(x, y, q), pconst(n, -1, q), q)
    gs = bool_constraints(n,q) + [g]
    D = 2
    mons, idx, rr, piv, rows, labels = truncated_ideal(n, gs, D, q)
    r = divisor_poly(n,q)
    rv = poly_vector(r, idx,q)
    valid = [(1,0),(0,1)]
    ok = 0
    for _ in range(trials):
        R = random_span_element(rr, rng, q)
        K = rng.randrange(q)
        C = [(R[i] + K*rv[i]) % q for i in range(len(rv))]
        # vector -> polynomial evaluation
        for w in valid:
            cv = 0
            for coeff, m in zip(C, mons):
                t = coeff
                for j,e in enumerate(m):
                    if e: t = t * pow(w[j],e,q) % q
                cv = (cv + t) % q
            rw = peval(r,w,q)
            if rw == 0 or cv * inv(rw,q) % q != K:
                raise AssertionError("true decapsulation failure")
            ok += 1
    return {"trials":trials, "witness_decaps":ok, "ambient":len(mons), "rank":len(rr)}


def false_separator_controls(rng, trials=300):
    clauses = full_assignment_blocking_3cnf()
    n=3; q=Q
    assert not formula_sat(n,clauses)[0]
    gs=bool_constraints(n,q)+[clause_poly(n,c,q) for c in clauses]
    r=divisor_poly(n,q)
    one=pconst(n,1,q)
    d1=min_degree(n,gs,one,6,q)
    dr=min_degree(n,gs,r,6,q)
    # At D=2 neither 1 nor r is in the span; separator recovers K.
    D=2
    mons,idx,rr,piv,rows,labels=truncated_ideal(n,gs,D,q)
    rv=poly_vector(r,idx,q)
    assert not in_span(rows,rv,q)
    lam=separator_for_shift(rows,rv,q)
    if lam is None: raise AssertionError("missing separator")
    sep_ok=0
    for _ in range(trials):
        R=random_span_element(rr,rng,q)
        K=rng.randrange(q)
        C=[(R[i]+K*rv[i])%q for i in range(len(rv))]
        if dot(lam,C,q)!=K:
            raise AssertionError("separator failed")
        sep_ok += 1
    # At D=dr, r lies in V; random shift by K*r stays in V.
    mons2,idx2,rr2,piv2,rows2,labels2=truncated_ideal(n,gs,dr,q)
    rv2=poly_vector(r,idx2,q)
    assert in_span(rows2,rv2,q)
    shift_members=0
    for _ in range(trials):
        R=random_span_element(rr2,rng,q)
        K=rng.randrange(q)
        C=[(R[i]+K*rv2[i])%q for i in range(len(rv2))]
        if not in_span(rows2,C,q):
            raise AssertionError("shift invariance membership failed")
        shift_members += 1
    return {"delta_one":d1,"delta_r":dr,"separator_trials":sep_ok,
            "shift_membership_trials":shift_members,"D_attack":D,
            "ambient_attack":len(mons),"rank_attack":len(rr)}


def degree_comparison_controls(rng, count=50):
    formulas, attempts=collect_unsat_4var_formulas(count,rng)
    rows=[]
    for i,clauses in enumerate(formulas):
        n=4;q=Q
        gs=bool_constraints(n,q)+[clause_poly(n,c,q) for c in clauses]
        one=pconst(n,1,q); r=divisor_poly(n,q)
        d1=min_degree(n,gs,one,7,q)
        dr=min_degree(n,gs,r,7,q)
        if d1 is None or dr is None: raise AssertionError("degree not found")
        if dr > d1 + 1: raise AssertionError("upper degree relation failed")
        if d1 > max(dr+n,n+1): raise AssertionError("inverse degree relation failed")
        rows.append({"delta_one":d1,"delta_r":dr})
    return {"count":count,"attempts":attempts,"pairs":rows}


def reciprocal_controls(max_n=10):
    out=[]; points=0
    for n in range(1,max_n+1):
        r=divisor_poly(n,Q)
        coeff=inverse_divisor_multilinear_coeffs(n,Q)
        s=coeffs_to_poly(n,coeff,Q)
        support=len(s); maxdeg=max(sum(m) for m in s)
        for a in product((0,1),repeat=n):
            rv=peval(r,a,Q); sv=peval(s,a,Q)
            if rv==0 or rv*sv%Q != 1:
                raise AssertionError("reciprocal control failed")
            points += 1
        residual=padd(pmul(r,s,Q),pconst(n,-1,Q),Q)
        if multilinear_reduce(residual,Q):
            raise AssertionError("boolean reduction residual nonzero")
        out.append({"n":n,"support":support,"max_degree":maxdeg,"cube_points":1<<n})
    return {"rows":out,"total_cube_points":points}


def main():
    rng=random.Random(SEED)
    result={
        "seed":SEED,
        "field_prime":Q,
        "candidate":"C_K(w)=K*r(w)+R(w), decap=C_K(w)/r(w)",
        "divisor":"r(w)=1+sum_i 2^i w_i",
    }
    result["true_correctness"] = true_relation_controls(rng)
    result["false_dichotomy"] = false_separator_controls(rng)
    result["unsat_4var_degree_pairs"] = degree_comparison_controls(rng)
    result["reciprocal"] = reciprocal_controls(10)

    pairs=result["unsat_4var_degree_pairs"]["pairs"]
    result["degree_pair_histogram"]={}
    for p in pairs:
        k=f"{p['delta_one']}->{p['delta_r']}"
        result["degree_pair_histogram"][k]=result["degree_pair_histogram"].get(k,0)+1
    result["all_checks_passed"] = True
    print(json.dumps(result, sort_keys=True, indent=2))

if __name__ == "__main__":
    main()
