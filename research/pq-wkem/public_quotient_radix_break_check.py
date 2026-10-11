#!/usr/bin/env python3
import collections
import hashlib
import json
import random
from itertools import product

SEED = 2026092215
PRIMES = (5, 7, 11, 13)
TRIALS = 80


def inv(a, p):
    return pow(a % p, -1, p)


def dot(a, b, mod=None):
    v = sum(x * y for x, y in zip(a, b))
    return v % mod if mod is not None else v


def matvec(H, x, mod=None):
    out = [sum(a * b for a, b in zip(row, x)) for row in H]
    if mod is not None:
        out = [v % mod for v in out]
    return out


def ht_y(H, y, Q):
    n = len(H[0])
    out = [0] * n
    for i, row in enumerate(H):
        yi = y[i] % Q
        for j, a in enumerate(row):
            out[j] = (out[j] + a * yi) % Q
    return out


def nullspace_mod_p(H, p):
    A = [[v % p for v in row] for row in H]
    m, n = len(A), len(A[0])
    pivots = []
    r = 0
    for c in range(n):
        pivot = next((i for i in range(r, m) if A[i][c] % p), None)
        if pivot is None:
            continue
        A[r], A[pivot] = A[pivot], A[r]
        scale = inv(A[r][c], p)
        A[r] = [(v * scale) % p for v in A[r]]
        for i in range(m):
            if i != r and A[i][c] % p:
                f = A[i][c] % p
                A[i] = [(A[i][j] - f * A[r][j]) % p for j in range(n)]
        pivots.append(c)
        r += 1
        if r == m:
            break
    free = [c for c in range(n) if c not in pivots]
    basis = []
    for f in free:
        x = [0] * n
        x[f] = 1
        for ri, c in enumerate(pivots):
            x[c] = (-A[ri][f]) % p
        assert all(v == 0 for v in matvec(H, x, p))
        basis.append(x)
    return basis


def build_compiler(nvars, clauses):
    """clauses: list of 3 signed integers, +i positive, -i negative; variables are 1-based."""
    m = len(clauses)
    npairs = nvars + 2 * m
    ncoord = 1 + 2 * npairs
    pairs = [(1 + 2 * i, 2 + 2 * i) for i in range(npairs)]
    H = []
    for u, ub in pairs:
        row = [0] * ncoord
        row[0] = -1
        row[u] = 1
        row[ub] = 1
        H.append(row)
    for j, clause in enumerate(clauses):
        row = [0] * ncoord
        row[0] = -4
        for lit in clause:
            vi = abs(lit) - 1
            u, ub = pairs[vi]
            row[u if lit > 0 else ub] += 1
        s1 = pairs[nvars + 2 * j][0]
        s2 = pairs[nvars + 2 * j + 1][0]
        row[s1] += 1
        row[s2] += 2
        H.append(row)
    return H, pairs


def relaxation_vector(nvars, clauses, pairs):
    """Public exact integer kernel point: all source variables 0; slacks solve each clause linearly."""
    x = [0] * (1 + 2 * len(pairs))
    x[0] = 1
    for i in range(nvars):
        u, ub = pairs[i]
        x[u], x[ub] = 0, 1
    for j, clause in enumerate(clauses):
        literal_sum = sum(1 for lit in clause if lit < 0)  # all source vars are zero
        target = 4 - literal_sum
        s2 = target // 2
        s1 = target - 2 * s2
        for pair_index, value in ((nvars + 2 * j, s1), (nvars + 2 * j + 1, s2)):
            u, ub = pairs[pair_index]
            x[u], x[ub] = value, 1 - value
    return x


def eval_formula(clauses, assignment):
    for clause in clauses:
        ok = False
        for lit in clause:
            bit = assignment[abs(lit) - 1]
            ok |= bool(bit if lit > 0 else 1 - bit)
        if not ok:
            return False
    return True


def root_direction(pair, alpha, t, p, ncoord):
    w = [0] * ncoord
    w[pair[0]] = 1
    w[pair[1]] = -1
    w[0] = -alpha + p * t
    return w


def components(p, pairs, ncoord):
    out = []
    for j, pair in enumerate(pairs):
        for alpha in range(p):
            if alpha in (1, p - 1):
                continue
            for t in (0, 1):
                out.append((j, alpha, t, root_direction(pair, alpha, t, p, ncoord)))
    return out


def setup(H, pairs, p, K, rng):
    Q = p * p
    ncoord = len(H[0])
    comps = components(p, pairs, ncoord)
    C = len(comps)
    shares = [rng.randrange(p) for _ in range(C - 1)]
    shares.append((K - sum(shares)) % p)
    pads = [[rng.randrange(p) for _ in range(ncoord)] for _ in range(C - 1)]
    pads.append([(-sum(pads[c][j] for c in range(C - 1))) % p for j in range(ncoord)])
    caps, zs = [], []
    for idx, (_, _, _, w) in enumerate(comps):
        y = [rng.randrange(Q) for _ in range(len(H))]
        z = rng.randrange(p)
        zs.append(z)
        base = ht_y(H, y, Q)
        cap = [
            (base[j] + z * w[j] + (p * shares[idx] if j == 0 else 0) + p * pads[idx][j]) % Q
            for j in range(ncoord)
        ]
        caps.append(cap)
    return comps, caps, zs


def quotient_functional(H, w, p, basis=None):
    if basis is None:
        basis = nullspace_mod_p(H, p)
    for lam in basis:
        e = dot(lam, w, p)
        if e:
            scale = inv(e, p)
            return [(v * scale) % p for v in lam]
    return None


def public_attack(H, pairs, p, comps, caps, x_relax):
    """Uses only H, public components/capsules, and the public linear relaxation; no Boolean witness."""
    Q = p * p
    basis = nullspace_mod_p(H, p)
    recovered_z = []
    total = [0] * len(H[0])
    quotient_failures = []
    for idx, (comp, cap) in enumerate(zip(comps, caps)):
        w = comp[3]
        lam = quotient_functional(H, w, p, basis)
        if lam is None:
            quotient_failures.append(idx)
            z = 0
        else:
            z = dot(lam, [v % p for v in cap], p)  # lambda(w)=1
        recovered_z.append(z)
        for j in range(len(total)):
            total[j] = (total[j] + cap[j] - z * w[j]) % Q
    if quotient_failures:
        return None, recovered_z, quotient_failures
    assert all(v == 0 for v in matvec(H, x_relax))
    assert x_relax[0] == 1
    scalar = dot([v % Q for v in x_relax], total, Q)
    assert scalar % p == 0
    return (scalar // p) % p, recovered_z, quotient_failures


def true_fixture():
    # True formula but all-zero assignment is false, so the public relaxation is not a source witness.
    return 1, [(1, 1, 1), (1, 1, 1)]


def false_fixture():
    return 1, [(1, 1, 1), (-1, -1, -1)]


def random_true_fixture(rng, nvars, m):
    witness = [rng.randrange(2) for _ in range(nvars)]
    if not any(witness):
        witness[0] = 1
    clauses = [(1, 1, 1)]  # forces all-zero to be false; hidden witness chosen with x1=1 below
    witness[0] = 1
    while len(clauses) < m:
        clause = []
        for _ in range(3):
            v = rng.randrange(1, nvars + 1)
            sign = 1 if rng.randrange(2) else -1
            clause.append(sign * v)
        if not eval_formula([tuple(clause)], witness):
            # flip first literal to make this clause true under the hidden witness
            v = abs(clause[0]) - 1
            clause[0] = (v + 1) if witness[v] else -(v + 1)
        clauses.append(tuple(clause))
    assert eval_formula(clauses, witness)
    return nvars, clauses, witness


def run_fixture(nvars, clauses, p, trials, rng):
    H, pairs = build_compiler(nvars, clauses)
    xrel = relaxation_vector(nvars, clauses, pairs)
    assert matvec(H, xrel) == [0] * len(H)
    comps = components(p, pairs, len(H[0]))
    basis = nullspace_mod_p(H, p)
    nonrow = sum(quotient_functional(H, c[3], p, basis) is not None for c in comps)
    successes = 0
    z_exact = 0
    for _ in range(trials):
        K = rng.randrange(p)
        comps2, caps, zs = setup(H, pairs, p, K, rng)
        assert [c[:3] for c in comps2] == [c[:3] for c in comps]
        got, zgot, fails = public_attack(H, pairs, p, comps2, caps, xrel)
        assert not fails
        successes += int(got == K)
        z_exact += int(zgot == zs)
    var_assignment = [xrel[pairs[i][0]] for i in range(nvars)]
    return {
        "nvars": nvars,
        "clauses": len(clauses),
        "coordinates": len(H[0]),
        "components": len(comps),
        "kernel_dimension_mod_p": len(basis),
        "root_directions_outside_rowspace": nonrow,
        "root_directions_total": len(comps),
        "relaxation_exact_integer_kernel": True,
        "relaxation_source_assignment_satisfies": eval_formula(clauses, var_assignment),
        "trials": trials,
        "z_vectors_recovered_exactly": z_exact,
        "keys_recovered": successes,
    }


def exhaustive_onevar_two_clause_suite(p, rng):
    clauses1 = [tuple(signs) for signs in product((1, -1), repeat=3)]
    total = sat = unsat = recovered = z_exact = nonrow_all = 0
    for c1 in clauses1:
        for c2 in clauses1:
            clauses = [c1, c2]
            is_sat = any(eval_formula(clauses, [z]) for z in (0, 1))
            sat += int(is_sat)
            unsat += int(not is_sat)
            H, pairs = build_compiler(1, clauses)
            xrel = relaxation_vector(1, clauses, pairs)
            assert matvec(H, xrel) == [0] * len(H)
            comps = components(p, pairs, len(H[0]))
            basis = nullspace_mod_p(H, p)
            nr = sum(quotient_functional(H, c[3], p, basis) is not None for c in comps)
            nonrow_all += int(nr == len(comps))
            K = rng.randrange(p)
            comps2, caps, zs = setup(H, pairs, p, K, rng)
            got, zgot, fails = public_attack(H, pairs, p, comps2, caps, xrel)
            assert not fails
            recovered += int(got == K)
            z_exact += int(zgot == zs)
            total += 1
    return {
        "formulas": total,
        "satisfiable": sat,
        "unsatisfiable": unsat,
        "all_root_directions_outside_rowspace": nonrow_all == total,
        "z_vectors_recovered_exactly": z_exact,
        "keys_recovered": recovered,
    }


def linfty_gap_onevar_two_clause_census():
    clauses1 = [tuple(signs) for signs in product((1, -1), repeat=3)]
    hist = collections.Counter()
    examples = []
    for c1 in clauses1:
        for c2 in clauses1:
            clauses = [c1, c2]
            sat = any(eval_formula(clauses, [z]) for z in (0, 1))
            H, pairs = build_compiler(1, clauses)
            best = None
            for vals in product(range(-2, 3), repeat=len(pairs)):
                x = [1]
                for value in vals:
                    x.extend((value, 1 - value))
                if matvec(H, x) == [0] * len(H):
                    norm_inf = max(abs(v) for v in x)
                    if best is None or norm_inf < best:
                        best = norm_inf
            hist[(sat, best)] += 1
            if len(examples) < 4 and not sat:
                examples.append({"clauses": clauses, "min_linfty": best})
    return {
        "satisfiable_min1": hist[(True, 1)],
        "unsatisfiable_min2": hist[(False, 2)],
        "other_cases": sum(v for (key, v) in hist.items() if key not in ((True, 1), (False, 2))),
        "unsat_examples": examples,
    }


def main():
    rng = random.Random(SEED)
    result = {
        "run": 35,
        "seed": SEED,
        "attack": "public row-space quotient recovers every radix z_c, then public normalized linear relaxation recovers aggregate key",
        "fixed_true": {},
        "fixed_false": {},
        "random_true": {},
        "exhaustive_onevar_two_clause": {},
        "linfty_gap_census": linfty_gap_onevar_two_clause_census(),
    }
    for label, fixture_fn in (("fixed_true", true_fixture), ("fixed_false", false_fixture)):
        nvars, clauses = fixture_fn()
        for p in PRIMES:
            result[label][str(p)] = run_fixture(nvars, clauses, p, TRIALS, rng)
    for p in PRIMES:
        result["exhaustive_onevar_two_clause"][str(p)] = exhaustive_onevar_two_clause_suite(p, rng)
        rows = []
        for case in range(20):
            nvars = 2 + (case % 4)
            m = 3 + (case % 5)
            nv, clauses, hidden_witness = random_true_fixture(rng, nvars, m)
            rec = run_fixture(nv, clauses, p, 10, rng)
            rec["hidden_witness_satisfies"] = eval_formula(clauses, hidden_witness)
            rows.append(rec)
        result["random_true"][str(p)] = {
            "instances": len(rows),
            "all_hidden_witnesses_valid": all(r["hidden_witness_satisfies"] for r in rows),
            "all_relaxations_nonwitness": all(not r["relaxation_source_assignment_satisfies"] for r in rows),
            "all_root_directions_outside_rowspace": all(r["root_directions_outside_rowspace"] == r["root_directions_total"] for r in rows),
            "total_trials": sum(r["trials"] for r in rows),
            "total_keys_recovered": sum(r["keys_recovered"] for r in rows),
            "total_z_vectors_recovered_exactly": sum(r["z_vectors_recovered_exactly"] for r in rows),
            "sample_shapes": rows[:4],
        }
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
