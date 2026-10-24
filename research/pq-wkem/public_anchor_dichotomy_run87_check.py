#!/usr/bin/env python3
"""Run 87 finite controls for the public-anchor dichotomy.

This checker validates finite linear-algebra identities and tiny exhaustive
source-space examples only.  It does not establish cryptographic or QPT
security and it does not implement a generic high-degree indicator compiler.
"""
from __future__ import annotations
import importlib.util
import json
import random
from pathlib import Path

SEED = 870087001
rng = random.Random(SEED)

# Prefer the exact published dependency when executed from the repository root.
candidates = [
    Path("research/pq-wkem/literature-20260924/rank_field_extensions.py"),
    Path("/mnt/data/rank_field_extensions_dependency.py"),
]
for dep in candidates:
    if dep.exists():
        spec = importlib.util.spec_from_file_location("rank_field_extensions", dep)
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        break
else:
    raise FileNotFoundError("rank_field_extensions.py dependency not found")

Field = mod.Field
spec_compiler = mod.spec
table_space = mod.table_space
rank = mod.rank
reshape = mod.reshape
lincomb = mod.lincomb
span = mod.span


def anchor(vec):
    # First flattened entry is the M_00 entry of the first h=1 block.
    # Every honest assignment encoding has this value exactly one.
    return vec[0]


def has_nonzero_anchor(basis):
    return any(anchor(v) != 0 for v in basis)


def normalize_public_anchor(basis, F):
    for j, v in enumerate(basis):
        a = anchor(v)
        if a:
            inv = F.inv[a]
            out = [F.mul[inv][x] for x in v]
            assert anchor(out) == 1
            return j, out
    return None, None


def sat_words(N, F, eqs):
    from itertools import product
    return [w for w in product((0, 1), repeat=N)
            if all(eq(w, F) == 0 for eq in eqs)]


def violation_indicator(eqs):
    # Exhaustive-oracle control only: returns zero exactly on simultaneous zeros.
    # This is NOT claimed to be linearly testable in the original quadratic table.
    def ind(w, F):
        return 0 if all(eq(w, F) == 0 for eq in eqs) else 1
    return ind


def make_linear_eq(coeffs):
    # coeffs = (c0,c1,...,cN)
    def eq(w, F):
        acc = coeffs[0] % F.q
        for c, b in zip(coeffs[1:], w):
            acc = F.add[acc][F.mul[c % F.q][b]]
        return acc
    return eq


def generic_dichotomy_controls():
    F = Field(17)
    checks = 0
    normalized = 0
    for _ in range(700):
        ambient = rng.randint(2, 10)
        gens = [[rng.randrange(F.q) for _ in range(ambient)]
                for __ in range(rng.randint(1, 8))]
        basis = span(gens, F)
        ell = [rng.randrange(F.q) for _ in range(ambient)]
        coords = [sum((e * x) for e, x in zip(ell, b)) % F.q for b in basis]
        # A linear functional vanishes on the whole span iff it vanishes on a basis.
        for _ in range(20):
            cc = [rng.randrange(F.q) for _ in basis]
            if not basis:
                vec = [0] * ambient
            else:
                vec = lincomb(basis, cc, F)
            lhs = sum((e * x) for e, x in zip(ell, vec)) % F.q
            rhs = sum((c * z) for c, z in zip(cc, coords)) % F.q
            assert lhs == rhs
            if not any(coords):
                assert lhs == 0
            checks += 1
        if any(coords):
            j = next(i for i, z in enumerate(coords) if z)
            c = [0] * len(basis)
            c[j] = F.inv[coords[j]]
            vec = lincomb(basis, c, F)
            assert sum((e * x) for e, x in zip(ell, vec)) % F.q == 1
            normalized += 1
    return checks, normalized


def actual_source_controls():
    F = Field(7)
    N, R = 3, 1
    S = spec_compiler(N, R, F)

    # One true and one false fixture used in the published compiler checks.
    true_eqs = [lambda w, F: F.sub(F.sum(w), 1)]
    false_eqs = [lambda w, F: F.sub(F.sum(w), 4)]

    _, _, true_basis = table_space(S, true_eqs)
    _, _, false_basis = table_space(S, false_eqs)
    assert has_nonzero_anchor(true_basis)
    assert has_nonzero_anchor(false_basis)

    j, normalized = normalize_public_anchor(false_basis, F)
    assert normalized is not None
    rr = rank(reshape(normalized, N + 1), F)

    # Exhaustive high-degree indicator ORACLE control.  If an exact polynomial-time
    # compiler could impose this relation generically, public anchor inspection
    # would decide satisfiability.  We only enumerate the tiny cube here.
    _, _, true_indicator_basis = table_space(
        S, true_eqs + [violation_indicator(true_eqs)])
    _, _, false_indicator_basis = table_space(
        S, false_eqs + [violation_indicator(false_eqs)])
    assert has_nonzero_anchor(true_indicator_basis)
    assert not has_nonzero_anchor(false_indicator_basis)

    return {
        "field": F.q,
        "N": N,
        "R": R,
        "true_source_dimension": len(true_basis),
        "false_source_dimension": len(false_basis),
        "true_has_public_nonzero_anchor": has_nonzero_anchor(true_basis),
        "false_has_public_nonzero_anchor": has_nonzero_anchor(false_basis),
        "normalized_false_basis_index": j,
        "normalized_false_matrix_rank": rr,
        "indicator_oracle_true_dimension": len(true_indicator_basis),
        "indicator_oracle_false_dimension": len(false_indicator_basis),
        "indicator_oracle_true_has_anchor": has_nonzero_anchor(true_indicator_basis),
        "indicator_oracle_false_has_anchor": has_nonzero_anchor(false_indicator_basis),
    }


def random_tiny_system_decision_controls():
    # Demonstrate, on tiny exhaustive systems, that if a compiler could add an
    # exact global violation-indicator constraint and still compute the basis,
    # simply checking public basis anchors decides satisfiability.
    F = Field(7)
    N, R = 3, 1
    S = spec_compiler(N, R, F)
    cases = []
    correct = 0
    for case in range(80):
        J = rng.randint(1, 3)
        coeff_sets = [tuple(rng.randrange(F.q) for _ in range(N + 1))
                      for __ in range(J)]
        eqs = [make_linear_eq(c) for c in coeff_sets]
        sats = sat_words(N, F, eqs)
        _, _, basis = table_space(S, eqs + [violation_indicator(eqs)])
        predicted_sat = has_nonzero_anchor(basis)
        actual_sat = bool(sats)
        assert predicted_sat == actual_sat
        correct += 1
        if case < 12:
            cases.append({
                "equations": [list(c) for c in coeff_sets],
                "satisfying_assignments": len(sats),
                "indicator_augmented_dimension": len(basis),
                "public_anchor_test": predicted_sat,
            })
    return correct, cases


def main():
    gchecks, gnorm = generic_dichotomy_controls()
    actual = actual_source_controls()
    decision_checks, sample_cases = random_tiny_system_decision_controls()
    out = {
        "seed": SEED,
        "scope": "finite linear algebra and tiny exhaustive oracle controls only; no cryptographic/QPT security inferred",
        "generic_basis_functional_identity_checks": gchecks,
        "generic_public_normalizations": gnorm,
        "actual_weighted_table_source_control": actual,
        "tiny_indicator_oracle_decision_checks": decision_checks,
        "tiny_indicator_oracle_sample_cases": sample_cases,
        "status": "PASS",
    }
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
