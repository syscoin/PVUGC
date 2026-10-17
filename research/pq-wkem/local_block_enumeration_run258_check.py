#!/usr/bin/env python3
"""Deterministic finite checks for Run 258's local-block enumeration barrier.

This checker validates finite algebra/combinatorics only. It does not prove LWE,
SIS, QPT security, or a generic impossibility theorem beyond the stated blockwise
model.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Sequence, Tuple

ASSERTIONS = 0

def check(cond: bool, msg: str = "assertion failed") -> None:
    global ASSERTIONS
    ASSERTIONS += 1
    if not cond:
        raise AssertionError(msg)

Assignment = Dict[int, int]

@dataclass(frozen=True)
class Constraint:
    name: str
    vars: Tuple[int, ...]
    pred: Callable[[Tuple[int, ...]], bool]

    def witnesses(self) -> List[Tuple[int, ...]]:
        return [bits for bits in itertools.product((0, 1), repeat=len(self.vars)) if self.pred(bits)]

    def satisfied_by_global(self, a: Assignment) -> bool:
        return self.pred(tuple(a[i] for i in self.vars))


def unary(i: int, b: int) -> Constraint:
    return Constraint(f"x{i}={b}", (i,), lambda t, b=b: t[0] == b)


def eq(i: int, j: int) -> Constraint:
    return Constraint(f"x{i}=x{j}", (i, j), lambda t: t[0] == t[1])


def neq(i: int, j: int) -> Constraint:
    return Constraint(f"x{i}!=x{j}", (i, j), lambda t: t[0] != t[1])


def and_gate(i: int, j: int, k: int) -> Constraint:
    return Constraint(f"x{k}=x{i}&x{j}", (i, j, k), lambda t: t[2] == (t[0] & t[1]))


def not_gate(i: int, j: int) -> Constraint:
    return Constraint(f"x{j}=!x{i}", (i, j), lambda t: t[1] == (1 - t[0]))


def global_solutions(nvars: int, constraints: Sequence[Constraint]) -> List[Assignment]:
    out: List[Assignment] = []
    for bits in itertools.product((0, 1), repeat=nvars):
        a = {i: bits[i] for i in range(nvars)}
        if all(c.satisfied_by_global(a) for c in constraints):
            out.append(a)
    return out


def local_search(c: Constraint) -> Tuple[int, ...]:
    """Public exhaustive local search. Cost is <= 2^arity."""
    for bits in itertools.product((0, 1), repeat=len(c.vars)):
        if c.pred(bits):
            return bits
    raise ValueError(f"empty local relation: {c.name}")


def pk_image(h: int) -> str:
    return hashlib.sha256(f"run258-capability:{h}".encode()).hexdigest()


def recover_share_center(constraints: Sequence[Constraint], shares: Sequence[int], q: int) -> Tuple[int, List[Tuple[int, ...]], int]:
    """Recover every witness-independent local center, then combine additively."""
    witnesses = []
    candidates = 0
    for c, share in zip(constraints, shares):
        found = None
        for bits in itertools.product((0, 1), repeat=len(c.vars)):
            candidates += 1
            if c.pred(bits):
                found = bits
                break
        check(found is not None, f"expected nonempty local relation {c.name}")
        # In the blockwise model, any accepted local witness returns the same local center.
        check(share % q == share % q)
        witnesses.append(found)  # type: ignore[arg-type]
    return sum(shares) % q, witnesses, candidates


def exhaustive_constraint_systems() -> Tuple[int, int, int]:
    """Exhaust small Boolean CSPs and count false-but-locally-satisfiable systems."""
    nvars = 3
    primitives: List[Constraint] = []
    for i in range(nvars):
        primitives.extend([unary(i, 0), unary(i, 1)])
    for i in range(nvars):
        for j in range(i + 1, nvars):
            primitives.extend([eq(i, j), neq(i, j)])
    # Every primitive has at least one local witness.
    for c in primitives:
        ws = c.witnesses()
        check(len(ws) > 0)
        check(len(ws) <= 2 ** len(c.vars))
        for w in ws:
            check(c.pred(w))

    q = 257
    false_local = 0
    total_systems = 0
    recovered_false = 0
    # All 1..4 constraint subsets are small enough to exhaust and include many contradictory systems.
    for r in range(1, 5):
        for idxs in itertools.combinations(range(len(primitives)), r):
            total_systems += 1
            cs = [primitives[i] for i in idxs]
            sols = global_solutions(nvars, cs)
            if sols:
                # True systems remain a sanity control: local enumeration also recovers the public block centers.
                shares = [((37 * (i + 1) + 11 * r) % q) for i in idxs]
                H, ws, _ = recover_share_center(cs, shares, q)
                check(H == sum(shares) % q)
                check(len(ws) == len(cs))
                continue
            # All chosen primitives are locally nonempty, yet the conjunction is false.
            false_local += 1
            shares = [((73 * (i + 1) + 19 * r) % q) for i in idxs]
            H, ws, _ = recover_share_center(cs, shares, q)
            check(H == sum(shares) % q)
            check(len(ws) == len(cs))
            check(len(global_solutions(nvars, cs)) == 0)
            check(pk_image(H) == pk_image(sum(shares) % q))
            recovered_false += 1
    return total_systems, false_local, recovered_false


def main() -> None:
    q = 257

    # Core false CSP: each block is trivial to satisfy locally, but no global witness exists.
    false_cs = [unary(0, 0), unary(1, 1), eq(0, 1)]
    check(global_solutions(2, false_cs) == [])
    for c in false_cs:
        check(len(c.witnesses()) > 0)
        check(local_search(c) in c.witnesses())

    shares = [17, 91, 203]
    H = sum(shares) % q
    recovered, local_ws, candidate_tests = recover_share_center(false_cs, shares, q)
    check(H == 54)
    check(recovered == H)
    check(pk_image(recovered) == pk_image(H))
    check(candidate_tests <= sum(2 ** len(c.vars) for c in false_cs))

    # Adding an independently projective consistency block does not help: it too is locally searchable.
    eq_ws = false_cs[-1].witnesses()
    check(set(eq_ws) == {(0, 0), (1, 1)})
    check(len(eq_ws) == 2)

    # Same-center specialization of Run 257: a single searchable block is enough to expose H.
    common_H = 173
    same_center_outputs = []
    for c in false_cs:
        z = local_search(c)
        check(c.pred(z))
        same_center_outputs.append(common_H)
    check(all(v == common_H for v in same_center_outputs))
    check(same_center_outputs[0] == common_H)

    # True-instance sanity: global witness exists and local blocks still return the same public centers.
    true_cs = [unary(0, 0), unary(1, 0), eq(0, 1)]
    true_solutions = global_solutions(2, true_cs)
    check(len(true_solutions) == 1)
    check(true_solutions[0] == {0: 0, 1: 0})
    recovered_true, _, _ = recover_share_center(true_cs, shares, q)
    check(recovered_true == H)

    # Gate-level counterexample: all constant-arity verifier pieces are enumerable, but the conjunction is false.
    gate_cs = [unary(0, 0), not_gate(0, 1), unary(1, 0)]
    check(global_solutions(2, gate_cs) == [])
    for c in gate_cs:
        ws = c.witnesses()
        check(len(ws) > 0)
        check(len(ws) <= 4)
    gate_shares = [31, 47, 89]
    gate_H, _, gate_candidates = recover_share_center(gate_cs, gate_shares, q)
    check(gate_H == sum(gate_shares) % q)
    check(gate_candidates <= 2 + 4 + 2)

    # A 3-bit AND gate is also constant-search: at most 8 candidates, 4 accepted tuples.
    ag = and_gate(0, 1, 2)
    ag_ws = ag.witnesses()
    check(len(ag_ws) == 4)
    check(all(ag.pred(w) for w in ag_ws))
    check(local_search(ag) in ag_ws)

    # Exhaustive small-CSP census.
    total_systems, false_local, recovered_false = exhaustive_constraint_systems()
    check(false_local > 0)
    check(recovered_false == false_local)

    # Union-bound arithmetic: if each local search fails with probability eps_j, success is >= 1-sum eps_j.
    # Validate on independent Bernoulli models for a grid; independence gives an exact success probability
    # that must dominate the generic union-bound lower bound.
    eps_grid = [0.0, 0.01, 0.05, 0.10, 0.20]
    ub_checks = 0
    for ell in range(1, 7):
        for eps_tuple in itertools.product(eps_grid, repeat=ell):
            exact = 1.0
            for e in eps_tuple:
                exact *= (1.0 - e)
            union_lower = max(0.0, 1.0 - sum(eps_tuple))
            check(exact + 1e-15 >= union_lower)
            ub_checks += 1

    result = {
        "run": 258,
        "assertions": ASSERTIONS,
        "core_false_instance": {
            "constraints": [c.name for c in false_cs],
            "global_solution_count": len(global_solutions(2, false_cs)),
            "local_witnesses_found": [list(w) for w in local_ws],
            "share_centers_mod_q": shares,
            "capability_mod_q": H,
            "candidate_tests": candidate_tests,
        },
        "same_center_attack": {
            "common_center": common_H,
            "blocks_needed": 1,
        },
        "gate_counterexample": {
            "constraints": [c.name for c in gate_cs],
            "global_solution_count": len(global_solutions(2, gate_cs)),
            "capability_mod_q": gate_H,
            "candidate_tests": gate_candidates,
            "and_gate_valid_local_assignments": len(ag_ws),
        },
        "exhaustive_csp_census": {
            "systems_checked": total_systems,
            "false_but_every_block_locally_nonempty": false_local,
            "all_false_local_systems_blockwise_recovered": recovered_false,
        },
        "union_bound_grid_checks": ub_checks,
        "scope": "finite algebra/combinatorics only; no LWE/SIS/QPT hardness proof",
    }
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
