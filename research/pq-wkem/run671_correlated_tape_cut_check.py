#!/usr/bin/env python3
"""Finite counting and reversible-search checks for Run 671.
No secure cipher, WE implementation, or quantum computer is used.
"""
from __future__ import annotations
import hashlib
import json
import math
from pathlib import Path

CHECKS = 0

def insist(predicate: bool, reason: str) -> None:
    global CHECKS
    CHECKS += 1
    if not predicate:
        raise AssertionError(reason)


def run_fixture(c: int, rho: int, masks: tuple[int, ...], honest_tape_mod: int | None = None, gauge: bool = False):
    mod = 1 << c
    num_tapes = 1 << rho
    insist(len(set(masks)) == len(masks), 'masks distinct')
    insist(all(0 <= x < mod for x in masks), 'mask range')
    a = 5 if gauge else 1
    insist(a % 2 == 1, 'gauge must be invertible')
    inv = pow(a, -1, mod)
    insist((a * inv) % mod == 1, 'correct inverse')
    k = 0xA6
    # A public checking-key toy; not a real SLH-DSA public key.
    vk = hashlib.sha256(b'RUN671-FIXED-BRANCH' + bytes((k,))).digest()
    verify = lambda z: z is not None and hashlib.sha256(b'RUN671-FIXED-BRANCH' + bytes((z,))).digest() == vk
    def tr(s, r):
        return (a * s + (7 * r + 1 if gauge else 0)) % mod
    def unt(s, r):
        return (inv * (s - (7 * r + 1 if gauge else 0))) % mod
    def good_r(r):
        return honest_tape_mod is None or r % honest_tape_mod != 0
    def honest_state(w, r):
        return tr((r + w) % mod, r)
    def D(s, r):
        basic = unt(s, r)
        return k if good_r(r) and ((basic - r) % mod) in masks else None
    global_states = set()
    marks_per_r = []
    mass_sum = 0
    for r in range(num_tapes):
        honest_states_r = {honest_state(w, r) for w in masks}
        global_states.update(honest_states_r)
        accepted_states_r = {s for s in range(mod) if verify(D(s, r))}
        expected = honest_states_r if good_r(r) else set()
        insist(accepted_states_r == expected, 'honest/per-tape accepted set')
        insist(len(accepted_states_r) == (len(masks) if good_r(r) else 0), 'per-tape count')
        marks_per_r.append(len(accepted_states_r))
        mass_sum += len(accepted_states_r)
        for w in masks:
            insist(verify(D(honest_state(w, r), r)) == good_r(r), 'honest per-tape correctness')
        for s in range(mod):
            insist(unt(tr(s, r), r) == s, 'gauge invertibility')
    p = mass_sum / (mod * num_tapes)
    mean_m = sum(marks_per_r) / num_tapes
    insist(abs(p - mean_m / mod) < 1e-14, 'double-count theorem')
    honest_prob = sum(bool(good_r(r)) for r in range(num_tapes)) / num_tapes
    insist(mean_m >= honest_prob - 1e-14, 'single witness lower bound')
    if good_r(0):
        insist(any(verify(D(s, 0)) for s in range(mod)), 'nonempty tape')
    return dict(
        c=c, rho=rho, valid_witness_offsets=list(masks), gauge=gauge,
        good_tape_fraction=honest_prob,
        distinct_global_cut_states=len(global_states),
        mean_per_tape_valid_states=mean_m,
        accepted_pairs=mass_sum, total_pairs=mod * num_tapes,
        actual_uniform_acceptance=p,
        classical_trial_upper=1 / p,
        quantum_query_scale_upper=1 / math.sqrt(p),
        misleading_global_state_lower=len(global_states) / mod,
    )


def grover_explicit(c: int, rho: int):
    n = 1 << (c+rho)
    marked = {((r << c) | s) for r in range(1 << rho) for s in range(1 << c) if s == r % (1 << c)}
    theta = math.asin(math.sqrt(len(marked)/n))
    a = [1 / math.sqrt(n)] * n
    probs = []
    for j in range(4):
        observed = sum(abs(a[z])**2 for z in marked)
        predicted = math.sin((2*j + 1)*theta)**2
        insist(abs(observed-predicted) < 1e-10, f'Grover iteration {j}')
        probs.append(round(observed, 12))
        for z in marked:
            a[z] = -a[z]
        mean = sum(a) / n
        a = [2*mean - z for z in a]
        insist(abs(sum(z*z for z in a)-1) < 1e-10, 'norm preserved')
    return probs


def main():
    fixtures = [
        run_fixture(4,4,(0,)),
        run_fixture(5,7,(0,3,7),honest_tape_mod=4),
        run_fixture(5,7,(0,3,7),honest_tape_mod=4,gauge=True),
        run_fixture(3,6,(0,1,2)),
    ]
    insist(fixtures[0]['distinct_global_cut_states'] == 16, 'global M example')
    insist(fixtures[0]['mean_per_tape_valid_states'] == 1, 'conditional M example')
    insist(fixtures[0]['actual_uniform_acceptance'] == 1/16, 'conditional success')
    insist(fixtures[0]['misleading_global_state_lower'] == 1, 'naive global M invalid')
    insist(fixtures[1]['actual_uniform_acceptance'] == 3*0.75/32, 'partial honest correctness')
    insist(fixtures[1]['accepted_pairs'] == fixtures[2]['accepted_pairs'], 'tape gauge mass invariant')
    insist(fixtures[1]['actual_uniform_acceptance'] == fixtures[2]['actual_uniform_acceptance'], 'frame mass invariant')
    insist(fixtures[3]['distinct_global_cut_states'] == 8, 'witness/tape collisions')
    insist(fixtures[3]['mean_per_tape_valid_states'] == 3, 'per-tape genuine count')
    result = dict(
        run='671', scope='counting and coherent-search algebra only, no PQ experiment',
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        check_count=CHECKS,
        fixtures=fixtures,
        exact_grover_success=grover_explicit(4,4),
    )
    result['check_count'] = CHECKS
    print(json.dumps(result, indent=2, sort_keys=True))

if __name__ == '__main__':
    main()
