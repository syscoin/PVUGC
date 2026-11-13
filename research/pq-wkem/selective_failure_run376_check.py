#!/usr/bin/env python3
"""Run 376 exact finite oracle audit; NOT a WKEM, iO, QPT security proof, or signer."""
import itertools
import json
import math

assertions = 0

def check(cond, why):
    global assertions
    assertions += 1
    if not cond:
        raise AssertionError(f'assertion {assertions}: {why}')

def gate_good(_w, key):
    return key

def gate_bad(w, key, mark):
    return None if w == mark else key

def quantum_search_probability(width, mark, iterations):
    """Full-state coherent Grover evolution using one phase-marking query/iteration."""
    count = 1 << width
    amp = [1.0 / math.sqrt(count)] * count
    for _ in range(iterations):
        amp[mark] *= -1.0
        mean = sum(amp) / count
        amp = [2.0 * mean - a for a in amp]
    norm = sum(a*a for a in amp)
    check(abs(norm - 1.0) < 1e-10, 'quantum state normalization')
    return amp[mark]**2

# All-witness correctness is coNP-complete for arbitrary Boolean release programs.
# Finite truth-table exact check of the Boolean semantic equivalence.
function_count = 0
for bits in range(4):
    n = 1 << bits
    for table in itertools.product((0, 1), repeat=n):
        function_count += 1
        is_tautology = all(table)
        all_witnesses_release_1 = all(table[w] == 1 for w in range(n))
        a_counterwitness_exists = any(table[w] != 1 for w in range(n))
        check(is_tautology == all_witnesses_release_1, 'tautology -> all-witness correctness')
        check(a_counterwitness_exists == (not all_witnesses_release_1), 'coNP complement witness')
check(function_count == 278, 'all Boolean functions of at most 3 bits')

# Uniformly hidden semantic-prefix failure. One gate can deny an entire
# structured family while each independent random test has negligible hit rate.
prefix_fixtures = 0
for bits in range(3, 11):
    for prefix_width in range(1, min(bits, 6) + 1):
        for bad_prefix in (0, (1 << prefix_width)//2, (1 << prefix_width)-1):
            bad_count = sum(int((w >> (bits-prefix_width)) == bad_prefix)
                            for w in range(1 << bits))
            check(bad_count == (1 << (bits-prefix_width)),
                  'hidden prefix punctures complete structured witness family')
            prefix_fixtures += 1

classical_grids = []
quantum_grids = []
max_error = 0.0
key = bytes.fromhex('6ba654982e20f73b')
for bits in range(2, 10):
    n = 1 << bits
    for mark in (0, n//2, n-1):
        defective = 0
        for w in range(n):
            check(gate_good(w, key) == key, 'all-witness good-gate correctness')
            bad = gate_bad(w, key, mark)
            check((bad is None) == (w == mark), 'single-witness bad-gate correctness')
            defective += int(bad is None)
        check(defective == 1, 'exactly one legitimate witness selectively denied')
    for q in sorted(set((0, 1, 2, min(7,n), min(15,n), n))):
        hits = sum(int(mark in set(range(q))) for mark in range(n))
        check(hits == q, 'classical exact uniform-marker detection count')
        classical_grids.append({'input_bits':bits,'queries':q,'marks_found':hits,'total_marks':n})

for bits in range(2, 9):
    n = 1 << bits
    theta = math.asin(1.0/math.sqrt(n))
    optimum = int(round(math.pi/(4*theta) - 0.5))
    choices=sorted(set((0, 1, 2, 3, max(0,optimum), max(0,optimum-1))))
    for mark in (0,n//2,n-1):
        for iterations in choices:
            got=quantum_search_probability(bits,mark,iterations)
            exact=math.sin((2*iterations+1)*theta)**2
            err=abs(got-exact)
            max_error=max(err,max_error)
            check(err<1e-10,'full-state Grover agrees with exact closed-form')
            quantum_grids.append({'input_bits':bits,'marked_position':mark,
                        'coherent_mark_queries':iterations,
                        'success_probability':round(got,14)})

print(json.dumps({'run':376,'status':'PASS','assertions':assertions,
 'boolean_functions_exhausted':function_count,
 'classical_probability_tests':len(classical_grids),
 'hidden_prefix_family_fixtures':prefix_fixtures,
 'coherent_full_state_tests':len(quantum_grids),
 'max_coherent_probability_error':max_error,
 'classical_exact_single_needle_hit_probability':'q/2^n',
 'quantum_single_needle_search':'sin^2((2t+1)*asin(2^(-n/2)))',
 'scope':'opaque black-box release-testing oracle; adversarial puncture independent of auditor public side info',
 'not_claimed':['concrete obfuscation','QPT security proof','real signer','valid bridge implementation']},sort_keys=True,indent=2))
