#!/usr/bin/env python3
"""Run 619: finite coherent-oracle hybrid and extraction-bound check.
No actual WE/FE, native signature, QPT security, or quantum hardware.
"""
import json, math, random


def h(state, bit):
    factor = 1 / math.sqrt(2)
    result = state.copy()
    for i in range(len(state)):
        if not (i & (1 << bit)):
            j = i | (1 << bit)
            result[i] = (state[i] + state[j]) * factor
            result[j] = (state[i] - state[j]) * factor
    return result


def cnot(state, control, target):
    result = [0j] * len(state)
    for i, amp in enumerate(state):
        j = i ^ (1 << target) if i & (1 << control) else i
        result[j] = amp
    return result


def z(state, bit):
    return [-v if i & (1 << bit) else v for i, v in enumerate(state)]


def query(state, n, marked):
    """Ideal XOR oracle: answer ^= K (K=1 here) iff R(x,w)=1."""
    result = [0j] * len(state)
    for i, amp in enumerate(state):
        w = i & ((1 << n) - 1)
        j = i ^ (1 << n) if w in marked else i
        result[j] = amp
    return result


def marked_mass(state, n, marked):
    return sum(abs(v) ** 2 for i, v in enumerate(state)
               if (i & ((1 << n) - 1)) in marked)


def answer_one(state, n):
    return sum(abs(v) ** 2 for i, v in enumerate(state) if i & (1 << n))


def layer(state, n, j, seed):
    state = h(state, (j + seed) % n)
    if (seed + j) % 3 == 0:
        state = cnot(state, (seed + 2 * j) % n, n)
    if (seed + j) % 2:
        state = z(state, (2 * seed + j) % n)
    return state


def experiment(n, marked, q, seed):
    size = 1 << (n + 1)
    a = [0j] * size
    a[0] = 1 + 0j
    for bit in range(n):
        a = h(a, bit)
    b = a.copy()
    masses = []
    for j in range(q):
        masses.append(marked_mass(b, n, marked))
        a = query(a, n, marked)
        a = layer(a, n, j, seed)
        b = layer(b, n, j, seed)
    p_real, p_empty = answer_one(a, n), answer_one(b, n)
    delta = abs(p_real - p_empty)
    p_extract = sum(masses) / q
    assert abs(sum(abs(v) ** 2 for v in a) - 1) < 1e-10
    assert abs(sum(abs(v) ** 2 for v in b) - 1) < 1e-10
    assert delta <= 2 * sum(math.sqrt(m) for m in masses) + 1e-10
    assert p_extract + 1e-10 >= delta * delta / (4 * q * q)
    return delta, p_extract


def main():
    rng = random.Random(6192026)
    checks = 0
    rows = 0
    nonzero = 0
    max_delta = 0.0
    min_excess = 1.0
    for n in (2, 3, 4, 5, 6):
        for m in (1, 2, 3, 5):
            if m > 1 << n:
                continue
            for q in (1, 2, 3, 5):
                for seed in range(8):
                    marked = set(rng.sample(range(1 << n), m))
                    delta, extraction = experiment(n, marked, q, seed)
                    checks += 4
                    rows += 1
                    nonzero += delta > 1e-12
                    max_delta = max(max_delta, delta)
                    min_excess = min(min_excess, extraction - delta * delta / (4*q*q))
    # An explicit one-query classical-access special case, verified by full
    # state-vector simulation: measure answer without later transforms.
    n = 7
    marked = {3, 5, 9}
    initial = [0j] * (1 << (n+1))
    initial[0] = 1 + 0j
    for bit in range(n):
        initial = h(initial, bit)
    p1 = answer_one(query(initial, n, marked), n)
    p0 = answer_one(initial, n)
    assert abs((p1-p0) - len(marked)/(1 << n)) < 1e-12
    checks += 1
    print(json.dumps({
        'run':619,'fixtures':rows,'checked_conditions':checks,
        'nonzero_distinguishing_fixtures':nonzero,
        'max_probability_difference':round(max_delta, 12),
        'minimum_extractor_bound_slack':round(min_excess, 12),
        'one_query_example':{'n':n,'marked':len(marked),'real_minus_baseline':p1-p0},
        'bound':'Pr[measure a random no-oracle query in R] >= (delta/(2q))^2',
        'model':'Ideal keyed relation-release XOR oracle, full coherent QPT queries',
        'real_FE_or_WE_compiler':'NOT CONSTRUCTED',
        'native_signature':'NOT IMPLEMENTED',
        'true_instance_original_extraction_for_real_circuits':'UNPROVED'
    }, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
