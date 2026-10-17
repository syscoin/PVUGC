#!/usr/bin/env python3
from __future__ import annotations
import itertools, json
from fractions import Fraction

ASSERTIONS = 0

def check(cond, msg='assertion failed'):
    global ASSERTIONS
    ASSERTIONS += 1
    if not cond:
        raise AssertionError(msg)

def parity(x: int) -> int:
    return x.bit_count() & 1

def mat_vec(A_rows, w, b):
    out = 0
    for j, row in enumerate(A_rows):
        bit = parity(row & w) ^ ((b >> j) & 1)
        out |= bit << j
    return out

# 1) Source-fiber cover theorem: t target instances, <=L accepted target witnesses each,
# each accepted target witness has source fiber size <=c => at most t*L*c sources covered.
cover_cases = 0
for M in range(1, 7):
    U = tuple(range(M))
    for t in range(1, 4):
        for L in range(1, 3):
            slots = t * L
            for c in range(1, 3):
                allowed = [frozenset(s) for r in range(c+1) for s in itertools.combinations(U, r)]
                # Exhaustive only when product remains moderate; otherwise deterministic sampled products.
                total = len(allowed) ** slots
                if total <= 20000:
                    prods = itertools.product(allowed, repeat=slots)
                else:
                    # Constructive worst-case + a small deterministic spread.
                    seqs = []
                    seqs.append(tuple(allowed[-1] for _ in range(slots)))
                    seqs.append(tuple(allowed[(i * 7 + M + c) % len(allowed)] for i in range(slots)))
                    seqs.append(tuple(allowed[(i * 11 + t + L) % len(allowed)] for i in range(slots)))
                    prods = seqs
                for assignment in prods:
                    union = frozenset().union(*assignment) if assignment else frozenset()
                    check(len(union) <= min(M, t*L*c), (M,t,L,c,assignment,union))
                    cover_cases += 1

# Constructive tightness where enough source points exist.
tight_cases = 0
for t in range(1,5):
    for L in range(1,4):
        for c in range(1,4):
            M = t*L*c + 2
            U = list(range(M))
            slots = []
            idx = 0
            for _ in range(t*L):
                slots.append(set(U[idx:idx+c])); idx += c
            union = set().union(*slots)
            check(len(union) == t*L*c)
            tight_cases += 1

# 2) Exact UP singleton cover: source-preserving UP component covers <=1 source witness.
up_singleton_cases = 0
for n in range(1, 9):
    M = 1 << n
    singleton_components = [{w} for w in range(M)]
    for t in [0,1,max(1,M//3),M-1,M]:
        chosen = singleton_components[:t]
        cov = set().union(*chosen) if chosen else set()
        check(len(cov) == min(t,M))
        if t < M:
            check(len(cov) < M)
        else:
            check(len(cov) == M)
        up_singleton_cases += 1

# 3) Affine hash family H_{A,b}: {0,1}^n -> {0,1}^k.
# For a fixed witness and fixed target bucket y=0, exact fraction over uniform A,b is 2^-k.
hash_membership_cases = 0
for n in range(1,5):
    for k in range(1,4):
        matrices = list(itertools.product(range(1<<n), repeat=k))
        for w in range(1<<n):
            hits = 0
            total = 0
            for A_rows in matrices:
                for b in range(1<<k):
                    total += 1
                    if mat_vec(A_rows, w, b) == 0:
                        hits += 1
            check(Fraction(hits,total) == Fraction(1,1<<k), (n,k,w,hits,total))
            hash_membership_cases += 1

# 4) If k<n, no nonempty affine bucket can be singleton: fibers have size >=2.
non_singleton_cases = 0
for n in range(2,5):
    for k in range(1,n):
        for A_rows in itertools.product(range(1<<n), repeat=k):
            for b in range(1<<k):
                counts = [0]*(1<<k)
                for w in range(1<<n):
                    counts[mat_vec(A_rows,w,b)] += 1
                for count in counts:
                    check(count == 0 or count >= 2, (n,k,A_rows,b,counts))
                non_singleton_cases += 1

# 5) When k=n and A is invertible, every bucket is singleton, but there are 2^n buckets.
# Brute force identify invertible-by-bijection matrices for n<=4.
injective_bucket_cases = 0
for n in range(1,5):
    k=n
    for A_rows in itertools.product(range(1<<n), repeat=n):
        image = {mat_vec(A_rows,w,0) for w in range(1<<n)}
        if len(image) != (1<<n):
            continue
        for b in [0, (1<<n)-1]:
            counts = [0]*(1<<n)
            for w in range(1<<n):
                counts[mat_vec(A_rows,w,b)] += 1
            check(all(c==1 for c in counts))
            check(sum(counts)==(1<<n))
            injective_bucket_cases += 1

# 6) Exact t-target coverage probability for one fixed witness under independent fixed buckets.
probability_cases = 0
prob_examples = []
for k in range(1,13):
    p = Fraction(1,1<<k)
    for t in [1,2,3,k,max(1,k*k),max(1,k**3)]:
        exact = 1 - (1-p)**t
        ub = min(Fraction(1,1), t*p)
        check(exact <= ub)
        check(exact >= p)
        probability_cases += 1
    n=k
    t=max(1,n**3)
    exact = 1 - (1-p)**t
    prob_examples.append({
        'n':n,'k':k,'t':t,
        'exact_float':float(exact),
        'union_bound_float':float(min(Fraction(1,1),t*p))
    })

# 7) Dense source relation correctness barrier and many-to-one escape control.
dense_cases = 0
for n in range(1,13):
    M=1<<n
    # source-preserving UP fixed targets require at least M components
    check((M-1)*1*1 < M)
    check(M*1*1 >= M)
    # many-to-one map can cover all with t=L=1 only if c=M
    check(1*1*M >= M)
    # but c=M is precisely a huge source fiber: one target witness represents all sources
    dense_cases += 3

# 8) General bounded-ambiguity/FewP arithmetic examples.
fewp_cases=[]
for n in [8,12,16,20]:
    M=1<<n
    for L in [1,n,n*n]:
        c=n
        t_needed=(M + L*c - 1)//(L*c)
        check(t_needed * L*c >= M)
        check((t_needed-1)*L*c < M)
        fewp_cases.append({'n':n,'M':M,'L':L,'c':c,'min_t':t_needed})

summary = {
    'run': 128,
    'result': 'PASS',
    'assertions': ASSERTIONS,
    'checks': {
        'source_fiber_cover_assignments': cover_cases,
        'cover_tightness_cases': tight_cases,
        'up_singleton_cover_cases': up_singleton_cases,
        'affine_hash_fixed_witness_membership_cases': hash_membership_cases,
        'affine_k_lt_n_no_singleton_bucket_maps': non_singleton_cases,
        'invertible_affine_bucket_cases': injective_bucket_cases,
        'fixed_bucket_probability_cases': probability_cases,
        'dense_relation_arithmetic_assertions': dense_cases,
        'fewp_parameter_cases': len(fewp_cases),
    },
    'theorem_controls': {
        'cover_bound': 'covered_source_witnesses <= t*L*c',
        'UP_source_preserving_special_case': 'L=c=1 => t >= |W_x| for universal all-witness coverage',
        'fixed_bucket_membership': 'Pr[h(w)=0]=2^-k over uniform affine (A,b)',
        't_independent_fixed_buckets': 'Pr[covered]=1-(1-2^-k)^t <= t/2^k',
        'many_to_one_escape': 'bound does not rule out c=|W_x|; that escape is intentionally preserved',
    },
    'probability_examples': prob_examples,
    'fewp_examples': fewp_cases,
    'scope': [
        'finite combinatorial/algebraic validation only',
        'does not prove LWE/evasive-LWE/WPRF hardness',
        'does not establish any QPT security theorem',
        'dense tautology examples are correctness/size controls, not hard-search examples'
    ]
}
print(json.dumps(summary, sort_keys=True, separators=(',',':')))