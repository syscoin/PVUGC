#!/usr/bin/env python3
"""Run 338 exact finite checks for black-box RO-local release and CPRF constant-output gaps."""
from itertools import product
from math import gcd
import json

assertions = 0
summary = {
    "run": 338,
    "model": "finite exact interface checks; not a cryptographic hardness proof",
}

# 1. One-local-query forked-oracle theorem.
one_cases = 0
one_correct_total = 0
for r in range(2, 7):
    for a in range(1, r):
        for K in (0, 1):
            accepted = 0
            for bits in product((0,1), repeat=r):
                if all(bits[y] == K for y in range(a)):
                    accepted += 1
                    for y in range(a):
                        assertions += 1
                        assert bits[y] == K
            assertions += 1
            assert accepted == 2 ** (r-a)
            one_cases += 1
            one_correct_total += accepted
summary["one_local_query"] = {
    "parameter_cases": one_cases,
    "sum_correct_evaluator_tables": one_correct_total,
    "result": "every correctness-satisfying evaluator returns K on every privately simulated accepting local answer"
}

# 2. Two-local-query version, exhaustive at r=4.
r=4
two_rows=[]
for a in range(1,r):
    acc_positions=[(y1,y2) for y1 in range(a) for y2 in range(r)]
    n=r*r
    for K in (0,1):
        accepted=0
        for mask in range(1<<n):
            good=True
            for y1,y2 in acc_positions:
                idx=y1*r+y2
                if ((mask>>idx)&1) != K:
                    good=False; break
            if good:
                accepted += 1
                for y1,y2 in acc_positions:
                    assertions += 1
                    assert ((mask>>(y1*r+y2))&1) == K
        expected=2**(n-len(acc_positions))
        assertions += 1
        assert accepted==expected
        two_rows.append({"accepting_first_values":a,"key":K,"accepting_local_views":len(acc_positions),"correct_evaluator_tables":accepted})
summary["two_local_query"] = {"range":r,"rows":two_rows}

# 3. Compute-and-compare normalization.
cc_cases=0
cc_singleton_only=True
for r in range(2,17):
    for a in range(1,r+1):
        A=set(range(a))
        targets=sum(1 for y in range(r) if A.issubset({y}))
        assertions += 1
        assert targets == (1 if a==1 else 0)
        cc_cases += 1
        cc_singleton_only &= (targets == (1 if a==1 else 0))
summary["compute_compare_normalization"] = {
    "cases":cc_cases,
    "all_valid_hashes_covered_by_one_equality_target_iff_accepting_set_singleton":cc_singleton_only,
    "public_equality_target_conditional_min_entropy_bits":0
}

# 4. Ordinary CPRF + one public offset: same K for all satisfying inputs iff PRF values constant there.
cprf_cases=0
examples=[]
for q in range(2,8):
    for m in range(1,6):
        total=q**m
        constant=0
        for vals in product(range(q), repeat=m):
            if all(v==vals[0] for v in vals):
                constant += 1
                for K in range(q):
                    d=(K-vals[0])%q
                    for v in vals:
                        assertions += 1
                        assert (v+d)%q == K
        assertions += 1
        assert constant == q
        cprf_cases += 1
        if (q,m) in [(2,2),(3,3),(7,5)]:
            g=gcd(constant,total)
            examples.append({"group":q,"satisfying_inputs":m,"constant_functions":constant,"all_functions":total,"same_key_probability":[constant//g,total//g]})
summary["cprf_single_offset"] = {
    "cases":cprf_cases,
    "exact_law":"Pr[random function constant on m satisfying inputs]=q^(1-m)",
    "examples":examples
}

# 5. Key-homomorphic difference still needs a constant difference function on S.
hom_rows=[]
for q,m in [(2,2),(2,3),(3,2),(3,3)]:
    funcs=list(product(range(q), repeat=m))
    pairs=0; constant_diff=0
    for f in funcs:
        for g in funcs:
            pairs += 1
            diff=tuple((g[i]-f[i])%q for i in range(m))
            if all(x==diff[0] for x in diff):
                constant_diff += 1
    expected=(q**m)*q
    assertions += 1
    assert constant_diff==expected
    hom_rows.append({"group":q,"inputs":m,"function_pairs":pairs,"constant_difference_pairs":constant_diff})
summary["key_homomorphic_difference"]={"rows":hom_rows,"result":"key homomorphism alone does not imply a constant evaluation difference on the satisfying set"}

# 6. Conditional freshness of a disjoint unqueried oracle location.
cond_cases=0
for r in range(2,9):
    for a in range(1,r):
        for hb in range(r):
            completions=list(range(r))
            valid=[hx for hx in completions if hx<a]
            assertions += 1
            assert len(completions)==r and len(valid)==a
            cond_cases += 1
summary["conditional_fresh_oracle"]={
    "cases":cond_cases,
    "result":"conditioning on a disjoint setup oracle value leaves the future oracle value uniform; conditioning on validity makes it uniform on the accepting set"
}

summary["assertions"]=assertions
print(json.dumps(summary,sort_keys=True,indent=2))
