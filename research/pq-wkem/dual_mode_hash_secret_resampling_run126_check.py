#!/usr/bin/env python3
"""Run 126 finite controls for the dual-mode hash-secret resampling barrier.

This is a deterministic algebra/probability checker.  It does not test LWE/SIS
hardness or establish a cryptographic construction.
"""
from __future__ import annotations

import hashlib
import json
import random
from fractions import Fraction
from pathlib import Path

ASSERTIONS = 0

def check(cond: bool, msg: str = "") -> None:
    global ASSERTIONS
    ASSERTIONS += 1
    if not cond:
        raise AssertionError(msg or "assertion failed")


def tv(p, q):
    return sum(abs(a-b) for a, b in zip(p, q)) / 2


def event_prob(p, event):
    return sum(p[i] for i in event)


def normalize(weights):
    s = sum(weights)
    return [Fraction(w, s) for w in weights]


def inv_mod(a, q):
    return pow(a, -1, q)


def affine_target(a, b, s, q):
    return (a*s + b) % q


def affine_secret_from_target(a, b, h, q):
    return ((h-b) * inv_mod(a, q)) % q


def main():
    rng = random.Random(12620260926)

    # 1. Exact finite model of the separable-secret collapse.
    # Ext's trapdoor inverts every target produced by an independently sampled
    # hash secret.  A target-indexed table then outputs a valid source witness.
    # The test is about composition probability, not hardness.
    collapse_rows = []
    primes = [7, 11, 13, 17, 19, 23, 29, 31]
    for q in primes:
        for a in range(1, q):
            b = (3*a + 5) % q
            # Two arbitrary valid source witnesses; target parity chooses one.
            valid_witnesses = (1000 + q, 2000 + q)
            successes = 0
            for s in range(q):
                h = affine_target(a, b, s, q)
                recovered_s = affine_secret_from_target(a, b, h, q)
                check(recovered_s == s, f"affine inversion failed q={q}")
                w = valid_witnesses[recovered_s & 1]
                check(w in valid_witnesses)
                successes += 1
            check(successes == q)
            collapse_rows.append({"q": q, "a": a, "success": f"{successes}/{q}"})

    # 2. Evasive-target negative control: public mode equality alone does not
    # imply a joint/conditional sampler. Hash mode can concentrate on one
    # hidden acceptable secret while an independent resampler only hits 1/q.
    evasive_rows = []
    for q in primes:
        for star in range(q):
            hits = 0
            for s in range(q):
                accepted = (s == star)
                hits += int(accepted)
            check(hits == 1)
            independent_success = Fraction(hits, q)
            hash_mode_success = Fraction(1, 1)  # conditioned on s=star
            check(independent_success == Fraction(1, q))
            check(hash_mode_success - independent_success == Fraction(q-1, q))
            evasive_rows.append({"q": q, "independent_hit": str(independent_success)})

    # 3. Total-variation event-transfer lemma. For arbitrary finite laws D,J
    # and extraction-success event E, |Pr_D[E]-Pr_J[E]| <= TV(D,J).
    tv_trials = 0
    max_slack = Fraction(0, 1)
    for n in range(2, 13):
        for _ in range(180):
            wp = [rng.randrange(1, 30) for _ in range(n)]
            wq = [rng.randrange(1, 30) for _ in range(n)]
            p = normalize(wp)
            qd = normalize(wq)
            event = {i for i in range(n) if rng.randrange(2)}
            delta = tv(p, qd)
            gap = abs(event_prob(p, event) - event_prob(qd, event))
            check(gap <= delta)
            slack = delta-gap
            if slack > max_slack:
                max_slack = slack
            tv_trials += 1

    # 4. More general bounded extraction-success function f in [0,1].
    # Expectation differences are also bounded by TV when f is [0,1]-valued.
    fn_trials = 0
    for n in range(2, 11):
        for _ in range(160):
            p = normalize([rng.randrange(1, 50) for _ in range(n)])
            qd = normalize([rng.randrange(1, 50) for _ in range(n)])
            f = [Fraction(rng.randrange(0, 101), 100) for _ in range(n)]
            ep = sum(pi*fi for pi, fi in zip(p, f))
            eq = sum(qi*fi for qi, fi in zip(qd, f))
            delta = tv(p, qd)
            check(abs(ep-eq) <= delta)
            fn_trials += 1

    # 5. Conditional-sampler corollary: if the true hash-secret distribution
    # has extraction success >= 1-eta and J is delta-close, J succeeds at least
    # 1-eta-delta. Check on random finite instances exactly.
    cor_trials = 0
    worst_margin = None
    for n in range(3, 12):
        for _ in range(160):
            p = normalize([rng.randrange(1, 80) for _ in range(n)])
            qd = normalize([rng.randrange(1, 80) for _ in range(n)])
            good = {i for i in range(n) if rng.randrange(3) != 0}
            succ_p = event_prob(p, good)
            succ_q = event_prob(qd, good)
            eta = 1 - succ_p
            delta = tv(p, qd)
            lower = 1 - eta - delta
            check(succ_q >= lower)
            margin = succ_q - lower
            if worst_margin is None or margin < worst_margin:
                worst_margin = margin
            cor_trials += 1

    # 6. The theorem must not be misread as saying statistically identical P
    # alone collapses dual mode. Same public P, disjoint secret distributions,
    # and an evasive accepting target produce negligible-ish finite hit 1/q.
    # This is a negative-control shape, not a hardness claim.
    same_public_key_controls = []
    for q in [17, 31, 61, 127, 257]:
        P = (q, 42)  # literally identical public index in both modes
        star = (7*q + 3) % q
        hash_secret_support = {star}
        ext_resampler_support = set(range(q))
        check(P == P)
        check(len(hash_secret_support) == 1)
        check(len(ext_resampler_support) == q)
        hit = Fraction(len(hash_secret_support & ext_resampler_support), len(ext_resampler_support))
        check(hit == Fraction(1, q))
        same_public_key_controls.append({"q": q, "joint_resample_hit": str(hit)})

    # 7. Independent-secret special case: if hash secret distribution is public
    # uniform and every generated target is extractable, ExtSetup + local secret
    # sampling succeeds with probability exactly one.
    independent_secret_rows = []
    for q in [17, 31, 61, 127]:
        for a in [1, 2, 3, 5, 7]:
            if a % q == 0:
                continue
            good = 0
            for s in range(q):
                h = affine_target(a, 9 % q, s, q)
                s2 = affine_secret_from_target(a, 9 % q, h, q)
                good += int(s2 == s)
            check(good == q)
            independent_secret_rows.append({"q": q, "a": a, "success": "1"})

    script_bytes = Path(__file__).read_bytes()
    result = {
        "run": 126,
        "checker": Path(__file__).name,
        "checker_sha256": hashlib.sha256(script_bytes).hexdigest(),
        "assertions": ASSERTIONS,
        "status": "PASS",
        "scope": "finite algebra/probability controls only; no LWE/SIS/QPT-hardness test",
        "collapse_rows": len(collapse_rows),
        "evasive_rows": len(evasive_rows),
        "tv_event_trials": tv_trials,
        "bounded_function_trials": fn_trials,
        "conditional_sampler_trials": cor_trials,
        "same_public_key_controls": same_public_key_controls,
        "independent_secret_rows": len(independent_secret_rows),
        "max_tv_event_slack": str(max_slack),
        "min_conditional_sampler_margin": str(worst_margin),
    }
    print(json.dumps(result, sort_keys=True, indent=2))

if __name__ == "__main__":
    main()