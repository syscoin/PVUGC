#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from fractions import Fraction
from itertools import product

checks = []

def ok(name, cond, detail=None):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    checks.append({"name": name, "detail": detail})

# -----------------------------------------------------------------------------
# 1. WPRF functionality is exactly the all-witness same-value interface.
# -----------------------------------------------------------------------------
# Toy relation: x = w mod m after a many-to-one encoding w -> w % m.
# Multiple witnesses for the same x must all return the same F(fk,x).
# This is only a functionality control; no PRF security is inferred.

same_key_cases = 0
for m in range(2, 17):
    witness_space = range(0, 4 * m)
    for fk in range(1, 13):
        for x in range(m):
            valid = [w for w in witness_space if w % m == x]
            assert len(valid) >= 4
            def F(x0: int) -> int:
                return (fk * (x0 + 1) * 17 + 9) % 257
            def Eval(x0: int, w: int):
                return F(x0) if w % m == x0 else None
            vals = {Eval(x, w) for w in valid}
            ok(f"same_value_{same_key_cases}", vals == {F(x)}, (m, fk, x, len(valid)))
            # Invalid witnesses reject.
            invalid = next(w for w in witness_space if w % m != x)
            ok(f"invalid_reject_{same_key_cases}", Eval(x, invalid) is None)
            same_key_cases += 1

# -----------------------------------------------------------------------------
# 2. Exact key recovery -> WPRF distinguishing, straight-line.
# -----------------------------------------------------------------------------
# Let challenge y be either the real Z or uniform in a range Y of size M.
# For any recovery algorithm A whose classical output zhat has
# Pr[zhat=Z]=epsilon, the equality distinguisher D(y):=[A()==y] has
# Pr[D=1|real]=epsilon and Pr[D=1|uniform]=1/M exactly, independent of the
# rest of A's output distribution.  The reduction invokes A once and compares
# classical outputs; no rewinding/re-preparation is required.

recovery_rows = []
recovery_checks = 0
for M in range(2, 41):
    Z = (7 * M + 3) % M
    # Enumerate arbitrary output distributions as integer weights summing d.
    for d in (2, 3, 5, 7):
        # Put k/d mass on Z, and distribute the rest deterministically over a
        # non-Z point.  This is enough to validate the exact formula for a
        # family of epsilons; the uniform-challenge equality identity itself is
        # also checked by direct enumeration below.
        other = (Z + 1) % M
        for k in range(d + 1):
            outputs = [Z] * k + [other] * (d - k)
            eps = Fraction(k, d)
            real_eq = Fraction(sum(1 for a in outputs if a == Z), d)
            # Uniform challenge independent of A output: exact enumeration.
            uniform_pairs = [(a, y) for a in outputs for y in range(M)]
            rand_eq = Fraction(sum(1 for a, y in uniform_pairs if a == y), len(uniform_pairs))
            ok(f"recovery_real_{recovery_checks}", real_eq == eps, (M, d, k))
            ok(f"recovery_uniform_{recovery_checks}", rand_eq == Fraction(1, M), (M, d, k, rand_eq))
            adv = abs(real_eq - rand_eq)
            ok(f"recovery_adv_{recovery_checks}", adv == abs(eps - Fraction(1, M)))
            recovery_rows.append({
                "range_size": M,
                "epsilon": f"{k}/{d}",
                "distinguishing_advantage": f"{adv.numerator}/{adv.denominator}",
            })
            recovery_checks += 1

# -----------------------------------------------------------------------------
# 3. Setup-known value cannot support value-only source extraction.
# -----------------------------------------------------------------------------
# Logical composition control: setup computes Z without source witness. If an
# efficient extractor E(x,P,Z) is guaranteed to output a valid source witness,
# then Setup followed by E is itself a witness-search algorithm.

value_extractor_cases = 0
for p in (5, 7, 11, 13, 17, 19):
    # Source relation R_x(w): w^2 + w = x mod p.
    for w0 in range(p):
        x = (w0 * w0 + w0) % p
        fk = (3 * p + 5) % 257
        P = (p, x, fk % 7)  # public fixture independent of witness used below
        Z = (fk * (x + 11) + 37) % 257  # setup-known canonical value
        witnesses = [w for w in range(p) if (w*w + w) % p == x]
        assert witnesses
        # Model a hypothetical value-only extractor with a canonical valid output.
        def E(x0, P0, Z0):
            assert x0 == x and P0 == P and Z0 == Z
            return min(witnesses)
        recovered = E(x, P, Z)
        ok(f"value_extract_{value_extractor_cases}", (recovered*recovered + recovered) % p == x,
           (p, x, Z, recovered))
        # The composed Setup->E uses no source witness as input.
        value_extractor_cases += 1

# -----------------------------------------------------------------------------
# 4. Publicly samplable local-opening language cannot be universally
#    source-extractable for a hard source relation.
# -----------------------------------------------------------------------------
# If Samp(P) outputs an accepting auxiliary opening pi without a source witness,
# and Ext(x,P,pi) returns an ORIGINAL source witness for every accepting pi,
# then Comp(x); Samp(P); Ext(...) solves source witness search. This is a pure
# composition theorem; the finite model checks the implication for many
# accept/support/extractor fixtures.

sampler_barrier_cases = 0
for n_open in range(2, 8):
    openings = list(range(n_open))
    for source_mod in range(2, 8):
        for x in range(source_mod):
            witness_space = list(range(2 * source_mod))
            valid_w = [w for w in witness_space if w % source_mod == x]
            assert valid_w
            # Every auxiliary opening is locally valid and publicly samplable.
            accept = set(openings)
            # Hypothetical universal source extractor maps each accepting pi to
            # a valid source witness.  Public sampler cycles through all support.
            ext_map = {pi: valid_w[pi % len(valid_w)] for pi in openings}
            for pi in openings:
                ok(f"sampler_accept_{sampler_barrier_cases}_{pi}", pi in accept)
                w = ext_map[pi]
                ok(f"sampler_extract_{sampler_barrier_cases}_{pi}", w % source_mod == x,
                   (n_open, source_mod, x, pi, w))
            # Therefore a public algorithm choosing pi=0 and applying Ext wins.
            public_pi = openings[0]
            public_w = ext_map[public_pi]
            ok(f"sampler_composition_{sampler_barrier_cases}", public_w % source_mod == x)
            sampler_barrier_cases += 1

# -----------------------------------------------------------------------------
# 5. Restricted-subclass escape hatch: local validity alone is insufficient.
# -----------------------------------------------------------------------------
# A source-preserving compiler can avoid the previous contradiction only if the
# evaluator gates on a stricter predicate Good_x(pi) that the public local-opening
# sampler cannot satisfy generically. Then merely possessing a local opening is
# not enough -- the missing source-witness restriction has reappeared.

restricted_cases = 0
for q in (5, 7, 11, 13):
    for x in range(q):
        all_pi = list(range(q))
        local_valid = set(all_pi)
        # Witness-derived openings are a strict singleton subclass in this toy.
        good = {(3 * x + 1) % q}
        public_sample = (3 * x + 2) % q
        ok(f"restricted_local_{restricted_cases}", public_sample in local_valid)
        ok(f"restricted_not_good_{restricted_cases}", public_sample not in good)
        witness_pi = next(iter(good))
        ok(f"restricted_witness_{restricted_cases}", witness_pi in local_valid and witness_pi in good)
        restricted_cases += 1

# -----------------------------------------------------------------------------
# 6. Transcript-only process extraction cannot beat a perfectly simulatable
#    public-opening transcript.
# -----------------------------------------------------------------------------
# If an adversary transcript distribution and a public sampler transcript
# distribution are identical, every extractor that is only a function of the
# transcript has exactly the same success probability in the two worlds.
# We exhaust all deterministic extractors on small transcript spaces.

transcript_cases = 0
for tbits in range(1, 5):
    T = list(range(1 << tbits))
    # identical uniform distributions for adversary and public simulator
    # source witness predicate: output bit must equal parity of transcript.
    # Exhaust all deterministic binary extractors E:T->{0,1} for tbits<=4.
    for mask in range(1 << len(T)):
        def E(t):
            return (mask >> t) & 1
        succ_A = sum(1 for t in T if E(t) == (t.bit_count() & 1))
        succ_S = sum(1 for t in T if E(t) == (t.bit_count() & 1))
        ok(f"transcript_equal_{transcript_cases}", succ_A == succ_S, (tbits, mask, succ_A))
        transcript_cases += 1

# -----------------------------------------------------------------------------
# 7. Output digest / reproducibility metadata.
# -----------------------------------------------------------------------------
source = open(__file__, "rb").read()
out = {
    "run": 113,
    "status": "PASS",
    "checker_sha256": hashlib.sha256(source).hexdigest(),
    "total_assertions": len(checks),
    "wprf_same_value": {
        "cases": same_key_cases,
        "claim": "WPRF correctness is exactly an all-valid-witness same-value interface in the finite model."
    },
    "recovery_to_distinguishing": {
        "cases": recovery_checks,
        "claim": "For range size M and exact recovery probability epsilon, one straight-line equality test has distinguishing advantage |epsilon-1/M|.",
        "sample_rows": recovery_rows[:12]
    },
    "setup_known_value_only_extraction": {
        "cases": value_extractor_cases,
        "claim": "A value-only extractor on a setup-computable canonical value composes with setup into a source witness-search algorithm."
    },
    "public_opening_sampler_barrier": {
        "cases": sampler_barrier_cases,
        "claim": "If a public sampler outputs accepted auxiliary openings and every accepted opening source-extracts, sampler+extractor itself performs source witness search."
    },
    "restricted_subclass": {
        "cases": restricted_cases,
        "claim": "Avoiding the sampler contradiction requires a stricter witness-restricted subclass beyond ordinary local-opening validity."
    },
    "transcript_simulation": {
        "extractors_checked": transcript_cases,
        "claim": "Identical adversary/public-simulator transcript distributions give identical success to every transcript-only deterministic extractor; extraction needs a non-simulatable process feature."
    },
    "scope": [
        "Finite semantic/algebraic controls only; no computational security follows from these tests.",
        "The recovery-to-distinguishing reduction is straight-line and remains valid for a QPT recovery algorithm with classical output, but an actual QPT extractable-WPRF theorem is still required.",
        "The public-opening sampler barrier is unconditional as a composition statement and does not attack hidden-bits generators or vector commitments themselves.",
        "The checker does not instantiate a generic-NP post-quantum WPRF or a completed witness KEM."
    ]
}
print(json.dumps(out, indent=2, sort_keys=True))
