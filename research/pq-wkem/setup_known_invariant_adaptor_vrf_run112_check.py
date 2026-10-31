#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from itertools import product

checks = []

def check(name: str, cond: bool, detail=None) -> None:
    if not cond:
        raise AssertionError(f"{name}: {detail!r}")
    checks.append({"name": name, "detail": detail})

def H(*xs: int, out_bits: int = 16) -> int:
    h = hashlib.sha256("|".join(map(str, xs)).encode()).digest()
    return int.from_bytes(h[:8], "big") & ((1 << out_bits) - 1)

value_only_cases = 0
for q in (5, 7, 11, 13, 17):
    witnesses = {
        x: [w for w in range(q) if (w * w + 3 * w + 1) % q == x]
        for x in range(q)
    }
    for x, ws in witnesses.items():
        if not ws:
            continue
        for rho in range(min(q, 7)):
            public_setup = (q, x, (5 * rho + 2 * x + 1) % q)
            z = H(q, x, rho)

            # Abstract value-only extractor, represented here by an exact finite
            # lookup. The theorem says *any* efficient E with this success
            # property can be composed after Setup; the lookup is only a semantic
            # witness to that composition in the finite test.
            def E(pub, recovered_z):
                qq, xx, _ = pub
                assert qq == q and xx == x and recovered_z == z
                return witnesses[xx][0]

            w = E(public_setup, z)
            check(
                f"value_only_composition_{value_only_cases}",
                (w * w + 3 * w + 1) % q == x,
                (q, x, rho, z, w),
            )
            value_only_cases += 1

prefix_exposure_cases = 0
for q in (17, 31, 61):
    for sk in range(1, min(q, 13)):
        for m in range(1, min(q, 9)):
            for Y in range(min(q, 7)):
                c = H(q, sk, m, Y, out_bits=12) % q
                bar_sigma = (sk * (m + 3 * Y + 5 * c + 1)) % q
                d0 = (7 * c + 2) % q
                pre = (bar_sigma, Y, c, d0)

                def invariant_of_shared_prefix(sigbar, yy, cc):
                    return H(q, sigbar, yy, cc, out_bits=12)

                z_from_pre = invariant_of_shared_prefix(pre[0], pre[1], pre[2])
                K = H(q, sk, m, Y, 999, out_bits=12)
                mask = K ^ z_from_pre

                # Multiple possible adapted openings; invariant ignores the only
                # changing component d.
                for witness_tag in range(4):
                    d = (d0 + (witness_tag + 1) * (Y + 1)) % q
                    full = (bar_sigma, Y, c, d)
                    z_from_full = invariant_of_shared_prefix(full[0], full[1], full[2])
                    check(
                        f"shared_prefix_invariant_{prefix_exposure_cases}_{witness_tag}",
                        z_from_full == z_from_pre,
                        (q, sk, m, Y, pre, full),
                    )
                    # Anyone seeing pre can recover the one-mask K immediately.
                    recovered = mask ^ invariant_of_shared_prefix(pre[0], pre[1], pre[2])
                    check(
                        f"shared_prefix_early_key_{prefix_exposure_cases}_{witness_tag}",
                        recovered == K,
                        (K, recovered),
                    )
                prefix_exposure_cases += 1

vrf_shape_cases = 0
for p in (17, 29, 61):
    for s in range(1, min(p, 10)):
        for mu in range(1, min(p, 8)):
            b = H(p, mu, out_bits=12) % p
            v = (b * s) % p
            proofs = []
            for nonce in range(6):
                # Non-unique proof encoding with a deterministic tag binding v.
                tag = H(p, mu, v, nonce, out_bits=12)
                pi = (nonce, tag)
                proofs.append(pi)
                check(
                    f"vrf_proof_accept_{vrf_shape_cases}_{nonce}",
                    pi[1] == H(p, mu, v, pi[0], out_bits=12),
                    (p, s, mu, v, pi),
                )
            check(
                f"vrf_proofs_nonunique_{vrf_shape_cases}",
                len(set(proofs)) == len(proofs),
                proofs,
            )
            # All proofs correspond to the same value v by construction.
            vals = {v for _ in proofs}
            check(f"vrf_value_singleton_{vrf_shape_cases}", vals == {v})
            vrf_shape_cases += 1

same_key_cases = 0
for k_bits in (8, 12, 16):
    maskmod = (1 << k_bits) - 1
    for statement in range(32):
        v = H(statement, 112, out_bits=k_bits)
        K = H(statement, 777, out_bits=k_bits)
        C = K ^ v
        # Treat 1..5 as syntactically distinct valid witnesses. They receive the
        # same v only because this block is testing the *conditional interface*.
        outs = [C ^ v for _w in range(1, 6)]
        check(
            f"same_key_if_common_value_{same_key_cases}",
            all(out == K for out in outs) and K <= maskmod,
            (statement, v, K, outs),
        )
        same_key_cases += 1

process_separation_cases = 0
for z in range(16):
    for trace_a, trace_b in (("source-mode", "hardness-mode"), ("left", "right")):
        output_a = z
        output_b = z
        check(
            f"same_output_different_process_{process_separation_cases}",
            output_a == output_b and trace_a != trace_b,
            (z, trace_a, trace_b),
        )
        # A value-only map has identical input on both executions.
        value_only_input_a = (z,)
        value_only_input_b = (z,)
        check(
            f"value_only_cannot_observe_trace_{process_separation_cases}",
            value_only_input_a == value_only_input_b,
            (value_only_input_a, value_only_input_b),
        )
        process_separation_cases += 1

out = {
    "run": 112,
    "status": "PASS",
    "total_assertions": len(checks),
    "value_only_extraction": {
        "cases": value_only_cases,
        "claim": "If witness-free setup computes z and an extractor given only public setup plus z returns a source witness, setup can invoke that extractor itself. The finite test validates the composition identity, not hardness."
    },
    "generic_adaptor_prefix_exposure": {
        "cases": prefix_exposure_cases,
        "claim": "For the 2024 generic adaptor syntax pre=(bar_sigma,Y,c,d0), full=(bar_sigma,Y,c,d), any public invariant of the unchanged prefix (bar_sigma,Y,c) is already computable from pre; one-mask keying by that invariant is therefore early-recoverable."
    },
    "vrf_common_value_shape": {
        "cases": vrf_shape_cases,
        "claim": "A unique/deterministic value can coexist with many randomized proof encodings; this is a canonicalization shape only, not a security proof."
    },
    "conditional_same_key": {
        "cases": same_key_cases,
        "claim": "If every valid witness can obtain the same hidden value v, C=K xor v gives exact all-witness same-key correctness. The missing witness-gated evaluator is intentionally not implemented."
    },
    "process_vs_value_extraction": {
        "cases": process_separation_cases,
        "claim": "The recovered value alone does not encode how it was obtained; a valid source-extraction reduction may need adversary code/trace/oracle behavior rather than only the final value."
    },
    "scope": [
        "Deterministic finite semantic/algebra checks only; no computational security is inferred.",
        "The 2024 adaptor shared-prefix claim is a syntactic consequence of the published generic construction; the checker models that syntax rather than re-proving the paper's security theorem.",
        "The VRF block checks only unique-value/non-unique-proof shape. It does not implement Esgin et al.'s lattice VRF and does not establish QPT/QROM security.",
        "Run 112 does not construct the missing witness-gated public evaluator."
    ]
}
print(json.dumps(out, indent=2, sort_keys=True))
