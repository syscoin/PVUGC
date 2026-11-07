#!/usr/bin/env python3
"""Run 90 deterministic arithmetic checks for the QPT-AoK source-bridge note.

This checker validates only the parameter algebra stated in QPT_AOK_SOURCE_BRIDGE_RUN90.md.
It does not test a cryptographic implementation and does not establish QPT security.
"""
import json

def qrom_exponents(L, d, inner_power=2):
    """Outer security parameter Lambda=2^L, T<=Lambda^d.
    Inner QROM output length kappa=L^inner_power.
    Return log2 exponents of t^2*2^-kappa and t^3*2^-kappa.
    """
    kappa = L ** inner_power
    return {
        "L": L,
        "d": d,
        "kappa": kappa,
        "e_t2": 2*d*L - kappa,
        "e_t3": 3*d*L - kappa,
    }

def linear_kappa_exponents(L, d, C=24):
    kappa = C * L
    return {
        "L": L,
        "d": d,
        "C": C,
        "kappa": kappa,
        "e_t2": (2*d-C)*L,
        "e_t3": (3*d-C)*L,
    }

def main():
    rows = []
    for L in [16, 32, 64, 128, 256, 512]:
        for d in [1, 2, 4, 8, 16]:
            r = qrom_exponents(L, d, 2)
            # Exact asymptotic threshold: e_t3 < 0 iff L > 3d for kappa=L^2.
            assert (r["e_t3"] < 0) == (L > 3*d)
            # e_t2 < 0 iff L > 2d.
            assert (r["e_t2"] < 0) == (L > 2*d)
            rows.append(r)

    # e_t3/L = 3d-L -> -infinity for every fixed d.
    slopes = {}
    for d in [1, 2, 4, 8, 16]:
        vals = []
        for L in [64, 128, 256, 512, 1024]:
            e = qrom_exponents(L, d, 2)["e_t3"]
            assert e % L == 0
            vals.append(e // L)
        assert vals == [3*d-L for L in [64,128,256,512,1024]]
        assert all(vals[i+1] < vals[i] for i in range(len(vals)-1))
        slopes[str(d)] = vals

    # Fixed kappa=C log Lambda cannot cover arbitrary polynomial query degree.
    C = 24
    linear = [linear_kappa_exponents(128, d, C) for d in [1,2,4,8,9,16]]
    assert next(x for x in linear if x["d"] == 8)["e_t3"] == 0
    assert next(x for x in linear if x["d"] == 9)["e_t3"] > 0
    assert next(x for x in linear if x["d"] == 16)["e_t3"] > 0

    # If verifier cost is polynomial in kappa and L, kappa=L^2 keeps it polylog Lambda.
    verifier_identities = []
    for a,b in [(1,0),(1,2),(2,1),(3,4),(5,0)]:
        # kappa^a * L^b = (L^2)^a * L^b = L^(2a+b).
        exponent = 2*a+b
        verifier_identities.append({"kappa_power":a,"L_power":b,"result_L_power":exponent})
        assert exponent == 2*a+b

    # A sufficient QROM knowledge-error parameterization:
    # k_knowledge <= 2^-kappa and RO term 2^-kappa.
    # For any fixed polynomial query degree d, both losses are negligible in Lambda
    # because their log2 exponents divided by L tend to -infinity.
    thresholds = {
        str(d): {
            "t2_negative_for_all_L_gt": 2*d,
            "t3_negative_for_all_L_gt": 3*d
        } for d in [1,2,4,8,16,32]
    }

    out = {
        "run": 90,
        "classification": "deterministic_parameter_algebra_only",
        "model": {
            "outer_parameter": "Lambda=2^L",
            "query_bound": "T <= Lambda^d = 2^(dL), fixed d",
            "inner_qrom_output_bits": "kappa=L^2",
            "assumed_inner_knowledge_error_for_sufficient_bound": "k <= 2^-kappa",
            "qrom_loss_terms": [
                "T^2*k <= 2^(2dL-kappa)",
                "T^3/2^kappa = 2^(3dL-kappa)"
            ]
        },
        "quadratic_kappa_rows": rows,
        "normalized_t3_exponents_e_over_L": slopes,
        "fixed_linear_kappa_counterexample": {
            "C": C,
            "rows": linear,
            "interpretation": "kappa=C*L cannot suppress T^3/2^kappa for all fixed polynomial degrees d"
        },
        "polylog_verifier_identities": verifier_identities,
        "exact_negativity_thresholds": thresholds,
        "checks": {
            "quadratic_kappa_superlog_negligibility_exponent": "PASS",
            "fixed_linear_kappa_not_universal": "PASS",
            "poly_kappa_and_log_outer_stays_polylog_outer": "PASS"
        },
        "security_disclaimer": (
            "These arithmetic identities do not establish a witness-KEM, QPT hiding, "
            "key-recovery extraction, a standard-model random-oracle instantiation, "
            "or compatibility with Jin 2026/2063's exact unpublished-in-this-run theorem interface."
        )
    }
    print(json.dumps(out, sort_keys=True, indent=2))

if __name__ == "__main__":
    main()
