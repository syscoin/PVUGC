# SAI97 — Conditional-source oracle coupling repair (NONQUALIFYING)

## Provenance and chosen unfinished equation
Read actual draft syscoin/PVUGC PR #1 at 2d98efdd8e06ceb6878b627a1589d3877663d191, research/pq-wkem-validation-20260918, SAI96 note blob 298f2b6a2e69afef0b98613cb6050425bbda31f3. The targeted issue-comment check since 2026-11-20 returned no new top-level comments. No Core #609 source or Core tests were inspected. Original relation, strict contextual tags, BTC source qualification and maturity, three OR branches, one-honest N-of-N setup and safe native cancel remain unchanged.

SAI96's two-opening polynomial lacked a source-carried secret. Here the exact missing operation is cryptographic binding of *authentic SHA/AuxPoW evidence* to one frozen signature's public release. One proposed source-specific compiler calls a public SHA oracle when evaluating the *entire* original checker, rather than checking merely a target prefix. The claimed repair to SAI94 is to demand correctness only for random-oracle histories conditioned on the honest miner finding qualifying work—not correctness for every arbitrarily modified oracle. I tested this weaker distributional premise directly, jointly with setup/public evaluation.

## Exact conditional-source lemma (restricted oracle model)
Let H:X->Y be a random oracle with independent uniform outputs. Build^H(x,S;r) is classical PPT and makes at most q hash queries TOTAL, including all public setup proofs, manifests and correlated sibling capsules. Let a future source-hash input U be independent of this entire setup query transcript, with maximum conditional point mass 2^-kappa. The candidate source certificate is otherwise already admissible, and its final acceptance is equivalent to H(U) in T(U), a public target set with density p=|T|/|Y|. This last fully qualified source-template premise is NOT established for actual Bitcoin/Syscoin histories or network best-chain membership.

Define H' by copying H at every point except U, and resampling H'(U) uniformly from T(U). For fixed U the COMPLETE table distribution of H' is exactly that of a new independent random oracle G CONDITIONED on G(U) in T(U). Proof: factor the independent product distribution into the coordinate U and all remaining coordinates; the first is uniform conditional on T, all others retain their original uniform law. Crucially, H' is NOT unconditionally uniform.

Assume the public hashed source gate Open^G(C,w) has externally interceptable G queries and useful completeness only in this honest one-shot conditioned-source experiment:

 Pr[Open^G(Build^G(x,S;r),w(U))=S | G(U) in T(U)] >= 1-epsilon.

Couple Build^H and Build^H' on identical r. Before their first U query their oracle answers agree, hence their entire public transcript is identical except with probability <= q*2^-kappa. An adversary who obtains C=Build^H locally simulates Open under H' by answering all H calls honestly except the fresh U call. This extracts S with probability >= 1-epsilon-q*2^-kappa. Meanwhile the real candidate w(U) fails H-target verification except probability p. By a union bound the attacker gets S without this candidate qualifying under real H with probability at least

 1 - epsilon - q*2^-kappa - p.

This is a CLASSICAL attack in this restricted model; it also defeats its QPT target. It does not establish no OTHER qualifying original witness exists, and it does not give a FALSE theorem for an arbitrary original source distribution. For t distinct patched future hash inputs, independently resampling each target output yields the analogous product-conditioned joint law, q*t*2^-kappa union-bound coupling under suitable conditional entropy, and real all-pass probability prod_j p_j. An authenticated ORIGINAL t-certificate realizing those hypotheses has NOT been constructed.

This is a nontrivial reduction in the SAI94 attack premise: no correctness for every possible altered oracle is required. It only assumes correctness in the source sampler's conditioned successful-PoW distribution. It is NOT a source-release advance or generic hash-only impossibility.

## Executed bounded finite distribution checker
Actually executed standard-library Python check.py twice (exit success and byte-identical outputs). A toy 4-point/4-value oracle enumerates all 4^4 tables, chooses t=1 or t=2 distinct future points, reprograms both targets to zero, and counts all preimages of each conditioned table. Each reprogrammed table has exact multiplicity 4^t, proving by census the conditional-distribution equivalence. If setup reads only point zero, probability it avoids selected source points is (4-t)/4; probability it also avoids them while all actual unpatched target checks FAIL is ((4-t)/4)*(3/4)^t, respectively 0.5625 and 0.28125. This is purely a small finite RO distribution experiment, NOT an FE scheme, original SHA/PoW evidence, Bitcoin Core run, native signature, or QPT test.

Checker SHA256 efac9e2bf49d9b3ca106321b2bbb2424fd1000313e6a0786343466eae47208e7; both outputs SHA256 71533675ce769e7d34920782e684f4cc75496d4145634742a1255be50aa31b34. The checker/output bytes are included in this research directory as check.py and output.json.

## Concrete repair screening, still missing
Reject the entire locally reprogrammable HASH-ORACLE-PARAMETRIC source gate under the stated source-template premises, even after changing every-oracle correctness to conditioned-honest-source correctness. External source verification cannot be counted as a protected release. A **concrete SHA256d Boolean circuit cryptographically embedded in a global secret-carrying encoding** is not covered by this oracle interception proof and is the necessary change of model. Merely hardcoding a public SHA routine or a public ZK verifier in unprotected software does NOT prevent bypass. All-input-label hash garbling, publicly accessible polynomial masks, source-independent GGM punctures and locally mixed tensor factors were already rejected in earlier notes; do not retest them without an exact structural repair.

The exact unfinished positive equation remains:
 C=Build_ORIGINAL(x_W,sigma_cancel;rho),
 Open_ORIGINAL(C,w)=sigma_cancel for EVERY qualified ORIGINAL witness w;
with full-public FALSE/hard-TRUE QPT unauthorized recovery/accepted native forgery implying ACTUAL qualifying source evidence or independent justified hash/native break, under malicious source/setup coins and sibling-capsule correlations. The next candidate must supply serialized bytes for an encoded non-black-box GLOBAL source gate and a joint-public simulator, not rename a secret source oracle, public if-check, or inaccessible private interpreter. No new required miner signatures or work condition was added.

NONQUALIFYING research note only; no breakthrough notification or PR comment. No Core/production write, deployment, funds transfer, approval, merge, or automation modification.
