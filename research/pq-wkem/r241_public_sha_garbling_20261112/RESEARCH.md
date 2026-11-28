# R241 — SHA source-garbled public input labels, candidate and repair

**NONQUALIFYING: no real original-source Build/Open, no QPT security, no deployed Bitcoin/Syscoin verifier.** This is a concrete constructed and falsified hash-only static gate-garbling family, not a general impossibility claim.

## Provenance

PVUGC PR #1, research/pq-wkem-validation-20260918, observed starting head 213d39610d81ead0ee00c23cfb2f4a2abb1c9e14, R240 minimal count correction; its parent bf66ef164554c4d05620a6971d51d74cfb0fea2f. Read R240 research blob e0e5a57bfa9bba8cad8c5bf52bdbfd01bd3df2ad and R239 single-source-pad note. Latest fetched ordinary PR comment since 2026-11-11T11:00Z: substantive R225. Core #609 verified activated canonical tag/modern child chain ID applies; Core PR head seen c91539de3c34937e57d7f5fda47c7b0502ff33f6. No Core write, general web/literature search, source mining or production tests.

Local CHECKPOINT_01.md recorded prior to experiments, SHA256 0f20eb1a36d9ed3e4432b476ba7b010df8b9f7bdb45e908f3924f42b8335eae7. Local full checker.py SHA256 9e526470998b951c54c45eef408a16db6f6bcf434c57882df0deeef4d92d1dfd executed twice, 18 explicit assertions, identical captured.json SHA256 0dfa42e4c4eeebd2d9fa56b0cfb7df836272a9cefd12990562c22f4f03e0ca7c. Full local note SHA256 a09639d76895ccf45e1136909464fa7618fa62ac58c7502d9772da28461c335b. Separately executed minimal checker_min.py twice with identical captured_min.json; local SHA256 260ce2de7b17bf0d7a8ad27a03686462a90c6146b57cbbd5d3fa7f773160b50f, captured 105ea2f5d583eb7776ffee14ff9bcb6391ef5ee5c5cbfb40d5ffe05b385a0efd. Local-only expanded checker is not a real source validator, quantum attack or deployed native signer.

## Original bridge relation is not replaced

One notary activates delayed withdrawal; ANYONE with ORIGINAL qualifying authenticated evidence challenges. OR branches: stronger relevant competing BTC accumulated work, finite authenticated burn fault, or qualified post-activation Syscoin claim-prefix/ancestor inconsistency/tag fault. Bind exact claim/UTXO, baseline, burn/recipient/amount, BTC source anchors/window and canonical contextual AuxPoW, child ID/tag/height/ancestry, fork depth, deadline, activation, native cancellation message/VK and capsule ID. N-of-N preauthorization is separate. Bitcoin receives only native intended cancellation signatures. No winner-decision or greater Syscoin work is required for qualified inconsistency. R225 native slot-global versus activation-specific portability remains unresolved.

## Candidate G241 — public SHA-garbled original-source verifier

Let F_x(w) be the Boolean verifier for the actual original relation. Offline builder holds frozen native cancellation contribution sigma and for each circuit wire v samples independently two private 128-bit labels L[v,0],L[v,1]. Each gate g publishes a SHA256-padded and authenticated table of output labels. For a binary gate row (i,j):

    T_g[i,j] = L[out, g(i,j)] XOR trunc128 SHA256(domain || g || L[in1,i] || L[in2,j]).

Unary gates likewise publish two rows, with separately domain-separated row-authentication tags. Publish c = sigma XOR trunc128 SHA256("seal"||L[out,1]). An honest Open on an actual qualifying source w should acquire only one label per original witness input and evaluate the fixed circuit, yielding the *same* accepting output label/sigma for every such witness.

The immediate missing operation is PublicInputLabel(C,w,i,w_i) for unknown, permissionlessly chosen future SHA/AuxPoW evidence, without giving out both labels or letting a fabricated w obtain acceptance. Merely placing the source verifier in the circuit cannot secure the public input-label distribution.

## Exact full-public FALSE attack

For unsatisfiable circuit F(x) = x AND NOT(x), honest evaluation on either input returns output-0. Publishing both labels for x (or making both retrievable from public source-independent data) gives a classical attacker:

1. Evaluate NOT using x=0 and obtain the label for NOT(x)=1.
2. Independently use the x=1 label as the first input to final AND.
3. Evaluate AND on (x=1, NOT(x)=1), obtaining terminal output-1 label, even though this combination comes from mutually inconsistent full assignments.
4. Recover sigma = c XOR trunc128 SHA256("seal"||L[out,1]).

No global x satisfies F. This is a straight-line public classical recovery without a source certificate, SHA inversion, a requested internal representation or honest Open call. Classical PPT attacks imply failure against arbitrary QPT as well. The checker builds actual SHA256 gate-pad ciphertexts/row checks and reproduces this. An independently evaluated satisfiable toy F(x,y)=x AND y OR x AND NOT(y) opens the exact same frozen sigma for the two distinct valid inputs (1,0), (1,1), demonstrating only correct terminal convergence, not hiding.

## Repair attempt: one global source-root-conditioned label family

Try labels L[i,b](rho) = trunc128 SHA256(domain || rho || i || b), with rho an authenticated complete source root. A single fixed offline gate table made for rho0 rejects labels for another future authentic rho1: every-original-witness completeness fails. The local checker verifies this for two synthetic SHA roots. Publishing both labels for rho0 still allows the same inconsistent-x attack entirely within rho0. A root hash is a consistency commitment, not a source-dependent secret. Publishing tables for all unknown future roots is not polynomial; providing a public programmable table generator with hidden output labels would require the *missing protected source-dependent compiler*, and is not instantiated by SHA root binding. A secret salt not derivable from public source evidence adds a forbidden online issuer. Do not relabel this as generic WE impossibility.

This differs from R240 directed graph-edge telescoping and R239 one-source-pad failure: this experiment targets a SHA-based static Boolean circuit with public gates and shows an exact fanout-occurrence label-mixing attack. The repair's all-future-source-root correctness failure remains unaddressed.

## Reproducibility, model and next equation

Run python3 checker_min.py; published captured_min.json records five asserted source-garbling properties, not BTC/SYS consensus/QPT. Full local checker recorded 18 assertions and same-sigma behavior for two toy satisfying witnesses. All public labels/tables and ciphertext are visible to attacker. The frozen native signature is opaque synthetic bytes; no real SLH signing or PQ-UTXO endpoint test. No quantum oracle security theorem, no native forgery reduction, no malicious setup/multi-capsule composition or source authentication was performed.

The exact OPEN equation remains unbuilt:

    Build_inc(x_W, sigma_cancel) -> C, classical PPT, before future source witnesses
    Open_inc(C, w) = SAME sigma_cancel for EVERY ORIGINAL qualifying w.

Full-public arbitrary QPT unauthorized final-key recovery or accepted native forgery must imply an ACTUAL ORIGINAL relevant BTC/Syscoin/burn certificate or an independent justified PQ hash/native break, with sibling capsules, checking/VK correlations, malicious source coins, selective opens and N-of-N setup. Public source-root commitments, fake source flags, ideal release oracles, source-signer secrets, independent PoW, on-chain NP verifier or exponential precomputed state tables do not meet it. G241 is rejected; no routine progress comment warranted.