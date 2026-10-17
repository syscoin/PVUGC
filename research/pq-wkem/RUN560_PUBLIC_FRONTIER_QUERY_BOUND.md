# Run 560 — public-checkable frontier-width quantum-search bound

Date: 2026-10-16. New research only for draft syscoin/PVUGC#1. Verified starting SHA 25fdffe787d7c53ae1b4cfe986911cd8c5e9ae23.

## New bounded lemma

Fix an honestly generated classical-PPT public release capsule and exactly bound statement x, including relation, claim/UTXO, branch, BTC/SYS anchors, windows, and native signature verification key. Assume the *entire accepted input interface* of a public deterministic evaluator L_x(s;r) consists of ell-bit state s and rho bits of freely selectable **public coins** r. There is no hidden external witness/authority/token elsewhere; if one exists it must be counted in the actual accepted input interface. Assume an efficient public predicate B_x(candidate), such as a signing-key-to-verification-key check or verification of an intended native branch signature, whose success really authorizes the intended path. Every classical-PPT algorithm here, including checking, can be run reversibly in superposition by an arbitrary QPT attacker given its public circuit.

Suppose D distinct witness-dependent states s_i, each produced by some valid ORIGINAL witness, satisfy Pr_r[B_x(L_x(s_i;r))=1] >= p for p>0. The states need not be canonical, uniformly distributed, or mutually related. Set N=2^(ell+rho) and M=number of state/coin pairs accepted by B_x. Counting disjoint s_i gives:

M >= D*p*2^rho;  M/N >= D*p/2^ell.

Uniform independent classical chosen-input trials return a usable credential in expected at most 2^ell/(D*p) trials. A coherent attacker constructs a clean marking oracle for B_x(L_x(s;r)) by reversible execution and uncomputation, then uses amplitude amplification or unknown-solution-count quantum search. It recovers some accepted pair in expected O(sqrt(2^ell/(D*p))) public oracle calls, with standard success amplification. The rho extra public randomness bits *cancel* from this ratio; rerandomization alone is no protection. If ell-log2(D)=O(log lambda) and p>=1/poly(lambda), this is a PPT attack already, not merely an exponential Grover attack. For larger ell the method is an exponential-query concrete bound, NOT an asymptotic QPT break.

In the ideal unit-cost coherent-query model with p=1, the quantum work exponent is (ell-log2 D)/2. For 128 query-bit resistance against this one attack, ell needs at least 256+log2 D: ell=256 with D=2^64 gives approximately 2^96 oracle calls; ell=320 with D=2^64 gives 2^128. These are **not** physical quantum gate costs, resource benchmarks, or sufficient concrete security conditions. Arbitrary structural attacks could be faster. Extra distinct valid states can only make generic chosen-state search easier.

The bound also applies to ideal black-box execution of a correctly functional local mixer: hiding the program internals does not remove accepting inputs when anyone may evaluate the public function. It neither refutes iO/RIO nor asserts a new primitive.

## Boundaries and source extraction

For ORIGINAL-false statements the lemma makes no positive hiding claim: there might be zero accepted pairs. For a true statement it proves access to an accepted credential, NOT automatically a witness-extraction failure. Run 259 only applies if a found state is an accepted **complete representation** in that theorem's real domain. When public prefix verification is performed only outside the protected evaluator, a chosen input can bypass it; a sound frontier must authenticate its *actual* accepted states or count the source-authentication proof as part of its input domain. A native signature verifier supplies B_x only when the candidate's successful check genuinely authorizes the intended claim/path. Malicious setup, aborts/erasure, retained builder secrets, false-instance QPT hiding, arbitrary native forgery, multi-capsule composition, concrete 128-bit gates/resources, and the hypothetical P2MR/native-SLH endpoint remain unproved.

Attack taxonomy: (1) no seam or local-mask cancellation; (2) no gauge synchronization; (3) no statistical gate fingerprint; (4) one capsule suffices, and shared master-secret cross-capsule leakage is separate; (5) arbitrary chosen public inputs essential; (6) honest setup sufficient; (7) fixed x and branch-key context, no replay inferred; (8) native public checking-key correlation essential; (9) genuine coherent Grover marking oracle. Explicit public randomness is searched in superposition. No quantum hardware test.

## Executed checker

The committed run560_frontier_width_check.js has the *exact function body executed* and prints JSON output in run560_frontier_width_validation.json. It exhaustively counts small state/coin pairs, compares honest success density with D*p/2^ell, tests publicly checkable candidate credentials, and simulates Grover reflection/diffusion amplitudes against the sine-square formula. These are toy integers and finite algebra only. An independent, larger Node 22 checker and full extended derivation were also executed and preserved in the current task's local archive (332,393 assertions); that local archive is NOT a GitHub-committed artifact.

## Focused primary literature applicability

Gheorghiu–Gupte–Havlicek–Liu, arXiv:2609.40289v1 (2026-09-30), https://arxiv.org/html/2609.40289v1, sections 6.1–6.2: Assumptions 6.3 (quantum split-circuit pseudorandomness) and 6.5 (quantum RIO including a correlated public-view *seam/join* clause) imply generic exact ancilla-free quantum iO in Theorem 6.6, using a recursive joining proof. The paper **does not instantiate those assumptions concretely**; the theorem is not independently justified weak/local WKEM security. Its actual correlated-seam game is important architectural evidence rather than a QPT security guarantee for our release frontier. This is a focused section/theorem audit, not a complete paper review. Quantum unknown-marked-item search: Boyer–Brassard–Hoyer–Tapp, Tight Bounds on Quantum Searching.

Next: require any proposed source-authenticating minimal mixer to expose its true frontier input length ell, count D distinct valid states and quantify public randomness, checking-key queries, and coherent quantum costs before asserting practical 128-bit security. Original off-chain witness -> same protected branch credential -> native on-chain signature remains UNPROVED. Production unchanged; no merges; stopping condition unmet.
