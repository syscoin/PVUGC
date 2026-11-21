# COMPOSE-CG-20261114: correction-circuit composition checkpoint

Interactive request: combine the earlier constructions to obtain the actual hash-only bridge release, not another unrelated component. No solved/security claim is made at this checkpoint.

Starting syscoin/PVUGC PR #1 head b06306610b8886cb2dd82fc65472f23faf03b4cc, open/draft/unmerged, branch research/pq-wkem-validation-20260918. Latest substantive ordinary comment read: R225, 6796383617. Exact current R263 note and local R275/R280/R287 notes were read. No external research, production writes or independent agent.

The concrete synthesis to test replaces R275's exponential correction table by an R280-style garbled correction circuit. For independent clause-restricted keyed hash functions F_i, compute E(w)=sigma XOR H(F_1(w) XOR ... XOR F_m(w)). Publish one permitted subtree/branch key per local condition and a public garbling of E. Every fully satisfying witness computes all F_i(w) and recovers the SAME precommitted sigma; no future witnesses need enumerating in Build. Unlike the old direct garbled accept-bit release, master seeds and sigma are fixed PRIVATE-input labels, not published label pairs, and the output varies with w. This is a substantive change to the candidate, NOT a secrecy proof.

The joint-public test must examine whether locally permitted evaluations calibrate hidden intermediate wire labels, allowing an attacker to splice an inconsistent mask vector into the final encryption computation. It must also test nonlinear outer hashing, not only linear output correction. Adversarial access is public rows, public witness input-label pairs, one active private-input label per fixed secret bit, permitted local keys and final output decoding. No builder-private label map may be used by the attack.

A second proposed composition uses N-of-N preauthorized competing UTXO spends to limit label choice. The question is whether this restricts off-chain access to prepublished label-unlocking data, rather than only restricting which spend confirms. No read-once memory or online label-release authority may be assumed.

Execution evidence will be appended only after the actual checker runs. Source/claim/activation wrapper binding, exact modern AuxPoW tags, fixed safe native cancellation, one-notary initiation and three OR challenge grounds are unchanged. The local contradictory-clause test is not an authenticated Syscoin relation or a QPT experiment. A successful toy test is not the requested bridge solution.
