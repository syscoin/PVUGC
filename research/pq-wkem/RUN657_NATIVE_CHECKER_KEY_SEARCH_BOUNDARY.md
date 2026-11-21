# Run 657 — publicly checkable native credential is an independent release bottleneck

Date: 2026-10-20. Research-only, syscoin/PVUGC#1. Actual starting branch: research/pq-wkem-validation-20260918, SHA bd0bbc8406ee7be834273bbd63f910de8fab3c80, open/draft/unmerged. Exact Run 259 source-binding blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2; exact CLZ applicability blob c19d9d9cd515140e3ce62eac960cd548c0add622. This note adds one bounded falsification of an overly strong security game and a native-level query-work filter. It is not a practical PQ WKEM or a solution for late-witness admission.

## Public candidate-checker model

Honest classical PPT Setup(1^lambda,x) produces a public transcript, capsule P_x, native branch verification object VK_x, and protected bearer signing capability K in an efficiently enumerable finite candidate domain S (N=|S|). In the relevant seed-derived native-signature setting, a publicly runnable classical PPT test

  A(VK_x,k) = NativeVerify(VK_x,context,SignFromSeed(k,context))

determines whether *supplied candidate* k authorizes the precisely bound challenge branch. Context includes relation, claim/UTXO, branch, anchors/window, and graph authorization. The signing test must be deterministic or use explicitly fixed valid signing coins. Honest completeness: Pr[A(VK_x,K)=1] >= 1-epsilon. Let delta(VK)=|{k in S:A(VK,k)=1}|/N. This theorem requires a directly testable bearer seed; it does not apply to an opaque token requiring an independent designated-owner secret. P2MR-like/native SLH transaction-signature verification is a conditional endpoint assumption, NOT currently deployed Bitcoin functionality.

## Theorem 1: native-checkability dichotomy

An adversary presented with (P_x,VK_x,Z), where Z is either the honest K or uniform independent U(S), simply returns A(VK_x,Z). Its acceptance-probability gap is at least

  1 - epsilon - E[delta(VK_x)].

Proof: correctness gives the first probability >=1-epsilon, while independence of U(S) gives the second exactly E[delta]. This adversary ignores the locally mixed release region, all source witnesses, local mask frames, and any other public auxiliary input. The result holds against classical PPT and hence arbitrary QPT distinguishers.

If delta is appreciable, independent candidate guessing yields appreciable native authorization. If delta is negligible, a supplied real seed is trivially distinguishable from an independent uniform candidate. Therefore a theorem claiming that the actual native signing capability K is indistinguishable from uniform *given its matching VK and supplied challenge K* conflicts with secure native public checking. This says NOTHING about efficient recovery of the unknown K from (P_x,VK_x) alone. False-instance release security must use the actual unauthorized key-recovery / native-forgery game, with the complete correlated public checking key, not this artificial real-versus-random-seed game. Do not infer that one-way key hiding is general-purpose ciphertext/message secrecy.

## Theorem 2: direct quantum candidate recovery

Fix a view for which M_VK>=1 different seeds in S pass A. Because the classical candidate-checker can be implemented coherently, amplitude amplification finds some accepted seed in O(sqrt(N/M_VK)) checker calls, subject to the reversible gate cost and availability of the specified candidate representation. For uniform h-bit native seeds, M_VK>=1 gives an O(2^(h/2)) *quantum-query upper bound*. This is exponential as h grows with the security parameter, NOT a polynomial-time QPT break; real quantum resources are not estimated. Candidate secrets with the same VK only increase M_VK and reduce the work. Native signature verification is an offline candidate tester; no ORIGINAL witness or accepted Run 259 representation is produced.

At a 128-bit *generic quantum query-work* target, an h-bit uniformly enumerable bearer seed must have h>=256 to filter this specific Grover attack. Thus a nominal 128-bit seed permits an O(2^64) generic query search. Do not confuse this query convention with NIST postquantum signature security categories, real circuit costs, or an attack claim against SLH-DSA. For one h-bit master seed deriving multiple context-bound native keys, checking against any one known context VK retains the same search-space upper bound. Context domain separation is still vital for replay resistance; it does not create entropy. Separately independent branch seeds do not satisfy the shared-master shortcut.

## Composition with the Run 656 separately callable suffix

Under that distinct conditional model, a d-bit independently callable release frontier admitting M distinct valid states of correctness >=1-epsilon has its own quantum candidate-search upper bound O(sqrt(2^d/(M(1-epsilon)))). If the *same design* also publishes a native VK checkable against an h-bit secret seed, the attacker can choose the easier of TWO independent attacks, giving a query exponent no greater than

  min( h/2, (d-log2(M))/2 )

for a unique accepted native seed, ignoring polynomial checker costs. E.g., frontier width d=384 with M=2^128 yields exponent 128, but a separate h=128-bit native seed makes the native-checker search exponent 64. To filter BOTH generic attacks at 128 quantum-query bits requires h>=256 AND d-log2(M)>=256. These necessary search-work filters prove neither a release construction nor concrete QPT security.

## Run 259 extraction and attack taxonomy

Run 259 binds an *accepted complete representation z* to an ORIGINAL witness, statistically with enough global folding or conditionally via the precisely stated QPT-SIS break. A guessed accepted signing seed or signature is not such a z. A full security reduction needs (recovery/forgery -> accepted complete z) OR an independently justified native QPT break, before invoking Run 259.

Nine-family audit: (1) local seams: bypassed; (2) global gauge alignment: not used; (3) statistical fingerprints: candidate testing only, not hidden-secret extraction; (4) multi-view/multi-capsule: shared seed testable against one VK, independent seeds not covered; (5) chosen-input: arbitrary native seed guesses; (6) malicious setup: not needed, honest N-of-N erasure does not stop native guessing; (7) cross-UTXO/relation replay: domain separation still needed, not entropy amplification; (8) checking-key correlations: central to the theorem; (9) genuinely coherent quantum search: square-root candidate attack.

## QPT ledger and outstanding construction

Honest setup, signing and checking are classical PPT. Theorem 1 is unconditional for its stated candidate checker and works against QPT with arbitrary additional public auxiliary views; it does not establish false-instance hiding. Theorem 2 is a coherent quantum query upper bound, NOT an efficient QPT break at asymptotic h. No new local-mixer hardness assumption is made. All-witness SAME-capability correctness for arbitrary ORIGINAL witnesses, late public SOURCE-bound witness admission, full-public false-instance QPT hiding, unauthorized true-instance recovery/native forgery extraction, malicious N-of-N setup/abort, multi-capsule composition and practical 128-bit resources remain UNPROVED. Existing conditional Bitcoin graph assumptions are unchanged.

The exact standard-library JS checker and captured JSON accompanying this note check small accepted-seed densities, the real-versus-random gap, amplitude-amplification trigonometry, and four parameter comparisons. They do NOT implement a real signature, local mixer, or quantum computer.

Relevant current architecture references (not audited as secure WKEM instantiations): https://simons.berkeley.edu/talks/ji-luo-mit-csail-2026-07-13 ; https://cris.tau.ac.il/en/publications/towards-general-purpose-program-obfuscation-vialocal-mixing/ . Source binding: live Run 259 file above.

Next constructive target: a classical-PPT, genuinely nonseparable public late-witness admission/update, with *one same bearer capability* for every valid ORIGINAL witness and a real arbitrary-QPT extraction or independently established break. The native checker bottleneck applies even if that local mixing eventually succeeds.