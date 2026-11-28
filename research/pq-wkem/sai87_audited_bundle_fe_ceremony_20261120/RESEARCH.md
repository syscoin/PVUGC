# SAI87 — audited-bundle ceremony for one-honest FE capsules (NONQUALIFYING)
 
## Scope and selection rationale

At live PVUGC#1 head `9d61bef2d39b7c778cf5dcdfdd7086afe70f7427` on `research/pq-wkem-validation-20260918`, SAI86's explicit hash-locked global-state machine still has NO practical source-dependent succinct transition/public FE evaluator. This attempt deliberately does **not** repeat its finite automaton, low-degree public-mask, tensor or tag-equality variants. Instead it asks a different indispensable setup question arising from the user's FE covenant proposal: can one honest setup party detect maliciously **unopenable** FE contributions *without* a general-purpose ZK of FE compilation? The answer for the simple audited-bundle design is conditional and does not provide the missing cryptographic release foundation.

No Core #609 source or tests, actual source certificate, Bitcoin Script execution, FE implementation, PQ attack, or deployment was used here. Previously observed strict post-PQ contextual rules remain the input policy, not a network activation claim. The previous FE note at `research/pq-wkem/fe_gate_assessment_20261118/RESEARCH.md` remains conditional.

## Candidate: commit, audit, retain disjoint native bundles

Fix an entire claim/session-bound cancellation policy P, an authenticated original witness relation R_x with the THREE independent OR challenge grounds, and a concrete FE compiler whose **formal** correctness is assumed only for purposes of analyzing the ceremony (no such compiler has been instantiated).

For each setup bundle j in [2t] and every participant i in [N]:

1. i independently generates a native spending key and FE capsule with intended protected evaluator F_(i,j). The bundle's native spend leaf requires **all N** keys for that same j.
2. Every participant binds its complete compiled capsule bytes, keys, policy, public randomness commitments and capsule transcript to a commitment **before** the audit selection. A single honest party contributes unpredictable unbiased selection entropy after all commitments are fixed.
3. Select uniformly t whole bundles to AUDIT. Reveal all test-only secrets/coins and check each opened bundle's exact FE compiler output and native keys against the committed bytes, under the assumption the compiler has an independently sound and complete implementation. Reject on any failure.
4. Retain only the t UNAUDITED bundle leaves in the funded graph. The revealed audit keys must NOT be capable of spending any funded branch.
5. A challenge watcher with one authentic R_x witness locally tries each retained whole bundle; one correct bundle returns all N native signatures. No participant responds online.

All malicious participant contributions are checked **per bundle**, not independently chosen indices per participant: independent choices could leave no common fully good bundle. Each retained branch needs every N signature (the challenge remains one-of-N initiation/watchers, not an online signature quorum). A malformed bundle is classified as bad if its committed construction cannot guarantee useful opening for *every* original qualifying witness. This notion requires actual FE correctness, not just a few successful test evaluations.

## Exact useful-completeness audit bound, with conditions

Let B be the fixed set of bad bundle indices prior to a genuinely uniform t-subset audit A. Pass means A ∩ B = empty. Every retained bundle bad means B contains the complement of A. Both occur only when |B| = t and A is exactly the set of all good indices, hence

    Pr[pass AND all retained bundles bad] = 1 / binom(2t,t)

for the maximally malicious fixed assignment with t bad and t good bundles. If |B| differs from t, the simultaneous event has probability zero. This is **unconditional combinatorics under fixed-commitment unbiased selection**, not a proof of a correct FE compiler, unbiasable distribution in a real network, or a no-bypass Bitcoin script.

In a bounded direct Python enumeration for t=1..6, every bad-set cardinality was checked against this formula. Larger exact integer probabilities: t=64 gives log2 failure -124.1714342; t=68 gives -132.1278685; t=70 gives -136.1070342. Repeated malicious abort/restart attempts accumulate risk; the procedure requires a binding funding session and a controlled rerun policy. A malicious party can always refuse to fund (liveness abort), which an audit cannot cure.

Local checker: `/mnt/data/pq_sai87_setup_check/check.py`, SHA256 `47424539e1a3e51dc8e74dd84901455c177493c2362a2a102d77d3afa5fc00bc`; captured `output.json` SHA256 `18b91b90416e768b977ead85ddbf26ff8158239426be949efb43b19ab5054b2e`. These bytes were actually executed locally, not committed. The result is only a combinatorial control.

## The fatal composition issue for fixed signatures

The set of retained leaves is unknown until after the audit. A Bitcoin activation output committing the surviving spending graph therefore has an unknown **nonwitness** output script and unknown activation txid/outpoint while the original 2t candidate capsules are being committed. But a frozen native cancellation signature is a signature on a message that commits to that exact final outpoint/graph. It cannot be precomputed for all candidate capsules at commit time without either:

- allowing an already leaked audited key to spend the eventual output;
- pre-signing over an output independent of the randomly selected leaves, which recreates an unsafe bypass / portability edge;
- enumerating all possible surviving subsets (binom(2t,t) variants, exponential); or
- assuming a nonnative sighash escape that weakens the safe-spend binding.

This is the exact unresolved dependency:

    C_(i,j) must bind m_cancel(root(survivors)),
    survivors depends on audit(C_(i,*)),
    audit cannot happen before commit(C_(i,*)).

Unconditionally retaining the audited leaves is unsafe because their private native keys were revealed. Building fresh capsules only AFTER the audit forfeits the precommitted random inspection, so a malicious contribution can be selected and made unopenable afterward.

Dynamic FE signing *could* defer native message selection and authenticate the final manifest/script root, but this is exactly the independently missing public nonlinear source-conditioned FE compiler. It also needs a noncircular binding of the accepted manifest and avoidance of all bypass graph edges. A transparent ZK of an implemented compiler may instead prove the final capsules directly, but proving correctness of nonexistent FE is no repair. The native N-of-N topology and graph-size/transaction/script constraints have not been checked here.

## Decision and handoff

The audit lemma is a conditional constructive option for malicious useful-completeness **only after** a concrete FE and a noncircular final-graph binding exist. Its naked fixed-signature form is rejected for the ORIGINAL future-claim bridge. It does NOT implement `Build_inc(x_W,S)->C`, `Open_inc(C,w)=S`, an arbitrary-QPT FALSE/hard-TRUE simulator/reduction, or an original-work lower bound. It must not produce a progress comment, user breakthrough notification, or stop the research task.

Return to SAI86's exact **source-conditioned, nonspliceable, succinct public release** equation. The next promising candidate must show the **serialized** cryptographic transition/merge and its complete joint-public simulator before introducing another setup wrapper or considering efficiency. Neither ordinary hash output nor new proof labels substitute for authenticated original source evidence.