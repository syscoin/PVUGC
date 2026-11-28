# ORIGINAL-source hash-root-locked release: screened construction and stop point (2026-11-23)

**NONQUALIFYING INTERNAL HANDOFF. DO NOT NOTIFY OR COMMENT AS PROGRESS.** This is a source-release attempt screened against the nearest prior attack *before implementation*. No practical ORIGINAL Build/Open, joint QPT security reduction, native signature, or real source validation is claimed. No checker was implemented or executed; the statements below are symbolic deductions, not experimental security measurements.

## Source and scope

Read open/draft/unmerged syscoin/PVUGC#1 metadata and recent substantive issue comments at start; branch `research/pq-wkem-validation-20260918`; inspected exact head `dd2c10b3ceb6f81194c63545bb65ec6e95a0a144` and `research/pq-wkem/r_state_enumerated_hash_gate_20261123/RESEARCH.md` (blob `27f87909b4384d2e00afa4a67c48cecff66df11a`). No web or Core source calls. Starting branch for this note is whichever same-branch head is checked immediately before the guarded commit, without modifying another branch.

**Exact missing ORIGINAL operation:** public, serialized `Open_inc(C,w)` must release one precommitted safe native cancel capability from ANY genuinely authenticated, claim-relevant witness for (i) same-anchor *greater exact BTC cumulative work*, (ii) a finite authenticated refutation of this withdrawal's burn authorization, OR (iii) a qualified actual-depth Syscoin inconsistency/tag fault. Arbitrary invalid or synthetic source strings must not do so; no second notary, preference for a Syscoin winner, or witness-carrying on-chain verifier. This remains a source cryptographic gate, not merely the public `Verify(x,w)` predicate.

## Candidate: globally witness-rooted, hidden hash-pad transitions

Take a SHA-domain-separated commitment `rho = H("ORIGINAL-evidence" || context || serialize(w))` to the *entire typed source certificate*, including the predecessor-linked histories and claim/deadline/activation scope. For every committed root rho, circuit step i, semantic state q, and transition choice b, a putative builder samples independent secret labels `L[rho,i,q]` and publishes

    E[rho,i,q,b] = L[rho,i+1,delta(q,b)] XOR
                    H("edge" || rho || i || q || b || L[rho,i,q]).
    D[rho,q_accept] = sigma_cancel XOR
                      H("final" || rho || L[rho,L,q_accept]).

Start labels are provided only through the corresponding root-indexed table. The opening path must carry the SAME rho through every step, and a *cryptographic* commitment-opening check must bind every actual consumed input field to one and the same complete witness and to genuine external source admission. Merely checking rho at the end in honest code, or testing source validity after recovering sigma, is disallowed.

**Change relative to the R289/R303/R327 family:** an intermediate label from a witness with root rho_0 cannot be substituted into the ciphertext of rho_1 with a different root except by guessing a hidden independent label or relevant random-oracle value. This changes the prior cross-witness label-splice algebra rather than just re-positioning an additive coefficient or hashing an unchecked source bit. It only supports a conditional ROM intuition for the *fully enumerated private-label variant*; it is NOT a QROM theorem, and it does not itself bind source authentication inside the cryptographic path.

## Explicit attempt to make it public and succinct — fails BEFORE tests

Let `R` be the set of roots for which all necessary public rows and opening labels are serialized at Build. A future qualifying witness with `rho(w) notin R` has **no public row**: its Open cannot run. To achieve the stipulated *every*-qualifying-original-witness correctness for unknown future Bitcoin/Syscoin headers, Build cannot restrict R to only observed/forecast/issuer-selected witnesses. For t-bit independent possible roots with no pre-setup restriction, enumerating every possible row uses at least `|R| * Omega(number_of_steps)` public row entries; in the simplified uniform-future-root model, a q-entry precomputed table covers a random new genuine root with probability at most q/2^t (e.g. q=2^32, t=256 gives 2^-224). Real SHA/PoW distributions are NOT asserted to be uniform; this bound is only for the explicitly stated uniform-root idealization, while the deterministic coverage failure for a qualifying missing root needs no such distribution.

The natural attempted polynomial repair is to set `L[rho,i,q]=H(k || rho || i || q)` from a retained, *secret* master seed k and publish a universal row generator. Three cases:

1. **Publish k, or enough information to compute every label directly:** public parties can derive accepting labels and `D` masks independent of an ORIGINAL certificate. The source condition becomes an optional honest-code check; FALSE and hard-TRUE claims fail.
2. **Hide k and publish only the indexed row table:** the unknown-rho row is absent, and the original every-witness correctness fails.
3. **Hide k and posit a public `Next` evaluator that converts an arbitrary, source-authenticated rho/state label to a hidden next label with no public invalid-source probing:** this is *precisely* the missing cryptographic evaluator (a constrained source-dependent functional key), not an algorithm obtained from SHA, ordinary garbling, or the certificate commitment. No code, independent QPT assumption, or simulator for this operation has been supplied.

This rejects **this exact root-table/GGM-style repair** before an implementation or another parameter sweep. It is **not** an impossibility theorem for all hash-only encodings, all source-specific languages, or all forms of witness encryption. In particular no claim of a lower bound on every succinct public algorithm follows from counting rows in an explicit table.

## Further composition checks to preserve

- Even for enumerated roots, publishing edge labels cannot substitute for full Bitcoin contextual admission, exact cumulative-work comparison, complete authorized burn refutation, or relevant LC-depth Syscoin ancestry. A correct hash-root commitment to fabricated evidence is not source authentication.
- A public list of *accepted* root identities may itself reveal easy openings or become an unauthorized index; row secrecy must be proved against the full public list and all related capsules, not a single hidden input.
- The frozen signature must spend only the intended cancel outpoint under the activation policy. R225's wtxid-only post-hoc metadata does not prevent a released same-message native signature from spending the common outpoint on another activation; choose explicit slot-global veto or genuine activation-specific message binding.
- A classical random-oracle hidden-label argument does not imply a coherent QROM joint simulation, and ordinary EUF does not automatically rule out same-message signature substitution. Malicious-source coins, malicious setup, auxiliary input, sibling capsules and selective openings remain adversarial.
- No N-of-N online signing, fabricated source PoW, hash puzzle, privately retained SourceOpen, or per-witness native output is silently introduced.

## Handoff / decision

**Rejected as a practical candidate.** The only mathematical delta over the prior label-splice attacks is a truly global, independently hidden root-indexed state; this correctly identifies how to stop the *specific* mixed-root splice, but loses classical-PPT public all-future-witness Build as soon as roots are not enumerable. No original gate was implemented, no actual SHA-based QPT theorem established, and no endpoint/real-source assumptions changed. A future proposal must write down a concrete, polynomially serialized arbitrary-rho public row-transition function and its *joint* full-public simulator **before** using this route. A named hypothetical gate is not progress; absent such an equation, do not rerun the same root/basis/threshold sweep. No PR conversation comment or user notification is warranted.
