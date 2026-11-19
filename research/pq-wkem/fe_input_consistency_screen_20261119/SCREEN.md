# Public whole-witness labels — screened candidate, not a release result (2026-11-19)

## Continuity and authority
Read the live open/draft syscoin/PVUGC PR #1 at research/pq-wkem-validation-20260918 head `573f8fdc0d6bc15c86fe5d6cc1273dc38c36635f` (R381, note blob `47cbfe93ed12577bc2e0c2ad960234d5f87eb7f8`) and its exact R380 note blob `05dd3308a8a9ed8cd65116b1c746562e824d63f8`. Checked top-level issue comments since 2026-11-18: empty. Core PR #609 currently advertises head `b3b4f643383a2149807a25fe38d26b5f058daa60` in metadata, but no Core source/tests were inspected here and no new consensus assertion is made. The strict contextual modern chain-ID/canonical SYS tag and user-corrected history-consistency scope are assumed *only as previously qualified*. All original independent OR challenge branches remain unchanged. No external web search, independent agents, or Core tests were used.

## One named candidate and its *distinct* intended repair
Try to fix the local-fragment splicing in the previous public garbling/tensor families by requiring all wire labels used in one evaluation to be bound to ONE entire source certificate `w`, not to independent clause assignments.

Let `d(w)=SHA256("global-original-witness" || Canonical(x,w))`. For every circuit wire `j` and value `b`, attempt to use
`L_(j,b)(w)=SHA256("global-label" || d(w) || j || b)`.
If all supplied labels really share the same `d`, mixing labels from distinct complete certificates `w_1,w_2` with different digests becomes detectably inconsistent. This eliminates the *specific unconstrained cross-certificate label substitution* at the **input formatting layer**, assuming exact digest-binding checks.

The exact missing crypto operation is more demanding: a classical-PPT builder must publish the FULL protected gate table for the unknown future family `{L_(j,b)(w): R_orig(x,w)=1}` with one frozen safe native cancellation capability, and an opener must recover it from EVERY qualifying ORIGINAL `w` without revealing it to a party supplying invalid `w` or arbitrary labels.

## Joint public evaluation and why this is not a source gate
With the literal hash above, `d(w)` and both `L_(j,0)(w),L_(j,1)(w)` are public for *any* serialized byte string `w`; they are not authenticated by a hash. An adversary may choose any `w`, including invalid fabricated work, and derive both candidate labels. Checking `R_orig(x,w)` in an ordinary wrapper after deriving them is not source-conditioned release. A public consistency check that all labels carry one digest rejects *mixed digests* but does not reject fabricated or internally inconsistent certificates, nor prevent both wire values at one digest.

One might salt labels with a setup secret `a`:
`L_(j,b)(w)=H("global-label"||a||d(w)||j||b)`.
Then Build can privately derive labels for any chosen `w`, but future parties cannot produce them unless the public capsule gives a source-conditioned evaluator. Publishing `a` reverts to the previous fully public label access; tabulating all future accepted `d(w)` is exponential/unknown at funding. A seed-public program that returns labels for *every* input digest still permits fabricated inputs to obtain both labels. Encrypting a global gate circuit with these labels changes the *representation*, not this source-authentication obligation.

To make a true gate, the serialized public capsule would have to jointly provide
`E(C,x,w)=(L_(1,w_1)(w),...,L_(m,w_m)(w))` **only when** the exact ORIGINAL `R_orig(x,w)=1`, with labels cryptographically unavailable on nonqualifying inputs and under arbitrary processing of *all* public bytes. This is not implemented by an input hash, ordinary public certificate verification, or a Merkle root; positing such a protected evaluator is precisely the missing scoped FE/WE component. Thus the change would bind one digest if a secure evaluator existed, but supplies no actual new release primitive.

## Soundness/completeness and quantitative obligations
Correctness cannot be obtained by simply normalizing all valid `d(w)` to `H("accept"||x)`: that is public, and with public label material it yields unwitnessed opening as in R381. Conversely, using the raw `d(w)` to derive the terminal pad prevents convergence of different valid witnesses, again R381. Neither approach gives the SAME frozen native safe authorization for the BTC greater-work, specific-burn-fault, and Syscoin inconsistency/tag-fault branches.

The necessary new operation is a **serialized nonlinear source-sensitive translator** that (a) binds one complete original source witness across the entire computation, (b) maps all qualifying and potentially unrelated future original certificates to the same frozen capability, (c) admits a joint full-public simulator and recovery/accepted-native-forgery -> ACTUAL original-certificate or independently justified hash/native break, including malicious setup, all sibling capsules and QPT joint access. No such Build/Open, simulator or witness extraction has been instantiated. No source-work quantitative claim follows from digest binding.

## Disposition
Screened/rejected *before coding* because the closest recorded failure (R381 certificate-digest nonconvergence plus public normalizer leak) applies unchanged to this proposed label derivation. There was **no new checker execution**, FE engine, native-signing test, genuine source certificate, or QPT proof in this execution. Do not rename, expand or optimize this label family in a later run without a mathematical operation that changes those failures. This screening is NOT a scientific breakthrough or a qualifying notification. No production, Core, comments, workflow, or automation changes.
