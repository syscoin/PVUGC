# Run 673 — Public native checking key separates one-way release from key indistinguishability

**Research-only.** Started at exact draft PR head `ebf44c677cae40bce5e09c367371979915f1c23b` on `research/pq-wkem-validation-20260918`. Dependencies: Run 672 blob `6626bd0fa13f1349d62f3c2ce5a06f10bcee95f8` (public-cover recovery attack) and Run 259 blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2` (accepted complete source representation -> ORIGINAL witness). This is a security-game falsifier, NOT a PQ witness-KEM.

## Honest classical model and exact adversary/game

Fix statement x binding relation identity, claim/UTXO, challenge branch, anchors/window/context. Classical PPT honest setup samples a native signing credential k, native verification key pk, and public release ciphertext P; setup does not require an ORIGINAL witness and may use a one-honest-party erased N-of-N ceremony. A valid ORIGINAL witness may produce arbitrary distinct intermediate states but must release exactly the same scoped k. Bitcoin native signature validation remains conditional, with no proposal activation assumed.

Let (KeyGen,Sign,Verify) be an ordinary public-verification native signature scheme. Fix a public, valid message m_x for the intended branch. Define an efficient public candidate-checking algorithm B(pk,t): sign m_x with candidate credential t (or reject malformed candidate strings) and verify the result under pk. Randomized Sign coins are sampled internally.

The **REAL-OR-UNIFORM-FINAL-SIGNING-CREDENTIAL** game gives an arbitrary QPT distinguisher (P,pk,all auxiliary public data, possibly other capsules) and a challenge T which is the true protected signing credential k in world REAL, or an independent uniform candidate-key bit string U in world RANDOM. The attacker runs B(pk,T).

**Theorem.** If native correctness gives Pr[B(pk,k)=1]>=1-delta and eta=Pr[B(pk,U)=1], then the attack distinguishing gap is at least 1-delta-eta, even with the *entire* public P and arbitrary QPT side computation. Under zero-query EUF-CMA unforgeability, eta is negligible: the straight-line, classical no-query forger given pk independently draws U, signs m_x with U, and submits that signature. No quantum random oracle, rewinding, source extraction, or generic-group assumption appears. Hence REAL-OR-UNIFORM *native full signing-key IND hiding is unattainable* even if x is false and P perfectly hides k. The tester is classical PPT, hence an allowed QPT adversary.

For native SLH-DSA-like keys, a candidate may also be checked by recomputing its associated public key, when the key format permits it. FIPS 205 gives public SLH-DSA verification (https://csrc.nist.gov/pubs/fips/205/final); no Bitcoin deployment is inferred.

**CRUCIAL SCOPE:** This is NOT an attack recovering k or signing a transaction from P. It rejects an impossible secrecy **game**, not the underlying one-way target. A legitimate false-instance security game gives the attacker only (P,pk,aux) and asks it to *output* the full k or a fresh accepted native branch signature. Those are two separately defined goals, and neither follows from REAL-OR-UNIFORM impossibility. The public checker is intentionally available and must appear in all reductions.

## Interaction with minimal local mixing and ORIGINAL extraction

This applies even with relation-dependent witness states, different valid ORIGINAL witnesses, masked release gates, independent capsules, public auxiliary keys, and honest distributed setup. Only the candidate final credential is exposed in the contested IND challenge; no assumption about a public short seam/cut is used. It is not a proof against a secure local release mechanism.

Run 672's public-cover route attacks *unauthorized recovery*. The present theorem is logically independent: it attacks an overstrong pseudorandomness formulation even when the public cover has high entropy. It falls under taxonomy (8) public native checking-key correlations and (5) public evaluation; the adversary is itself classical, so (9) quantum attacks add no requirement for this game. Seams/gauge/fingerprints, malicious setup, related-UTXO replay and correlated capsules remain unaudited for actual release constructions.

Run 259 only transforms a supplied **complete residual-accepted source representation** into an ORIGINAL witness (statistically, or via its precise SIS assumption). An accepted final signing credential or a valid transaction signature is *not* such a representation; the upstream QPT extraction arrow remains UNPROVED.

An ordinary IND-style payload WE argument must use an independently hidden payload bit/key rather than treating a publicly pk-bound signing key as pseudorandom. Converting one-way recoverability into semantic payload hiding requires another justified QPT reduction including (P,pk,aux); salting/hashing k is not itself such a proof. Additional payload encryption is not a substitute for WE-like release.

## Executed exact finite control

The exact published Python checker implements a deliberately **INSECURE** 10-bit Lamport-OTS toy, derives secret labels using SHAKE and public hashes using SHA-256, and enumerates all 1024 independent candidate seeds. For one honestly generated pk, only its actual seed passes public signature verification, so the real-vs-independent-random distinguishing gap is 1023/1024. It also verifies the result is unaffected by arbitrary true/false relation labels. `py_compile` passes, repeated execution is byte-identical, and 1,037 assertion counts pass. These tests check arithmetic only, not WE/PQ or FIPS 205 security.

## Outcome and ledger

Established: an unconditional PUBLIC-KEY-CORRELATION distinction between pseudorandom-final-native-signing-key IND games (impossible) and the intended QPT one-way/accepted-signature security games (still open). No new cryptographic assumption, complete local mixer, practical 128-bit parameters, or QPT ORIGINAL extraction. Actual ciphertext attacks (1–4,6–7), full false-instance recovery security, true hard-instance extraction, malicious/abort-secure N-of-N, multiple-capsule composition, and the conditional P2MR/SLH graph all remain UNPROVED. No production change; PR remains draft/unmerged.
