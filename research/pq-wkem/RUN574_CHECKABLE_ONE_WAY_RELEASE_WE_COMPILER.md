# Run 574 — one-way SAME-credential release plus unique public checking already implies bit-WE

2026-10-16. One bounded research-only conditional theorem. Starting live PR head: b3afe1e27e067158a9a7b595b0805326cf00c1d0, branch research/pq-wkem-validation-20260918, draft/open/unmerged. Run 573's denied, local-only payload is not retried.

## Narrow question
Run 573 identified that a genuine native signing credential is publicly recognizable and therefore need not look like an independent uniformly random key. Does replacing real-or-random hiding by *false-ORIGINAL-instance recovery one-wayness* produce a fundamentally weaker-than-WE generic release assumption? Under the conditions below, **no**.

## Exact conditional interface
For every NP relation R, an honest classical-PPT sampler Gen(x) produces full public P and a credential K in {0,1}^n. P includes the native checking key, context, all public programs, permissible ceremony transcripts, correlated capsules/public auxiliary information and any disclosure the one-way security game allows. A public classical-PPT Release(P,w) returns the **same** K for every fixed ORIGINAL-valid w with overwhelming probability; intermediate source states may differ. Public deterministic Check(P,k) accepts K and, except negligible honest-setup probability, accepts no other k. This unique-secret-key property is an **additional hypothesis**, not implied by native SLH-DSA signature verification or EUF-CMA.

For every ORIGINAL-false x, a QPT adversary given the full classical P plus independently rerunnable public QPT evaluation and classical auxiliary inputs has negligible probability of outputting K. The adversary may evaluate public functions coherently inside each invocation. The reduction uses fresh workspace for each invocation; a nonclonable one-copy quantum auxiliary state correlated with K is not covered by the statement without further work. Multi-capsule and malicious-setup exposure must enter the exact one-wayness premise separately.

This premise is *not instantiated*. It is stronger than ordinary signature unforgeability. The honest N-of-N ceremony may be simulated by Gen with independently sampled party randomness and honest erasure; the optional malicious sole builder retaining every coin is not assumed.

## Compiler and theorem
Define a public encryption algorithm for one chosen bit b:
  (P,K) <- Gen(x);
  r <- {0,1}^n;
  c = b XOR <K,r> mod 2;
  WE.Enc_R(x,b) = (P,r,c).
For any ORIGINAL-valid w, compute k=Release(P,w) and output c XOR <k,r>. All-witness SAME-capability correctness gives bit correctness.

**Theorem (scoped QPT false-instance hiding).** Under the hypotheses above, no rerunnable QPT adversary with the stipulated full public view distinguishes WE.Enc_R(x,0) from WE.Enc_R(x,1) with nonnegligible advantage for an ORIGINAL-false x.

Proof. Given a distinguishing algorithm D and (P,r), select u uniformly and predict <K,r> by u XOR D(P,r,u), flipping D's decision direction when necessary. The bit u is distributed exactly like the ciphertext tag for the uniformly random hidden message b=u XOR <K,r>. Thus if D has distinguishing gap delta, this is a noisy parity predictor with success 1/2+delta/2. Conditional on a nonnegligible set of capsules P it has inverse-polynomial correlation with the Boolean character r -> <K,r>. Goldreich–Levin Fourier/list decoding uses polynomially many classical queries to the rerunnable QPT predictor, returns a polynomial candidate list containing K with nonnegligible probability, and the stipulated **unique public** Check selects K. This constructs an arbitrary-QPT recovery adversary using straight-line fresh invocations, contradicting false-instance one-wayness. No quantum-state rewinding is used. The claim does not extend by fiat to arbitrary single-copy correlated quantum advice. QED.

Classical GL: Goldreich–Levin, *A hard-core predicate for all one-way functions*, STOC 1989, https://doi.org/10.1145/73007.73010 . Relevant quantum analysis: Adcock–Cleve, *A quantum Goldreich–Levin theorem with cryptographic applications*, https://arxiv.org/abs/quant-ph/0108095 . The present proof uses the classical list decoder with fresh QPT predictor invocations on classical queries. These papers are foundational; no new GL algorithm is claimed.

Independent capsules per bit yield longer-message WE under a suitable multi-capsule one-wayness/hybrid hypothesis, not from an unqualified single-capsule statement. The implication WKEM -> bit-WE is only **one-way**: ordinary WE alone does not supply source extraction from a bare native signature, full protocol safety, QPT assumptions or practical parameters.

## Specific consequences and nonconsequences
1. Public Check makes REAL-vs-UNIFORM final-key indistinguishability impossible in this wrapper (Run 573), but its *one-wayness* plus UNIQUE checking can still yield WE message hiding through GL. Therefore merely calling a proposed generic local release object "one-way, not WE" is not evidence that its cryptographic strength is substantively below WE.
2. If Check accepts several different secret seeds, GL candidate selection can fail. A native public verification key is not known to satisfy the theorem's uniqueness hypothesis; adding an extra key commitment changes the attacker's view and requires a **new proof** of one-wayness under that view.
3. The theorem does not prevent a specialized mixer for a restricted Syscoin relation, nor a different signature-only game, and it does not defeat actual CCMR/CLZ. It is a dependency/lower-bound warning for claims about arbitrary NP relations.
4. False-instance ORIGINAL one-wayness is the premise. Run 567 warns that replacing this by mathematical emptiness of a merely SIS-folded language is invalid in general; Run 259's source binding only applies after a complete accepted representation z is supplied. Neither theorem gives an unauthorized signature -> z reduction.
5. All local seam, chosen-evaluation, cross-capsule, malicious-setup, checking-key and genuine coherent-quantum attacks from earlier runs remain open against any future *construction*; this conditional compiler is not a new protected mixer. In particular Run 573's reused native signing secret can compromise another branch without breaking the mixer.

## Executed validation and handoff
The accompanying exact self-contained JavaScript checker ran with 175,534 assertions and verified the exact ciphertext-distinguishing / parity-prediction identity for 768 bounded independent Boolean distinguishers. An independent local Python checker passed 788,690 assertions, including all n=2..8 finite correctness and a deliberately insecure 3/4-success toy public leak. These are finite algebra checks, *not* a working encryption primitive or security proof.

Constructive priority remains the small source-authenticated late-witness release frontier, but do not assume an arbitrary-NP one-way, uniquely checkable SAME-key release interface is fundamentally below witness encryption: this theorem already compiles it to bit-WE under its exact security premise. A practical classical-PPT instantiation, QPT true-instance unauthorized recovery/native forgery -> ORIGINAL or independent break, joint auxiliary/malicious setup, multi-capsule, 128-bit costs, and the conditional native-SLH Bitcoin branch are UNPROVED. Leave research automation enabled; production unchanged.