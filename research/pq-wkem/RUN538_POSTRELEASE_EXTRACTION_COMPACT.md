# Run 538 — black-box post-release source-extraction separation

Research-only; verified starting PR head 7de2a4d847a8d722b010eab53e5bb43e7c20cc1c. Draft, unmerged. No production changes.

## Scope and exact theorem
This is a theorem about output-only ORIGINAL-witness knowledge extraction, NOT an impossibility theorem for the user's witnessless-adversary security game, and NOT a local mixer construction. It extends the interface concerns raised by Run 537 without repeating its computational-proof hidden-bypass counterexample.

Assume a quantum-secure one-way permutation f_lambda and choose w uniformly, x=f_lambda(w). Honest *classical PPT* Setup(x,K;rho) generates a full public view V (claim, UTXO, branch, anchors/window, native VK(K), presignatures and public correlations) from x, fresh K, and rho, without knowing w. Hypothetically, a correct common-capability release algorithm lets a genuine witness holder obtain that same K off-chain.

Let O_w expose only post-release results: K if requested, ordinary native Sign(K,m;coins) on requested messages, and public views computable from (x,K,rho). It does not expose witness-dependent protected states, transcripts, original proofs, or side channels.

**Theorem (exact post-release black-box separation).** If a uniform QPT black-box extractor E with inputs (x,V) and oracle access only to O_w outputs a w' satisfying f_lambda(w')=x with nonnegligible probability, a uniform QPT inverter for f_lambda succeeds with the same probability. Inverter I receives x, samples K,rho, runs Setup(x,K;rho), and answers E's key, signature, and public-view queries itself, without knowing w. The oracle response distributions are identical for any valid witness because all exposed outputs depend only on (x,K,rho). Output the w' that E finds. No rewinding, QROM programming, or solver for the NP relation is used.

If coherent reversible access to a *deterministic* post-release function g_{K,x} is specifically made available, I can implement |q,z> -> |q,z XOR g_{K,x}(q)> with its known K,x. This proves channel identity even for coherent queries; it does NOT claim Bitcoin exposes such an oracle. Arbitrary witness-correlated quantum auxiliary advice, private-state quantum side channels, pre-release operations, and white-box access to the adversary's hardcoded witness are **outside this theorem**.

The adversary with a private genuine w is an **authorized holder**. Thus the theorem does not refute the requested security guarantee against genuinely unauthorized/witnessless early signing; it refutes only the overstrong suggestion that a standalone ordinary native signature or a recovered K must *itself* permit efficient black-box extraction of ORIGINAL evidence.

## Composition and attack model
Run 259's accepted *complete source representation* -> ORIGINAL witness/SIS implication applies only when such a representation actually appears and satisfies its bound/residual hypotheses; it says nothing about a bare key or signature. An actual release construction must prove that a successful unauthorized QPT attacker internally yields such a representation or supplies some independently justified reduction. Declaring this extractor as part of a new primitive is circular.

Taxonomy: seam/gauge/fingerprint attacks are not needed; chosen-message signing queries and correlated public VK, branch/context, and setup-generated multiple capsules are simulatable from x,K,rho. Malicious N-of-N setup/retained randomness and arbitrary witness-dependent auxiliary views are NOT addressed. Coherent oracle simulation is exact within its stated post-release interface, not a claim about QPT hiding of a mixed terminal.

## Checker, literature, unresolved items
The exact deterministic compact JavaScript checker below exercises a toy family of invertible maps, a toy signing surrogate and matched genuine/simulated post-release oracles, including reversible basis-action equality. It verifies finite interface identity, NOT one-way hardness, a practical WKEM, or a native PQ signature.

Relevant literature to audit, NOT a new full-proof certification: Unruh, Quantum Proofs of Knowledge, IACR 2010/212 (rev. 2015); Ambainis/Rosmanis/Unruh, Quantum Attacks on Classical Proof Systems -- The Hardness of Quantum Rewinding, arXiv 1404.6898. Neither supplies ordinary-signature-only source extraction.

No new hardness assumption beyond the explicitly conditional qOWP is proposed. Any final scheme still needs classical practical common-key recovery for every valid ORIGINAL witness; full-public-output false-instance arbitrary-QPT hiding; unauthorized true-instance key recovery/native forgery -> ORIGINAL evidence or independent QPT break; honest-eraser N-of-N malicious setup and abort; multiple-capsule and checking-key composition; concrete 128-bit resources; and conditional P2MR/native SLH signature graph. The research stopping condition is NOT met.
