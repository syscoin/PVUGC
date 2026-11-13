# R189 — Source-independent AuxPoW evidence does not evaluate a hidden affine share

**Status: restricted mathematical construction/repair result only. NOT an ORIGINAL source-bound KEM, native cancellation mechanism, QPT-security proof, or reportable breakthrough.**

## Pinned continuation
syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918. Observed starting head d3d6a2e23d161899a564c25e9222d48a8673a9df, which contains R188 (affine source-share normalization). Read exact R188 and R187 research files, current PR metadata, and recent issue comments (none since 2026-11-09T23:00Z). No full PR diff or unrelated source was read; no web/literature, independent agent, production changes, real source mining, quantum testing, or native signing. A genuine intermediate hypothesis checkpoint was written locally before running the checker and published to this branch at 72e73ca9e611e9b1cddbf2c2e71da5d5a6978396. Checkpoint publication is not a research result.

## Exact candidate / input distribution
R188 chooses p prime, independently uniform K,a in Fp, authenticated fixed baseline z0 != 0, publishes s0 = K+a*z0 (mod p) and proposes a public future-source evaluator producing s(z)=K+a*z for ANY qualified ORIGINAL fork witness w with z=z(w) != z0. With this hypothetical evaluation, reconstruct:

    K = (z*s0 - z0*s(z)) / (z-z0)   (mod p).

All legitimate different z yield the same K. The intercept identity is correct but leaves the source-to-hidden-evaluation operation unimplemented.

Now restrict to a capsule whose only hidden-affine-dependent field is s0 and whose further public source data T are independent of a conditional on (s0,z0). The authentic future Bitcoin/Syscoin witness W, including AuxPoW proof, parent header and coinbase, child ancestry, tags, window/anchor and tag-divergence qualifications, may be sampled or selected adaptively from (s0,T) using public computation but has no access to secret K,a. Let Z=Z(W), and condition on Z != z0. Do not replace W with a privately issued evaluation token.

## Exact restricted theorem
Conditioned on fixed s0, every a in Fp has one K=s0-a*z0 with the same prior mass; therefore a is uniformly distributed. Since Z-z0 != 0, the map

    a -> s0 + a*(Z-z0)

is bijective on Fp. For any estimator A whose entire input is (s0,T,W,Z) plus randomness/quantum side information independent of hidden a given these fields,

    Pr[A(s0,T,W,Z)=s(Z) | s0,T,W,Z] = 1/p.

This is an information-theoretic statement about the precisely specified restricted distribution, even if W is an authentic source witness and Z is chosen from the public capsule. It does NOT rule out a radically different setup-produced ciphertext C jointly correlated with K and the source relation, in which the witness is a computational decryption trapdoor. Nor does it imply source witness generation itself is computationally easy.

The actual candidate's CHECKING key CK=H_check(K), sealed native signature D=sigma_cancel XOR H_pad(K), VK, auxiliary fields and related capsules are K-correlated and are NOT independent side information T. The exact one-over-p posterior does not extend to the full public view by fiat; a toy disclosure of K mod 2 narrows evaluation support from 7 to 3 or 4 candidates. A real construction must analyze the full joint QPT game.

## Multiple-baseline correction: hidden shares are correlated
For t independent slopes a_i but ONE common intercept K, published baseline evaluations s0_i=K+a_i*z0_i, z0_i!=0, are individually uniform and jointly independent of K. Conditional on all observed s0_i, K remains uniform but a_i=(s0_i-K)/z0_i. Therefore

    s_i(z_i) = (z_i/z0_i)*s0_i + (1-z_i/z0_i)*K.

Each unseen evaluation is uniform when z_i!=z0_i, but the entire t-vector lies on a ONE-DIMENSIONAL affine line indexed by K, rather than a product of independent masks. A full-public OR-of-three-challenges proof must account for this exact correlation; it cannot multiply single-branch marginal probabilities. Once any genuine complete evaluation s_i(z_i) is available, K is intentionally reconstructed; once any fabricated evaluation is available through a raw public function, the SAME early extraction also works.

## Five repair attempts, none provides the source-dependent compiler
A. Publishing the affine coefficients or a publicly callable polynomial evaluator allows any arbitrary forged semantic z!=z0 to reconstruct K. An ORIGINAL verifier invoked only by honest Open cannot prevent bypass of that raw evaluator.

B. Publishing H(a), H(K), CK or similar public commitments does not let an independent future AuxPoW proof compute the hidden slope. Recovering a by brute force or Grover is unauthorized secret recovery, not witness-conditioned release. This requires full-public security analysis rather than the restricted independence theorem.

C. Publishing a secret correction row for each semantic z lets fabricated z bypass the source condition. Indexing rows by a complete authenticated WorkID/Bitcoin coinbase/history proof instead requires predicting all potentially valid future certificates or building a genuinely constrained evaluator; the space is exponential. Parent WorkID changes for the same pure Syscoin child do not create a fork.

D. Treating source hash root rho as a public encryption key and any ORIGINAL opening as a private decryption key is a potentially different design, but an ordinary SHA/Merkle commitment does not give a sender who only knows rho an encryption pad recoverable by an unknown preimage. This would require an independently instantiated source-witness public-key encryption primitive, not a restatement of it as an assumption. R187's unique fixed-root nonmembership path is not enough.

E. Requiring actual source signers to reveal the secret slope inside future coinbases or special signed transcripts changes the ORIGINAL source relation and recreates retained-source-secret or online-authority vulnerabilities shown in R173. Existing Bitcoin/Syscoin headers and tags do not encode the setup's hidden affine coefficient.

No synthesis of an additional polynomial-size setup ciphertext field met these constraints in this pass. There is therefore NO BuildSourceShare, no public authenticated EvalSourceShare and no same-capability native cancellation release.

## Test provenance / limitations
Executed exact checker.py (Git blob 7fb7ada24d849361fdc2e53ac293f14b343ef79d, SHA256 b56a915cf2afeedde0e560843dedb337df0946587f3b1df5a97ce2e599dbf606) twice locally with byte-identical captured JSON (SHA256 3b9a9cb4cc98acc91a779af395618f140d95e357a0178ce05639523193dade68). 1,261 assertions on the tiny toy field F7: conditional uniformity, adaptive choice from s0, rank-one multiple-branch correlation, fabricated-z early recovery, and source-independent synthetic hash labels. These tests are algebraic sanity checks, NOT SHA-256 cryptanalysis, deployed Bitcoin/Syscoin evidence, native PQ signature execution or quantum simulation. Exact executed source and output are separate research files. No test helper is a working public source evaluator.

## What the future algorithm still must do
For the approved three-way R_cancel = R1 heavier relevant BTC work OR R2 refutable missing/invalid authorized burn OR R3 authentic Syscoin AuxPoW fork/tag inconsistency, construct a classical-PPT public capsule from the exact bound withdrawal context (claim/UTXO, asserted roots, anchors, window, fork depth, native cancel message/VK and capsule ID) before future source evidence. ANY ONE original qualifying challenge witness must noninteractively produce the same frozen claim/path-scoped N-of-N cancellation contribution, including when witnesses encode distinct valid source histories. The capsule must cryptographically bind complete BTC/SYS source authentication to raw release, not merely apply an honest-verifier check. Under the full public view, arbitrary QPT unauthorized recovery or accepted native forgery must lead to an ACTUAL ORIGINAL witness or an independent justified PQ hash/native break. Malicious setup, erasure/abort, full DA and correlated sibling/multi-capsule security remain open.

The missing equation is still a polynomial, publicly executable **authenticated-source-restricted hidden-function evaluation**, generated by Build without knowing future authentic source evidence and simulatable against general QPT attackers. This cannot be assumed under a new name or replaced with a fake PoW, independent hash puzzle, online issuer, source-retained signing labels, generic statistical hiding claim or native Bitcoin proof verifier. More affine coefficient optimization is not warranted before this exists.

No ordinary PR progress comment is warranted; preserve these tests and attempted repairs to avoid repeating them as progress.
