# R172 intermediate checkpoint — remove the exact-sigma premise from the generic native-signature transport implication

Status: substantive proof-repair attempt IN PROGRESS. This is not a new hash-only ORIGINAL source compiler, practical witness-KEM, or QPT implementation.

## Continuity and precise correction target
Repository syscoin/PVUGC PR #1 (open, draft, unmerged), branch research/pq-wkem-validation-20260918. Observed start HEAD 7b8c06d03792af820b1e9140cf35fb5fa0c0e07f, tree 44f664bdb2b41b0e583f8c208d8a68a58af3398a. Exact source_quotient_20261109/RESEARCH.md at blob e3f5a7536b64d5f6d6cd2b8ec540ca14a83e3d73 was inspected. That R171 note says its generic-NP-to-IND-CPA implication needs exact frozen-sigma recovery security in addition to hard-TRUE native forgery protection. Test whether that extra assumption was unnecessarily imposed.

## Proposed reduction, not yet promoted
Given pk=h(s) for a hard one-way SHA-preimage NP relation, the sender samples a fresh native signature pair (sk_sig,VK), computes frozen sigma=Sign(sk_sig,M), calls generic witnessless Build_hash(R_preimage,pk,sigma), and publishes capsule C,VK,M, uniform r, and t=b XOR <sigma,r>. Owner of s recovers exactly sigma from Open(C,s) and obtains b.

Suppose a QPT IND-bit distinguisher D sees a publicly sampled challenge capsule and returns b with nonnegligible advantage. Define P_C(r): sample t uniformly; output t XOR D(pk,C,VK,M,r,t). For uniform challenge bit b, t is uniform even conditioned on C,r,sigma. Therefore predicting <sigma,r> with the same advantage is equivalent to D's IND advantage. A classical-output list decoder for the noisy parity oracle P_C (with fresh re-runnable QPT invocations of D and polynomial advice copies) outputs a list including the EXACT sigma for nonnegligibly many challenge capsules.

Critical proposed repair: do not select a uniform list element as in R171, nor demand an exact-sigma hiding game. Instead simply test each listed candidate with PUBLIC native Verify(VK,M,sigma_i); output any accepted one. Since the actual frozen sigma is a valid candidate, the list guarantees an accepted native signature. This is a hard-TRUE TARGET NATIVE FORGERY even when the signature scheme is randomized/nonunique. The original hard-TRUE accepted-native-signature security notion itself supplies ORIGINAL-witness extraction or independent PQ break.

The reduction must NOT be presented as a hash-only construction: it is a necessary implication conditional on a hypothetical generic public release primitive. It may be a material correction to R171's hypothesis, but rigorous average-capsule quantifiers, replayable QPT oracle access, auxiliary input and chosen-message restrictions must be validated before finalizing.

## Preliminary actual local functional check
Actually executed a Python 3 standard-library artificial-parity-predictor checker with a 10-bit toy signature, 24 fixtures and a full 1024-point Walsh-Hadamard transform. All 49,248 assertions passed; each list contained the frozen sigma and public hash-verification selected a valid candidate. Source SHA256 0e110b55455533409d0e19fd1c3619fe8a50c601eaa790c10a82bf27ba0fc1dd; captured SHA256 1e43f9b6fdfe526f616a3391dd3308edb13d38a105a7324e6704985e90d177d1. The predictor is deliberately artificial; this tests a finite reduction identity only, NOT an IND adversary against real encryption, a QPT GL implementation, a practical witness-KEM, a chain parser or SHA security.

## Remaining before conclusion
(1) Formalize averaging over capsule samples and the polynomial success probability of the list decoder; (2) check that the forger can run D without knowing sigma and may generate chosen public (r,t) auxiliary fields; (3) ensure a witness extractor for native target forgery, not merely standalone EUF-CMA signature unforgeability, is the exact premise; (4) preserve complete proof, test and provenance to research/pq-wkem only, and distinguish necessary implication from actual compiler progress.
