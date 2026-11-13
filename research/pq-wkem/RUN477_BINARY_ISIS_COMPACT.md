# Run 477: trapdoor-free false-proof saturation under conditional QPT SIS

Live source: syscoin/PVUGC#1, draft branch research/pq-wkem-validation-20260918, parent bce95a14124f0f16944941e022947913ddb3356d. This extends Run 476's planted-token counterexample to honest classical PPT setup **with no party knowing an accepting false proof**. It does not construct a release primitive.

## Verifier and existential mismatch

For a fixed claim/UTXO/branch/source relation x, sample independent uniform A in Z_q^(n x m) and b in Z_q^n, odd prime q>=5. Publish (x,A,b). Add to any source-complete base verifier V0(x,pi) the alternative proof branch V'(x,(1,u)) = [u in {0,1}^m AND Au=b mod q], retaining V'(x,(0,pi))=V0(x,pi). Context binding prevents a proof from one claim authorizing another, but not same-claim false-proof existence.

Put N=2^m, B=q^n, and let Z(A,b) count binary preimages of b. For distinct binary u,v, A(u-v) is uniform. The indicators 1[Au=b] are pairwise independent, so E[Z]=N/B and Var(Z)=N(1/B)(1-1/B). The second-moment inequality gives

Pr[Z=0] <= (B-1)/(N+B-1).

If m >= n log2(q)+lambda, almost every honestly sampled (A,b) therefore admits a tag-1 proof, even for an ORIGINAL-false x. This is **mathematical membership**, not efficient discovery. Ordinary witness encryption for the proof-existence relation exists pi':V'(x,pi')=1 has no false-language hiding premise for such x.

## Straight-line arbitrary-QPT search reduction

Consider any QPT solver, on uniform public (A,b), returning a classical binary u with Au=b with probability epsilon. A reduction samples A, hidden uniform binary t, sets b=At, runs the solver once, and returns z=u-t if nonzero. Successful z has entries in {-1,0,1}, is nonzero, satisfies Az=0, and has Euclidean norm at most sqrt(m). No rewinding or quantum oracle programming is used.

Two-universality yields TV((A,At),(A,U_b)) <= delta = 0.5 sqrt(B/N). Conditional on (A,b), the planted t is uniform over its binary preimages; for **any** solver not holding extra information about t, Pr[u=t] <= B/N. Hence

epsilon <= Adv_QPT_SIS(n,m,q, infinity_norm<=1) + 0.5 sqrt(B/N) + B/N.

The SIS hardness requirement is **parameter-specific** for random A and a nonzero ternary kernel vector. QPT hardness is not proved here. The statement covers arbitrary QPT computation, coherent evaluation of all public arithmetic and independent or simulatable quantum advice. Advice or public checking keys leaking t, arbitrary malicious setup, correlated capsules and arbitrary signature-only extraction are NOT covered. At an entropy surplus m-n log2(q)>=256, the two statistical reduction losses are bounded by 2^-129 and 2^-256; this says nothing about concrete SIS attack cost. Exclude q=2,3, where short ternary SIS is trivially solvable by linear algebra.

## Why this does not solve witness-KEM

A computationally hard-to-find accepted inner proof need not be an ORIGINAL witness or a Run-259 accepted complete source representation. On an ORIGINAL-false statement, the inner language is nevertheless true. An independent source-false QPT release-hiding theorem or setup-wide mathematical source-language alignment is still missing. Merely assuming a private common release value on this true inner language restates the target. The native public checking key proves a signature verifies, not source provenance.

Attack checks: alternate acceptance seam (1); no gauge needed (2); public syndrome statistics not source binding (3); independent context capsules still contain fake preimages (4,7); arbitrary chosen/coherent public tests included by QPT SIS game (5,9); malicious planted t defeats setup (6); correlated native key/presignature leakage not handled by reduction (8).

## Reproducibility and limitations

run477_compact_check.js exhaustively enumerates tiny n=1 matrix and target spaces for (q,m)=(5,2),(5,3),(5,4),(7,3), checks exact first/second moments, the missing-preimage inequality, and every nonmatching planted-preimage extraction to a short SIS vector. Its captured run477_compact_validation.json records **43,258 passing assertions**; two runs were byte-identical and node --check passed. An independent extended Python checker also passed **158,797 assertions** across six exact finite regimes; the extended derivation/checker/output are local-only. Toy exhaustive solvers are not evidence for 128-bit QPT SIS hardness or cryptographic signing.

References: Ajtai, *Generating Hard Instances of Lattice Problems*, STOC 1996, https://research.ibm.com/publications/generating-hard-instances-of-lattice-problems ; classical universal hashing/leftover bound, https://crypto.stanford.edu/pbc/notes/crypto/session.html . No full modern lattice-hardness audit is claimed.

**Handoff:** find a truly source-aligned compact proof frontier, then independently justify ALL-witness SAME native capability, full-view false-instance QPT hiding, and arbitrary signature-to-ORIGINAL extraction. Preserve Run 259 only downstream of an accepted complete representation. No practical WE/WKEM, malicious N-of-N proof, multi-capsule security, concrete 128-bit resources or P2MR/SLH endpoint exists here. Production unchanged; PR draft/unmerged.
