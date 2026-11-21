# R293 — Coordinate-canceling public cube release (NONQUALIFYING for ORIGINAL source)

## Start and source scope
PVUGC PR #1 existing open/draft research branch, observed start a199d4edb895cc17ea2eb8716338b2e4fed5c621; continues R292 explicit Boolean-quotient correction blob `0a289aa752b277410c5e1ff8592e13959acaa702` after R291/R289. Last substantive ordinary comment is R225 #6796383617. No web/literature, Core tests, network release, native PQ or actual AuxPoW admission. Core #609 contextual modern chain-ID/exact parent-tag constraints and R287 carrier provenance stay mandatory but are NOT implemented here.

**Outcome: a new complete-public, exact FALSE-hiding toy for polynomially enumerated cube systems, NOT an ORIGINAL-source Build/Open or secure bridge.** This does not qualify as the requested practical hash-only witness-KEM, nor as an advance solving its source-release foundation.

## Concrete restricted Build / Open
For each independently randomized term t with a single full n-bit witness w and m local conjunctions `C_i(w)=AND_j[w_j in A_(i,j)]`, each `A_(i,j)` is one of `{0},{1},{0,1}`. The target policy is an explicitly listed polynomial-size OR of such terms. Freeze one lambda-bit payload K.

Build per term: choose n coordinate shares K_j with XOR_j K_j=K; split each K_j into m independent uniform shares k_(i,j) with XOR_i k_(i,j)=K_j. For every (j,b), choose m masks r_(i,j,b) with XOR_i r_(i,j,b)=0. Publish **only** tokens
```
 T_(i,j,b) = k_(i,j) XOR r_(i,j,b), if b belongs to A_(i,j).
```
Fresh independent mask/share randomness for EACH term; sharing K is the only cross-term correlation. Public Open for any full witness w satisfying a term XORs T_(i,j,w_j) over all i,j and returns exactly K. Every satisfying witness and satisfying term returns the SAME K without enumerating witnesses. Build size O(Tmn*lambda), classical PPT for explicitly polynomial T, with no secret future row generator. Uniform setup randomness, not SHA PRG security, supports the exact theorem.

## Complete-public FALSE theorem and independent-term composition
Each token is a linear form in independent uniform K, coordinate shares, clause shares and masks. Suppose an adversary's public linear combination equals K. At each j, mask cancellation forces its coefficients a_(i,b) to be constant over i for each b: beta_b. Share cancellation forces a_(i,0)+a_(i,1)=alpha_j constant over i. Thus alpha_j=beta_0+beta_1. Beta_b can be nonzero only if b is allowed by ALL clauses at j. To recover K, independent coordinate pads force alpha_j=1 for EVERY j. Therefore K belongs to the row span of ALL public tokens **iff** a common w exists for that cube term. A FALSE cube has a contradictory coordinate, so K is outside the span. For fresh uniform linear variables, the complete public transcript distribution conditioned on any fixed K is identical: exact statistical FALSE secrecy against arbitrary classical or QPT postprocessing of the sampled classical bytes. This is not a QROM, hard-TRUE, malicious-setup or correlated-auxiliary theorem.

For an OR of independently sampled FALSE terms, each term's complete transcript is K-independent conditional on K, and term transcripts are independent conditional on K. Their joint distribution is therefore K-independent. Any TRUE term admits the same frozen K. This is a legitimate restricted composition, not the ORIGINAL relation.

## Failure of reusing a term across OR branches
FALSE relation `(x=0 OR y=0) AND (x=1 AND y=1)`: using the SAME coordinate-mask family for the two alternatives x=0 and y=0 exposes both bit choices for both coordinates of the first clause. A fabricated common w=(1,1) then XORs public tokens to recover K. Independent whole-term capsules fix this leakage only inside the restricted polynomial-DNF model.

## Concrete SHA circuit obstacle to using this as original release
For actual SHA-256 Boolean choice function `Ch(x,y,z)=(x AND y) OR ((NOT x) AND z)`, with output v, graph `v=Ch(x,y,z)` has 8 satisfying assignments. Any contained Boolean cube covers at most 2, and 4 cubes suffice. With L DISJOINT Ch gadgets, graph has 8^L assignments, each contained cube at most 2^L, hence exact direct cube-DNF requires **at least 4^L terms**, and products of four basic cubes attain it. This does not prove an exponential lower bound for full SHA (wires are shared) or arbitrary obfuscated representations. But the proposed direct DNF compiler is exponential already on independent SHA-type nonlinear gates. No polynomial ORIGINAL verifier compilation is supplied.

Original claim binding, authenticated AuxPoW/Merkle+Bitcoin anchors, exact modern contextual tags, relevant semantic ancestor at h_rel, fault-wrapper pinning, LC depth, burn authorization, three OR grounds, deadlines/reset, native VK/message and N-of-N ceremony do NOT reduce to the toy subcube policy. They cannot be checked after capability extraction. Hard-TRUE source-free recovery/accepted native forgery -> actual ORIGINAL certificate or independent PQ hash/native break is entirely missing. Trivial publicly readable cube witnesses are not hard-TRUE source certificates. No size optimization or production code proposed.

## Exact bounded checks and local evidence
Local Python 3 standard-library checker generated public linear token vectors, tested their GF(2) row spans, and numerical 256-bit Build/Open controls. Exhaustive 729 (m=2,n=3) systems: 343 TRUE, 386 FALSE, all agreed with span criterion. 400 random systems: 55 TRUE / 345 FALSE; 250 independent multi-term DNF systems: 113 TRUE / 137 FALSE. 532 explicit input opening/rejection checks, including four distinct same-K witnesses. Verified OR-reuse FALSE disclosure and independent-term repair. Enumerated 3^4 and 3^8 candidate cubes of one and two disjoint Ch gadgets. Two final outputs byte-identical.

Checker SHA256 `06c4d33316acdba1a1f3d663cc7ae761a564f66f1df2b22fa224d976bd2e8cba`; each run JSON SHA256 `203993fd3d4ed9fca0ce4b47ec7e9c1cc676ce3bde1ea54289bc68fd336c9071`. Detailed derivation/source/two outputs local-only archive `R293_cube_subspace_20261115.tar.gz`, SHA256 `ce082dec67f85ce9ca3caeaed69119ed40ce469297cb7a1be6a0074afc3aec40`; NOT committed or claimed on GitHub. Deterministic SHA256 coins only reproduce synthetic numerical examples, not full-independent-real-coin security of SHA.

## Unfinished ORIGINAL equation
Construct classical-PPT `Build_inc(x_W,sigma_cancel)`, public `Open_inc(C,w)`, with **all** future qualifying ORIGINAL authenticated challenge witnesses recovering the identical frozen safe cancellation authorization, without exponential SHA-cube enumeration, publicly annihilable quotient coefficient spaces, reusable-garbling cut splicing, repeated-bit-state mismatch or public-only source forgery. Establish full-public QPT hard-TRUE recovery/native forgery extraction into ORIGINAL evidence or independent hash/native break, with sibling/auxiliary/malicious setup and endpoint reuse scoped. No such construction is established here; no PR comment, milestone, or automation stop warranted.
