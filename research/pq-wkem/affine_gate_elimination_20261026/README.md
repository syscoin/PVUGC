# Affine-gate elimination for the Fourier-filtered SOURCE carrier

Research-only checkpoint, 2026-10-26, run affine-multiplicative-20261026T2102Z. Exact predecessor: syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, commit 72e57de2d2b0892b9f79a5ec4a0cfcdb2d0c7b4e; the predecessor research/pq-wkem/fourier_filtered_gate_noise_20261026/README.md has blob 73141f5b899bbcf09cbbc32bf57fa3e65884949c. NO web/literature research, production edit, deploy, completed PQ WKEM, source-opening oracle or QPT-LWE reduction is claimed.

## New compiler/release operation

The predecessor made ALL Boolean gates noisy NAND assignment factors, so honest BSC reliability decayed exponentially in total gate count. In the new construction, express the ORIGINAL relation as a GF(2) circuit with exact *affine* gates (XOR, XNOR, NOT, equality, public pins) and only AND/NAND nonlinear factors. Let g count ONLY nonlinear factors, not the total G Boolean gates. This yields a concrete classical compiler and common capability opening, without altering the predecessor's factor-noise law.

For each Boolean wire i introduce binary one-hot coordinates v_(i,0),v_(i,1) and normalized constant c=v_0. Impose v_(i,0)+v_(i,1)+c=0 over GF(2). For every affine gate y = epsilon XOR (XOR over input wires i), add exactly one SOURCE matrix row

  v_(y,1) + SUM_i v_(i,1) + epsilon*c = 0.

A pinned bit i=b has row v_(i,1)+b*c=0. AND/NAND gate f(a,b;y) retains the predecessor's four satisfying assignment-label coordinates v_(f,t), one factor row SUM_t v_(f,t)+c=0 and incidence rows SUM_(t:t_i=z) v_(f,t)+v_(i,z)=0 for each incident wire i and z in {0,1}. Public C_x is the complete row matrix. These are HOMOGENEOUS equations, not an unproved nonlinear rank assumption.

Take a public GF(2) row basis R of ker C_x and b=R e0. For each independent release column choose uniform X_j, per nonlinear factor independently sample E_f=0000 with probability 1/3 or one of four one-hot errors with probability 1/6 each, and set ALL wire/constant/affine coordinates of E to zero. Publish Q_j=R E_j+b X_j. Keep the predecessor's public polar frozen helper W=(X G_L)_F, independent Toeplitz H, pad T=K XOR H X, native checking key vk(K), exact ORIGINAL relation/claim/UTXO/branch/anchor/context and auxiliary data. All honest algorithms are classical polynomial time in emitted length L; generic L remains EXPONENTIAL in g, so the required practical polynomial-in-circuit-length setup is NOT achieved.

## Honest every-ORIGINAL-witness theorem

Every valid ORIGINAL witness w extends to possibly distinct circuit intermediate states, a normalized one-hot vector v_w with (v_w)_0=1, one wire bit per wire, one satisfying assignment-label per nonlinear gate, and C_x v_w=0. Affine rows hold because they encode XOR identities EXACTLY. Since rows of R span ker C_x, the opener computes public alpha_w with alpha_w R=v_w^T. For every release column

  alpha_w Q_j = X_j + v_w^T E_j.

There is no noise at affine gates. One assignment label is selected at each nonlinear factor, which contributes independent Bernoulli(1/6) error. Thus every valid w observes the SAME marginal BSC, bias rho^g=(2/3)^g, and uses the SAME public frozen helper to recover the SAME precommitted K=T XOR H X (subject to finite-block decoding error). No common witness representation or intermediate state is assumed.

When an affine output wire is freshly introduced without any additional constraints, its two wire-label coordinates are balanced by its one normalization row and its one affine-gate row. This does NOT increase dim ker C_x, hence does not increase the public quotient dimension. One two-input XOR implemented through four NAND factors instead reduces honest bias by rho^4 and, in the small-bias Shannon regime, inflates the theoretical number of columns by approximately (9/4)^4 = 6561/256 = 25.62890625. Replacing XOR factors with exact affine rows therefore gives a meaningful relative efficiency improvement WITHOUT weaker predecessor false-instance secrecy. The improvement does NOT overcome exponential cost in the number of AND/NAND gates.

## Complete false-source Fourier theorem

For any v in ker C_x with v_0=1, wire-normalization rows select exactly one of each wire's two bit labels. Each nonlinear four-label factor has odd selected-label cardinality, hence 1 or 3. If every nonlinear gate selected 1, its incidence rows would force those assignment labels to agree with all wire bits; every exact affine row and every pin would also hold. These wires therefore describe a satisfying ORIGINAL circuit state. On a FALSE ORIGINAL instance that is impossible, so EVERY odd-constant kernel vector contains at least one nonlinear factor selecting 3 labels.

The unchanged single-gate noise law has exact parity Fourier coefficients phi(0)=1, phi(1)=2/3, phi(2)=1/3, phi(3)=0, phi(4)=-1/3. For every public Fourier character a of the COMPLETE quotient and v=aR,

  E[(-1)^(a.Q_j) | X_j=t] = (-1)^(t*v_0) PRODUCT_f phi(number of factor labels selected by v).

If v_0=0 this is t-independent. If v_0=1 on FALSE x, one phi(3)=0. Fourier inversion proves the complete Q distribution conditioned on X_j=0 is EXACTLY the distribution conditioned on X_j=1. An explicit false challenge simulator computes C_x,R, samples fresh E from the above joint law and emits Q=R E without X,K or a SourceOpen oracle. Fresh columns give full Q^L independence. This is exact CLASSICAL distributional equality and therefore remains indistinguishable under arbitrary QPT postprocessing with independent quantum side information. Correlated quantum setup advice/retained coins are not covered.

For a false instance, W reveals r_F linearly independent bits of uniform X^L, Q is independent of X^L, and H_min(X^L|Q^L,W)=L-r_F. With independent two-universal Toeplitz H, the statistical leftover-hash distance for HX from uniform is at most 1/2 sqrt(2^(k-(L-r_F))). The *ideal simulator retains the REAL vk(K), x, context and admissible auxiliary information* but replaces T by uniform. The claim requires hidden release coins independent of that auxiliary checking material conditioned on public context and K; it does not protect against a checking key already revealing K. Fresh independently generated unopened related capsules compose via additive hybrids only under independent-pad and selective-opening exclusions. An N-of-N malicious ceremony, erase/retention/abort properties, native verifier, and full Bitcoin graph remain unproved.

## Executed, reproducible checks

Independent JavaScript checker check_affine_source.js (exact source in this commit) was EXECUTED with 428 assertions: exact GF(2) kernel and quotient, exhaustive conditional quotient distribution of the mixed two-XOR/one-NAND FALSE instance, distinct valid ORIGINAL witnesses 01/10/11 on a TRUE instance, their same-X release projection and exact Bernoulli(1/6) marginal, and rank neutrality of inserted affine wires. Output captured in checker_output.txt.

A larger standalone offline Python checker passed 195 assertions twice with byte-identical stdout. It additionally checks pure affine cases, extensions of 1,4,12,32 wires and independent g=1..8 parity convolution. Its exact proof, source, output and SHA256 sums are in the user-delivered local archive WKEM_AFFINE_MULTIPLICATIVE_20261026.tar.xz (SHA256 7e5c66f1ca8373be382d20e0440d34d80d12d171048ace54a7dcd28316876d74). Do NOT count local-only Python materials as GitHub-published.

## Boundary / exact next proof obligation

This is a verified CONSTRUCTION/COMPILER EFFICIENCY improvement for an existing restricted full-false-view carrier, not a generic practical WKEM. It retains L=Omega((9/4)^g) worst-case honest projection cost, no independent QPT-LWE or other PQ reduction, and NO proof converting ARBITRARY unauthorized hard-true recovery/native forgery (without volunteering an internal representation) into an ORIGINAL witness or independently justified QPT break.

Needed next: a polynomial-length classical-PPT sampler and release with joint public (x, relation, SOURCE capsule, checking key, W,H,T,context,auxiliary data,related capsules), an explicit challenge simulator with every source/opening correlation, every-valid-ORIGINAL-witness same-K correctness, and a reduction for any QPT key recovery/native forgery to an ORIGINAL witness or independent QPT cryptographic break. The previously established supplied-representation -> ORIGINAL witness lemma does not fill that gap. Not a claim about deployed PQ Bitcoin scripting or Syscoin consensus.
