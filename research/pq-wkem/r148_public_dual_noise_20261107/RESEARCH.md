# R148 — Public minimum-noise dual for ORIGINAL ideal-mask release

Status: REJECTED nonmodular bounded-noise repair class; exploratory modular case. NO positive advance toward a generic ORIGINAL-witness WKEM, no optimization. Routine failed candidate; do not send a progress notification.

Continuity: initial PR #1 head 3e85b5d501fb8b8b3b776022a00b2b31e7481840 on research/pq-wkem-validation-20260918, open/draft/unmerged. Read exact R147 RESEARCH.md blob 669cdee1514b5490071759379aba42a25717c7ed. That checkpoint proved universal public cleartext coefficient projection for TRUE instances; encrypted source was uninstantiated. This run tests whether additive bounded or Gaussian noise alone repairs its public projector.

## Nonmodular full-public source and theorem

Compile ORIGINAL verifier/statement, claim/UTXO, branch, anchors/window, context and native VK identity into Boolean polynomial constraints. Let M_x in Z^(N x t) be the polynomial coefficient matrix for selected ideal generators and e0 in Z^N the constant monomial vector. In this candidate the issuer chooses the SAME precommitted integer capability K, hidden r and errors eta with public coordinate bounds |eta_i| <= B_i, and publishes P=Delta K e0+M_x r+eta in Q^N, with all checking key/CK/J/Aux/context and related capsules. An ORIGINAL witness w yields v_w (its Boolean monomial evaluations) with M_x^T v_w=0, e0^T v_w=1. Off-chain Open verifies the actual ORIGINAL witness and evaluates Round(v_w^T P/Delta). Every witness opens the SAME K if sum_i B_i |(v_w)_i| < Delta/2.

**Theorem (public bounded-noise dual).** On any TRUE ORIGINAL instance the linear constraints M_x^T lambda=0 and e0^T lambda=1 are feasible because at least one honest witness v_w meets them. Independently of knowing w, solve the public rational linear program

    minimize sum_i B_i |lambda_i|
    subject to M_x^T lambda=0 and e0^T lambda=1.

Exact rational LP is classical polynomial time for polynomial-size integer/rational inputs and polynomial-bit rational certificates. Its optimum lambda* obeys sum_i B_i|lambda*_i| <= sum_i B_i|(v_w)_i| for EVERY genuine witness. It cancels the unknown source mask: lambda*^T P=Delta K+lambda*^T eta. If correctness is guaranteed on all error tapes by the displayed coordinate bounds for honest evaluation, the public witness-free linear functional has the SAME deterministic rounding guarantee. The attack is classical and only uses a subset of the full public distribution, so CK/J/Aux or sibling capsules cannot repair it. Arbitrary correlation between bounded error coordinates does not help.

**Gaussian extension.** For centered real Gaussian eta with publicly known rational positive definite covariance Sigma, minimize lambda^T Sigma lambda under the SAME linear constraints. The public optimizer has variance no larger than any witness evaluator, hence at least as good centered Gaussian rounding probability. When Sigma=I and C=[M_x^T;e0^T] has full row rank, lambda*=C^T(CC^T)^(-1)b with b=(0,...,0,1). For general Sigma use weighted normal equations. This is not a PQ security reduction or a hardness assumption.

This rejects the entire stated NONMODULAR affine bounded-noise or Gaussian source class, not witness encryption in general.

## Important modular qualification

For ciphertext residues P=(Delta K e0+M_x r+eta) mod q, a *rational* optimizer may have denominators whose modular inverses are large and unknown wraps prevent using its real-valued shortness as a mod-q noise bound. Therefore the general theorem must NOT be lifted to standard modular QPT-LWE. Whether short INTEGRAL/mod-q unauthorized duals always exist is unresolved. No ordinary LWE challenge simulator jointly reproducing a structured ORIGINAL-dependent M_x, checking keys, context, auxiliary outputs, related capsules or selective openings was constructed. No arbitrary final-key-recovery -> ORIGINAL-witness extraction was constructed.

A small, deliberately EASY true formula shows some integer short unauthorized duals do exist even mod q. With monomials [1,x,y,x^2,xy,y^2] and constraints [x^2-x, y^2-y, (1-x)(1-y)], the public coefficient matrix is

    [[0,0,1],[-1,0,-1],[0,-1,-1],[1,0,0],[0,0,1],[0,1,0]].

All three assignments (0,1),(1,0),(1,1) satisfy it. An EXACT PUBLIC integer dual (1,0,0,0,-1,0) has l1=2 versus minimum actual witness l1=3; its integral coefficients preserve modular cancellation. The exact public minimum-isotropic-variance rational dual is (1,1/4,1/4,1/4,-1/2,1/4), squared norm 3/2 versus minimum honest squared norm 3. This concrete example is NOT a hard-TRUE witness-search break and does not rule out every higher-degree modular construction.

## Executed check and next equation

The attached EXACT offline checker.py (Python standard library plus SymPy 1.14.0) enumerates rational basic-feasible duals, verifies public constraints and actual witness equations, checks both optima, and runs 2048 independent modular honest encryptions with q=65521, Delta=64, eta_i in {-1,0,1}, K=1. Every genuine witness and the public integral dual recover the bit on all tested tapes. The attached captured.json is the exact output. These are functional checks, not QPT attack experiments.

Needed next: a genuinely modular ORIGINAL-dependent source in which every actual ORIGINAL witness yields the SAME precommitted native capability, but the reduction can jointly simulate all statement-dependent source keys/ciphertexts, CK/J/Aux, context, related capsules, permitted openings and quantum advice under independently justified QPT assumptions. Arbitrary final-key recovery or accepted native forgery must imply an actual ORIGINAL witness or independent PQ break, with NO adversary-volunteered internal vector. False-instance, hard-TRUE, malicious N-of-N setup/abort, data availability and hypothetical Bitcoin PQ endpoint remain unproved.

Provenance: authorized GitHub PR metadata, current commit metadata, latest relevant issue-comment query, exact R147 note. Local bounded SymPy execution. No web/external literature, entire PR diff, independent agent, production change, merge, on-chain functionality or deployment.