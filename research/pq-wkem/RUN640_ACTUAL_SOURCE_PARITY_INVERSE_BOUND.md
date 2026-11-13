# Run 640 — Actual Gaussian SOURCE parity law forces a norm floor for every modular right inverse

2026-10-19. syscoin/PVUGC PR #1, draft research branch research/pq-wkem-validation-20260918, starting SHA 89dc1ef8b59f897e2ab0ec94f1c45d5270222ecf. This is a **conditional project-specific obstruction**, not a completed WE/WKEM, not a security break, and not a production change.

## Exact precondition from the actual SOURCE packet

The October 18 GPT_PRO_WE_REVIEW_PACKET.md, Appendix A07 (actual noisy-source residue theorem), proves, under its original fresh-error, full-rank-current-key and discrete-Gaussian-fiber smoothing hypotheses,

  TV((W,D mod 2),(W,U)) <= delta_slice,

where q=2^k, D=[D_0 D_1] is the genuinely sampled m by t (t=2m) integer transition, U is independent uniform in F_2^(m by t), and W can retain the boundary and all later transitions but excludes current error/quotient-revealing data. Its named error is bounded by

  delta_slice = N*t*delta_E(2) + t*epsilon/(1-epsilon) + beta_bad + eta_impl,

  delta_E(2) <= exp(-pi*(s_E/2)^2)/(1-exp(-pi*(s_E/2)^2)).

These are honest-classical-setup conditions, not a theorem about malicious setup, arbitrary quantum-correlated advice, or the full integer D being uniform mod q. The actual two correlated branches and their shared SOURCE key are preserved in the imported premise. Run 638 establishes only conditional simulation if a short J exists; Run 639's uniform-mod-q ISIS argument alone does not cover the genuine SOURCE law.

## New all-inverses theorem

For any integer R>=0, define E_R as existence of an integer t-by-m matrix J satisfying DJ=I_m modulo q and squared Frobenius norm <= R. Then

  Pr_actual[E_R] <= min(1,delta_slice + 2^(-m*m) sum_{i=0}^{min(R,tm)} binom(tm,i)).

For 0<R<=tm/2 this is at most

  delta_slice + 2^(-m*m + tm H_2(R/(tm))).

Proof: Any such J reduces to U_J=J mod 2 with Dbar U_J=I_m, hence rank(U_J)=m, and wt(U_J)<=||J||_F^2<=R. For each fixed full-column-rank binary U_J, a uniform Dbar maps every independent row to uniform F_2^m; thus Pr[Dbar U_J=I_m]=2^(-m*m). Union bound over the at most sum binom(tm,i) low-weight binary candidates; transfer via the actual-SOURCE joint TV bound, paying delta_slice. The theorem excludes existence even for an unbounded inverse finder on the corresponding good event. It does not assert that binary solvability suffices for inversion mod 2^k.

Consequently, except with the displayed bad probability, every possible full-modulus inverse has

  ||J||_F >= sqrt(R+1),  ||J||_op >= sqrt((R+1)/m).

For t=2m and rho< H_2^(-1)(1/2)=0.110027864438..., choosing R=floor(2*rho*m*m) makes the binary reference failure exp(-Omega(m*m)); the additive SOURCE error delta_slice remains essential. Taking rho=0.1 gives asymptotic floors ||J||_F >= sqrt(0.2)*m and ||J||_op >= sqrt(0.2*m).

Illustration only, not certified SOURCE cryptographic parameters: m=256,t=512,R=13107 yields reference exponent <-4064.44 binary bits and floors ||J||_F>=114.490 and ||J||_op>=7.1556. The real bound is delta_slice plus that reference probability; delta_slice may dominate. The packet's sufficient large-security regime has N,k>=lambda and m=2Nk, so m=256 must not be claimed as its λ=128 instantiation.

## Impact on existing conditional Gaussian reconstruction

Run 638's positive-definite residual requires (sigma_G/s_F)^2 ||J||_op^2<1. The present theorem makes that norm certificate unavailable whenever (s_F/sigma_G)^2 <= (R+1)/m, on the high-probability parity event.

The packet Appendix A11's noisy retained-image reconstruction uses K_required=eta*s_F/sqrt(pi*r_T*v_G/2) and demands ||J||_F<=K_required. It cannot meet this *particular sufficient certificate* if K_required^2<R+1. Thus this proof route needs s_F>=sqrt(R+1)*sqrt(pi*r_T*v_G/2)/eta in the good-residue regime. It is not a general lower bound on every conceivable simulator or on WKEM itself.

## Validation, QPT scope, and handoff

The exact standard-library Python checker was compiled and run twice, yielding byte-identical 325-assertion output. It enumerates all D and all full-rank U for (m,t)=(1,2),(2,4), checks each image probability and the full sparse-right-inverse event for every weight threshold, tests rational TV-contamination mixtures, and checks the binary entropy inequality. Finite checks do not prove the imported SOURCE smoothing hypothesis or cryptographic security.

This is an information-theoretic statement about honest-generated public matrices; arbitrary QPT effort or coherent public evaluation cannot create an inverse that does not exist. It does not imply false-instance QPT key hiding, hard-true unauthorized key recovery/accepted signature to ORIGINAL extraction, malicious N-of-N erasure security, related-capsule independence, or a PQ Bitcoin endpoint. Cross-capsule use requires each source slice to satisfy the stated conditional residue theorem; no new setup assumption or release gadget is introduced.

The next step is to substitute actual permitted boundary/preimage/noise widths and retained row count into these *necessary* norm budgets. If the inequalities are satisfied, the public short-inverse existence and PPT-finding problem is still open, as are the full globally SOURCE-conditioned QPT security proof and the Run 259 recovery-to-ORIGINAL arrow. No complete practical PQ witness-KEM. PR remains draft/unmerged; automation stopping criterion unmet.
