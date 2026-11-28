# Fourier-filtered gate-local noise — exact generic false-SOURCE secrecy

Research-only checkpoint, 2026-10-26. Prior exact version: syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, head 9f4579adc4c564b4afab772f0821b2462e8a2bf9, predecessor factor_only_noise_20261026/README.md, blob be48a801acc9851d6ca712a568a9aa959baec0c3. NO practical, polynomial-resource generic-NP WKEM or QPT-LWE reduction is claimed.

## Complete release and honest opening

Compile ORIGINAL R_x(w) into bounded-fan-in NAND gates, each with four permitted triples (input0,input1,output), plus public copy, pin and context-binding constraints. Ensure every satisfying circuit assignment projects to a valid ORIGINAL witness; each original witness extends to its own circuit state. This is a source-compiler condition, not a proof of Bitcoin native verifier deployment. Claim/UTXO, branch, actual authorization/burn/output, anchors/window, intended native vk, relation ID and context must be included in x.

Use binary one-hot homogeneous SOURCE C_x with coordinates v_0, v_(wire,bit), v_(factor,allowed assignment), rows:
  v_(i,0)+v_(i,1)+v_0=0;
  sum_(a in A_f) v_(f,a)+v_0=0;
  sum_(a in A_f:a_i=b) v_(f,a)+v_(i,b)=0.
Let public R be a GF(2) row basis of ker(C_x), b=R e_0. For EACH column j, choose independent uniform X_j, and INDEPENDENTLY for every four-label NAND gate sample error E_f,j from:
  P(0000)=1/3, P(1000)=P(0100)=P(0010)=P(0001)=1/6.
Constant/wire/copy/pin errors are zero. Emit the ENTIRE SOURCE capsule Q_j=R E_j+b X_j. No SourceOpen oracle, hidden S or public NP verification on Bitcoin. Publish polar frozen helper W=(X G_L)_F for the BSC below, independent public two-universal Toeplitz H, T=K XOR H X, the PRECOMMITTED native checking key vk(K), and full x/context/aux. Honest Build/Open take classical time polynomial in explicitly emitted L, but L itself is exponentially large in generic gate count.

For ANY valid ORIGINAL w, check R_x(w) off-chain, compute its distinct binary one-hot lift v_w, solve public alpha_w R=v_w^T, and observe alpha_w Q_j=X_j+v_w^T E_j. Since exactly one label is selected in every NAND factor, EVERY valid witness sees an independent-over-columns BSC of bias rho^g=(2/3)^g, g=#gates, and capacity C_h=J(rho^g), J(t)=1-h2((1+t)/2). Decode X using W, then K=T XOR H X. All valid ORIGINAL witnesses recover THE SAME precommitted K after successful decoding, without a canonical/common witness state. Witness projections for different w may be correlated.

## Proof of ENTIRE false-source output independence (no hardness assumption)

The FOUR-label local parity Fourier spectrum is phi(S)=1,2/3,1/3,0,-1/3 for subset sizes |S|=0,1,2,3,4 respectively. Any binary v in ker(C_x) with v_0=1 selects an ODD number of assignment labels at each four-label gate, and exactly one bit label per wire. If each factor selected exactly ONE label, its linkage rows would make a globally consistent satisfying NAND circuit assignment and hence a valid ORIGINAL witness. For false ORIGINAL x no such assignment exists. Therefore EVERY odd-constant kernel vector v selects THREE labels at at least one NAND factor, whose local Fourier coefficient is EXACTLY ZERO.

For any public quotient character a and fixed hidden bit t, the full conditional character is
  E[(-1)^(a.Q_j)|X_j=t] = (-1)^(t*(aR)_0) product_f phi_f(S_f(aR)).
If (aR)_0=0 it is independent of t. If (aR)_0=1, false SOURCE forces a zero factor. Fourier inversion then proves EXACTLY
  Law(Q_j | false x,X_j=0)=Law(Q_j | false x,X_j=1).
This covers the WHOLE Q (every Fourier character, every nonlinear classical/QPT operation), not isolated marginal probes. Fresh columns imply Q^L independent of X^L. The classical false-SOURCE simulator computes C,R, samples fresh gate errors E and outputs Q=RE without X, secret K or witness. The source-dependent setup and simulator are instantiated TOGETHER; this does not invoke LWE.

## Full public helper/hash/checking-key correlations

For false x, public frozen helper W is rank-r_F LINEAR in the uniform X^L. Q^L is independent of X^L and W, hence exact H_min(X^L|Q^L,W)=L-r_F. Fresh public two-universal Toeplitz H gives
  TV[(Q,W,H,HX),(Q,W,H,U_k)] <= 0.5 sqrt(2^(k-(L-r_F))).
At k<=L-r_F-2lambda-2 this is <=2^(-lambda-2). A complete false-source challenge simulator emits Q=RE, generates independent X for W, fresh H and UNIFORM T, and carries the REAL precommitted vk(K), full x/context and admissible auxiliary info unchanged. The real and ideal complete views differ only by this statistical bound EVEN with arbitrary quantum postprocessing/advice conditionally INDEPENDENT of hidden X,E,H given x,K,vk and context. Native vk may itself reveal K if its underlying PQ signature assumption fails: security is incremental, not absolute. Fresh independent related unopened capsules compose by additive hybrid error ONLY if none exposes the challenged K through a known true witness. Reuse/opening of challenge E/X, malicious setup coin retention, correlated quantum setup advice or selectively opened challenge pads is not covered.

## Optimality and fatal scalability limitation

For d allowed local assignments and signs s_i=(-1)^(E_i), put Z=sum_i s_i, rho_d=1/E_uniform|Z| and P_d(s)=2^(1-d)*rho_d*max(Z,0). This is normalized and nonnegative. It has singleton odd Fourier coefficient rho_d and ZERO all odd Fourier coefficients of degree >=3. Conversely if equal singleton rho and all higher odd Fourier coefficients vanish, Fourier inversion forces
  P(s)-P(-s)=2^(1-d)*rho*sum_i s_i.
Nonnegativity summed over positive Z gives rho<=1/E|Z|. Thus rho_4=2/3 is OPTIMAL for this specific INDEPENDENT FACTOR-LOCAL filter. For seven-label 3-CNF factors rho_7=16/35. This is no lower bound on global correlated samplers or other computational approaches.

Honest capacity C_h=J((2/3)^g) asymptotically (4/9)^g/(2 ln 2), requiring Omega((9/4)^g) columns just for witness-projection decoding. Shannon-only 256-bit floors: g=2 ->1735, g=4 ->9036, g=8 ->233048, g=16 ->153114227; actual security/reconciliation requires MORE. This exponential honest size violates practical classical PPT-in-input requirements. LWE wrapping cannot increase this weak honest capacity. The filtered release is a TRUE generic false-instance leakage repair and useful exact proof component, NOT a practical WKEM.

## Reproducibility and exact remaining obligation

Independent offline standard-library Python checker passed 7,414 assertions TWICE with byte-identical output. Its local archive containing full longer proof, exact source, output and SHA provenance: WKEM_FOURIER_FILTER_GATE_20261026.tar.xz, SHA256 63d5aac1f5f346f502dfec5afddb7918a081444b1275ef23bcfff9b18fb598af. The local checker exhaustively verifies BOTH hidden-bit full Q laws in a contradictory NAND/AND fixture (m=15, rank11, h4; eight odd modes killed), four distinct true NAND/NAND witnesses and 1024 honest opening identities, d4/d7 Fourier laws, and samples 2048 characters on larger eight-clause false 3CNF (NOT exhaustive at h28). This directory contains a smaller INDEPENDENTLY EXECUTED JS checker with exact captured output/provenance.

The decisive missing equation remains arbitrary QPT unauthorized bare-K recovery or accepted native signature forgery on FULL (x,ctx,C,R,Q,W,H,T,vk,aux,related capsules) => actual ORIGINAL witness or INDEPENDENT QPT break, without demanding alpha, v or X from attacker. Hard-true soundness is UNSOLVED. Practical polynomial-rate PQ construction, independent LWE challenge simulator, malicious N-of-N setup/abort/erasure/coin-retention proofs, full Bitcoin graph and PQ native endpoint are also UNSOLVED. PR stays draft/open/unmerged; no production/workflows affected.
