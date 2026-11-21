# Adaptive independent-claim openings for transverse-LWE × ORIGINAL-NP release

Research-only, 2026-10-27, bounded offline iteration adaptive-independent-lwe-20261027-turn9. Existing draft PR syscoin/PVUGC#1 branch research/pq-wkem-validation-20260918, starting head 1d46ab641973d8a6192c68ef1437eb79c774c232. Exact predecessor: research/pq-wkem/cardinality_transverse_lwe_20261027/PROOF.md, blob 2260a962953b11dd3bbcf1b92784e73d9460e439.

## Constructive delta and hard boundary

This extends the actual independently instantiated cardinality-pinned transverse ordinary-QPT-LWE + physical Fourier/polar arbitrary ORIGINAL-NP AND release to POLYNOMIALLY MANY INDEPENDENT native-key claims, adaptive non-target full-secret disclosure, and target NP-share/NP-randomness disclosure. It yields a straight-line whole-public-output reduction for whichever uncompromised claim the adversary selects AFTER observing and opening related capsules. This is a previously excluded restricted selective-opening case. It is NOT a general arbitrary correlated-key or arbitrary leakage theorem, and NOT a Bitcoin PoW to LWE-kernel compiler. All claims must have independently generated native signing seeds. A single claim still recovers one SAME precommitted K from every valid witness pair.

## Complete distribution and classical release

For m polynomially bounded separate claim/UTXO/native-spending scopes, independently generate actual uniform native signing seeds K_i in {0,1}^k with real checking keys pk_i=NativePK(K_i). All public contexts ctx_i explicitly bind relation identity, claim, burn/authorization/output, UTXO, branch, anchors/window and intended native signature scopes. ctx_i and public row multipliers b'_i may depend on all public pk_j but not target secret K_i, target LWE errors, future witness or other target hidden randomness. Source relations are defined solely from public context.

For each claim i choose q_i=2^a_i, 0<=nu_i<a_i, g_i=2^nu_i, h_i|g_i, c_i=g_i/h_i, dimensions n_i,d_i, c_i*n_i<q_i, noise chi_i supported in [-beta_i,beta_i], g_i>2*h_i*beta_i. Sample B_i independently uniformly in Z_q^{d_i x n_i}. Let alpha_i=c_i*(1,...,1) in Z_q^{n_i}. Choose public b'_i=(1,h'_i,2,...,h'_i,d_i+1) deterministically from pk_all,ctx_i BEFORE drawing B_i. Reconstruct A_i with first row alpha_i and subsequent rows B_i,row+h'_i,row*alpha_i, and b_i=g_i*b'_i. The actual linear ORIGINAL relation is

  R_L,i(B_i;w) := [ w in {0,1}^{n_i}, weight(w)=h_i, B_i*w=0 mod q_i ].

It is equivalent to A_i*w=b_i for binary w under c_i*n_i<q_i. This random-binary-kernel relation is an independently instantiated restricted reference source, NOT the claim-bound Bitcoin/Syscoin NP relation.

Independently sample U_i uniform {0,1}^k and put V_i=K_i XOR U_i. Let r_i=a_i-nu_i, ell_i=ceil(k/r_i); choose a fixed public rank-k GF(2) map L_i on ell_i*r_i bits. For each column j independently draw t_ij uniform Z_q, u_ij uniform Z_q^{d_i}, e_ij sampled from chi_i^{n_i}, then publish

  p_ij = alpha_i*t_ij + B_i^T*u_ij + e_ij (mod q_i),
  z_ij = t_ij mod(q_i/g_i),
  D_i  = U_i XOR L_i(z_i1 || ... || z_i,ell_i).

Generate an ACTUAL physical Fourier/polar NP capsule F_i under a public arbitrary ORIGINAL relation R_N,i(pk_all,B_i,ctx_i;v), encrypting V_i with independent sampler coins and public dither. Publish all B_i,A_i,b_i,alpha_i,g_i,D_i,p_ij,F_i,pk_all,ctx_i, native scopes, related capsules and expressly allowed auxiliary context. Setup has no access to future linear or NP witness and no SourceOpen oracle. Honest participants must protect/erase K,U,V,t,u,e and SOURCE sampler randomness; malicious N-of-N/abort and keyless Build are NOT proved.

Recover_i(w,v) checks the actual two relations; for valid w, w^T*p_ij=g_i*t_ij+sum_{a:w_a=1}e_ij,a mod q_i. Bounded error h_i*beta_i<g_i/2 ensures nearest-mod-g rounding yields z_ij EXACTLY for EVERY accepted linear w. Then Uhat_i=D_i XOR L_i(z_i); existing certified physical Fourier/polar decoder gives Vhat_i for ANY accepted ORIGINAL NP v with its previously proved simultaneous all-witness error eps_N,i. Output Khat_i=Uhat_i XOR Vhat_i after actual native checking-key verification and sign only the intended claim/path challenge offline. Over m claims total honest all-witness error <= sum_i eps_N,i. Distinct valid witnesses keep distinct intermediate states.

## Exact adaptive disclosure game and conditions

Arbitrary coherent QPT adversary A sees ALL public outputs, all real checking keys, declared native signing/presigning interfaces, and jointly computable public context/auxiliary data. It may adaptively call:

  OpenNP(i): reveal V_i and ALL target NP-side private sampler/decoder coins. This is allowed EVEN for the target ultimately attacked.

  OpenLinear(j): reveal U_j, all t_ij/u_ij/e_ij linear coins, optional entire K_j, and any permitted valid reference witness. This puts claim j into compromised set S_L. No success for j can be called unauthorized afterwards.

It may open every other claim, including all their native keys and ciphertext randomness. It may adaptively choose a target AFTER these disclosures. It wins at i only if i is NEVER in S_L and it outputs exact K_i or a truly fresh unauthorized native signature for i's bound path. A target valid R_L witness or equivalent source-dependent opening token, arbitrary function leaking uncompromised U_i/t/u/e, reused K across independently spendable claims, correlated secret signing paths, or malicious B selected after setup are NOT allowed. QPT auxiliary/advice is independent of target freshly generated LWE secrets/errors; native correlated signatures must be provided through a legitimate challenger signing interface. Cross-context public correlations are fine when the simulator can compute them from public pk and independently generated unrelated keys.

## Straight-line whole-view ordinary-QPT-LWE simulation

Fix any i and let Win_i be exact unauthorized success at i with no prior OpenLinear(i). A simulator may immediately abort with outcome false when OpenLinear(i) is requested; this changes NO event contributing to Win_i. OpenLinear(j) for all j != i is answered exactly using independently sampled non-target claim secrets. OpenNP(i) is answered exactly using the actual chosen target V_i and F_i coins, including its full private NP release randomness.

Build ell_i adjacent hybrids H_i,j which replace first j target noisy vectors p_ij by uniform Z_q^{n_i}; all other instance capsules, checking keys, target NP-side share and coins, native interfaces, related public context, and non-target opening replies remain their actual joint distributions.

For each single transition, an ordinary decisional-LWE challenger gives uniform B_i and c in Z_q^{n_i} either c=B_i^T*u+e with u uniform Z_q^{d_i}, e~chi_i^{n_i}, or independent uniform. The straight-line reduction samples the REAL native K_i and pk_i, real U_i,V_i, t_ij and other coins, places p_ij=alpha_i*t_ij+c, and generates every other target column honestly or uniformly as dictated by the hybrid, plus all other capsules and allowed opening responses. This is the ACTUAL full source and checking-key distribution; it does not call SourceOpen or learn the challenge hidden u/e. Other public checking keys may be sampled first, and b'_i determined before uniform B_i.

At final H_i,ell_i, all p_ij are uniform independent of t_ij, other public outputs and any unrelated disclosed coins. Since t_ij uniform mod q_i, each z_ij is uniform on r_i bits; rank-k L_i makes P_i=L_i(z_i) exactly uniform k bits. Conditioned on ANY fixed actual K_i and pk_i(K_i), because U_i and P_i are independent uniform,

  (D_i,V_i)=(U_i XOR P_i,K_i XOR U_i)

is jointly uniform on 2k bits and independent of (K_i,pk_i). Moreover full NP-side coins and ciphertexts have their ACTUAL conditional law given V_i, and may all be revealed, while target uniform p and D stay independent. Thus a native challenger given only pk_i can choose independent uniform D_i,V_i, uniform target p_ij, fresh B_i and actual F_i generated on the chosen V_i, then answer all OpenNP(i), all unrelated OpenLinear(j), and allowed native signer queries. It cannot answer OpenLinear(i), which by definition makes Win_i false and causes abort. No quantum rewinding or representation volunteering is invoked.

Consequently for each i, using native QPT seed-recovery or fresh scoped-signature security and ordinary QPT decisional-LWE exactly at (d_i,n_i,q_i,chi_i),

  Pr[Win_i] <= eps_native,i(B_i*) + sum_{j=1}^{ell_i} Adv_decQPT-LWE,i,j(B_i*).

Resources B_i* include the complete coherent QPT attacker, reduction, its native-signing/advice interfaces, all public checking-key/related-capsule simulation and every opening response; advice must remain independent of target challenge hidden randomness. For an adaptively chosen one-or-more target event Win_any, the union bound over polynomial m gives sum_i of the right-hand sides. No target index needs to be guessed before disclosure. Claim/UTXO keys are independent and domain scoped. A standard native signature interface alone cannot simulate custom secret-derived presignature leakage without an additional proof.

## False arbitrary ORIGINAL NP when the linear share is disclosed

For any false R_N,i, the already established physical whole-quotient Fourier law P0=P1 makes target F_i simulated from real pk_i independently of hidden V_i. This remains exact even after OpenLinear(i) reveals U_i and all linear coins, and after unrelated claims are fully opened. The simulator with native challenger pk_i generates real target U_i and linear release/coins, then samples false NP columns from their common P0 law. It cannot also answer OpenNP(i) because that would explicitly reveal the hidden remaining V_i, so false-instance secrecy is stated with target NP share unopened. Arbitrary false R_L,i chosen adversarially is NOT covered by average-case B-LWE; false NP is the only arbitrary-NP false theorem here.

## Concrete limitation and next equation

This theorem closes a strictly defined adaptive independently keyed related-capsule opening case. It does NOT make the random kernel witness represent arbitrary ORIGINAL Bitcoin evidence. The unproved compiler must produce in classical PPT a public B_x and mapping f_x with

  for EVERY ORIGINAL accepted W, B_x*f_x(W)=0 (mod q), weight(f_x(W))=h,

and also maintain the full-joint standard-QPT-LWE challenge simulator from the SAME source-dependent distribution, including actual pk, context, auxiliary and related capsules and native private path. For uniform B_x and a fixed nonzero f_x(W) not depending on fresh B_x, this kernel identity holds with probability q^-d only. Adding a public NP check outside the release is insecure; a padded or scalar LWE wrapper does not solve this missing equation. General Fourier source still has exponential honest work in the count of independent nonlinear gates. No practical 128-bit QPT parameters, Bitcoin PoW 100-block work bound, malicious N-of-N/abort graph, adaptive cross-claim secret leakage or deployed native PQ Bitcoin endpoint is claimed.

## Executed exact validation and provenance

Published check_adaptive.py uses Python stdlib only: run python3 check_adaptive.py. Exact toy q=32,g=4,h=1,n=3,B=(0,0,5),alpha=(4,4,4),e in {-1,0,1}^3, k=2; two different accepted witnesses e0 and e1 recover SAME U over ALL 32^2*27 real noisy-column combinations; the code checks exact LWE challenge substitution and exhaustive joint-null (D,V) histogram conditional on fixed actual K and arbitrary independent other claim-opened coins. Two executions produced identical output.json, 859212 assertions per run. These finite-ring checks are not a quantum proof, LWE-hardness experiment, native-signer test, or original SYS/BTC circuit implementation. No external literature/web research; research files only.
