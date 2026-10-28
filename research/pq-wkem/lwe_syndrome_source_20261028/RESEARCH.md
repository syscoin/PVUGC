# Compact LWE-syndrome SOURCE: source challenge and full-public simulator together

Record: lwe-syndrome-source-20261028-turn11. Offline analysis only. The verified predecessor is open/draft/unmerged syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, starting SHA 577f365518ee19c257b44671d07745928cb275ae, latest substantive comment 6478968730. Exact predecessor read: research/pq-wkem/degree3_boolean_quotient_xor_20261028/RESEARCH.md, Git blob 409961a0632f3366a067c2f8dbaf5f490d94fff0.

## What is and is not established

A genuinely instantiated LWE-*instance*-restricted source-dependent release and complete-public QPT hybrid is given below: classical witness-free Build from public (A,b), every valid ORIGINAL LWE witness releases the same precommitted native capability, and unauthorized hard-true final-key recovery/native forgery reduces to an exact ordinary QPT decisional-LWE game or native EUF-CMA. The compiler does NOT apply to arbitrary NP, its false and true security are AVERAGE-CASE over specified public-key distributions, and its crypto is the familiar LWE public-key encryption algebra rather than a newly invented KEM. This is a concrete independently specified hard-true subcomponent and an efficiency improvement over the previous uniform-rowmask SOURCE, NOT an independently justified complete WKEM. Ternary LWE parameters are NOT calibrated to 128-bit QPT security.

## Source relation, Build, actual release

Let q be odd prime, m>n, B=1. EXACT source relation:
  R_LWE((A,b,C),(s,e)) = [A in F_q^(m×n), s in F_q^n,
        e in {-1,0,1}^m, b=As+e mod q,
        typed context C matches the intended claim/path/checking key].
The ORIGINAL for this restricted example is this exact LWE witness predicate, not a generic user NP predicate. The context C binds relation identity, claim/UTXO, branch, anchor/window, intended checking key and signature path. The relation as written DOES NOT validate Bitcoin/Syscoin headers, burns, AuxPoW, tags, branch ancestry, DA or ownership.

TRUE distribution T: A uniform, s uniform F_q^n, e independent ternary, b=As+e. UNIFORM comparison U: A,b independent uniform. The explicit independent cryptographic assumption in the theorem is QPT decisional LWE for precisely T versus U at chosen (q,n,m,chi). No unproved lifting from classical security, no planted-SIS assumption and no SourceOpen oracle.

Honest classical Build sees ONLY (A,b,C). Independently generate the REAL native signing capability K and REAL checking key pk(K). Sample independent kappa-bit U,Z and publish D=U xor Z, V=K xor U. Choose scale g=2mB+1, q>=2g, radix t=floor(q/g)>=2; encode Z into ell=ceil(log_t(2^kappa)) digits a_j. For each digit choose independent r_j uniform {-1,0,1}^m and publish the compact ciphertext
  c_j = A^T r_j in F_q^n,
  d_j = b^T r_j + g a_j in F_q.
Public complete view is (R,x,C,pk,D,V,all (c_j,d_j), public auxiliary and eligible related capsules). All r_j remain unpublished.

OFF-CHAIN Release FIRST checks the actual R_LWE(x,(s,e))=1, then computes
  d_j - s^T c_j = g a_j + e^T r_j (mod q).
Since |e^T r_j|<=mB<g/2, nearest-center cyclic decoding is unambiguous and returns every digit of the precommitted Z. Return K=V xor D xor Z. Every ORIGINAL-valid (s,e), including mutually different ones, recovers SAME K, with no canonical witness, common preimage or common intermediate state. The final off-chain signer produces the ordinary native intended-path signature. This says nothing about deployed PQ-only Bitcoin output semantics.

This is EXACT compression from the earlier rowspace SOURCE. Let G=[A I_m -b], w=(s,e,1), p=(A^T u,u+r,-b^T u+g a). For every accepted ORIGINAL w, Gw=0 and w^T p=g a+e^T r. The PUBLIC linear projection
  (A^T p_e-p_s, b^T p_e+p_anchor)=(A^T r,b^T r+g a)
discards the m-dimensional mask block and constructs exactly (c,d). Per digit output shrinks from m+n+1 to n+1 field elements. It may be built directly without sampling u. This is standard LWE PKE, explicitly NOT generic NP witness encryption.

## EXACT whole-public statistical and QPT hybrid

Let H=[A b] in F_q^(m×(n+1)). In U, H is UNIFORM. For independent r uniform {-1,0,1}^m, h_H(r)=H^T r is a two-universal hash family: for every r!=r' the difference is nonzero mod q and Pr_H[H^T(r-r')=0]=q^-(n+1). Accordingly,
  E_H Coll(h_H(r))=3^-m+(1-3^-m)q^-(n+1),
  E_H TV((H,H^T r),(H,Unif(F_q^(n+1))))
       <= delta = (1/2)sqrt((q^(n+1)-1)/3^m).   (1)
This is a WHOLE-ciphertext vector lemma, conditional on public H and averaged over U; no marginal pad-only step. Arbitrary fixed digit shifts d+=g a preserve the bound. For ell independently sampled ciphertext columns under a SHARED H and potentially correlated digits of one Z, condition on H and digit values and hybrid each column: the complete target view changes by at most ell*delta, including real pk, true XOR shares, C, and public-samplable auxiliary strings. Conditional on ANY fixed K, the mapping (U,Z)->(D=U xor Z,V=K xor U) is bijective. Hence D,V are independent uniforms conditioned on K, even when pk(K) is real.

Given exact decisional-LWE challenge (A,b) with unknown s,e, reduction B generates real K, real pk(K), U,Z, (c,d) and ALL their correlations, then runs any QPT A as a black box and checks whether its returned K is usable or its intended-path signature verifies freshly. No SOURCE witness, challenge secret, simulator-only opening oracle or rewinding is used. T-branch equals genuine Build exactly. In U-branch apply (1) to switch all target c,d to uniform values. A separate native-EUF-CMA simulator supplied with genuine challenge pk (WITHOUT secret K) samples H,D,V and uniform target ciphertexts, answers permissible classical signing queries via its native signing oracle, and maps any usable recovered K to a fresh intended-path signature, or forwards a fresh accepted signature directly. Therefore, for arbitrary internally coherent QPT A with classical public inputs and classical oracle interfaces,
  Pr_T[unauthorized usable K or fresh intended native forgery]
    <= Adv_QPT-DecLWE_(q,n,m,ternary)(B)
        + Adv_QPT-native-EUF-CMA(F) + ell*delta.    (2)
This is an independently instantiated conditional hard-TRUE security reduction to ordinary QPT-DecLWE and native EUF, NOT arbitrary fixed-true ORIGINAL extraction. No quantum rewinding, classical-to-QPT generic lifting, or unsimulatable checking-key substitution occurs. The precise target signing-query freshness, C and checking-key binding are necessary assumptions.

Multiple-capsule selective openings: with independent target-key share capsules Z_i under independent H_i, publish D=U xor all_i Z_i and V=K xor U. A nominated challenged capsule must remain unopened; independently samplable other capsules, their coins, their known witnesses and allowed classical openings can be generated faithfully. A hybrid for this surviving share retains all real pk/XOR correlations, and a guess among t possible independent surviving indices costs up to a t factor. Unrestricted maliciously correlated capsules, secret-correlated auxiliary leakage, coherent/superposition opening queries, an opened last protected share, arbitrary same-key true siblings yielding K, malicious N-of-N setup, abort and erasure are NOT covered.

Uniform (A,b) is false for bounded ternary LWE relation except with probability at most q^(n-m)*3^m by union bound, so (1) is average-case FALSE full-public hiding, not security for every fixed false ORIGINAL statement. Likewise (2) concerns true public keys sampled from T, not adversarially selected fixed hard-true instances.

## Quantitative illustrative resources, exact reproduction

For q=65537 (17-bit field), n=128, m=1600, B=1, g=3201, radix=20, kappa=256, ell=60:
  log2 delta=-236.9686; log2(ell*delta)=-231.0617.
  Public A: 204800 field elements (435200 bytes at packed 17 bits or 614400 bytes at three bytes).
  Compact capsule: 7740 field elements (16448 bytes packed or 23220 bytes at 3 bytes).
  Prior full p: 103740 field elements at the same ell.
This is an algebraic size estimate, NOT measured performance, 128-bit QPT-LWE hardness, actual native SLH signing-key length or an on-chain proof-size estimate. Narrow-error LWE demands independent quantum cryptanalysis and parameter calibration. kappa=256 is a mock signing-capability size, not a universal native secret-key serialization.

Exact published verify.js and captured js_output.json: deterministic 5,177 finite assertions, executed twice identically; 16 complete mock 256-bit same-K trials with two distinct ORIGINAL-valid LWE witnesses, 100 exact rowmask-source-to-compact projections, exhaustive 15,625 small-field H matrices establishing the two-universal collision identity, and complete conditional XOR-share bijections. Extended independent local Python checker executed twice identically: 6,456 assertions, including 15 two-witness full-key trials, 4 standard randomized LWE full-key trials, exact collision identity 17/225, 96 sampled full-vector TV comparisons against the bound, and independent size arithmetic. These are NOT QPT or native-SLH experiments.

EXACT GENERIC HANDOFF: Need a public PPT compiler taking ARBITRARY ORIGINAL (R,x,C), with no witness, to a challenge-simulatable source plus Open_x(W) for EVERY valid ORIGINAL witness, maintaining SAME K and enabling arbitrary QPT unauthorized hard-true K recovery/native forgery -> ORIGINAL W or a separately justified PQ break for the FULL joint view. Appending an unrelated secure LWE public key to x does NOT tie its secret to the ORIGINAL evidence. A generic fixed-false statement theorem, malicious N-of-N preauthorization/erasure/abort graph proof, real SYS/BTC source authentication, finite observation/DA/censorship bounds, and a hypothetical PQ-only Bitcoin endpoint are all still unresolved. Keep existing research automation enabled.
