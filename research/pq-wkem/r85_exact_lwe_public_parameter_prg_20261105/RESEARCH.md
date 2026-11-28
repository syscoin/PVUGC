# R85 — Exact ordinary-LWE public-parameter PRG instantiation for R84

Run: R85-LWE-EXACT-PRG-20261105.
Repo/PR: syscoin/PVUGC#1, branch research/pq-wkem-validation-20260918.
Verified opening head: 0dfc387c1361dc85e04affa6c69d108e0b1b6053, open/draft/unmerged.
Exact predecessor: R84 RESEARCH_AND_CHECKER.md at blob 0d58a89fda5d4c3d754d224d5c427e701c2753cf. Latest substantive ordinary comment: 6654996100.
Research: OFFLINE. The connected GitHub source is the authorized existing project, not external literature research.

## Status and constructive delta

R84 proved a restricted, honestly generated LWE-key-witness release assuming a separate unspecified classical-PPT, QPT-secure stretch PRG. R85 removes that unspecified PRG primitive: it instantiates the full stretch algorithm using a precisely stated, **independent ordinary decisional-QPT-LWE distribution**, with an elementary straight-line QPT hybrid even when a single public matrix is reused. Its uniform initial seed is exactly the plaintext of R84's source encryption. This is a real conditional composition and a constrained source-bandwidth improvement over R83, but it does NOT establish that the required LWE parameters are hard, nor a generic-NP or arbitrary-ORIGINAL WKEM.

## 1. Exact distributions and independent assumption

Fix lambda, positive integers n,m,L,t with 1<=t<L, q=2^L, k=nL+mt and d=mL-k=m(L-t)-nL>0. Honest public setup samples one A_G uniformly from Z_q^(m x n). Every seed S uniform in {0,1}^k parses into independent, exactly uniform s in Z_q^n (n L-bit words) and e in chi_t^m, where chi_t is **exactly uniform** on the integers {-2^(t-1),...,+2^(t-1)-1} (m t-bit error coins). Define

G_A(S)=Encode_L(A_G s+e mod q) in {0,1}^{mL}.

Encode_L is a fixed-length unambiguous q-adic vector encoding. Evaluating this deterministic generator is classical PPT; A_G is public and independent of the separate ORIGINAL LWE public key x=(A_x,b_x), seed S, native signing and attestation keys. No secret oracle, source-opening oracle, or unknown-witness setup is used.

**Only additional hardness premise:** for nonuniform arbitrary QPT D with quantum advice independent of the sampled challenge, distinguishability of (A_G,A_G s+e) from (A_G,U(Z_q^m)) is eps_LWE(lambda) for this *exact* (n,m,q,chi_t), with uniform secret s and A_G. The error is bounded-uniform, NOT silently Gaussian. Neither a classical hardness estimate nor the bare word "LWE" proves the exact QPT assumption. This premise is ordinary decisional LWE, not witness encryption, an extractable source, iO, SIS, or a promise of common-key release.

**One-step lemma (proved):** (A_G,G_A(U_k)) and (A_G,U_{k+d}) are eps_LWE-QPT-indistinguishable. This is precisely the declared decisional-LWE challenge with the vector encoded into mL bits; no other assumption is used.

## 2. Explicit polynomial extension with one reused public matrix

Split G_A(S) as (S_next,O), first k bits and last d bits. Start S_0 <- U_k. Repeat r=ceil(N/d) rounds of (S_{i+1},O_i)=G_A(S_i), and output the first N bits of O_0||...||O_{r-1}. N is exactly 8*(Lsig+LB) for the native signature byte length Lsig and checking-seed byte length LB. The first 8Lsig bits are P, and the next 8LB bits are B. Encrypt ONLY S_0 in the R84 source, not this expanded output.

**Public-A_G QPT lemma (proved conditionally on the exact ordinary-LWE premise):** the joint distribution (A_G,O_0,...,O_{r-1}) is within QPT distinguishing advantage <=r*eps_LWE of (A_G,U_{rd}). Proof: replace the first (S_1,O_0)=G_A(S_0) by (U_k,U_d), then deterministically run later rounds with the SAME A_G on the new uniform state. The one-step replacement embeds an actual ordinary-LWE challenge, not a made-up fresh secret matrix. Apply induction to the now-independent uniform S_1, and finally truncate. Every hybrid is straight-line classical sampling plus arbitrary permitted coherent quantum postprocessing of public classical fields; no classical rewind/extractor is lifted to QPT.

For independently seeded related capsules sharing this same A_G, replace only the unopened target's generator output and honestly generate all other seeds, checking records and permitted independent non-target openings. A sibling opening that leaks the target LWE secret, target seed, target signature or same-key decryption ability is NOT covered. Polynomial adaptive target selection needs an explicit guessing/union loss; arbitrary target-correlated quantum advice is not allowed. Malicious A_G generation is NOT covered: A_G=0 reveals short errors and is immediately distinguishable, as the checker confirms.

## 3. Explicit restricted full-public release and actual challenge simulation

Keep R84's special honestly generated ORIGINAL instance x=(A_x,b_x), where b_x=A_x s_x+e_x and ORIGINAL valid witnesses (s',e') satisfy b_x=A_x s'+e' mod q_x with ||e'||_infinity<=beta and m_x beta<q_x/4-1. This relation also binds relation identity, UTXO/claim, branch, anchors/window/context, frozen graph manifest and native vk. The public key x and its Regev bit encryption must separately satisfy multi-bit QPT-INDCPA under the honestly generated source-key distribution. This is NOT implied by the independent A_G LWE premise.

Honest Build: sample S_0 uniformly; derive P||B by the exact generator above; pre-sign the intended frozen challenge message sigma=Sign(sk_native,m0); Regev-encrypt all k bits of S_0 with fresh coins to form C=(u_j,v_j) where u_j=A_x^T r_j, v_j=b_x^T r_j+Delta*S_0[j] mod q_x; publish Dsig=sigma XOR P, CK=F(B,Dsig,C,x,A_G,context,prevCK), Aux=H(B,Dsig,CK,C,x,A_G,context,prevCK), signed independent attestation, source C, native vk, A_G and entire frozen context. F,H are deterministic PPT, and may NOT expose P or S_0, a direct sigma fingerprint, a public seed tag, or any additional target-secret-correlated checking value. All public dependence on Dsig/C is recomputed in every hybrid. A sound publicly verifiable preflight proof requiring hidden challenge encryption coins is NOT simulated here without its own simulator.

Open(x,w,C,...): for ANY valid ORIGINAL short-error witness w=(s',e'), decode v_j-s'^T u_j=e'^T r_j+Delta*S_0[j]; the uniform bound m_x beta<q_x/4-1 gives the identical exact S_0 for every such witness. Regenerate P,B, verify CK/Aux/frozen context, derive sigma=Dsig XOR P, and verify the ordinary native signature on m0. No common witness states, canonical witnesses or common short preimages are required. The native verifier is on the off-chain recovered capability, not on-chain NP verification.

**Complete-target QPT hybrids:**
H0 real entire view with Enc_x(S_0), G_A(S_0), Dsig, CK, Aux, native vk, context, permitted siblings/attestations.
H1 use an ACTUAL chosen-message PKE-INDCPA challenge of Enc_x(S_0) versus Enc_x(S'_0) for independent sampled S'_0. The simulator knows both plaintexts, A_G and the generator output, but NOT the LWE secret or challenge ciphertext coins; it builds the CK/Aux/related public records from the received challenge ciphertext. The target opening cannot be supplied in the wrong-seed hybrid.
H2 C now encrypts independent S'_0. Embed r ordinary QPT decisional-LWE challenges in the exact expansion above and replace full joint (P,B) by U_N. Simulate every checking-key and auxiliary correlation jointly as deterministic postprocessing; do not assume marginal pad hiding.
H3 uniform P is independent of B,C,vk,context, hence Dsig is exactly uniform even with CK/Aux depending on Dsig. Embed native QPT-EUF-CMA verification key without querying its signing oracle on the intended already-preauthorized m0. Any accepted native target signature, including one derived by alleged recovered S, is a valid EUF forgery. Signatures on messages never authorized are separately addressed by R81's signing-oracle substitution.

For a fixed target, with appropriate permitted non-target related capsules and honest setup, the **restricted** bound is
Pr[accepted preauthorized target native signature] <= Adv_QPT_INDCPA^(multi-bit PKE) + r*Adv_QPT_DLWE^(n,m,q,chi_t) + Adv_QPT_EUF(native) + eps_setup/independent-attestation.
Count multi-bit PKE hybrids and target-selection losses separately. Arbitrary FALSE and hard-TRUE ORIGINAL extraction and malicious setup/abort are NOT thereby proved.

The seed-checking B projection need NOT be injective. In this run's executed toy checker, seed S and S XOR 1 produce the same checking-key B in 24/24 negative controls even though their P values differ. CK equality alone cannot certify unique seed or independent release. Open MUST verify the actual native signature and frozen challenge path; a counterfeit accepted signature is governed by independent QPT native EUF, not CK injectivity. This catches a misleading possible R84 checker interpretation without invalidating its restricted theorem.

## 4. Accurate resources, no silent parameter calibration

The independently stated but **uncalibrated** example n=256,m=768,L=16,t=9 gives k=11,008 uniform seed bits, mL=12,288 output bits per call, stretch d=1,280 and 52 rounds for N=65,792 bits (8,192-byte native signature plus 32-byte checking seed). Public A_G has 196,608 16-bit elements (~393,216 bytes) before amortization. R83 encrypts 65,792 seed/pad bits; this explicit R85 instantiation encrypts 11,008 bits, ~5.98x source-ciphertext count improvement, NOT R84's earlier hypothetical 257x ratio requiring an uninstantiated 256-bit seed PRG. No concrete proof of 128-bit quantum security for this exact LWE error law, source encryption or native signature is supplied. The source PKE noise parameters must meet correctness and INDCPA independently.

## 5. Reproducibility, exact status and next step

The exact attached Python checker was executed offline (2,257 explicit assertions, 2,016 source-bit decodings, 72 releases with THREE distinct valid ORIGINAL short-error witnesses, 24 complete public real/signing-oracle couplings, and 24 wrong-seed CK collisions rejected by native signature verification). A separate **local-only** longer checker also executed 8,835 assertions and additional zero-A_G controls. Both use insecure toy parameters, deterministic test randomness and non-post-quantum Ed25519 test signatures; neither measures or establishes QPT hardness. The local research packet contains full expanded derivation, local checker and captured logs.

**Next unsolved equation:** on an arbitrary hard-TRUE ORIGINAL x, not this special LWE-key-witness relation, construct public source and true challenge simulator together and prove Pr[accepted already pre-signed capability] <= Pr[R_original(x,Ext^A(full joint view))=1]+Adv_independent_QPT+negl without asking A for an internal representation. Generic FALSE security, corrupt N-of-N ceremony/abort/pre-funding DA, no-committee native Bitcoin PQ endpoint and practical parameters remain open. Do not disable the research automation.