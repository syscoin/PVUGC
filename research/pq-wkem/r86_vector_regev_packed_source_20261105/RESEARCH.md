# R86 — Packed vector-Regev source for R85's honestly generated LWE-key-witness capsule

Run: R86-VECTOR-REGEV-PACKED-SOURCE-20261105. Repository: syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918. Starting head ad86d98b8de2eea33c21ca4b2d42e968dda4b31f (open/draft/unmerged). Exact input R85 RESEARCH.md blob a5df14e40955875255c3a905db210d446f45465e; R85 checker blob 4791e4a146f08007552aa2a6db160f2429e4feb5; latest substantive ordinary comment 6656181757. OFFLINE derivation, no external research.

## Constructive delta and exact resource

R85 encrypts k bits of its ordinary-QPT-LWE PRG seed using k separate Regev ciphertexts, each with n+1 elements in Z_q. This iteration instantiates a PACKED source by widening the restricted ORIGINAL LWE-key-witness public key to ell independent LWE columns B_j under one honest A. Fresh subset randomness r_g is used **once per group**, yielding one n-vector u_g and up to ell scalar v_g,j. The source contains ceil(k/ell)*n+k Z_q elements rather than k*(n+1). For R85 illustrative k=11008, n=256, ell=16, the source is reduced from **2,829,056 to 187,136 Z_q elements, 15.117647x**; this is the ciphertext only. The new public key adds (ell-1)*m elements, and every ORIGINAL witness includes ell secret/error columns. q, beta, m, full key size, concrete QPT security and the native-signature length must be calibrated separately. At an uncalibrated hypothetical 16-bit modulus, ciphertext bytes fall 5,658,112 -> 374,272. This is a genuine restricted computational/bandwidth improvement, NOT a generic NP witness-KEM.

## Exact setup distribution and relation

Fix security parameter lambda, integers n,m,ell,q>=3 (q may be composite), bounded efficiently sampled error chi with |e|<=beta, and Delta=floor(q/2). Require m*beta<q/4-1 for every-ORIGINAL-witness decoding; require m>=(n+ell)*log2(q)+2lambda+2 for leftover-hash smoothing. Honest classical-PPT setup samples A uniform in Z_q^(m*n), S uniform in Z_q^(n*ell), E independent from chi^(m*ell), and publishes ORIGINAL statement x=(A,B=AS+E mod q). The ONLY special ORIGINAL relation in this result is

R_vec(x,(S',E')) := [ B=A S'+E' (mod q), all |E'_ij|<=beta, and exact BindOriginal(relation identity, claim/UTXO, branch, anchor/window, context, frozen N-of-N graph, intended native verification key/path) ].

This is a hard-TRUE relation **under the honestly generated LWE-key distribution**, not an arbitrary ORIGINAL SYS/BTC claim compiler. Source Build needs only public x, not S or E. It DOES assume no adversary retains/learns a valid secret S' for x; malicious setup and one-honest erasure are unfinished. Distinct valid ORIGINAL witnesses may have distinct secrets and errors; no canonical intermediate state is assumed.

## Complete packed Build and Open

Independently sample R85's exact public PRG matrix A_G (uniform). Its independent LWE parameters n_G,m_G,q_G=2^L_G, error chi_t and exact uniform seed length k=n_G L_G+m_G t_G, one-call stretch d_G=m_G(L_G-t_G)-n_G L_G>0 are unchanged. Sample T uniformly in {0,1}^k. Let (P,B_check)=G_{A_G}^iter(T), with disjoint signature-pad and checking-seed output, length N=8*(native-signature bytes + checking-seed bytes).

Split T into h=ceil(k/ell) groups. In each group g independently sample r_g uniformly in {0,1}^m and publish

u_g=A^T r_g mod q
v_(g,j)= B_j^T r_g + Delta*T_(g*ell+j) mod q, for each populated slot j.

No r_g reuse across groups and no repeated public B_j within a group. The same r_g across distinct INDEPENDENT LWE public-key columns is intentional; reusing one identical B for two plaintexts is unsafe. The full capsule publishes C={(u_g,v_g)}, a fixed pre-signed native challenge message M bound to the ORIGINAL claim/branch/window/vk, Dsig=sigma XOR P, CK=F(B_check,Dsig,C,x,A_G,context,prevCK), Aux=H(B_check,Dsig,CK,C,x,A_G,context,prevCK), intended native vk, independent honest ceremony attestation and permitted related capsules. F and H are public deterministic acyclic classical PPT. They cannot expose T/P/sigma, direct signature fingerprint, seed tag, or hidden plaintext information apart from allowed dependencies. Public NP proofs whose simulator would require unknown challenge encryption coins/secret witnesses are excluded.

For ANY valid ORIGINAL witness w=(S',E'), the slot equation is exactly

v_(g,j) - (S'_j)^T u_g = (E'_j)^T r_g + Delta*T_(g*ell+j) (mod q).

Every cyclic error magnitude is <=m*beta<q/4-1, so nearest-bit decoding recovers precisely T for ALL valid ORIGINAL witnesses, including completely different S' and E'. Regenerate P,B_check, recompute/check entire CK/Aux and the frozen manifest, recover the SAME precommitted sigma=Dsig XOR P, and verify the ordinary native signature under vk on M. Reject inconsistent seeds/signatures. This is only off-chain capability recovery; no NP verifier or proof verifier is requested on Bitcoin.

## Ordinary decisional QPT-LWE proof for vector packing; real challenge embedding

Define epsilon_LWE as the maximum arbitrary QPT distinguishing advantage, including nonuniform quantum advice independent of the sampled challenge, between (A,As+e) and (A,U_m) for EXACT parameters q,n,m,chi, uniform s. The public A is genuinely uniform, and each column s_j,e_j is independently sampled. One column of B can be replaced with a uniform vector by an **actual one-column ordinary-LWE challenge**; every other column is synthesized with the same A. Repeating ell times gives at most ell*epsilon_LWE indistinguishability per direction, and no new vector-LWE hardness assumption.

In the all-uniform-B hybrid, D=[A|B] is uniformly sampled in Z_q^(m*(n+ell)). Define h_D(r)=D^T r with r uniform in {0,1}^m. For distinct binary r,r', one coefficient of r-r' is ±1, which is invertible even modulo composite q, so D^T(r-r') is uniform; this is an exact two-universal family. The statistical leftover-hash lemma gives

TV[(D,D^T r),(D,U(Z_q^(n+ell)))] <= epsilon_LHL = 0.5 * sqrt(q^(n+ell)/2^m) <= 2^(-lambda-2).

The additive Delta-bit vector only shifts uniform coordinates, preserving the **whole joint vector's** independence of its ell message bits. With independent r_g per group, the h-block joint distribution is within h*epsilon_LHL of uniform ciphertexts even though D is reused. Thus a conservative two-message QPT IND-CPA distinguishing bound for one whole seed ciphertext is 2ell*epsilon_LWE + 2h*epsilon_LHL; for additional same-key encryption queries count their extra h blocks and selective-opening conditions. This is a genuine classical-PPT construction/reduction, not an ideal source-opening primitive. The LHL step is statistical, so coherent quantum postprocessing cannot increase its distinguishing advantage; ordinary-LWE QPT hardness supplies the computational step. No quantum rewinding or proof-of-knowledge extraction is assumed.

In the **actual R85 full-public challenge** H0, set C=Enc_x(T), Dsig=sigma XOR G_A_G(T)_P, CK/Aux from B_check,C and every other public field. For H1 the IND-CPA reduction requests a REAL packed PKE encryption of T versus independent T' under x; it knows T and T', but not the secret S, encryption coins or a SourceOpen oracle, and recomputes ALL CK/Aux/attestation functions from the returned challenge C. No target witness/root/seed opening is available in the wrong-seed world. In H2 replace R85 G_A_G^iter(T) by uniform (P,B_check) via r_G=ceil(N/d_G) **separate exact ordinary decisional-QPT-LWE challenges** and the R85 same-A_G straight-line argument, with independently generated A_G. In H3, uniform P makes Dsig statistically independent of the unknown pre-signed sigma *jointly with CK, Aux, source C, native vk, context, other permissible capsules and quantum advice*. Embed an independent QPT-EUF-CMA native verification key, never query the signing oracle on target M, and forward any accepted native signature on M as an EUF forgery. Authorized sibling messages can use its ordinary signing oracle only when distinct from M.

For ONE fixed target and the stated honest independent setup/no-target-opening restrictions, a conservative bound is

Pr[unauthorized accepted already-presigned target native signature] <= 2ell*epsilon_LWE_vec + 2h*epsilon_LHL + r_G*epsilon_LWE_PRG + Adv_QPT_EUF_native + eps_independent_attestation.

Multiple capsules/same-key encryptions add statistical losses for all packed blocks and target selection/guessing factors; independent non-target seed/signature openings are allowed if the simulator knows those seeds and they never disclose the target witness or same native target signature. Disclosing any sibling ORIGINAL decryption secret S' for the SAME x breaks target secrecy; target/same-key witness openings are not claimed. Adversarial quantum advice correlated with the withheld secret is excluded. This does not prove honest distribution under malicious A or B, arbitrary FALSE security, or generic TRUE extraction.

## Verification and negative controls

The exact attached executable JavaScript checker, executed in the connected V8 tool, returned **14,530 assertions**, 4,608 packed-bit decodings, 192 all-ORIGINAL-witness releases across three *different* valid witness matrices in each of 64 fixtures, 64 toy complete-public-view couplings and 256 repeated-column negative controls. Independently the extended local Python fixture executed **11,763 assertions**, 144 openings from three distinct valid ORIGINAL witnesses, 4,032 bit decodings, 48 full-public-output/native-signing-oracle bytewise couplings, 192 negative controls and frozen-scope checks. A full exact q=2 census of 4,096 public hash matrices and 16 binary r per matrix gave mean TV 0.198883056640625 versus LHL upper bound 0.3535533905932738. The toy q=257 n=2 ell=3 m=8 example used 48 rather than 84 ciphertext symbols for 24-28 input bits. All test key matrices are deliberately structured/insecure, and toy generator, Ed25519, and finite enumeration are NOT evidence of 128-bit QPT hardness. See checker.js and captured-output.json for the exact published V8 execution. The extended Python checker/derivation and output are independently retained locally.

A necessary negative control is the unsafe old-column shortcut: if both slots reuse identical b and identical r, then v_a-v_b = Delta*(bit_a-bit_b) mod q exactly. Packing therefore requires independently generated LWE public B columns, not naive correlated reuse of coins in R85's original scalar key.

## Still missing, no security/deployment claim

This does NOT solve generic NP witness encryption or the mandatory ORIGINAL reduction: for arbitrary hard-TRUE x and complete public V_x, prove

Pr[A obtains target already-presigned capability] <= Pr[R_ORIGINAL(x,Ext^A(V_x))=1] + Adv_independent_QPT_break + negl,

without A supplying a representation and without an oracle for source-opening correlations. No arbitrary-ORIGINAL to vector-LWE-key compilation is provided. Arbitrary-FALSE full-public security, corrupt N-of-N ceremony/abort and pre-funding data availability, optional keyless Build, parameter calibration to real 128-bit PQ security, and the conditional no-EC-key-path Bitcoin SLH-like endpoint all remain open. BitVM remains covenant plumbing only; no live Bitcoin functionality is claimed. Do not disable the existing research automation.
