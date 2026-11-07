# Joint SOURCE attestation versus ordinary-QPT-LWE: precise simulation obstruction

**Research checkpoint, not a positive generic-NP witness-KEM advance.** This bounded offline iteration continues the exact adaptive-cohort LWE SOURCE at PR #1 head 83960a608d44d62cf4af425bcc79442b1c2e36d7; selected predecessor research/pq-wkem/adaptive_cohort_lwe_20261029/RESEARCH.md, blob 1e46d73185d1e54a3543af2d44a002021b8e77e2, ordinary PR comment 6506777833. Branch research/pq-wkem-validation-20260918 is open/draft/unmerged. The full independent local derivation and checker are separately preserved. No external research.

## Candidate and complete public output

The predecessor generates A uniform in F_q^(n x m), s uniform in F_q^n, e from bounded chi with |e_j| <= B, sets b=A^T s+e, H=[A;b^T]. The native signing secret sk is additively shared among N contributors; signed-ternary exact-weight coins encrypt q-ary contributor shares, and all ciphertexts and native pk are public. A valid LWE SOURCE preimage (s',e') releases the same actual sk for every honest share/capsule when g>2NwB. The predecessor proves a restricted honest-TRUE QPT reduction, explicitly excluding source-dependent checking proofs, malicious setup, retained witnesses and arbitrary auxiliary leakage. This checkpoint does not retract that result.

Consider adding a public source-certificate checking key ck and proof pi. Public statement S consists of the ORIGINAL relation identity/x, claim/UTXO, branch/anchors/window/context, H, native pk, all contributor ciphertexts, aggregate capsules, and participant commitments. A proposed setup witness consists of s,e, actual native sk and key-generation consistency data, additive shares and encryption coins. The certificate verifies short-source equations, genuine native pk-to-sk binding, sharing/ciphertext equations and context. It DOES NOT prove existence of an unknown ORIGINAL NP witness W. The full public view also contains ck, pi, permitted auxiliary data, related capsules and adaptive classical disclosures; all are included in the security experiment. Checking key ck is distinct from native pk.

## Proved impossibility for a same-sound-CRS certificate simulator

For independently uniform (A,b), the number of b values admitting a short source preimage is at most q^n (2B+1)^m, giving

Pr_uniform[exists s,e: b=A^T s+e mod q, |e|_infty<=B]
 <= min(1, q^(n-m) (2B+1)^m).

At q=16777213, n=256, m=6800, B=128, log2 of this union bound is -102617.751377. So a uniform-H ordinary-LWE hybrid has an overwhelmingly FALSE SOURCE instance even though an honestly sampled H always has a short preimage.

Suppose public Verify(ck,S,pi) is complete for honestly produced SOURCE certificates and QPT-sound under the same real ck. A classical PPT or arbitrary QPT simulator given uniform H and no s,e cannot produce an accepting pi for that FALSE SOURCE with nonnegligible probability; doing so itself violates proof soundness. Keeping pi from the old true H fails verification under the new H. Thus ordinary decisional-QPT-LWE security for H ALONE does NOT allow a hybrid replacing the *joint* (H,ck,pi,pk,capsules,aux) distribution. A public source-membership verifier distinguishes a real certified H from a uniformly sampled H without an accepting certificate. This does not contradict the predecessor: it explicitly excluded such certificates.

Concrete exact check: fix q=7, n=1, m=5, B=0, A=(1,2,3,4,5). Precisely 7 of the 7^5=16807 possible b vectors have a source witness, so checking SOURCE membership distinguishes honest from uniform b with advantage 2400/2401. The self-contained exact executable check.py enumerates all 16807 and verifies the large-parameter bound; OUTPUT.json is the twice-identically-captured output. No claim of implementing a real NIZK or QPT experiment.

## Attempted repair: real/simulation dual-mode certificate (NOT instantiated)

A non-circular repair would have to instantiate an actual classical-PPT, QPT-secure dual-mode NP proof system. In the real setup, SoundSetup produces publicly sound ck_s and an honest dealer proves S using s,e,sk,all shares/coins, then erases protected secrets. For reduction only, SimSetup produces a computationally indistinguishable ck_z with private simulation trapdoor td, so SimProve(td,S) can issue an accepting simulated proof even for uniformly sampled FALSE H. All source/capsule/authenticator checking-key correlations and classical adaptive corruption transcripts must be covered by the same QPT multi-theorem simulation definition, including a polynomial collection of related capsules; no unproved quantum rewinding, random-oracle programming or secret-correlated auxiliary simulation is imported.

The conditional joint game route is:
(ck_s,H_LWE,pi_real,pk_real,capsules)
 -> (ck_z,H_LWE,pi_sim,pk_real,capsules)
 -> (ck_z,H_uniform,pi_sim,pk_real,capsules)
 -> (ck_z,H_uniform,pi_sim,pk_real,zero-protected-contributions).

The second switch can be an ORDINARY LWE challenge only AFTER the simulated-proof mode exists. Native-EUF simulation thereafter must retain the genuine challenger pk and all admissible openings. Real-world malicious N-of-N soundness, trusted/no-bypass CRS creation and QPT extraction have not been instantiated. This candidate is a proof opportunity, not an actual cryptographic composition, and is NOT counted as a positive advance.

Private proofs/audits are not automatically a shortcut: transcripts seen by N-1 corrupted preauthorizers are part of their auxiliary view and likewise need witness-free joint simulation. Publishing s,e to facilitate auditing reveals the release capability. A dealer signature on its own assertion without independent checking does not establish malicious-setup soundness.

## Exact remaining ORIGINAL-witness reduction

Even a successful joint LWE certificate would prove only existence of some SOURCE (s,e) and correct encryptions. It would neither bind every accepted preimage to an ORIGINAL W nor prevent the source sampler retaining s,e and releasing sk. Inserting an ORIGINAL W into the setup proof assumes a witness exists at funding and violates witness-free preauthorization. All earlier public signed-pseudo-opening and false-source counterexamples remain binding.

Missing: classical-PPT Comp(R_original,x,context,pk) independent of W; classical-PPT Release(Comp(...),W) returning the SAME precommitted sk for every valid ORIGINAL W; QPT full-public key hiding for EVERY fixed FALSE x; and arbitrary unauthorized hard-TRUE sk recovery/native forgery -> actual ORIGINAL W or independently justified QPT break, without SourceOpen, adversary-supplied representations or a retained builder bypass. Malicious N-of-N ceremony, abort/presignature/graph, actual SYS/BTC evidence validation and the hypothetical native PQ Bitcoin endpoint remain open.

**No positive advance satisfying the research standard, no claim of solved WKEM, and no automation stop.**
