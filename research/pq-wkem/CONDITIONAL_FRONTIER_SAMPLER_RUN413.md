# Run 413: public-sampler transfer barrier for a locally mixed release frontier

**New scoped conditional theorem; no WKEM construction.** At execution start, syscoin/PVUGC#1 was open/draft/unmerged, branch research/pq-wkem-validation-20260918, SHA 7c639078b1d4aacbeb04bbe79b4944d1304fc528. Read exact prior Run 412 note, blob 056571f6ad23c56fbc62ca6126a309035a17e080, Run 259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2 and CLZ assessment blob c19d9d9cd515140e3ce62eac960cd548c0add622. Latest substantive ordinary comment: 6067040320.

## Theorem: joint-state public-sampler transfer

Classical PPT setup publishes a full view V_x containing source program, local mixer, related capsule information, claim/UTXO/branch/anchor context, and the native signing verification key correlated with hidden K_x. Honest valid ORIGINAL witness distribution W (analysis distribution, not asserted efficiently sampleable to outsiders) induces witness-dependent source state U_real=S(V_x,w;r). An independently callable public randomized release evaluator M, native signer and published verification key give an efficiently public checking bit B(V_x,u). Suppose Pr[B(V_x,U_real)=1] >= 1-delta.

Suppose a *witness-free* classical PPT sampler D(V_x) yields U_fake. If the **joint** views (V_x,aux,U_real) and (V_x,aux,U_fake) are computationally indistinguishable to advantage <=epsilon for arbitrary QPT distinguishers, including B, then

    Pr[B(V_x,U_fake)=1] >= 1-delta-epsilon.

Proof: B itself is a distinguisher; the inequality is its advantage bound. The witness-free adversary runs D then M/sign/verify. This is straight-line and requires no rewinding, generic extraction, QROM programming, common preimage or canonical witness. If QROM or quantum advice is included, it must be included consistently in both joint experiments. The native checking key is NEVER omitted from V_x.

Corollary: requiring public-sampler unauthorized early success <=nu forces distinguishing advantage >=1-delta-nu between the two *joint* distributions. Therefore marginally pseudorandom or uniform-looking valid source labels do not establish authentication; security requires non-publicly-simulatable source/program correlation or a protected, inseparable frontier. This is a falsifier for one proposed assumption class, not a new assumption or a general local-mixing impossibility theorem. It applies only when release is independently callable on the sampler's inputs. An attacker obtaining an actual ORIGINAL witness is legitimate; Run 259 can bind only an accepted complete representation, not a bare final signature. False original statements have no valid-witness W, so the theorem itself does not prove false-instance hiding.

## Exact finite counterexample to marginal analysis

Let public toy package A be uniform over h-element subsets of N labels. Honest U_real is uniform on A. Witness-free U_fake is uniform on N. Averaged over A, BOTH state marginals are exactly uniform. But the *joint* package/state total variation is 1-h/N, achieved by the public predicate u in A: honest acceptance=1, public uniform-sampler acceptance=h/N. For N=8,h=1 this gives marginal TV 0 but joint TV 7/8; for N=8,h=4 it gives joint TV 1/2. A mixture sampler succeeds with 1-eta+eta*h/N. This is a known-membership finite oracle toy, not encrypted local mixing or cryptographic security.

The exact executed JavaScript checker passed 3,028 deterministic assertions across 24 exhaustive subset families and 1,344 toy checking-key cases. Captured output is committed alongside it. The checker was syntax checked and rerun with byte-identical stdout. No practical QPT hardness or Bitcoin signature is demonstrated.

## Attack taxonomy, context and obligations

Seam/public chosen-input checking and correlated verification-key fingerprint are explicitly tested; marginal statistical uniformity fails to imply joint indistinguishability. Multiple capsules can be included as auxiliary view, but their security is NOT proved. No gauge inversion, malicious setup break or new genuinely quantum algorithm is claimed; the distinguishing bound applies also to QPT. Run 412 covers quantum amplitude amplification of uniform acceptance density; this theorem covers arbitrary efficient witness-free samplers and joint-correlated distributions.

Literature context only: Canetti et al., *Towards General-Purpose Program Obfuscation via Local Mixing*, TCC 2024, https://eprint.iacr.org/2024/006 ; Canetti–Luo–Zhang, *How to Encrypt with Random Reversible Circuits*, CRYPTO 2026, https://doi.org/10.1007/978-3-032-35367-2_18 . Full proofs were not re-audited this run. Neither provides concrete proven QPT security for this WKEM.

**Still unproved:** real compact classical protected release; every valid ORIGINAL witness returns SAME K; complete-public false-instance QPT hiding; unauthorized pre-release final-key recovery/accepted forgery -> ORIGINAL representation or independent QPT break; malicious N-of-N setup, abort, erasure, multi-capsule/branch composition; practical resources; conditional Bitcoin P2MR/SLH endpoint. Production unchanged, PR draft/unmerged. No stopping condition met.
