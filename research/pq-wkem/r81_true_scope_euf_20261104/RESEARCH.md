# R81 — Hard-TRUE ORIGINAL native-scope partition and exact signing-oracle composition

Run: R81-TRUE-SCOPE-EUF-20261104.
Status: restricted positive *native-signature* security composition, not a generic witness-KEM and not a hard-TRUE recovery-to-ORIGINAL-witness theorem. Independent offline derivation/checker available with this research record. No web/literature research.

## Exact continuity

Started from live open/draft/unmerged syscoin/PVUGC PR #1 at 41427d2729505e8bc14033437bff4631081ac6b8, branch research/pq-wkem-validation-20260918, latest top-level substantive comment 6650906327. Exact relevant R80 blob 5756f4326425c4098f6e662f64c3c471ea1581b4, R79 blob 3bff84f668966fac7d5bfefa13f536d1f7e64671, and R75 blob 26c7c14932bceab441ee4751eff0cf43a0a7d2e7 were read. No PR diff, unrelated repository read, or historical sweep. This is a bounded R81 execution.

## Two events that MUST NOT be conflated

Freeze a finite polynomial-size set M_auth of ALL exact native messages pre-signed by the one protected honest participant before irreversible funding. Each message binds the real ORIGINAL relation, claim/outpoint, branch, anchor/window/context, graph identity and intended verification key, without self-reference to its own signature or capsule. All N-of-N graph paths, including timeout and challenge paths, must be accounted for: a previously authorized message is NOT new.

E_out: A QPT adversary outputs m_prime,sigma_prime with Verify(vk_h,m_prime,sigma_prime)=1 and m_prime not in the full honest signing-oracle query set M_auth. An out-of-scope claim/branch/anchor signing success is such an event only if it truly was never signed. E_in: the adversary releases the precommitted signature or any other valid signature on m_i in M_auth, or learns the corresponding precommitted capability. Ordinary EUF-CMA NEVER bounds E_in, because the honest signer already signed m_i. E_bypass: a graph/ceremony/key-leak/availability failure that spends without a fresh signature by the protected key; no native EUF conclusion can address it.

R79/R80 handled E_out only for certified-FALSE source targets using a no-target-signature EUF embedding after source-blinding. For TRUE statements, that embedding is invalid: a valid ORIGINAL witness opens a true source and recovers the genuinely pre-signed sigma. R81 instead uses a genuine native signing-oracle query on the intended target message, permissible when proving security of *different, unqueried* messages. This removes the ORIGINAL statement-class restriction for E_out, not for E_in.

## Explicit honest classical-PPT Build

Let the hypothetical future native signature scheme Sig=(KeyGen,Sign,Verify) be independently QPT-EUF-CMA secure for classical signing-oracle queries. KeyGen/Sign/Verify are classical PPT. The Bitcoin no-EC-key-path and native SLH-like acceptance remain CONDITIONAL, not deployed. Honest N-of-N preauthorization, at least one protected/erasing signer, pre-signature/data availability, no bypass spending edges and safe abort handling are separate requirements. The finite M_auth is frozen and signed before funding; later dynamic capsule references cannot create a new authorized path.

For polynomially many preauthorized slots i, independently sample uniform roots K_i, an honestly sampled shared public A_com if using R71's ordinary-LWE PRG, and independent source noise/coins. Query Sign(sk_h,m_i) for sigma_i. Define U_i=H_(A_com)(K_i), where R71's conditional ordinary-QPT-LWE PRG has public A_com sampled uniformly and output partition disjointly into P_i (exactly native signature length) and independent-looking B_i. If using R71's specific generator, choose its exact parameters and expansion so that the pad and B lengths fit; no 128-bit parameter calibration is claimed. D_i=sigma_i XOR P_i.

Compile the actual public ORIGINAL x_i into A_(x_i),e0_i by the existing fixed-degree moment compiler (or the corresponding actual chosen source). For each word j, Build, which already knows K_i, samples independent uniform z_ij and bounded e_ij, then publishes

    C_ij = Round_(q->p)(A_(x_i) z_ij + e_ij + Delta mu_j(K_i) e0_i).

This computation DOES NOT REQUIRE any witness w, even when x_i is TRUE and difficult. Build computes CK_i and Aux_i as explicit acyclic PPT functions of B_i,D_i,frozen scope,C_i,previous public CK/Aux and permitted related references. No raw P_i, K_i, signer coins, signer secret, or extra signature fingerprint leaks from CK/Aux. The source, CK, native vk, immutable context, all related capsules and honest pre-funding WELLFORMED preflight certificates comprise the public view. The WELLFORMED prover can be run honestly because Build knows K_i,sigma_i,z_ij,e_ij; it does not authenticate ORIGINAL truth. Its generic NP-to-3COLOR implementation and malicious-setup proof are separate, unfulfilled obligations.

For EVERY genuine ORIGINAL witness w with normalized moment vector r_w, r_w^T A_x=0 and r_w^T e0=1. Assuming the exact source's bounded-error decoder works, the public source yields each mu_j(K_i), reconstructing SAME precommitted K_i, hence P_i and sigma_i. Distinct witnesses can have distinct vectors and intermediate states. This correctness property does not constrain non-witness key-recovery attacks.

## QPT-EUF reduction and perfect joint-public-output coupling

In the ordinary QPT-EUF-CMA experiment reduction B receives vk_h and a classical signing oracle but not sk_h. It samples every honest source/private ROOT/pad/public context variable itself, using the true x_i-dependent source compiler and sampler above. It asks the oracle to sign exactly each frozen m_i in M_auth and uses those returned native signatures as sigma_i. It constructs the ACTUAL D_i, CK_i, Aux_i, all related references and genuinely accepting WELLFORMED proofs, with exactly the same source/signature distributions and causal ordering as the real pre-funded protocol. It can serve all protocol-permitted adaptive classical public capsule messages and openings using its known local coins, signatures and roots. It NEVER needs SourceOpen, an ORIGINAL witness, an ordinary-LWE challenge simulator, a certificate for FALSE instances, a supplied representation or quantum rewinding.

Formally, for any fixed public parameters/scope and independent auxiliary advice, couple every real Sign(sk_h,m_i) response to its QPT-EUF signing-oracle response. By definition of the oracle, including randomized signing coins, the source, roots and all downstream public fields are IDENTICAL in the coupled experiments. Even if the QPT adversary processes the entire classical transcript coherently, identical public classical/quantum conditional states have identical final distributions. If the adversary outputs an accepted native signature for m_prime not queried to the oracle, B forwards m_prime,sigma_prime. Thus the exact, no-extra-loss equation is

    Pr_real[E_out] = Pr_QPT-EUF-CMA[B wins]
                  <= Adv_QPT-EUF-CMA_Sig(B).

This works for arbitrary TRUE, FALSE, easy or hard ORIGINAL x_i because the honest source sampler never needs a witness to *construct* ciphertexts. It is the actual signer/oracle distribution, not an LWE simulation. The reduction is classical PPT apart from its QPT adversary, is straight-line, and permits QPT advice independently sampled of sk_h and signer randomness; no coherent signing-interface queries or signer-side hidden auxiliary leaks are available. The full public view includes checking-key/context/auxiliary and related-capsule correlations generated jointly, not just a signature marginal. If there are multiple honest native verification keys, use one such bound per key and a union bound. If a signer signs additional future messages, these messages MUST be added to the actual query set, and the theorem does not call them forgeries. Adversarial selective abort is copied with the real transcript; useful completeness and secret-dependent setup bias are not proved.

This is a genuine composition of ordinary native QPT-EUF security with the actual statement-dependent Build distribution. It is **not** a security reduction for the pre-signed same-message capability and does not instantiate source-dependent ordinary-LWE challenge simulation for hard TRUE.

## Precise remaining obligation and actual source attacks

The only remaining hard-TRUE *cryptographic release* event is E_in: an arbitrary QPT adversary can recover the root/signature for an ALREADY PREAUTHORIZED message without a valid ORIGINAL witness. Ordinary EUF is silent about it, even if the attacker outputs signature bytes not identical to the sampled sigma_i. Still required: a classical-PPT source/release algorithm, full joint-public view including other capsule/CK/aux correlations, malicious setup/abort and openings, and a reduction of

    Pr[A(V_x) recovers K_i or any accepted preauthorized capability]
    <= Pr[R_ORIGINAL(x,Ext^A(V_x))=1]
       + Adv_independently_justified_QPT_break + negl(lambda).

Ext must work for arbitrary QPT A without demanding an internal representation, quantum rewinding, SourceOpen oracle, canonical witness or common intermediate state. Its source challenge simulator must instantiate the actual x-dependent source and all public CK/Aux together under independently justified QPT assumptions. R58 Boolean-quotient bypass, R63/R67 short signed-kernel attacks, arbitrary FALSE security, malicious ceremony/abort, 128-bit QPT parameters, and the conditional Bitcoin endpoint remain open. We neither have a complete WKEM nor a reason to disable its research automation.

## Executed bounded fixture and limitations

The adjacent exact executed checker.py and its captured checker-output.json are separate repository files. The checker passed 14,592 assertions across 64 deterministic cases: 64 *complete serialized* actual-signing versus oracle-signing public-view couplings; 384 genuine openings by three distinct ORIGINAL witnesses on two signed branches; 384 checking-key/aux recomputations; and 256 negative checks on different claim/branch messages. Test ORIGINAL x is a+b+c=1, A_x=(-1,1,1,1)^T, q=256, Delta=16, zero noise, 16-byte roots, two scoped signed messages. Its Ed25519, SHAKE-based pad and toy source parameters are only deterministic local fixtures; Ed25519 is NOT claimed PQ-secure, the generic off-chain preflight/Bitcoin script was NOT implemented, and no QPT adversary or ordinary-LWE hardness was tested. The proof is an exact oracle-substitution argument under a separately assumed compatible QPT-EUF native scheme, not an empirical security claim.

No new production/main/workflow files, reviews, approvals, merges, deployments or transfers. All research files in this run belong under research/pq-wkem/r81_true_scope_euf_20261104/ on the actual existing PR #1 branch.
