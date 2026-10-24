# Run 705 — Remove augmented-native tag hardness from the Run 704 false-instance shield

Research only, 2026-10-22. Exact starting PR head: 35c321bec188155936842af2d17603e855682d39 (open, draft, unmerged); Run 704 proof blob 67e2ea70503c0b4cf9379b89b90d98a536e56bba; Run 259 binding blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2; Run 703 exact-native adapter is LOCAL ONLY after a GitHub safety denial. This composes established semi-classical quantum one-way-to-hiding (O2H), not a newly invented oracle assumption.

## Concrete change and unchanged algorithms

Run 704 proves perfect full-ciphertext key independence for false instances with a bounded Nullstellensatz unit certificate, but explicitly assumes hardness of native public key PLUS the Run 703 tag. Here that additional augmented-native assumption is eliminated in an **independent ideal quantum random-oracle model for the tag**: ordinary native QPT EUF-CMA suffices under the precisely scoped conditions below. No generic-NP or true-instance release security is claimed.

Build fixes x=(relation,UTXO,branch,anchors/window,native context) before tag-oracle sampling; draws claim-specific native B=SK.seed||SK.prf, publishes pk and tau=H_tag(d||B), where d unambiguously length-delimits the domain, x and pk. H_tag:{0,1}*->{0,1}^512 is independently sampled, has coherent QPT access, and is separate from native-signing hashes. Encode B injectively as field K (Run 703 uses q=2^256+297) and privately sample M independently of B and uniform mask polynomials Q_i in public fixed spaces P_i tensor Mat_N(F_q). Publish the **entire** polynomial coefficient array (or public reversible codec) for

C_x(z)=M_x(z)+K I_N+sum_i r_i(z)Q_i(z),

plus pk,tau, x, field, spaces and decode rules; never the private factors, mask coins or B. Every r_i vanishes on any complete accepted SOURCE. Encode ORIGINAL witness w to the Run 701 SOURCE z; all valid w recover the SAME B through the unchanged Run 696 spectral decoder and Run 703 exact-tag native credential selector, even if M(z) differs. Recover remains OFF CHAIN; native signature verification on Bitcoin remains conditional.

## Lemma A: false full-ciphertext simulation, with all pk correlations intact

For FALSE x, suppose scalar p_i in P_i satisfy the formal polynomial identity sum_i r_i(z)p_i(z)=1. Fix arbitrary B,B', with field encodings K,K' and delta=K'-K. Translating each secret uniform mask by Q_i'=Q_i-delta*p_i*I is a distribution-preserving bijection, and for ALL inputs z (valid, invalid, or non-Boolean),

M+K'I+sum_i r_i Q_i' = M+KI+sum_i r_i Q_i.

Thus the **whole public coefficient array C** has exactly the same distribution for every K, even conditional on native pk and tau, provided M and mask distributions are independent of B conditional on x and the public spaces are fixed independently of B. It is essential that pk and tau THEMSELVES remain correlated with B; this lemma does not erase their correlation. A simulator without B creates C using dummy K*=0 and correctly reproduces the joint false-instance view (pk,tau,C) as soon as it is given (pk,tau). It need not know the certificate p_i. The conclusion holds under arbitrary QPT coherent evaluation of the full public C. Fresh masks and independent M are required per capsule.

## Lemma B: remove public tag without assuming augmented-native hardness

Define native QPT EUF-CMA with normal classical signing queries and arbitrary permitted correlated auxiliary quantum advice, but no information that trivially supplies B. Signing, key generation, advice and context generation are **independent of the fresh H_tag**; any honest signing operations use independently domain-separated hashes. Let A make at most Q polynomially many coherent tag-oracle queries and try either (i) to output exact B or (ii) to forge a valid native signature on an unqueried designated message. The input includes the complete FALSE-instance C from Lemma A.

G_real: sample native (B,pk), random H_tag and tau=H_tag(d||B). G_rand: sample same (B,pk), H_tag and independent uniform 512-bit tau. In G_rand, the simulator knows pk but not B, samples tau and the dummy-key C, and forwards a win to the standard native EUF-CMA challenger; if A outputs exact B, reconstruct the Run 703 native signer and sign a fresh unqueried message, also constituting a native EUF-CMA forgery.

Reprogramming formulation: sample H_tag and independent uniform tau, then change H_tag(d||B) to tau. This produces EXACTLY the G_real joint law, while leaving all other oracle points independently random. Therefore G_real/G_rand differ only by a hidden point d||B of a quantum-accessible random oracle. The standard semi-classical O2H lemma supplies a QPT query-finding reduction E: a nonnegligible distinguishing advantage implies nonnegligible probability E obtains the exact queried d||B, with an explicit polynomial loss in Q. Under the common SC-O2H convention,

|Pr[G_real:Win]-Pr[G_rand:Win]| <= O(Q sqrt(Pr[E finds d||B])),

and equivalent variants have at most an additional polynomial query factor. This is an ASYMPTOTIC reduction, **not a concrete tight bit-security estimate**; fix an O2H formulation before sizing parameters. An E returning d||B knows exact B. With public pk it reconstructs a native private DER signer (Run 703), signs a new message, and wins ordinary native EUF-CMA. Thus both the G_rand success and the hidden-point search probability are bounded by ordinary native QPT EUF-CMA success for explicitly constructed straight-line quantum reductions. In particular, assuming native QPT EUF-CMA, the entire (x,pk,tau,C) false-instance release game is QPT secure for the unit-certificate class in the **independent ideal QROM**, without postulating a new augmented-native hardness assumption. No ORIGINAL witness extraction is claimed for a false x.

No classical rewinding, QROM secret-point programming by the reduction, or classical-only oracle queries are asserted. The O2H theorem, rather than the finite checker, supplies the quantum claim. QPT oracle simulation external to the native scheme can use 2Q-wise independence for at most Q coherent queries on a fixed-length encoding domain (Zhandry); alternatively formulate native EUF-CMA with an independent auxiliary tag oracle.

## Multi-capsule and excluded adversaries

For polynomially many FALSE capsules sharing a native B, with separate masks and independent private M, the joint full-C distribution still factors and is B-independent. Tags H_tag(d_j||B) use distinct, unambiguous contexts and can be removed in a polynomial-length O2H hybrid (polynomial loss in Q and capsule count). This DOES NOT cover any shared-B TRUE capsule, mask reuse, retained native setup secrets, context generation depending on H_tag, advice correlated with hidden mask coins, malicious N-of-N ceremonies, quantum signing oracle access, or real SHA3-512 instantiation.

SLH-DSA-SHA2-128s currently exposes public seed/root while SK.prf has 128 fresh bits in the tested native layout, so no unjustified claim of 128-bit quantum-operation resistance follows from a 512-bit tag output. Native EUF-CMA strength, concrete Grover resources and any 256-strength variant require independent accounting. This theorem neither improves signature strength nor gives the release carrier hard-TRUE extraction.

## Executed validation, provenance and precise next gap

The standard-library Python checker run705_tag_hybrid_check.py ran twice with identical results: 203 assertions. Exhaustively across all 256 functions on a four-element domain it verifies exact equality of the (pk,tau,oracle) law for tau=H(B) and tau uniform with oracle reprogrammed at B, while pk deliberately leaks one key bit. Three independent false-capsule 2x2 full coefficient matrices verify the nonconstant identity (1-u)+u(1-v)+uv=1 and simultaneous exact key/mask coupling, with all 192 tested arbitrary evaluations equal. These finite checks DO NOT prove native EUF-CMA or the quantum O2H lemma. Read run705_tag_hybrid_validation.json for captured output.

Run 704's extra augmented-native assumption is removed for the stated false subclass, a real composition proof improvement. **Still missing:** hard-TRUE arbitrary recovery/forgery -> accepted SOURCE (Run 259 only applies AFTER SOURCE is output), polynomial certificate spaces for all false SYS/BTC evidence, full spectral QPT hiding, malicious setup and abort, mixed true views, practical 128-bit resources, and real Bitcoin native PQ transaction graph. Next candidate step must construct the actual hard-TRUE secured local carrier; do not substitute further coding/compression or this native lemma for its proof.

Primary method sources: Ambainis et al., CRYPTO 2019 SC-O2H, and Bao–Ge–Xue (2024) QROM O2H analysis, https://link.springer.com/article/10.1186/s42400-024-00228-6 ; Zhandry quantum 2Q-wise oracle simulation, https://eprint.iacr.org/2012/182 .
