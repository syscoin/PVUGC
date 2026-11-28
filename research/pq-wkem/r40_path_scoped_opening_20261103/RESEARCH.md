# R40 — PATH-SEPARATED-SOURCE-OPENINGS: exact non-target source-witness selective opening for the restricted Regev surrogate

**Date:** 2026-11-03. **Status:** a rigorously instantiated, restricted multi-path composition; NOT generic-NP witness-KEM and NOT recovery-to-ORIGINAL-witness. Offline mathematical continuation of R39 at start head 8e85082dd760ed4b7073cf4b0a4e6e52497ca46d on syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918. No outside literature/web consulted.

## Construction and precise distributions

Fix security parameter λ and polynomial number P of **distinct claim/path credentials**, with designated target t fixed before setup. Each credential i uses its **independent** LWE public source:
- q odd prime; n,m polynomial in λ; error distribution χ supported on integers [-B,B].
- independently sample A_i uniform in Z_q^(n×m), s_i uniform in Z_q^n, e_i←χ^m, b_i=A_i^T s_i+e_i mod q.
- publish pk_i=(A_i,b_i), retain (s_i,e_i) only as source witness; honest setup does not publish the target secret.
- surrogate relation R_i(pk_i,(s',e'))=[b_i=A_i^T s'+e' mod q and ||e'||∞≤B].
This is **NOT** the ORIGINAL SYS/BTC/NP relation. In particular any party holding s_i can decrypt without authentic ORIGINAL evidence. No generic x→pk_i compiler is claimed.

Independently sample native signing (sk_N,vk_N). Before irreversible funding, form each DISTINCT immutable message
m_i=M(relation identity, claim/UTXO, designated branch/path i, anchors/window, pk_i, vk_N, context),
with canonical encodings and collision-free domain separation for this path set. Privately pre-sign σ_i=Sign(sk_N,m_i). The SAME native signing key may sign different path messages, requiring multi-message QPT EUF-CMA security; Lamport toy signatures used in checker do NOT satisfy this assumption. Native Bitcoin SLH-like verifier/no-EC-key-path remains hypothetical.

For each path i independently choose uniform K_i∈{0,1}^κ. Fix QPT-secure PRG G:{0,1}^κ→{0,1}^L with public domain/path separation and L equal to the canonical native signature length. Let D_i=enc(σ_i) XOR G(K_i;domain,i,context). For each bit j and independent scope a, choose fresh r_i,j,a uniform in {0,1}^m and publish Regev encryption:
u_i,j,a=A_i r_i,j,a mod q,
v_i,j,a=b_i^T r_i,j,a+Δ K_i[j] mod q,  Δ=(q-1)/2.
No r is reused, even within one path. Let T_t=κ times the number of target scopes.

Full public output is V=(all R_i and statements pk_i, claim/UTXO/path/anchors/window/context, vk_N, all m_i, D_i, all target and related ciphertexts, CK, aux), where CK and aux are polynomial-time **publicly reproducible** functions/samplers of V's other public fields and independently sampled randomness. Public auxiliary data may condition on revealed non-target (K_i,σ_i,s_i,e_i) if its sampler and correlations are known to the reduction. The restriction excludes an independent secret-correlated checking key, target secret key, target SOURCE witness, target K/σ, target openings, and arbitrary advice tied to the unrevealed native signing secret.

The selective-opening oracle has a **fixed publicly specified target t** and returns, for i≠t, (K_i,σ_i,s_i,e_i); for i=t it always returns ⊥. Since its table is fixed, a simulator knowing all non-target entries can even implement the coherent reversible table oracle |i,z⟩↦|i,z⊕Open(i)⟩, with a canonical length/padding encoding and ⊥ on target. The adversary may make adaptive classical or coherent QPT queries. The game does not include adaptive target selection after opening, target-scope openings, or a target-correlated auxiliary oracle. Opened non-target source witnesses are **included**, unlike a weaker capability-only opening game.

## Proved correctness for every surrogate witness

If (s',e') is ANY valid witness to R_i and q,m,B satisfy mB<Δ/2, then
v_i,j,a−(s')^T u_i,j,a = (e')^T r_i,j,a+ΔK_i[j] mod q
with |(e')^T r_i,j,a|≤mB. Nearest-center decoding recovers K_i[j] deterministically for all j,a and all witnesses, even witnesses selected after the public transcript is seen. All valid witnesses to a **particular** path recover its SAME precommitted K_i and prescribed σ_i. Distinct claim/path credentials use independent capabilities; this does NOT replace R33's required shared capability for different ORIGINAL witness branches of one claim. It is essential that the path's signing message be fixed and privately pre-signed before funding.

## Straight-line full-public QPT proof including other source secrets

Assumptions:
(A1) QPT decisional-LWE advantage Adv_DLWE for the exact (n,m,q,χ) distribution (A,A^T s+e) versus independent uniform (A,b). Honest A_i must be uniform; the correctness checker deliberately uses degenerate A and is NOT an LWE-hardness experiment.
(A2) Independent QPT PRG security of G on a uniform κ-bit seed, including polynomial classical/quantum auxiliary input independent of the unrevealed seed.
(A3) QPT EUF-CMA security of the native **multi-use** signature on a never-queried distinct m_t, even though other path messages are signed by the same key; the reduction's signing queries are classical.
(A4) Independent source keys and K_i across different paths, fresh independent target ciphertext randomness, publicly simulatable CK/aux, no malicious ceremony or target-secret leakage.
The reduction receives the exact classical public challenge and has oracle access to A as a QPT circuit (with independent nonuniform advice allowed), and may run A once with its coherent opening interface. It does not invert A, measure A's private state, rewind a quantum circuit, or require A to produce a representation.

Let H0 be the full real transcript and opening oracle. In H1 ONLY target ciphertexts are changed to Regev encryptions of 0, while retaining K_t, σ_t, vk_N, D_t, all non-target pk_i, their actual source witnesses, revealed K_i, σ_i, all related capsules, public CK and context. The two decisional-LWE transitions (honestly LWE-generated target pk_t→uniform pk_t→honest target pk_t) and two leftover-hash transitions imply

  |Pr[A wins H0]−Pr[A wins H1]| ≤ 2 Adv_DLWE + 2 T_t δ,
  δ = 1/2 sqrt(q^(n+1)/2^m).

Here the universal family for q odd is h_(A,b)(r)=(Ar,b^T r). For distinct binary r,r', their difference includes an invertible ±1 coordinate mod q, so h is 2-universal under uniform (A,b). The strong leftover-hash lemma applies to the **joint public seed and ciphertext** averaged over random (A,b), not to every adversarial fixed key. The target ciphertext hybrid also preserves correlations with all other public fields: other source statements, their secret witnesses and opening responses are independently samplable given the target public pk and the local native signing key/vk; they cannot increase the statistical distance. For T_t same-key target ciphertexts with independent r, sequential hybrids cost T_tδ. The simulator implements the exact same responsive coherent opening table; only target opening is always ⊥. All public CK/context/aux are recomputed under the current hybrid, rather than frozen inconsistently.

In H1, K_t appears only in D_t because target encryptions are zero and all other K_i are independent. Replace G(K_t;domain,t,ctx) with uniform length-L bits to obtain H2. This costs at most Adv_QPT-PRG; the signature σ_t is then perfectly one-time masked. H2 can be simulated given a native EUF-CMA challenger vk_N: independently generate all pk_i and other signing messages m_i; request signatures for i≠t (which are DISTINCT from m_t); encrypt other path keys honestly; put zero-message ciphertexts in the target, choose uniformly random D_t and publicly regenerate CK/aux. The simulator requests **no signature on m_t** and needs neither s_t nor σ_t. Thus any accepted signature on m_t is an EUF-CMA forgery, including the prescribed σ_t, so

  Pr[accepted native signature on unopened path t]
  ≤ Adv_QPT-EUF(native) + Adv_QPT-PRG(G)
    + 2 Adv_QPT-DLWE(n,m,q,χ) + 2T_t δ.

This proof is **valid for the restricted honestly LWE-generated surrogate source** with the stated independent, simulatable full joint view and target-fixed opening game. It is not a direct black-box extraction of an ORIGINAL witness. The same signature verification key, its pk/UTXO-dependent m_i, all related ciphertexts, source witnesses for every non-target path, and the public checking-key dependencies are present in both the game and its simulator.

A sufficient **statistical only** condition to make 2T_tδ≤2^-λ is m≥(n+1)log2 q+2λ+2log2 T_t; independently require mB<Δ/2. Neither these inequalities nor the toy check assess QPT-DLWE hardness, QPT native EUF security, or practical 128-bit parameters.

## Why the two separations are necessary

If the target and an opened non-target path share K, the revealed K directly unmasks D_t and its native signature, despite separate public keys. If they instead share pk and revealing the non-target source witness includes an (s,e) for that pk, the witness decrypts the target ciphertexts, even with independent K_i. Both are deterministic bypasses. Therefore BOTH independent source pk_i and independent K_i are required for this stronger source-witness opening game. If multiple target scopes necessarily encode the SAME capability, opening ANY target scope is forbidden; if two ORIGINAL witness branches must open the same claim's capability, they cannot be split into independently releasable path claims merely to make the theorem apply. The proof is NOT a general composable selective-opening theorem for all graph semantics, nor does it survive adversarially correlated setup.

## Exact executed checks and scope

CHECKER.js was executed twice in offline V8 before its Git blob was created; its captured OUTPUT.json was also created from that execution. Results: **9,093 assertions each time, byte-identical**; q=257, n=2, m=16, B=1, 3 independently instantiated toy sources, 2 ciphertext scopes per path, 128-bit keys, 3 distinct surrogate witnesses per path, 2,304 correct same-key bit recoveries, 8 non-target opening queries including source witnesses and exact DEM/checking-key validation, and zero target-source or target-native-signing calls by the simulator. Negative controls explicitly break the target when either K or pk is shared.

An independent exact finite q=3,n=1,m=4 exhaustive check enumerated 6,561 candidate public (A,b) seeds and 16 binary masks each, then adjoined an independently fixed opened non-target source witness/ciphertext distribution. The average target and full joint statistical distances were **identical** at 0.37098003353147385; an exceptional fixed key had TV=1, illustrating why the strong leftover hash lemma is an **average over keys**. This small-field test does not prove LWE or quantum security.

The toy A sources set their second matrix row to zero solely to supply three easily verified distinct witnesses. The toy native hash, Lamport-like signature, PRG and PRNG are deliberately insecure; the signer is reused over paths only to test syntax, NOT as a secure native implementation. Exact checking output, code and derivation are preserved. Local container/Python were unavailable (connection/session errors); no independent agents or external research were used.

## Recovered-seed and native-forgery events

The theorem bounds arbitrary accepted native signature production on the **unopened designated message**, not merely production of an alternative signature. An arbitrary QPT algorithm outputting the exact target K_t can be transformed straight-line, with no loss and no attacker-supplied representation, into an accepted-signature algorithm: compute σ_t=D_t XOR G(K_t;domain,t,context), then submit that σ_t. Therefore **exact target K_t recovery** is bounded by the same right-hand side. If an attacker outputs an accepted native signature without recovering K_t, the direct EUF route already bounds it. This is a reduction only to an independent native-signature break **for the restricted honest LWE surrogate**; it does not extract actual ORIGINAL evidence, and it does not imply that every successful native signature reveals K_t.

## Exact handoff / unresolved original theorem

The missing compiler must start from a **genuine arbitrary ORIGINAL statement x and its actual witnesses w**, not from secretly selected LWE s_i. It must publicly generate setup/opening such that every valid ORIGINAL w independently recovers the same bound capability and no unrelated LWE decryption key opens it; then prove the unrestricted quantum full-public hard-TRUE recovery/native-forgery→**ORIGINAL witness or independent QPT break** reduction without an attacker-supplied representation. Arbitrary adversarial FALSE statements, secret-correlated checking keys, arbitrary adaptive-target selective opening, malicious one-honest N-of-N setup/abort, pre-funding graph safety, realistic resources and native Bitcoin PQ verification remain wholly open. In particular this R40 theorem does not bind authenticated SYS/BTC fork/burn evidence and does not repair the known R39 surrogate bypass.
