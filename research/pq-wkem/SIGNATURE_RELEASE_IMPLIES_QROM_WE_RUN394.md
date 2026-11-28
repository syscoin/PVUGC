# Run 394 — Universal signature release entails QROM witness encryption

Date 2026-10-09. Live connected-GitHub start: syscoin/PVUGC#1 draft branch `research/pq-wkem-validation-20260918`, head `a3f98f8c6bf7e8c7e0dc507be1e4e76a815c2e5e`. Dependencies: Run 393 note blob `7ee3cc73f1115a2788a4d54021ca808f865405dd`; Run 259 note blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`. This is a **lower-bound compiler implication**, NOT a WKEM construction, local-mixer security theorem or new hardness assumption.

## Precise premise

For an NP-universal ORIGINAL relation R(x,w), assume *classical PPT* Sig.KeyGen, Build(x,sk)->P, and Recover(P,w). For every valid ORIGINAL w, Recover returns the SAME sk with overwhelming probability, although intermediate states can differ. Fix a public context-bound message m*(x,vk) and deterministic valid signing algorithm DSign(sk,m*)=sigma*. Setup publishes the full correlated (x,vk,P,aux) view. Its separate **false-instance operational authorization property** says: for every false x, no arbitrary QPT algorithm with this complete view, auxiliary quantum advice and a fresh independent quantum random oracle can output ANY signature accepted by Verify(vk,m*,.). This property is *not* inferred from native EUF-CMA, since P may itself leak the signing key. Auxiliary states must be available to a simulator/reduction and independent of the fresh oracle. Multiple capsules require a JOINT version of this assumption.

## Construction and proof

To encrypt a chosen message M of ell bits to NP instance x, generate (vk,sk), build P, compute sigma*=DSign(sk,m*(x,vk)), and output

`CT=(x,vk,P, M XOR H("WKEM-to-WE/v1" || encode(x,vk) || sigma*))`.

Any valid ORIGINAL w recovers exactly sk, recomputes deterministic sigma* and decrypts. Only semantic output must agree; no canonical witness, shared source state or common short preimage is required.

For a false x, couple uniform oracle H0 and independent uniform U with H1=H0 except H1(tau)=U, where tau=("WKEM-to-WE/v1",encode(x,vk),sigma*). H1 is itself a uniform random oracle; ciphertext C=M_b XOR U is its **real** encryption. The **ideal** oracle H0 leaves C a uniform one-time pad independent of b. The public correlated (x,vk,P,aux) is identical in both worlds.

For any arbitrary QPT attacker making q>=1 coherent oracle queries, let eps be the difference in acceptance probabilities between real and ideal experiments. An oracle-difference hybrid on the ideal prequery states gives eps<=2 sum_j sqrt(a_j)<=2q sqrt(p_hit), where a_j is the query probability of point tau and p_hit is the probability obtained by measuring a uniformly chosen ideal-world oracle query. The resulting straight-line QPT forger needs neither sk nor sigma*: measure that query, parse the candidate signature, and check Verify(vk,m*,candidate). Whenever the measured point equals tau it yields a valid native signature. Thus

`Adv_WE_QROM <= 2q sqrt(Adv_FalseSignatureForge)`.

No rewinding or classical-query assumption is used. The fresh domain-separated oracle must be independent of signing/setup; quantum prechallenge queries may be included in q. For polynomial q, negligible false-instance signature-forgery probability entails false-instance NP witness-encryption IND in the **QROM**. This is NOT a plain-model theorem. Known technique: Ambainis–Hamburg–Unruh O2H, CRYPTO 2019.

## Consequences, negative controls, and exact limits

This shows that a generic NP-capable, all-witness same-native-key release primitive with full-public-output false-instance QPT authorization security is **at least WE-powerful in the QROM**. A supposedly strictly weaker-than-WE assumption for *all NP* therefore requires a genuine restriction or security-model qualification, not merely a smaller mixed region. NP-universality of the specific Syscoin fork-evidence relation has NOT been demonstrated, so a narrower relation-specific path remains open.

Public vk is explicitly retained. A naive game distinguishing encryption of two **chosen signing keys** is trivially broken by comparing their derived public keys; this theorem converts operational false-instance forgery hardness to message secrecy instead and does NOT assume the signing secret looks random given vk. Honest deterministic signing is sufficient; valid signature uniqueness is unnecessary. A deterministic FIPS 205 SLH-DSA mode exists, but Bitcoin-native deployment is hypothetical.

**Multi-capsule falsifier:** same pad index gives C0 XOR C1=M0 XOR M1 without oracle queries. Bind statement/relation/UTXO/branch/capsule ID, and use separate challenge signing credentials. Distinct KDF domain tags cannot protect a reused actual signing key if a witness to another branch already releases it. Joint security is unproved.

**Run 259 scope:** accepted COMPLETE representation => ORIGINAL witness (or precisely specified SIS break). This QROM compiler proves only false-instance hiding, not an accepted signature => accepted representation. Run 393's *ideal oracle* source extractor cannot be assumed for a white-box public local mixer.

Attack taxonomy: (1) seam and (2) gauge and (3) fingerprints remain unproved for actual mixers; (4) identical multi-capsule pad reuse falsified; (5) adaptive oracle queries captured by O2H; (6) malicious setup coins excluded; (7) cross-claim signing-key reuse falsified; (8) public checking-key retained and used by extraction; (9) genuinely coherent oracle queries included. Setup/evaluation classical PPT, adversary arbitrary QPT, H quantum-accessible, nonuniform aux must be H-independent.

**Validation:** exact deterministic Node checker enumerates 8192 toy couplings (sigma,H0,U,b), H1 uniformity, one-query advantage 0.0625, measured-query hit 0.125, theoretical bound 0.0009765625, reused-pad XOR and domain-separated control. 22 PASS checks, byte-identical repeated execution. The checker does NOT simulate quantum queries or prove a concrete scheme.

**Open:** public local source-enforcing release construction, false-instance QPT guarantee with its complete view, true-instance arbitrary-QPT ORIGINAL extraction, malicious one-honest N-of-N setup/abort/erasure, joint capsule security, 128-bit practical resources, and conditional native Bitcoin PQ endpoint. No production changes, PR stays draft, stopping condition unmet.

Literature: https://research.ibm.com/publications/witness-encryption-and-its-applications ; https://kodu.ut.ee/~unruh/publications/semiclassical.html ; https://csrc.nist.gov/pubs/fips/205/final .
