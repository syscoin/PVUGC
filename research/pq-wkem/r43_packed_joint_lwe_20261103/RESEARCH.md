# R43 — PACKED-JOINT-LWE (offline, 2026-11-03)

**Constructive efficiency theorem for R42's restricted LWE-decryption-witness SOURCE; not generic PQ witness-KEM, not a recovery-to-ORIGINAL-witness reduction, not concrete 128-bit security.**

Provenance: checked actual open/draft PR #1 at `bbf35d10628870f24172d76beede0afcfbfbc645` on branch `research/pq-wkem-validation-20260918`. Exact R42 RESEARCH.md blob `8134b7987ae436f5e5017b6d03daf5c062cdc978` and CHECKER.js blob `7378b54ed780636e9ee41e3ce2bebedc04e65b6b`; latest R42 PR comment 6610044046. No external literature or web research.

## Classical algorithm and universal correctness

Parameters: security parameter lambda; prime q, n,m polynomial, signed error distribution chi supported on [-B,B], branch count J, seeds K_bind and K_pad independently uniform in {0,1}^kappa, and polynomial independently randomized scopes s. Let p=2^b, 2<=p<=q, with a public center tau(a)=floor(qa/p) for a in Z_p. Define g=floor(q/p). **Require 2mB<g.** Since q residues are cyclic, any two adjacent centers have cyclic gap at least g.

For each independent claim/branch, draw A uniformly in Z_q^{n x m}, secret s uniformly in Z_q^n, short e from chi^m, and publish b=A^T s+e. The **restricted source relation** is R_LWE((A,b),(s',e')) iff b=A^T s'+e' and ||e'||_infinity<=B. This is **not the ORIGINAL SYS/BTC relation**. Keep R42's one claim-specific, privately pre-signed fixed-path signature sigma, native vk, DEM D=sigma XOR G(K_pad;domain,claim,context), CK=F(public statement/claim/UTXO/anchors/window/path, pks, all ciphertexts, vk, m, D, K_bind), and allowed aux dependent on public fields, CK, K_bind, independent coins and non-target opened records. CK may not additionally leak K_pad, target sigma, target source secrets. All original evidence remains off chain.

Replace each bitwise Regev ciphertext with **one b-bit symbol ciphertext**. Split each role seed's little-endian bits into b-bit chunks, zero-pad the last chunk, and independently draw fresh binary r in {0,1}^m for **every** role/chunk/branch/scope. Publish (u,v)=(Ar,b^T r+tau(a)) mod q. No randomness reuse. OffChainOpen checks the restricted relation and public context, computes z=v-s'^T u, decodes the uniquely nearest cyclic center tau(a), checks agreement of independent scopes and zero-padding, concatenates bits to the original two seeds, checks CK/aux, derives D XOR G(K_pad), verifies native signature OFF CHAIN, then releases the exact bytes for the conditional native endpoint.

**Proved deterministic SAME-capability correctness:** For ANY valid restricted witness (s',e') in ANY OR branch, z=e'^T r+tau(a) and |e'^T r|<=mB<g/2. Thus every such witness decodes every symbol correctly and recovers the SAME precommitted K_bind, K_pad, sigma regardless of branch or its internal witness state. Honest algorithms are classical PPT. This theorem does not authenticate arbitrary ORIGINAL evidence.

## Full-public-output QPT hybrid, no strengthened computational assumption

Assume the same independently specified **QPT exact-distribution decisional-LWE**, **QPT-secure PRG**, and **multi-message QPT native EUF-CMA** assumptions as R42. LWE public keys are independently honestly generated for each target branch. The adversary is arbitrary nonuniform QPT, receives relation, statement, public source pk, *all* target/related capsules, CK, context, vk and fixed-path message, simulator-reproducible aux, and may query a complete fixed polynomial table of **non-target** source witness/seed/native-signature openings coherently via a reversible oracle. Target claim predesignated and unopened; auxiliary quantum advice is independent of target secret generation. No malicious target setup, secret-correlated K_pad advice, quantum access to encryption coins, adaptive target selection, or target openings are claimed secure.

For uniform (A,b), the 2-universal map h_(A,b)(r)=(Ar,b^T r) with r uniform binary has the average strong-leftover-hash bound delta=0.5 sqrt(q^(n+1)/2^m). **Adding any packed symbol offset tau(a) to the final coordinate is a bijection**, preserving TV to uniform; this is unchanged by replacing one encoded bit with a b-bit symbol. Fresh ciphertext coins and the standard LWE->uniform-pk->uniform-ciphertext->uniform-pk zero-symbol->LWE sandwich therefore zero all target source ciphertexts, at cost 2 J Adv_QPT-DLWE + 2 T delta, where T=J*s*2*ceil(kappa/b). All CK/aux are recomputed with the original K_bind and the *actual* ciphertexts and D; non-target openings remain exactly simulated. In the zero-capsule hybrid K_pad is still independent of K_bind, so replacing G(K_pad) by uniform makes D independent of the unqueried target sigma. The QPT native EUF challenger signs only distinct non-target messages, never the target. Coherent QPT postprocessing cannot amplify the stated classical statistical gap, and no rewinding or adversary-supplied representation is required.

Therefore for this **restricted honestly generated source and admissible full-public view**:

    Pr[A produces an accepted native target signature]
    <= Adv_QPT-native-EUF + Adv_QPT-PRG
       + 2 J Adv_QPT-DLWE + 2 T delta.

Exact K_pad recovery also produces sigma and obeys that bound. CK collision resistance for adversarially modified bindings requires a separate QPT collision-resistance assumption; this is not inferred from a toy checksum. An unbounded correlation that leaks K_pad invalidates the proof. Arbitrary FALSE keys (e.g. R39's A=0 case), malicious setup, original-witness extraction, target selective openings, and the conditional Bitcoin-native PQ endpoint remain unproved.

## Measured algebraic work reduction, not measured runtime

With J=3, kappa=256 per seed role, one scope, q=65537, n=64, m=2048, B=1, p=8 (b=3), the cyclic center gap g=8192 exceeds 2mB=4096. Original bit capsules total 1536, packed capsules total 516, **66.40625% fewer**, with identical ciphertext vector dimensions. Conditional log2(delta)=-504.9993, log2(2T delta)=-494.9881. This is NOT a concrete 128-bit LWE-hardness claim; those parameters' attack cost and practicality need independent analysis.

## Actually executed bounded checks and exact missing equation

The exact published V8 CHECKER.js was executed twice byte-identically with 282 assertions, three OR branch decodings, 536 counted packed symbols, a two-distinct-witness degenerate control, and exhaustive 6,561 tiny q=3 public keys x 16 r vectors. Average small-field statistical distance = 16120/59049 (<3/8 LHL bound), all 3 additive offsets preserve distance to uniform. Deterministic PRNG, FNV tag, and toy DEM are **not cryptographic**. Independent LOCAL-ONLY Node (331 assertions) and Python rational checker independently confirmed the algebra and 16120/59049 exact rational value; the extended local archive contains their exact executed code and outputs. No QPT security is established by tests.

**Still missing:** classically build a public S_x from arbitrary genuine ORIGINAL NP/SYS-BTC statement x without a hidden LWE-secret bypass; prove every valid ORIGINAL witness w decodes the SAME sigma, and derive for arbitrary QPT unauthorized recovery or accepted native forgery in the COMPLETE correlated view:

    Pr[A wins] <= Pr[straight-line reducer produces w: R_ORIGINAL(x,w)=1]
                  + Adv_QPT-independently instantiated PQ break + negligible.

Do not assume SourceOpen or adversary-submitted representations. Merely tagging R_ORIGINAL in CK or checking it in the off-chain Open API does not prevent a party holding s from decrypting and signing. Malicious one-honest N-of-N ceremony/abort, useful DA/observation, generic false-instance security and native PQ Bitcoin endpoint remain separate unsolved requirements.
