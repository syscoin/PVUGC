# Run 387 — Public FHE evaluation is not witness-gated plaintext release

2026-10-09. **Scoped QPT hybrid theorem; neither a WKEM nor an attack on LWE-FHE.**

## Exact live source
Read connected `syscoin/PVUGC#1`: open/draft/unmerged branch `research/pq-wkem-validation-20260918`, initial head `40d3e24e1724a35e1bae7d1a4c003d197d5e384c`. Latest ordinary comment `6067040320`. Exact-head dependencies: `CLZ_APPLICABILITY_20261008.md` blob `c19d9d9cd515140e3ce62eac960cd548c0add622` and `REVERSIBLE_DENSITY_BRIEF_RUN385.md` blob `c973d19d9967870b4ef4d74f4062ee510e5fcfdd`. Run 386 is a local-only checkpoint, not a committed dependency.

## Theorem: ciphertext-only FHE cannot supply public native authorization

Fix a true-instance/witness sampler that is classical PPT and samples `(x,w)` without access to native signing secret `K` or FHE decryption secret. Generate `(vk,K)` via classical native Sign.KeyGen and `(pk,dk,evk)` independently via classical FHE.KeyGen. Give an arbitrary QPT attacker the full public statement/context, `vk`, all public FHE evaluation keys and algorithms, `w`, any polynomial number `t` of honestly independently randomized `Enc_pk(f_i(K))` ciphertexts, all public related-capsule evaluations, and additional auxiliary information simulatable from public values plus allowed signing-oracle replies. The functions `f_i` are classical PPT; public evaluation may be run coherently. No further K-correlated release token, functional decryption key, secret decoder, retained decryption key, or non-simulatable proof is present.

Assume FHE multi-message QPT IND-CPA **including its actual evaluation keys/quantum-access model**, and native QPT EUF-CMA for a correctly bound target message `m_x` that has not been pre-signed. Then

`Pr[public attacker outputs fresh valid Sign.Verify(vk,m_x,sigma)=1] <= t*Adv_FHE_QIND-CPA + Adv_Sig_QEUF-CMA + simulation_error`.

**Proof.** Fix the same native `vk` through hybrids `H_0,...,H_t`. In `H_j` replace the first `j` secret-dependent FHE ciphertexts by honest encryptions of zero. Each neighboring gap is reduced to one standard FHE IND-CPA challenge: the reduction samples `K` itself to retain the correct `vk=VK(K)`, prepares both challenge messages and every other encrypted/plain auxiliary value, then runs the arbitrary QPT attacker without rewinding. All public FHE evaluation and joint coherent postprocessing are available to that reduction. In `H_t` the whole remaining public distribution is simulatable from a native EUF-CMA challenger `vk`, FHE encryptions of zero, an independent true-instance witness sampler, and any allowed signing queries. A valid fresh target signature therefore breaks native QPT EUF-CMA. Sum the hybrid gaps. Correlation with the public signature checking key is **not ignored**: the identical `vk` stays visible in all hybrids.

If an honest public `Recover(view,x,w)` recovered the common native signing capability from those ciphertexts with noticeable probability, its output would permit a fresh native signature and contradict the bound. **Ordinary public later-witness FHE evaluation remains possible, but its output stays encrypted.** An independent witness-gated plaintext release object must contain additional secret-correlated machinery not covered by the theorem; its source security is the unsolved work, not an implication of FHE.

## Scope and local-mixing falsification
This argument requires an efficiently simulatable true-instance/witness distribution, independent honest FHE and signature key generation, simulatable non-FHE auxiliaries, and quantum security under the exact public evaluation/QROM model. It excludes malicious setup or retained `dk`, non-simulatable graph presignatures, extra release material, private online oracles, oracle programming, and arbitrary advice correlated with hidden K/challenge bit. No proof of an arbitrary native-signature-to-Run-259 accepted representation follows. This is a **no-go only for a ciphertext-only architecture**, not generic WE/FE/iO/RIO.

Relevant taxonomy: (4) polynomial related ciphertext views are handled by hybrids under independent honest randomness; (5) chosen inputs and public evaluation are just adversarial computation; (8) the native `vk` remains in the complete view; (9) the reduction is straight-line for QPT, including coherent public circuits. (1)-(3) local seams/gauge/fingerprint require a specific new release token. (6) malicious setup and (7) cross-UTXO branch replay remain separate unproved protocol obligations.

## Checker and handoff
The attached exact checker uses an **idealized additive-mask toy, not public-key FHE**. For `K in Z_8`, independently uniform ciphertext masks, witness `w` independent of K, and toy `vk=K mod 2`, the full public view (up to 3 capsules and public transformations) leaves an exactly uniform 4-key posterior. Publishing the actual pad immediately leaks K even for false witness claims. Validation: `7139` assertions, syntax PASS, two byte-identical runs. This does not test QPT assumptions or real signature security.

Literature: Brakerski–Vaikuntanathan, DOI `10.1137/120868669`, supplies FHE public evaluation but not plaintext release; Canetti–Luo–Zhang, DOI `10.1007/978-3-032-35367-2_18`, explicitly requires additional controlled homomorphic/functional-decryption machinery. No full-paper proof audit this iteration.

**UNPROVED:** minimal secret-correlated source-enforcing release, all-witness same K for an actual secure instantiation, false-instance full-public QPT hiding, arbitrary unauthorized key/accepted native signature -> Run-259 representation -> ORIGINAL/SIS, one-honest-party N-of-N ceremony/abort/erasure, multi-claim/replay composition, concrete 128-bit resources, and hypothetical Bitcoin P2MR/native SLH-DSA deployment. No production/graph changes. Do not disable the research automation.
