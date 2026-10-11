# Run 410 — ciphertext-only public release cannot output an ordinary native signature

**Scope:** a new sharply limited TRUE-instance impossibility statement for a PKE/FHE-only attempted witness-KEM. NOT a generic impossibility for local mixing, iO, RIO, WE, public witness admission, or a real Bitcoin/PQ system. The exact extended proof is preserved separately. No production changes.

Live starting state: syscoin/PVUGC#1, draft/unmerged branch research/pq-wkem-validation-20260918, SHA 2a745f9035f1f5e8412b686426ea98b0a4a086b4; latest substantive PR comment 6067040320. Exact dependencies read: Run405 blob 314686b02acec45f57cc21acee677dea61b41b89, Run406 blob cb5ec5144694669d7134d3759a18972745e1530f, Run409 blob 7fb3310e3a808aea4b523211c2f9ed242fbc8c46, Run259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2.

## The exact candidate class

Take a known-valid (x,w), publicly generatable without the native signing secret sk (for a universal NP compiler use the relation R=1 and w=0). Honest native KeyGen outputs (sk,vk). Independently generate a public encryption/evaluation package epub whose IND-CPA game includes all public evaluation keys, even ones correlated with the **encryption** secret key. Publish vk, simulatable public context Aux(epub,vk,x), and a polynomial number t of independent encryptions c_i=Enc_epub(F_i(sk,vk,x)), where all F_i are efficiently computable given sk. Every other public object is obtained from these ciphertexts and public parameters by PPT processing, possibly involving arbitrary FHE evaluation, encryption of a later witness chosen by an attacker, rerandomization, and many chosen-input queries. No other published object depends on native sk except through vk and these ciphertexts. No native signing or decryption oracle exists. In particular, a separately correlated protected release program is OUTSIDE this premise.

All public classical programs are available as quantum-coherent computations to the arbitrary QPT attacker, under the same exact IND-CPA model. All additional quantum advice must be generatable from the simulated public view without secret signing-state entanglement. The theorem does not cover arbitrary secret-dependent setup advice, correlated ciphertext randomness outside multi-message IND-CPA, malicious N-of-N setup, or multiple native keys.

## Theorem (QPT, straight line)

Assume honest classical PPT setup; QPT IND-CPA security of the COMPLETE public encryption/evaluation package; and QPT EUF-CMA native signature security for a fresh output-bound message M(x). If arbitrary QPT A, given the complete ciphertext-only package and the known-valid w, outputs a valid native signature for M(x) with probability p, then straight-line QPT algorithms B_i and F exist such that

p <= SUM_{i=1}^t Adv_QPT_INDCPA(B_i) + Adv_QPT_EUF-CMA(F) + eps_sim.

Proof: For i=1..t replace ciphertext c_i=Enc(F_i(sk,vk,x)) with Enc(0^{|F_i|}), preserving the SAME native vk in every hybrid. An IND-CPA reduction receives epub, generates (sk,vk) itself, computes all F_j(sk), produces other real or zero encryptions, and uses its IND-CPA challenge for the i-th ciphertext. It invokes A only once and distinguishes by verifying the returned native signature under vk. In the final all-zero world an EUF-CMA reduction receives native vk, generates epub, all zero ciphertexts and Aux(epub,vk,x), then forwards any fresh accepted signature from A as a native forgery. It never requests signatures. Triangle inequality gives the displayed bound. All reductions are straight-line QPT, without rewinding or QROM programming. Public native checking-key correlation is RETAINED, not artificially removed.

Therefore, for a publicly known valid witness and negligible IND-CPA/EUF advantages, this entire ciphertext-only class cannot implement successful native-capability release. This formalizes why public (even FHE) insertion of a newly discovered witness into a ciphertext carrying hidden sk is insufficient to produce a usable native signature. A real mixer needs additional, precisely specified source-dependent cryptographic correlation outside this premise. This is NOT an assumption that such a mixer already exists.

## Attack / applicability ledger

(1) Public seam manipulation is covered by public postprocessing; a secret-correlated helper is not. (2) Public gauge changes cannot escape IND-CPA data-processing closure. (3) Native-secret-dependent program fingerprints are excluded and need independent audit. (4) Independently encrypted polynomially many functions of sk are covered by t hybrids; shared coins/key reuse across UTXOs are not. (5) Arbitrary chosen watcher ciphertexts/evaluator calls are available to A. (6) Malicious ceremony, retained native sk, setup abort, erasure and presignature graph are unproved. (7) M(x) requires exact relation, claim, UTXO, branch, anchor/window and output-binding. (8) vk correlation is explicitly preserved throughout the proof. (9) No quantum-specific attack algorithm is constructed; QPT security only follows *conditionally* from the assumptions in the theorem.

Necessity of Aux simulation is real: if a setup participant publicly includes a valid challenge signature as auxiliary data, the signature is already available. This does not violate ordinary PKE IND-CPA or fresh-message EUF-CMA: the message was signed during setup, so it is not fresh. Such auxiliary material is outside the theorem. The genuine N-of-N ceremony and pre-signed graph therefore require separate review.

## Exact bounded validation

The executed Python checker reports 41,004 assertions. It checks 13,310 tiny ElGamal (p=23, q=11) public witness-ciphertext insertion/cancellation cases, and exact toy pad-hybrid distributions with an auxiliary public key that leaks one secret bit. These are ONLY finite arithmetic and probability checks. Tiny ElGamal is not post-quantum; the ideal pad is not a PKE. Neither tests nor the conditional hybrid supply a practical WE, release mixer, 128-bit parameter set, native SLH signature or QPT cryptanalytic experiment.

## Handoff and literature scope

The distinction from Run405 is TRUE-instance correctness (not false-instance WE signing safety). The distinction from Run406 is a formal PKE/FHE-only lower boundary retaining the real native vk and polynomially many related ciphertexts (not a generic FE assumption). Run259 applies only after an accepted complete ORIGINAL representation is actually supplied; no recovery-to-representation arrow is established here.

The CRYPTO 2026 Canetti–Luo–Zhang functional/controlled-homomorphism construction (DOI 10.1007/978-3-032-35367-2_18) and TCC 2024 Canetti–Chamon–Mucciolo–Ruckenstein RIO/local-mixing work (DOI 10.1007/978-3-031-78023-3_2) may provide additional correlated release primitives. This result neither audits their full proofs nor refutes them. A next useful constructive pass must specify an actual protected source-dependent release helper with independently justified QPT assumptions and aggressively test all joint views.

Unproved: a concrete minimal secure mixer, all-witness SAME sk, full-public false-instance QPT hiding, early unauthorized recovery/accepted forgery to ORIGINAL witness or independent hard break, malicious one-honest N-of-N setup, cross-claim composition, realistic resources, and conditional P2MR/native SLH Bitcoin endpoint. PR draft/unmerged; production unchanged.
