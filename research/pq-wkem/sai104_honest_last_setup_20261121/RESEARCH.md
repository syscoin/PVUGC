# SAI104 — one-honest setup coins and the all-witness correctness quantifier (RESTRICTED; NO ORIGINAL WKEM)

## Exact continuity and problem selected
At this execution's live read, syscoin/PVUGC PR #1 was open/draft at \`5e386271f3276de165c35cf45375bf9fdf02ce36\` on \`research/pq-wkem-validation-20260918\` (SAI103); no issue comments were returned by the scoped read since 2026-11-18 19:24 UTC. Core #609 PR metadata was read only; no Core code/test/network was run. The current path-capsule SAI103 compiles explicit enumerated DAGs, not the ORIGINAL Bitcoin/Syscoin relation; a polynomial graph that publicly decodes each accepting path into an original source certificate admits a polynomial BFS certificate search. Its missing implicit source-conditioned public edge-token compiler remains missing. The prior FE covenant analysis has no FE implementation and identified malicious setup/abort/useful-completeness as a separate boundary.

This iteration investigates a specific indispensable *malicious setup* security component, not another hash-pad/affine/group carrier. It attempts to prevent N-1 malicious setup parties from selecting FE random coins specifically to make their otherwise correctly proven capsules unusable after a valid challenge. The resulting lemma is conditional on a still-unconstructed FE compiler and does NOT reduce the ORIGINAL source-release obligation. It is recorded as a regression and next-interface requirement, not a breakthrough.

## Candidate: privately committed tapes, public honest-last beacon, provable deterministic generation

Before any irreversible funding, fix a noncircular session \`sid\`, the source policy/relation version \`x\`, authorized native key set, claim/activation-graph class, and exact serialized algorithms. Every party i selects a private seed \`r_i\`, a native secret \`sk_i\`, and publishes binding commitments to this seed, its native public key, and the *entire agreed setup context*; no future capsule bytes are yet required. The honest participant keeps its private seed and signing key confidential. Other parties can know their own seeds and keys, but must bind them before the honest beacon is revealed.

After ALL such commitments, at least one honest party samples a fresh uniform \`b_h\` in {0,1}^k and supplies it as a public beacon b (or parties precommit beacon contributions and combine them by XOR, with at least one honest uniform share; omission/abort prevents funding). The attacker cannot select another \`r_i\`, \`sk_i\`, public key, policy or session ID after b, nor choose an alternate program if a seed is undesirable. For each party derive separate coin tapes

    rho_i=H("FE coins"||sid||i||r_i||b)
    rho_setup,i=H("setup"||rho_i), rho_enc,i=H("enc"||rho_i),
    rho_key,i=H("key"||rho_i), rho_proof,i=H("proof"||rho_i).

All relevant FE setup/encryption/keygen and native signing operations are deterministic given the committed private inputs and these tapes. A zero-knowledge proof of exact byte generation binds the commitment openings, coin derivation, honest/native verification keys, fixed session and source policy, ciphertext and function key, and any fixed safe signature (or the permitted dynamic signing circuit). A verifier rejects any unproven contribution before funding; complete capsule bytes and any required presignatures must be available first.

This does NOT assume a complete FE, merely specifies how to make *its* input randomness non-selective if it were built. Honest-only secret r_h is NOT revealed; publishing it would expose the honest deterministic FE secret tapes. A public beacon b on its own must never be used as the private FE secret key.

## Classical ideal-random-oracle timing lemma (NOT SHA or QPT security)

Assume an ideal H on domain-separated inputs, binding commitments, fixed parties/keys/context/algorithms before b, a truly fresh honest uniform k-bit b, and Q total pre-beacon classical H queries. For a particular already committed r_i, an adversary can previously query H at at most Q candidate beacon values. Thus it hits the future exact input ("FE coins",sid,i,r_i,b) with probability at most Q/2^k. Across N committed participants a union bound gives NQ/2^k (loose but sufficient). Otherwise each new domain-separated rho_i is independently uniform over H outputs at its first evaluation, including for maliciously selected (but precommitted) r_i. The adversary may know its own rho_i after b; it cannot retroactively choose it.

If an actual FE compiler had a uniformly bounded *simultaneous* all-witness useful-correctness error epsilon_all over these honest-distribution tapes for ANY fixed accepted key/policy, and the generation ZK is sound, then for one *unaborted* ceremony the bad-capsule risk from malicious bias is bounded by roughly

    Pr[bad acceptable ceremony] <= epsilon_all + NQ/2^k + eps_bind + eps_zk,

plus source/availability failures not modeled here. If the adversary can SELECTIVELY ABORT and retry A accepted-or-aborted ceremonies, the elementary union upper bound becomes A times that expression, even if each individual ceremony used fresh honest coins. A participant should refuse same-vault repeated setup retries beyond a documented budget; otherwise the adversary can cherry-pick a rare bad accepted session by aborting the others. Public sources controlled by the adversary (a mined beacon or candidate Bitcoin hash) are NOT a substitute for the honest unbiased beacon.

This is a *classical ideal-RO distributional lemma only*. A QPT adversary may query H coherently before b; the classical Q/2^k argument cannot be lifted verbatim. Any QROM or concrete-SHA instantiation requires separate proof. Also the conclusion does NOT say that a correctly generated capsule is safe: cryptographic FE correctness and security were assumed rather than constructed. A proof that coins were honestly derived only enforces generation; it cannot certify erased secrets or FE secrecy.

## A separate, decisive correctness quantifier

For the protocol, one valid ORIGINAL challenge must open **all** independently precommitted contributions for the same frozen native authorization class. Therefore the actual correctness property needed is simultaneous:

    Pr_{coins} [ for EVERY w with R_original(x,w)=1,
                  Open_i(C_i,w)=sigma_i ] >= 1-epsilon_all.

Do NOT replace it with the ordinary pointwise assertion

    for EVERY fixed w, Pr_{coins}[Open_i(C_i,w)=sigma_i] >= 1-epsilon_point.

These two quantifiers are not equivalent with an exponential witness space. Counterexample: take a toy relation accepting all n-bit witnesses, sample hidden z uniformly, and make an otherwise correctly generated capsule reject ONLY witness w=z. Each fixed w fails with probability 2^-n, yet EVERY capsule rejects some valid witness, so simultaneous correctness succeeds with probability zero. Worse, if a malicious source producer can find/choose the exceptional valid witness after setup, it can target the failure. The toy counterexample does not establish that any actual FE or ORIGINAL Syscoin relation has this defect. It proves that pointwise negligible correctness, setup tapes, and a correct-generation ZK proof do not logically imply the required all-witness guarantee.

A sufficiently strong FE all-input correctness theorem, or a proof of deterministic correct evaluation for all accepted parameters/coins, is necessary. A naive union bound over 2^n possible ORIGINAL certificates would erase a merely 2^-n pointwise guarantee. An invalid/unopenable malicious capsule must not be silently accepted or leave a funded vault stuck. Pre-funding proofs and availability are necessary but not alone sufficient.

## Executed finite check and local-only artifacts
Two invocations of a Python 3 standard-library finite timing-game checker at \`/mnt/data/sai104_coin_ceremony/check.py\` produced byte-identical output. The checker fixes a 12-bit public beacon domain, committed seed 0x12345678, and intentionally defective toy generator which fails iff the first 4 SHA256-derived coin bits equal zero. Exhaustive enumeration gives 247 bad beacons out of 4096 (0.060302734375); a party seeing the beacon first finds a bad private seed among the first nine candidates. Pre-beacon fixed guesses hit with exactly Q/4096 for Q in {1,4,32,256}, and the A-attempt risk is explicitly union bounded. These numerical results are illustrative SHA256 toy observations, **not** an ideal-RO proof or a real FE failure rate.

A second \`quantifier_check.py\` exhaustively verifies the n=10 all-accepted toy: pointwise failure 1/1024 while every capsule has exactly one bad valid witness. The first checker/output SHA256 are respectively d31df46351ef65612dd5826818c9d15684eba40f03f81c8c4aa00813e3fe7df4 and c7744002e27bcb27cea22a9fb59b8a9142e48363216e9459f0e042d1bff21126; second checker/output SHA256 respectively ada958835473d4c791f837048b3f41fb4beacc87d35af0b1817c95524522dc15 and 122f29a92a780053922c4283e09459aa0559753e1420b15b9e8c456874fed3b3. The complete checkers and outputs remain **local only**. These tests did not run FE, a source verifier, a Bitcoin signature, Core tests, quantum attacks or a native Bitcoin VM.

## Disposition and the ORIGINAL obstacle
The honest-beacon construction is a source-independent malicious-coin *setup* subcomponent. It has not been coupled to an independent FE source-release compiler. **NONQUALIFYING:** no classical-PPT public \`Build_original(x,sigma)->C\` and \`Open_original(C,w)=sigma\` for every qualifying ORIGINAL Bitcoin/Syscoin three-branch certificate; no FALSE/hard-TRUE joint-public QPT extraction; no native-forgery/one-honest full graph proof; no applicable source mining-work theorem. The required OR relation, contextual strict modern AuxPoW/tag rules, actual ancestry conflict and LC depth, finite burn fault, same-anchor strictly greater Bitcoin work, deadlines and safe claim-scoped native message all remain unchanged. No extra ChainLock/second notary/greater Syscoin work may be imposed.

The next critical equation still is a *serialized PUBLIC* source-dependent FE-like gate whose one honest component has all-witness correctness under malicious setup and is jointly simulatable with native VK, source coins, proofs and sibling capsules. A randomized coin ceremony does not construct that gate. Reject any future attempt to promote this conditional subcomponent to an ORIGINAL WKEM advance. No PR progress comment, production modification, deployment, network activation, or scheduled-task change.
