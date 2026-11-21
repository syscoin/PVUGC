# R56 — BRANCH-OR-SAME-SEED: multi-ORIGINAL release with a full-joint same-secret certified-FALSE simulator

**Run:** R56-BRANCH-OR-SAME-SEED-20261104. **Classification:** a restricted new release/composition result, NOT a generic PQ WKEM and NOT a hard-TRUE secrecy/extraction proof. The significant change over R55 is that many separately compiled ORIGINAL branches may encrypt the SAME precommitted capability; the certified-FALSE joint-view simulator now permits their same-secret correlations, correlated noises and selected noise disclosure, with no additional LWE-security hybrid per branch. It does not establish any hard-TRUE secrecy, arbitrary-FALSE secrecy, or a route from arbitrary accepted native forgery to an ACTUAL ORIGINAL witness.

## Verified continuity and scope

Before research, syscoin/PVUGC PR #1 was checked open/draft/unmerged, head branch `research/pq-wkem-validation-20260918` at `e727041742f87e4ed65db1d36ff840cc537e3ca5`. Latest substantive ordinary PR comment: `6623647233`. Exact-version R55 blobs read: `RESEARCH.md` SHA `82070908785dad84f3598ab26b270b3b71d44747` and `CHECKER.js` SHA `e1582678f76c0fc773f9395ea177bc7a003eced0`. Exact R54 note: `b93bbeb71ee065b9e5db28c816701339d0690d34`. No PR-wide diff, external literature/site, unrelated repository, historical replay or independent agent.

## A concrete BuildOR / OpenOR release

Fix an ordered, bounded polynomial-size manifest M listing B permissible **genuine ORIGINAL** relations R_j(x_j,w_j), original verifier IDs, evidence/authorization requirements, common claim/UTXO, source branch and header/auxiliary-PoW/coinbase-tag/ancestor-window/lag/direction/outputs, release version, data-availability conditions, intended fixed native verification key `vk` and bound native challenge message `m*(M,vk)`, plus native preauthorization graph/timeout/challenge paths. **OR is intentional and must be explicitly authorized**: the holder may release if *some* listed ORIGINAL branch has a valid witness. The design cannot add a weaker branch to an existing stricter claim. The manifest/order must be bound by the permitted preauthorization ceremony; a SHA hash alone does not prove malicious N-of-N graph safety.

Use the R54/R55 classical source compiler for each R_j: Boolean quotient coefficient space `F_q^M_j`, genuine clause-failure polynomials f_i, public mask space
`W_j = span{f_i f_k : i <= k} + span{ z_S f_i : |S| <= 2 }`,
public canonical quotient map `P_j` with ker `W_j` and public section `S_j`. Explicit coefficient dimension `M_j` may be exponential in the ORIGINAL NP verifier's Boolean variables; arbitrary-NP polynomial-size compilation is NOT established.

Before irreversible funding, the honest authorization parties must already have produced and safely stored the exact target-path native presignature `sigma* = Sign(sk_N, m*(M,vk))` under the *separately conditional* one-honest-N-of-N graph/preauthorization/erasure model. Choose one shared secret byte string `T = Encode(r0,s,e,K_bind)` carrying the R52 LWE-tree matrix seed, pad secret/error and independently chosen CK seed, and produce `A(r0)` with public matrix/commitment `A0, alpha`. Mask the precommitted native signature by the R52 pad `Y = A(r0)s + e` (in its separately stated power-of-two LWE modulus), publishing `D = Encode(sigma*) XOR Encode(Y)`. No signature, target-opening secret or source witness is published.

For each branch j and byte t choose bounded centered coefficient error `eta_{j,t}`, independently of unknown target LWE secrets/signing secret (the errors may be arbitrarily correlated **across** branch capsules if the entire joint noise tape is challenge-independently samplable). Publish:

`Z_{j,t} = P_j(Delta*T[t]*1 + eta_{j,t})`

with SOURCE field `q_s = 16,777,259`, `Delta = 65,536`, each `T[t] in {0,...,255}`, and canonical fixed-length field encoding. The circular code distance is `min(Delta, q_s-255Delta) = 65,536`. Require this to exceed `2 M_max B_err` for absolute bound B_err on every coefficient error.

**OpenOR(j,w_j)** first checks `R_j(x_j,w_j)=1` using the *actual ORIGINAL verifier OFF CHAIN*. It evaluates `Ev_{w_j}(S_j(Z_{j,t}))` and nearest-codepoint decodes T. Since `Ev_{w_j}(W_j)=0`, for every genuine valid ORIGINAL w_j:

`Ev_{w_j}(S_j(Z_{j,t})) = Delta*T[t] + Ev_{w_j}(eta_{j,t}) (mod q_s)`,
`|Ev_{w_j}(eta_{j,t})| <= M_j B_err`.

Every valid witness, including witnesses across entirely different branches with different internal states, therefore obtains the SAME original T, A(r0), LWE pad, CK seed and exact Build-presigned sigma*. OpenOR checks scope-bound alpha, CK, Aux and `Verify_native(vk,m*,sigma*)`, then returns only sigma* as the public off-chain capability. Bitcoin executes no ORIGINAL NP verifier, general proof, VM, LWE check, BitVM disputes or SHA trace; BitVM is only conditional covenant-emulation plumbing. A future native SLH-like signature and no-EC-key-path output are CONDITIONAL, not deployed.

Define a versioned checking tag over canonical *ordered* public data:
`CK = F(K_bind, "R56-CK", M, vk, m*, A0, alpha, D, Z_all, related_public, context)`,
and `Aux = AuxAlg(K_bind, CK, M, Z_all, related_public, context; independent_aux_coins)`.
F genuinely depends on K_bind and must be instantiated with separately justified QPT binding security if adversarial rebinding matters. For tests, only, we used Node SHA3-256, without claiming concrete QPT binding strength. Aux must not reveal the challenged target LWE seed or native signature and must be challenge-simulatable from the stated public fields plus independently known K_bind. A purportedly valid target-related TRUE opened capsule sharing T is expressly **not** simulated here.

## Proved exact joint simulation (the new component)

Take a precommitted polynomial-size batch of B target branches, ALL of which have publicly checkable `P_j(1)=0` in every hybrid-consistent source context. The SAME hidden T is encrypted by every branch, and the vector of all joint errors `E=(eta_{j,t})` may have any classically PPT-samplable correlation, including literal reuse across distinct branch statements, provided the simulator can generate E given public context without the challenged target LWE/signature secrets. For every possible T and E:

`P_j(Delta*T[t]*1 + eta_{j,t}) = P_j(eta_{j,t})`.

This pointwise equality holds for **every** j,t simultaneously. Hence one straight-line simulator, given the real challenged public matrix/commitment, D, vk and context, and knowing independently sampled K_bind, samples E once, outputs the **exact full set** `Z_{j,t}=P_j(eta_{j,t})`, then computes the genuinely K_bind-dependent CK and allowed auxiliary records. Even if `P_j` depends on public alpha or D, it is still efficiently computed from those supplied values: we require only conditional challenge simulability of the coefficients, **not** unconditional independence of the *whole* public view from the target seed.

An arbitrary QPT adversary may adaptively choose which **preauthorized** branch source records to reveal after inspecting previous public records (including CK and D); the simulator reveals consistent entries from that same sampled table. It may disclose any specified selection of the source noise tapes themselves, because those were chosen without the target challenge secret. Legitimate permitted unrelated opening queries must be independently seeded and fully simulatable with known coins/witnesses. No unrestricted target plaintext opening, target-secret-dependent noise oracle, shared-secret TRUE related opening, challenge-dependent quantum advice, or malicious branch insertion is permitted. Coherent/joint QPT processing of an identical classical public and opening distribution, with separately preparable challenge-independent quantum advice, changes nothing; no quantum rewinding, random-oracle programming, supplied internal representation or SourceOpen oracle occurs.

After this exact coupling, the original **restricted**, predesignated unopened certified-FALSE R52 QPT hybrids are available: honest uniform shared A0, the explicitly specified LWE node/secret/error distributions, quantum decisional LWE for the tree and final pad, distinct native target message with QPT EUF-CMA, and all context/certificate predicates invariant through the challenge. The same final bound, NOT multiplied by B, holds:

`Pr[A_QPT obtains an accepted target native signature] <= (2^d-1) Adv_QPT-DLWE_tree + Adv_QPT-DLWE_pad + Adv_QPT-EUF-CMA_native + negligible.`

Adversarial rebinding requires a separate QPT hash/commitment binding term; this theorem does not infer binding from a toy hash output. This is a **restricted all-certified-FALSE full-JOINT-view extension** to shared-source, noise-correlated, adaptively presented branches. Mixed hard-TRUE/FALSE cases, arbitrary-FALSE, hostile signer/setup, ciphertext-dependent side information outside the simulator and true-target accepted native forgery -> ORIGINAL extraction are NOT covered. The theorem does not promote a marginal pad-hiding result to unsupported general security.

## Exact bounded execution and reproducibility

`CHECKER.js` is the **exact locally executed** Node.js v22.16.0 checker; `OUTPUT.json` is its verbatim captured output. Run: `node CHECKER.js`. Repeated execution produced identical output. It builds actual 4-variable Boolean-quotient failure spaces and public RREF projections, not just symbolic fake probabilities. Two distinct genuine TRUE 3CNF source branches, one constraining bit 0 and one bit 1, each have 8 valid ORIGINAL witnesses; each decodes all 256 possible shared secret bytes (4,096 genuine openings across both branches). Three different genuine contradictory 3CNF source branches have mask rank 14/16, NONZERO quotient dimension 2, no valid witnesses, and public `P_j(1)=0`.

For 256 trials and two DIFFERENT 12-byte hidden target-secret ensembles, the checker reuses the same noise coefficients ACROSS all three FALSE branches and shows every byte capsule matches exactly. It additionally checks complete secret-K_bind-dependent SHA3-256 CK/Aux transcripts under an adaptive reveal schedule, with selected noise tapes revealed, exactly couple. Negative controls prove that one TRUE source invalidates the all-FALSE source-simulator identity and that reordering the branch list changes the CK. **8,718 assertions passed, twice identically**. Toy execution does not test QPT LWE/PRG/native EUF-CMA/hash resistance or 128-bit parameters, and is not evidence of hard-TRUE security. No independent agent or external online research was used.

## Exact missing central equation and preservation boundary

The indispensable theorem still unproved, for the complete actual hard-TRUE ORIGINAL public view `V=(R,x,Z_target,Z_same_secret_related,CK,Aux,context,A0,alpha,D,vk,openings)`, is:

`Pr[A_QPT(V) recovers bound capability or obtains accepted native forgery] <= Pr[Ext^A outputs ACTUAL ORIGINAL w with R_ORIGINAL(x,w)=1] + Adv_QPT(independently justified explicit primitive break) + negl(lambda).`

The extractor must not require A to volunteer a dual, local representation, witness-derived state or intermediate SHA trace. Also unresolved: arbitrary-FALSE security, malicious one-honest-N-of-N graph composition, abort/useful completeness and prior DA, timely admissible challenge inclusion under realistic BTC censorship, keyless Build with retention of all builder coins, 128-bit practical quantum parameter selection, and the undeployed conditional Bitcoin-native PQ endpoint. Earlier ghost-dual/pseudoevaluation and failed affine/LWE joins remain adversarial tests. **Do not disable the existing research automation.**
