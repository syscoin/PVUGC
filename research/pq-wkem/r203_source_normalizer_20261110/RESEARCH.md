# R203 — MASH: Merkle-Anchored Source Hash normalizer

**Classification:** Restrained hash-only construction attempt; an exact, reusable Merkle-membership common-pad lemma was established, but it fails to implement the ORIGINAL authenticated Bitcoin/Syscoin challenge relation. It is **not** a witness-KEM, not a false-instance or hard-TRUE security proof, and not a deployed source protocol. No qualifying bridge breakthrough.

## Provenance and continuity

Interactive source branch: `syscoin/PVUGC` PR #1, `research/pq-wkem-validation-20260918`. Starting head `7b159e6dad80fdc477504ca74eaf1e9ea445b74d`; last research R202 in `r202_work_factor_gate_20261110/RESEARCH.md`, blob `248a4b1d48e51907a6af873bcad92221a0004f8b`. Latest ordinary PR issue comments since 2026-11-10T08:00Z: none. The intermediate `CHECKPOINT_01.md` was published at commit `72746016bd685e664b2dc2e45567a328f543928e` before these checks. No web search, literature, other repositories, independent agents, production changes or quantum simulation. This note includes exact executed standard-library Python regression source and JSON output in adjacent files; two local executions were byte-identical.

## Named original-dependent candidate

The genuine target is release of the same precommitted cancellation capability for any qualifying R1 Bitcoin work, R2 authenticated PoB fault, or R3 qualified Syscoin inconsistency/fault evidence, with one-notary withdrawal initiation, any-watcher challenge, N-of-N preauthorization, no online release actor and all source authentication inside release. The candidate tries to exploit a cryptographically authenticated Merkle source root instead of an independent puzzle.

Let an honest binary Merkle source tree of height at least 1 have public root `rho = H_node(L,R)` and private ordered root children `t=(L,R)`, with domain-separated SHA256 for leaves, nodes and pads. A valid leaf-membership witness `(index, leaf, siblings)` computes its own top child plus its sibling, producing a *candidate* ordered `t_w=(L_w,R_w)`, and checks `H_node(t_w)=rho`.

Honest source builder at setup possesses `t` and freezes a native claim/path-specific cancellation signature `sigma`. Construct:

    Build_MASH(x,rho,t,sigma):
        E = sigma XOR H_pad(x,L,R)
        publish C=(x,rho,E,checking data and intended native VK)

    Open_MASH(C,w):
        (L_w,R_w) = RecoverRootChildren(w)
        require H_node(L_w,R_w) == rho
        return E XOR H_pad(x,L_w,R_w)

The plaintext leaf/entire source tree is NOT claimed confidential in Bitcoin or Syscoin. That question is the point of this test.

### Exact functional lemma for the restricted membership relation

For any two accepted membership witnesses `w1,w2` against the same fixed root, if their extracted ordered root children differ, the witnesses themselves exhibit a collision for `H_node`:

    (L_1,R_1) != (L_2,R_2),
    H_node(L_1,R_1) = H_node(L_2,R_2) = rho.

Therefore, assuming no such collision, *every* valid member opening has the exact same `(L,R)` and yields the same precommitted `sigma`. This is a simple deterministic collision-extraction statement, not a QPT reduction from arbitrary key recovery. Its premise is independently checkable cryptographic collision resistance, rather than an assumption that already promises key release. It also does not guarantee all ORIGINAL fault witnesses carry a membership proof for this same source tree.

Unlike R202's publicly known work-range normalization, the pair `(L,R)` need not be readily computed from `rho` alone when the tree is hidden. Thus a public fake digest such as `y=0` does not automatically reproduce the pad. **This only fixes a narrow shared-output correctness issue for private Merkle membership.**

### The decisive failure for actual source evidence

1. The builder/source actor that created the tree necessarily knew `(L,R)` before any fork or PoB fault. A corrupt source/builder retaining them computes `sigma=E XOR H_pad(x,L,R)` immediately. N-of-N honest erasure can protect a separate honestly generated share, but does not force genuine future Bitcoin/Syscoin evidence to carry its hidden opening.
2. **Any** authenticated membership proof for that root reveals both top child hashes, regardless of what leaf or event it proves. A routine, valid, non-challenge inclusion proof decrypts `E`; no fork, heavier competing Bitcoin chain or PoB fault is needed. When source blocks/transactions are publicly available, a watcher can simply reconstruct the root children without a challenge. The source graph's public root cannot by itself distinguish a fault proof from an ordinary member proof.
3. An attempted two-history pad `H_pad(x,t_A,t_B)` avoids the one-tree early leak only if B is unknown, but setup cannot precompute a fixed encryption pad before that future fork root exists. Choosing a guessed alternate root B1 fails same-capability correctness for a different genuine B2. R1/R2/R3 need not even have a common second history. This is not fixed by asking for a second input in the honest Open wrapper: an attacker may run the raw pad computation.
4. Requiring two distinct leaf *preimages* from opposite branches would amount to a source-coordinated two-opening carrier. It needs the actual Bitcoin/Syscoin source to deliver hidden committed preimages only upon a qualifying fault, while dishonest source owners must not retain both before the event. No such consensus source-to-hidden-opening compiler exists in this proposal. Simply adding both labels to a notary's private source key is the known retained-label failure of R173, not a repair.

A native signature verifier or a post-hoc `CheckRealAuxPoW` inside Open does not save the raw public pad; the adversary can derive it from available root children without invoking Open. The proof target is unauthorized arbitrary recovery from the full public capsule, sibling capsules, source history and setup coins, not just honesty of Open.

## Tests actually run

`checker.py` is a 4-leaf (depth-2) SHA256-domain-separated toy Merkle fixture. Across 64 deterministic seeds it confirms all four authentic leaf openings yield the same secret, forged leaves/siblings fail root authentication, a nonfault first membership proof opens early, a retaining builder opens early, a publicly root-normalized pad is computable immediately, different source roots change keys, and two distinct hypothetical future fork roots cause incompatible joint masks. No proof of Bitcoin/Syscoin work, Merkle+coinbase AuxPoW inclusion, best-chain membership, full tag history, original source relation, native signature, or quantum security is implemented. QPT collision resistance is an independent premise only; toy regressions do not test it.

`checker.py`: SHA-256 of tested bytes `b4ead42d7de510c568f112114caceb1236c48528254a382c73369de83d766d6a`.
`captured.json` and byte-identical `rerun.json`: SHA-256 `7d47275508ac797f4f3cb0147d9138e8facbcf9dc632f707016a378dddbd20b2`.
1,152 functional assertions, no security-experiment count. The counterexamples are unconditional on SHA hardness for the stated source-known/public-proof cases.

## Exact remaining equation and next experiment

Construct a **polynomial, source-anchored** `Build_inc(x_W,sigma_cancel)` whose capsule is assembled before future qualified source proofs, and a public `Open_inc(C,w)` recovering the *same* sigma for every ORIGINAL R1/R2/R3 witness. Any public source proof exposing a common recovery pad must be *inaccessible* in all non-challenge public source histories, while setup/source actors that could retain coins must not thereby acquire that pad. No actual source mechanism satisfying both is furnished here. An anchor or Merkle root alone authenticates bytes but cannot force this selective exposure.

A next candidate would need a source-driven selective opening obtained from the actual SHA/AuxPoW computation without requiring an online signer or miner-provided invented labels. It must be specified together with the full-public QPT simulator/extractor before any optimization or native endpoint claim. R203 leaves this missing, and the automation should remain enabled. No ordinary PR progress comment is warranted.
