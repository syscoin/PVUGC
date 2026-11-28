# R200 — BIP141 mined-assertion identity required by the public challenge relation

**Research-only source-binding lemma; NOT a secure hash-based witness-KEM, Build/Open, or QPT security proof.** This work extends the conditional R191 witness-only activation design. It must not be reported as a key-release advance.

## Continuity and actual work

Existing syscoin/PVUGC PR #1 branch research/pq-wkem-validation-20260918, observed head 92473aecc81006b87e1901b344484ed75acfcf6b. Exact R199 research read at blob 18b97d943322060277bc7b70e0f422c0bd30cac4 and relevant R198 predecessor; recent ordinary comments since 2026-11-10T06:00Z returned none. Intermediate hypothesis checkpoint committed first at 0c09fe361edc2ae8bc3dd586a10332877d99374a, parent 92473ae. No external web/literature, real BTC/SYS mining or chain validation, production write, independent agent, native signature or quantum test.

Full local checker SHA256 aec64784eea26ac4443f7095892f68b45fd3665f96ae917c89e0b640722c090c, local captured output SHA256 5443907b5549c744015718478f3debe369111c1e066fde9ea77d87090bd0596f. Local Python checker executed twice with identical output: 833 functional assertions on 64 paired witness-only assertions. An initial test expecting 64 distinct cancel outpoints failed because ALL different assertions intentionally share the exact same stripped txid; the test was corrected to require one outpoint, then rerun and recorded. These local full bytes are LOCAL ONLY.

The separately published reduced Python checker was actually executed twice with byte-identical output, 193 functional assertions. Exact checker source SHA256 6f8abe7737e7b70207decf54b6582fc8c2b95761da90b31221de4ed7a64f0aa1 (Git blob 7afe7e3b1449e2989b70ba65e14f998b0640f272). Captured output SHA256 4ee2429d344cac989f5fdf9ddf12cd610b27be6d5cd170b5dd5ddd9bc5cd5110 (Git blob e2b1cd1c5ffab046d4b68f81e4864399c4c8cdc3). These use synthetic witness assertions, not valid notary signatures or mined Bitcoin blocks. No WKEM code or QPT adversary was run.

## Same txid does not identify later assertion

For a fixed stripped SegWit transaction T and different later one-notary assertions A and B placed solely in witness bytes:

    txid(T,A) = SHA256d(SerializeStripped(T)) = txid(T,B) = u,
    wtxid(T,A) = SHA256d(SerializeWithWitness(T,A)) = v_A,
    wtxid(T,B) = SHA256d(SerializeWithWitness(T,B)) = v_B.

A frozen N-of-N cancel signature can spend the same (u,index), independently of A or B. This is the useful conditional feature of R191, not inherently a vulnerability. But a purported source-conditioned key release examining only u cannot determine the actually mined assertion. Across the 64 local pairs all 128 assertion encodings shared the same outpoint, while the variant wtxids, witness commitment, coinbase txid, block ordinary Merkle root and unmined block-header digest differed.

The BIP141 witness Merkle root includes zero as the coinbase witness leaf. The coinbase commitment is SHA256d(witness_root || witness_reserved_value), committed in a coinbase output, whose ordinary txid enters the Bitcoin header's transaction Merkle root. A complete validated proof can bind A to a specific mined Bitcoin block: include raw witness serialization, activation txid/wtxid paths, full coinbase and reserved value, and authenticated header chain. The block's real PoW, difficulty and anchor/window admission, plus actual native one-notary signature and assertion semantics, are additional checks. BIP141 does NOT give finality or select which of two competing Bitcoin branches contains the authoritative activation.

## Two-world necessity lemma

Consider two hypothetical accepted histories with the same stripped T and different mined assertions A,B, such that Fault(A,Q)=true but Fault(B,Q)=false for a proposed source challenge Q. Any deterministic release decision using ONLY (u,Q) receives identical inputs in those two worlds and cannot be both correct for the fault and sound for the nonfault. Thus witness-specific *authenticated mined activation identity* is a necessary input to the ORIGINAL challenge relation when witness-only activations are allowed. This is an elementary functional observation, NOT a cryptographic impossibility result. A real release circuit may use full authenticated evidence; the missing algorithm must protect the secret even when all its public code is inspected.

## Explicit template-scoped ORIGINAL relation

When the N-of-N setup freezes the cancellation signature BEFORE one notary chooses witness assertion A, Build cannot silently assume a future fixed claim x_W. Let x_T bind the vault/cancel outpoint, native cancellation VK and exact message/path, authorized activation template, capsule IDs, participant manifests, BTC/SYS anchors and observation/reset policy.

    R_T(x_T,w) =
      BTCAdmit(header path, anchor, relevant window)
      AND VerifyBIP141WitnessCommitment(A,coinbase,reserved,
                                         txid Merkle,wtxid Merkle,header)
      AND txid(Stripped(A)) = x_T.bound_txid
      AND VerifyAuthorizedNotaryActivation(A, x_T)
      AND UniqueAdmissibleActivation(A, x_T, reorg/reset policy)
      AND ( GreaterRelevantBTCWork(A,w)
         OR MissingOrInvalidAuthorizedPoB(A,w)
         OR QualifiedSyscoinPrefixForkOrTagFault(A,w) ).

The BTCAdmit and UniqueAdmissibleActivation terms are concrete necessary *verification obligations*, not magically implemented Boolean oracles. Bitcoin witness inclusion alone cannot decide a reorg/censorship policy. The three branches must bind actual original burn/amount/recipient/reserve, BTC chainwork/anchors, SYS pure-child ancestry, Nexus tag semantics, interval rules and required fork depth. Different parent-work wrappers for the SAME child are not forks. Malformed-tag faults must authenticate their outer carrier without assuming the disputed tag passes. No stronger SYS-work requirement is imposed for the inconsistent-tag veto.

Build before activation thus needs an **activation-universal** ORIGINAL relation over all allowed later mined assertions A, if no online N-of-N return is permitted. Preselecting A at setup is a valid alternative but restricts later one-notary freedom. The output can be one vault-slot/path-scoped safe cancellation package, not an unrestricted signing key.

## Conditional explicit classical evidence-binding reduction

If two different raw witness assertions supposedly occupy the same accepted wtxid position in the same authenticated Bitcoin block, and the complete witness/Merkle/coinbase contexts verify to one committed root, they imply either equal wtxids for different encodings or two different internal Merkle hash inputs with identical outputs. A classical extractor walks the supplied explicit Merkle paths and finds the SHA256d collision. This is straight-line on TWO classical certificate outputs, NOT a quantum extraction of an arbitrary cancellation-key recovery algorithm. Full source authenticity and header admission remain required. A 256-bit output hash has generic quantum collision-search costs on the order of 2^(256/3) oracle queries in suitable coherent-access models; one cannot automatically claim 128-bit concrete QPT collision-binding from the phrase SHA256 collision resistance. This is a security-margin caveat, NOT a claim of actual Bitcoin/SHA forgery.

## Failed concrete public release formula

Try freezing native cancel signature sigma with

    Build(A0): E = sigma XOR SHA256d("R200/pad" || wtxid(A0)).
    Open(A):   sigma_A = E XOR SHA256d("R200/pad" || wtxid(A)).

The bounded checker shows an authorized future A != A0 normally gives a different sigma_A, breaking SAME-output completeness. Worse, wtxid(A0) and E are public, so the original sigma opens BEFORE any qualified BTC-work/PoB/SYS fault. The shared stripped txid is no better because it is public. Putting an honest source verifier before this XOR does not prevent raw evaluation; a table over all future witness identities is not a PPT compiler. No source-correlated hidden unlocking input has been created by this construction.

## Exact remaining gap

Construct classical PPT hash-only Build_T(x_T,sigma) before witness-only activation, and public Open_T(C,w)=SAME precommitted safe cancellation capability from EVERY admitted mined A and EVERY qualifying ORIGINAL challenge. Prove arbitrary full-public nonuniform QPT recovery/native forgery, with corrupted setup coins, auxiliary information, related capsules and coherent hash queries, yields actual ORIGINAL evidence or independently justified QPT hash/native break. Honest erasure and N-of-N graph constraints remain separate, and neither genuine source inclusion nor source collision resistance supplies the secret-release gate. No online authority, invented source label or Bitcoin general verifier may substitute for it.

**No qualifying cryptographic result or ordinary PR progress comment; continuing task remains enabled.**
