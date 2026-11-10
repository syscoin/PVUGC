# R188 — Affine source-share normalization, but no source-dependent key release

**Classification: incomplete candidate, NOT a secure hash-only witness-KEM or reportable cryptographic breakthrough.** The algebra below is real and independently checked, but the essential public BuildSourceShare/OpenSourceShare mechanism from ORIGINAL authenticated Bitcoin/Syscoin evidence is missing. No QPT security argument or native cancellation signature was constructed.

## Continuity and provenance

Repository syscoin/PVUGC, draft/open/unmerged PR #1, existing branch research/pq-wkem-validation-20260918. Observed starting head 7b7fb024e36b2977a696272d792f09e31e917d9e. Read only R187 at research/pq-wkem/r187_merkle_unique_open_20261110/RESEARCH.md, blob 3d0808d4882ea00aa37ba9bb0d772e01f36cf7c4, and recent relevant PR issue comments on R176/R177. Intermediate hypothesis checkpoint was published **before** executing any new checker at commit 321633883ee06cd3be9cb39b75f7ec856dad10bf. No external web/literature, unrelated repository, native signing, real source parser, quantum experiment, or independent agent.

The user-approved bridge continues to require one-of-N notary withdrawal activation, anyone-can-challenge with no later release authority, and N-of-N preauthorization with one honest protected/erasing participant. The three independent source grounds R1 (higher-work competing Bitcoin branch), R2 (incorrect/absent authorized burn in the bound source state), R3 (qualified Syscoin AuxPoW tag/fork inconsistency) form an OR for the SAME claim/path-specific cancellation authorization. This experiment concerns the R3 claim-prefix subrelation only. It does not solve R1 or R2 and cannot substitute for source validation.

## Proposed FSP-2 hash-only source normalization

Freeze the actual withdrawal claim/UTXO, authorized burn identity, amount, output, source observation window and BTC anchor, qualified baseline A, source-prefix height h_rel, required LC fork depth, tag schedule and lag checks, exact native cancellation message/VK and capsule ID before the relevant challenge. Full original source qualification must authenticate the candidate child history through its real AuxPoW parent work, complete coinbase, parsing, all relevant tags, Bitcoin header anchoring, child height and ancestry, allowed window and descendant depth. No hand-waved qualified flag is a cryptographic input to release.

Define z(B) from the **pure Syscoin child-header identity at the FIXED claim-relevant height h_rel**, after authenticated ancestry to that height. Do not use the mutable Bitcoin parent WorkID as the semantic identity. An alternative parent-work certificate for the same child yields the same z. A fork which starts strictly after h_rel is deliberately outside this claim-prefix subrelation; a valid fork with first divergence d<=h_rel yields z(B)!=z(A), absent collision of different pure child headers. This is only a source semantic lemma, not authentication.

Let F be the prime field mod p=2^521-1, used for elementary arithmetic and **not** as a discrete-log group. Injectively encode a 256-bit child hash as z=1+uint256(hash), which lies in [1,2^256] inside F. Let z0 denote authenticated baseline A's value. For each honest N-of-N participant choose independent hidden K,a uniformly in F, and set

    f(z) = K + a*z       (mod p)
    s0   = f(z0)        (published baseline share)
    D    = native_cancel_signature XOR SHAKE256(context || canonical(K))

The native signature and context must be precommitted and N-of-N graph bound. This hash pad is **only a proposed wrapping**, with no formal native QPT forgery theorem.

Suppose, hypothetically, an ORIGINAL qualified future alternative source certificate w could yield the hidden polynomial evaluation s=f(z(w)) through a public source-restricted evaluator. For z!=z0, reconstruct

    K = ( z*s0 - z0*s ) * inv(z-z0)    (mod p)

and then unmask the already frozen native cancellation signature. Expanding the right-hand side gives (z(K+a z0)-z0(K+a z))/(z-z0)=K. **Every** distinct qualified fork value reconstructs the SAME intercept regardless of its child hash, while a same-child/work-certificate variant has z=z0, giving no second independent point. Different valid witnesses may produce different states and shares. The identity uses no discrete-log assumption.

### Proved restricted public-share distribution

For every fixed z0!=0 and K, independently uniform a maps bijectively to s0=K+a z0. Thus a public baseline share is **exactly uniform and statistically independent of K**. With independent a_j per branch, t baseline shares at nonzero fixed z0_j jointly are uniform independent of K. This proof is only for these published baseline shares, not the hidden evaluator, checking key, sealed signature, correlated source keys, related capsules, malicious setup or the joint quantum security game.

Do NOT reuse a slope a across two different public baseline z values. Two baseline shares (s0,s1) at z0!=z1 then immediately yield K=(z1*s0-z0*s1)/(z1-z0) without challenge. Likewise, any source actor retaining a obtains K=s0-a*z0 immediately. Each setup participant must keep its coefficients private, and an honest participant must erase/protect them. Retaining a through the source signer is fatal.

### Essential missing algorithm and attempted repairs

The mandatory operation would be

    BuildSourceShare(x_W,K,a) -> PUBLIC capsule C  [classical PPT, before source]
    EvalSourceShare(C,w) -> (z(w), K+a*z(w))       [for every qualified ORIGINAL source w]

while rendering any attempt to obtain a second point for a fabricated/out-of-window/unanchored source quantum-infeasible (or reducible to ORIGINAL evidence/hash break). This gate must handle the entire public source history, independent auxiliary input, VK, sibling capsules, selective openings and QPT attackers who need not disclose query logs/representations. It must be constructed together with its simulator. **It is not instantiated here.** It may be as difficult as the original bridge WKEM: the affine layer solves a common-output equality identity but does not by itself reduce the cryptographic ORIGINAL-dependent task.

Investigated repairs:
- Publishing a or K or a raw public affine evaluator reveals K through the baseline s0. An honest verifier if-condition cannot protect a publicly inspectable raw evaluator.
- Publishing H(a), H(K) instead of coefficients has no method to compute a new hidden evaluation from original source evidence; a later signer revealing the coefficients would be an online release authority and may leak early.
- Publish one correction row per possible z/source certificate: setup does not know future valid work certificates, and the full 256-bit semantic domain or history space is exponential. A row indexed only by z lets a fabricated string use it, without authenticating actual source.
- Replace f(z) with H(z): a public source can compute it, but Build has no common frozen K from every future z; semantic hashing alone is not secret-keyed affine evaluation.
- Mask a by a future SHA256 midstate or external source-generated randomness: setup cannot predetermine its correlation to a, and source-selected/retained secrets are not harmless. No fake PoW, synthetic Lamport label or independent puzzle can be substituted for real AuxPoW.

Hence a noninteractive *authenticated-source-restricted hidden-function evaluation* remains the full missing primitive, not an independent assumption that solves the task. The same issue persists if source labels are introduced as a separate helper. Do not optimize this carrier or present a source-evaluation oracle as a construction.

## Bounded actual mathematical checks

A Python 3 standard-library checker was executed twice locally on exactly the source preserved as checker.py. The two 1002-byte JSON outputs were byte-identical, with 26,303 functional assertions. Synthetic SHA256 child identities, 128 fixtures, five alternate WorkID metadata values, and 64 distinct child outcomes per fixture validate the field interpolation identity, same-child normalization and unguarded fake-source/retained-slope early recovery. Exhaustive F_7 enumerations validate the exact one- and three-share public masking distribution and same-slope multi-baseline disclosure. The function named private_TEST_ONLY_eval explicitly uses PRIVATE (K,a); it is *not* a public authenticated source compiler. Test seed sampling via deterministic SHAKE256 mod p is not perfectly uniform cryptographic key generation. No genuine Bitcoin/Syscoin headers, chainwork, native PQ signatures, QPT extractor or malicious setup integration were run.

Exact tested checker Git blob: 47c43a5973bc077923231d75d35e4dc38f941b3a, SHA256 06157d1605b3aecc4f2c984fbd44ea0c3b24eb64da440c77045b0e00c54e0534. Captured output Git blob 6033adcd3a61db9c11244f4787413b69cc448b32, SHA256 90fe44252791482b40669c89ec73798ee99cffe22891be191cbaa1f9ed0ca8f1. Full local derivation and byte-identical rerun remain in the run artifact. The intermediate checkpoint preceded tests; this research file follows them. No top-level PR progress comment or notification is warranted by this incomplete candidate.

## Handoff

Focus on constructing an authenticated-source SHA/AuxPoW hidden evaluator, **not** on more share interpolation or code packing. A solution must jointly instantiate classical-PPT Build and public off-chain Open from every ORIGINAL witness for one frozen native cancel capability and reduce arbitrary QPT unauthorized recovery/native forgery to ORIGINAL evidence or independently justified hash/native break, under full correlated auxiliary, malicious setup and related capsules. The source-signing party cannot retain a and cannot issue shares online. N-of-N authorization, source-availability assumptions, and pre-funding graph audit remain independent obligations. This work does not satisfy the stopping condition.
