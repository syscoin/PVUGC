# R230 — source-work common-token attempt (research-only)

**No qualifying construction advance.** This is a scoped falsification of direct SHA256d-work-derived hash-pad release, not a no-go theorem for hash-only witness encryption. The actual source-dependent Build/Open and full-public QPT security remain missing. No ordinary PR progress comment.

## Exact continuity and provenance

Repository syscoin/PVUGC, existing draft PR #1, branch research/pq-wkem-validation-20260918. Initial observed head 663d96b99d3d15327b925776786ba48f454dbcc8. Exact-version reads: R229 public-source-finder note (Git blob 6c65d78be1fb624589eb06c5c58699c46e433ef1), R227 source-label gate (3bef7943c233ff04ae020ebabfa1f2d7272ab308), R226 OR-SEAL (685f4371f781cf45d8c31f57d44d1b831d85a8c3), plus recent PR comments. Intermediate hypothesis committed as 8e519945e56fe9a824d207bbadacff93bc7c0f18, after which the local checker actually executed twice with byte-identical results.

Exact executed checker.py: SHA256 1a59df7e033c1fdf453fd0e374c95aab8f841fdedca366dfd6d724bf3f8ea52f, Git blob 0122c050c310980ed79765cf382b5beb26f012da. Exact captured.json: SHA256 42397bf809d2cc196cb99afad3a004b18797c8e4c729320ecc08439684d5a2a6, Git blob 2760e5cc07253a92c40634ea3d30081b4fb3df77. Both object hashes independently checked before adding them to the research tree. No external web or literature, no production code, real Bitcoin/Syscoin consensus validator, native PQ signature, agent, quantum security test or real source-conditioned release was invoked.

## Candidate source-derived pad

Freeze one native claim/path-scoped cancellation authorization sigma at N-of-N preauthorization. Given a qualifying future AuxPoW observation P, consider three source projections:

    WorkID(P) = SHA256d(P.bitcoin_parent_header)
    OutcomeID(P) = PureChildHash(P.syscoin_child)
    AnchorID(P) = authenticated claim-prefix anchor already fixed in public x.

Try a direct hash pad D = sigma XOR H_pad(Z(P)). Build must know the single pad at setup although source evidence and future work hashes are not yet fixed; Open must derive that SAME pad from EVERY qualifying ORIGINAL witness. The release must not be computable from public capsule plus nonqualified bytes.

**A: WorkID.** Distinct valid Bitcoin parent headers can certify the same Syscoin pure child. WorkID hashes then differ although there is no semantic fork. The tester mined two distinct 80-byte SHA256d parent headers per child, satisfying one easy toy target. Their H_pad(WorkID) values differed, so one frozen D cannot open consistently from both. This tests SHA work-output identity, not actual source admission.

**B: Target-invariant work prefix.** A toy target T=2^248 constrains the most significant digest BYTE to zero under little-endian integer interpretation. All 72 mined parent digests had final raw digest byte zero. Choosing Z as this common prefix achieves equality across certificates, but Z=0 is PUBLICLY known from T. A ciphertext D=sigma XOR H_pad(0) was immediately opened without any source witness, in each fixture. This is an unconditional FALSE-instance leakage for this direct-prefix family. The toy target is not Bitcoin consensus difficulty, and no security parameter is inferred from the repetitions.

**C: OutcomeID or anchor.** Using the pure-child identity makes the pad invariant under multiple parent-work certificates for the same child, but two genuinely different child outcomes produce different pads. Using the common ancestor anchor makes the pad equal, but that public anchor is known before the supposed challenge and decrypts early. Adding a public salt to the anchor preserves public decryptability; hiding the salt breaks public opening unless some new authenticated source-to-token transfer exists. A source miner inserting a secret label can retain it before genuine inclusion, while an honest source that refuses future signing cannot guarantee eventual opening.

## Exact scoped direct-pad lemma

Let Build output fixed D = sigma XOR H_pad(z0), and public Open on ORIGINAL witness w compute D XOR H_pad(Z_x(w)) for a deterministic public source projection Z_x. For correct recovery from any two valid original witnesses w0,w1, one must have

    H_pad(Z_x(w0)) = H_pad(z0) = H_pad(Z_x(w1)).

Under a suitably idealized domain-separated n-bit random oracle, distinct fresh Z values produce matching pads with probability 2^-n. Do not apply this numerical claim to unproved SHA256 behavior or to correlated quantum queries without a QROM proof. If every valid witness instead has Z_x(w)=z_public(x) and this invariant is efficiently computable from the public claim, then D XOR H_pad(z_public(x)) immediately reveals sigma even without a witness. The lemma applies ONLY to the specified direct hash-pad family, not to an arbitrary protected nonlinear encoding or generic WE. It does not exclude a genuinely hidden common source-derived invariant, but none is produced by the three tested projections.

The OR of the three ORIGINAL challenge predicates—greater contradictory Bitcoin cumulative work, absent/invalid authorized burn, and qualified Syscoin fork/tag inconsistency—has no established universal hidden header digest, pure-child hash or nonce carried by every accepting witness. R226 provides a conditional per-branch wrapper, not source-dependent leaf release; it cannot fill this missing interface by itself. Selecting a Boolean TRUE after honest source verification is publicly reproducible and does not conceal a native signature from a malicious evaluator.

## Tests, limitations, and next step

The standard-library Python fixture creates 24 pairs of distinct synthetic pure-child hashes and 72 synthetic 80-byte Bitcoin parent headers with genuine SHA256d work under a non-consensus easy target; its coinbase digest is synthetic, not a serialized Bitcoin transaction, and the reference tag lacks full contextual Syscoin consensus validation. It completed 434 functional assertions with two byte-identical runs. These do NOT demonstrate actual Bitcoin best-chain membership, Syscoin child validity, source admissibility or QPT security. Privately mining a syntactically valid parent is not enough to satisfy ORIGINAL source rules.

The necessary *constructive* next equation remains an actual classical-PPT Build_hash(R_original,x,sigma) and public Open_hash(C,w) that produce the SAME frozen capability from every qualifying ORIGINAL witness, while unauthorized arbitrary QPT final-key recovery/native forgery yields an actual original certificate or independent hash/native break under all public checking keys, sibling capsules, malicious setup, quantum queries and retained source secrets. A secret allegedly released by an on-chain event must be cryptographically coupled to authentic evidence—not inserted by a source actor who can retain it or unlocked by a public prefix. No source-to-common-secret transfer or full-public simulator was obtained this execution; do not repeat or optimize this direct-pad construction without a new exact mechanism.
