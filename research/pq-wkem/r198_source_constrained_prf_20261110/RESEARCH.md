# R198 — SHA constrained PRF on real PoW digest ranges: attempted conditional source release

**Research-only negative checkpoint, not a witness-KEM or constructive ORIGINAL release.** This is a source-specific hash-only Build/Open candidate plus three explicit repairs, not a claim of generic hash-WE impossibility or a security proof. No release improvement or user/PR progress notification is warranted.

## Provenance and exact continuity

- Repository: syscoin/PVUGC PR #1, open/draft/unmerged; existing branch research/pq-wkem-validation-20260918.
- Observed initial head: ab437d21b56dd81bf032a2e57708ef17840b8e3b; R197 public garbling research file at blob 008919d0d101ab3aa903d8830858448673c17dc0 read exactly. Latest ordinary comments since 2026-11-10T09:00Z: none returned. R197 tested public witness-label mixing and witness-salt failure; R198 does NOT re-run that family.
- Intermediate hypothesis checkpoint was written to a local file *before* checker execution, then published as cc8276d7dd108062c53a1b6b4e19648f14ec68ce with parent ab437d21b56dd81bf032a2e57708ef17840b8e3b; the expected-head branch update was acknowledged and subsequently re-read. Checkpoint publication is not mathematical progress.
- Local Python stdlib checker.py executed twice, byte-identical outputs: checker SHA256 e2d01829549ac31f6faf11860f4e1f786173c33f36a55a69f3bd1f8f5f7b7e12; captured SHA256 c4f6404664045c27c4314cbbcbd0f52337c7278802a06f25ca709a90fde959fa; 2,543 bounded functional assertions.
- A smaller independently executed and twice reproduced published_checker.py has SHA256 42e387a650221ca3f1702af0d6ae0ccec81f3958854c21ed7b9474c032b6cb83, Git blob ff80815b4d29c18d85a9a17af93806338f42015d. Published captured stdout SHA256 4c173915db801f5674ded0684dd11b9d613895a8272ad3fe61ef57ef7bcc581b, Git blob ddee18c8000b4e0147aa1c8141353bb693349f54. The short reproduction covers the interval-key/fixed-output/leakage counterexamples; it is NOT the 2,543-case checker.
- No web, external literature, independent agent, real BTC/SYS mining or consensus validation, native signature generation, production change, or QPT experiment. Local finite tests are synthetic SHA-256 fixtures, not Bitcoin SHA256d protocol conformance.

## Original target and setup/attack model

One notary initiates a withdrawal already constrained by the N-of-N covenant-emulation ceremony. Anyone with ONE ORIGINAL qualified BTC higher-work, burn/PoB fault, or SYS authenticated prefix/tag fork/fault certificate should recover the SAME frozen claim-scoped native cancellation signature per honest setup participant. No on-chain original verifier or BitVM trace dispute, online signer, lattice/group crypto, independent hash puzzle, or fake parent header is permitted. Fix x_W to the exact claim/UTXO, burn/recipient/amount/reserve, accepted activation and BTC anchor/window, SYS source height and tags/ancestry, cancel message and VK, capsule ID, and all public checking keys.

Build_inc(x_W,sigma) must be classical PPT before future challenge evidence is generated. Open_inc(C,w) must work for EVERY ORIGINAL qualifying certificate, even when the parent-work wrapper changes without changing the pure SYS child. A malicious source may choose and retain header nonces and source coins. The full-public arbitrary nonuniform QPT adversary receives x_W, C, VK, all checking keys, source commitments, auxiliary inputs, sibling capsules, opened components and any corrupted setup contributions; ideal quantum oracle access must be stated separately if invoked. Recovery of the final cancellation signature without an ORIGINAL certificate must yield an actual qualifying certificate or a separately justified QPT SHA/native break. This pass does not provide that reduction.

## Named candidate R198: SHA constrained GGM for the PoW target interval

For a real Bitcoin header h, the digest y = SHA256d(h), interpreted as a 256-bit integer, is compared to the *contextually valid* target T. The output constraint D_T={y in {0,1}^256 : int(y)<=T} admits an exact disjoint dyadic binary-prefix cover P_T of at most 256 nodes (with the inclusive-bound convention). This is an interval property of the *actual* PoW hash, not an independent puzzle, although the experimental fixture uses n=10 and a separate synthetic hash solely to exercise the prefix-cover arithmetic.

Let a hash-only GGM tree use G_b(s)=SHA256(DOMAIN,b,s). For every prefix p in P_T, Build samples a master seed s and publishes its constrained subtree seed s_p=G_p(s). A public evaluator taking y in D_T finds its covering p and computes s_y=G_{y[|p|:]}(s_p). This works for arbitrary y strings in the interval. Crucially, obtaining s_y does NOT require supplying a preimage header h such that SHA256d(h)=y, and does not establish a real Bitcoin chain, valid parent coinbase, AuxPoW child, relevant SYS tagged history, burn, or withdrawal.

### Attempt A — frozen leaf pad

Choose an eligible digest y_* and publish E=sigma XOR Hpad(s_{y_*}); honest Open on a certificate with parent digest y computes E XOR Hpad(s_y). For two different qualified work certificates with y0 != y1, s_{y0} and s_{y1} generally differ, so only the selected y_* opens the frozen signature. Even two different Bitcoin parent-work wrappers for the SAME pure Syscoin child would ordinarily open differently. This violates both every-qualifying-witness completeness and semantic WorkID invariance. When y_* is a future header digest unknown at setup, Build cannot compute its pad in advance.

The bounded fixture explicitly showed different GGM pads on permitted digests 42 and 43 and a fixed ciphertext opening only with the chosen pad. This is a correctness counterexample, not a QPT entropy estimate.

### Attempt B — prefix-row repair

Publish a row for each interval-cover prefix p:

    s_p = G_p(s) ; E_p = sigma XOR Hpad(p,s_p).

Now every y in the target interval can identify a prefix row whose intended output is the SAME sigma. But s_p is openly published in the constrained evaluator. An adversary reads any (p,s_p,E_p) and computes sigma=E_p XOR Hpad(p,s_p) *without a digest, PoW header, source certificate or fork*. This is an exact unconditional classical attack on these equations, regardless of hash one-wayness or a QROM idealization. Giving every N-of-N participant a capsule of this form releases the honest participant's contribution too; keeping one source signer honest does not repair a public seed.

The checker exhibited this for every cover node in the exact n=10,target=301 interval and for multiple independent participant secrets; it does not claim actual source validity.

### Attempt C — place a public source verifier in front

Adding an evaluator-side condition "require SHA256d(h)=y<=T, valid contextual header/work, AuxPoW coinbase Merkle proof, correct SYS tag and ancestry" before returning s_y does not protect public s_p. An arbitrary attacker runs the public GGM evaluation on chosen y directly, ignoring that conditional. A syntactically valid digest y<=T is not itself an ORIGINAL certificate. In the checker a freely selected y=0 opened the public range-key interface without providing ANY header. It was not mined or asserted to satisfy genuine source qualification.

This differs from R197's witness-input label mixing: the failed privilege boundary here is an **interval-constrained key for SHA output** being mistaken for a **preimage/source-certificate-constrained key**. Even ideal quantum resistance of the GGM PRF would not fix the mismatch.

### Attempt D — hide seeds under source preimages

One could publish Y_p=H(r_p) and E_p=sigma XOR Hpad(r_p), keeping r_p secret. This is a valid hashlock *only when a qualifying ORIGINAL source certificate necessarily produces a suitable setup-correlated r_p*. Source miners' as-yet-unmined BTC headers/child tags contain no precommitted setup salt by default. Taking r_p=SHA256d(header*) for one preselected private header makes one selected certificate open but not every future valid one and allows source-selecting setup actors to retain it. A public common anchor/r_p known at setup and present in every branch is also visible before the fault. Publishing a row for every possible future header is not polynomial. Postulating a source-to-r_p release oracle is the missing algorithm, not a repair.

### Attempt E — use a Merkle root as authenticated source salt

A fixed root authenticates the leaves and paths in a concrete history; it does not itself furnish an unknown secret to future forks. Using H(root) as the universal pad leaks sigma immediately because root is public. Using H(path) changes across future witnesses, and Build cannot precompute arbitrary future paths. A source membership predicate checked honestly after decryption does not secure arbitrary public recovery. R196 already ruled out the common-prefix/variable-history ratchet for its exact equations; no separate credit is taken here.

## Finite execution and exact scope

The full local checker (not all uploaded bytes) tested 1,024 digest values, 302 permitted range keys, 1,199 synthetic nonce-derived permitted digests, an exact inclusive-prefix cover, candidate fixed-leaf decryption, immediate per-prefix key exposure, and two stipulated parent wrappers for the same child producing different key pads. Its 2,543 assertions are **functional regression checks, not statistical or quantum security evidence**. The posted reduced checker, executed twice before publication, checks the common-output and public-key issues in 1,024-domain range enumeration. All actual checker limitations are explicit in the source.

Neither checker implements chainwork/DAA, Bitcoin header serialization and SHA256d, Merkle coinbase proof, AuxPoW, Nexus tags, SYS ancestor context/lag or interval rules, PoB, native PQ signatures, the original three-way OR verifier, or quantum adversaries. Those are still mandatory in the ORIGINAL security game. No functionality or reduction from a fake y to real source evidence is supplied.

## Remaining construction equation / next experiment

A target-prefix-constrained PRF is a polynomially compact way to classify **hash outputs**; it is *not* a hash-only release mechanism conditioned on possession of a valid **preimage and authenticated SYS/BTC history**. The exact uninstantiated interface is:

    Build_hash(R_original,x_W,sigma;setup coins) -> (C,CK)
    Open_hash(C,(challenge selector,actual ORIGINAL evidence)) = SAME sigma
    unauthorized full-public QPT recovery/native forgery
        -> actual ORIGINAL evidence OR independently justified QPT hash/native break.

A credible next candidate needs a **source-enforced, setup-correlated hidden preimage** that exists for every future qualifying ORIGINAL source witness and is unavailable from choosing a digest in the target interval; or a genuinely nonblackbox compact compiler whose full-public joint QPT simulation proves the same result. Neither is demonstrated here. Do not pursue prefix packing/performance or claim progress merely because dyadic covers are compact.

**Conclusion:** no secure hash-only ORIGINAL Build/Open, no security theorem, no qualifying progress comment; leave the continuing task enabled.
