# R381 — source-conditioned directed SHA edge coequalizer (NONQUALIFYING)

## Provenance and exact continuation
Opened the existing open/draft syscoin/PVUGC PR #1 branch research/pq-wkem-validation-20260918 at 4ba185a019e375230aef2982cb7aa24789507bde (R380); read exact R380 note blob 05dd3308a8a9ed8cd65116b1c746562e824d63f8 and R379 precursor blob 137b210e947b31652cc3507ed861b2ae985dfeff. Recent top-level PR comments since 2026-11-17 returned none. No Core #609 source or tests were revisited. The user-corrected strict-PQ contextual tag history relation remains intact.

The missing R380 operation was *source-conditioned edge authorization*: permit all future ORIGINAL qualifying Bitcoin/Syscoin challenge certificates to unlock a common frozen terminal capability, without a public source-independent graph path, online authority, arbitrary new hash puzzle, private source key or a verifier if-check outside the cryptographic gate.

This iteration changes R380's SHA edge pad to incorporate the actual future *certificate digest*. This distinguishes it from the prior source-independent edge lock, but introduces a requirement of **key convergence across distinct certificates** which it fails. It is not an ORIGINAL WKEM advance; do not optimize this exact syntax further.

## Concrete Build/Open attempt
Keep R_orig(x,w)=R_BTC_greater OR R_specific_burn_fault OR R_qualified_Syscoin_inconsistency_or_tag_fault, binding full chain/protocol IDs, claim/outpoint, burn/amount/recipient/replay, source baseline and anchors/window, relevance and LC depth, deadline/reset, safe native message/VK, and capsule ID. Greater Syscoin work is NOT required for the third OR branch. Different valid Bitcoin parent certificates for the same child do NOT alone constitute a fork. An applicable malformed tag wrapper must have its *outer carrier* authenticated independently of the tag rule it violates.

Given a previously available SHA node key k_u, target k_v and reference source digest z0, the setup publishes one edge label

    c_uv = k_v XOR SHA256("R381/direct-edge" || k_u || z0).

An opener given *some* qualifying original w computes its actual certificate digest z(w)=SHA256(CanonicalCertificateBytes(x,w)), and would update

    k'_v(w) = c_uv XOR SHA256("R381/direct-edge" || k_u || z(w)).

For every pair w1,w2 with R_orig(x,wi)=1, correctness REQUIRES

    SHA256(domain || k_u || z(w1)) = SHA256(domain || k_u || z(w2)).   (1)

With distinct inputs and a uniform random oracle this holds for one fixed pair with probability 2^-256. Neither strict modern Syscoin tags nor a source ancestor conflict makes all possible certificates share their complete serialized digest; the ORIGINAL three OR grounds can also produce unrelated evidence types. This is a *correctness condition of this restricted syntax*, NOT a SHA attack or an impossibility for source-specific WE/FE.

### Explicit attempted repair: a public accepted-source normalizer
Make z(w)=z_accept(x)=SHA256("accepted" || x) whenever VerifyOriginal(x,w)=1. This enforces (1), but if k_u is public/obtainable as in R380's public path root, anyone computes

    k_v = c_uv XOR SHA256(domain || k_u || z_accept(x))

without a witness. If D=S XOR k_v is the frozen masked capability, it also recovers S directly. FALSE-instance secrecy already fails. A normalizer outputting the same public accepted value is not a cryptographic gate, even if ordinary software checks a certificate before calling Open.

Keeping k_u secret shifts the requirement to a PUBLIC source-dependent method to recover k_u; putting that key in a private evaluator violates offline public Open, and publishing it exposes the mask. To compensate later for varying z(w), one needs a REAL serialized nonlocal, witness-conditioned SHA correction with a joint full-public security reduction. Merely naming it as FE/WE is not a construction; R379's exhaustive differential corrections are exponential, while R327's exposed polynomial masks have public extraction regressions.

This closes only fixed-label single-edge SHA certificate gating with a known or independently accessible root, and its public-constant normalizer. It does not rule out other encodings, genuinely hidden gated state, or any postquantum hash-based general solution. No black-box QPT theorem is claimed.

## Bounded executed control and reproducibility
Executed Python standard-library SHA256 checker twice, complete success and byte-identical output. A fixed 256-bit public root and edge c with three **synthetic distinct certificate digests** (greater Bitcoin work, burn refutation, Syscoin inconsistency placeholders, NOT real ORIGINAL evidence) produce three *different* terminal keys, none equal to frozen k_v. The public accepted-value normalizer instead returns k_v and S without a certificate. The executed control is not a Core test, actual Bitcoin/Syscoin PoW validation, native signing, QPT attack or source security proof.

Checker SHA256: 8db852f88213a6c654cb99787db3f25466da9b69c5750d434175d389a73f9077.
Both output SHA256: 25c8295a81086c4b012dc379e49e46d33eeea3d9ea5a22fa7dc62fcdc192b88a.
Full local-only research note and checker/output archive: /mnt/data/R381_source_edge_coequalizer_20261119.tar.gz, SHA256 127b1a22065dac15110a1d8cb4f2195f3c526fcc70dc7d0d065df3077970fa6b. The checker/output are NOT GitHub-published by this note.

## Next actual unsolved equation
Still missing any classical-PPT serialized

    C=Build_orig(x_W,sigma_cancel;rho),
    Open_orig(C,w)=sigma_cancel FOR EVERY qualified ORIGINAL w,

and complete-public FALSE / hard-TRUE QPT unauthorized recovery or accepted native forgery -> an ACTUAL qualified original source certificate or independently justified hash/native break, including malicious one-honest N-of-N setup, siblings, selective opening and R225 activation binding. Source-authenticated Merkle roots, ordinary verifier bits, independent hash puzzles and purported secret functions left as private services do not establish this.

NONQUALIFYING, no PR progress comment, no user breakthrough notification, no Core/production edit, no deployment and no automation change.