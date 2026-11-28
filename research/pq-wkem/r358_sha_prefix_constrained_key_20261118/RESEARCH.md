# R358 — SHA-prefix-constrained hash-only key attempt (NONQUALIFYING)

**No ORIGINAL hash-only witness-KEM advance, no independent QPT proof, no native signature release; do not notify or publish a progress comment.**

## Provenance

Read syscoin/PVUGC PR #1 open/draft at actual head `29b3e0b3e13cf967af582451a3861c782132e488` on `research/pq-wkem-validation-20260918`, R357 note blob `ccb87a44728ce6ffb548af63004374e41ed4e3aa`, R356 blob `8e161fe26a554b8de6e0d82e100b8c102cefed0a`, and issue comments since Nov 17 (none). Core #609 was not reread/tested in this pass; previously confirmed strict post-PQ contextual rules remain the model, and public-network deployment is NOT inferred. This run does not report an offline-work duration.

### Missing operation and distinct constructive hypothesis

R357 needs a publicly serialized whole-ORIGINAL-certificate gate supplying one frozen cancel capability for *every unknown future authenticated witness*. In contrast to previous affine, masked-ideal, and explicitly listed source-DAG designs, try an actual hash-only **binary GGM prefix-constrained PRF** as the source-credential generator. PoW gives SHA256d digest targets; perhaps a public key restricted to the target prefix could permit all future valid headers to open without enumerating them. This pass constructs the PRF and tests complete public key exposure, all-witness convergence and source authenticity jointly, not an ideal row API.

Let H_b(k) = SHA256('R358/GGM/' || b || k), b in {0,1}, and G(k,b_1...b_n) the iterated expansion. Let p = 0^d denote a toy accepted SHA digest prefix, k a uniformly seeded 256-bit GGM root, and k_p = G(k,p) the constrained key. Build chooses a pre-funding frozen safe signature/capability S and capsule ID cid, and publishes k_p. For a header digest h = SHA256d(header) with prefix p, define Leaf(k_p,h)=SHA256('R358/LEAF' || G(k_p, suffix_p(h))). This is a concrete classical PPT public evaluator in the hash-only setting. It is NOT authenticated source work: ORIGINAL verification additionally requires target correctness, Bitcoin work/ancestry, modern contextual AuxPoW, strict canonical tags, actual relevant fork/maturity or specific burn fault, and full claim/window/native bindings.

## Option A — frozen common key, explicit FALSE/full-public attack

K = SHA256('R358/COMMON' || cid || k_p); D = S XOR K. Open on any valid original w can compute K from published k_p and recover S, providing same-output correctness. But adversary can do so with zero witness queries: K is literally publicly computable. Thus for a complete-public S-vs-S' challenge, the classical adversary recovers the chosen S with probability 1, also breaking QPT security. An honest-code VerifyOriginal after recovery is irrelevant. Hiding k_p would negate the claimed public constrained-key evaluator.

## Option B — leaf-specific keys, explicit UNKNOWN-witness table gap

K_h = Leaf(k_p,h); D_h = S XOR K_h. Builder can produce D_h for any already-known h; a holder of each explicit (h,D_h) obtains the SAME S. But different legitimate future headers have distinct digests and generally distinct K_h, so no single pre-funding D will open for every valid h. A table containing a row for every future authentic ORIGINAL certificate is exponentially large and depends on future source data. Publishing any listed row and the public constrained seed exposes S even to a party lacking its header or authenticated proof. A polynomial public generator of D_h would need to hide the constant S while enforcing the *full* ORIGINAL predicate; that is exactly the unbuilt release algorithm, not a consequence of GGM. A transparent formula S XOR Leaf(k_p,h) trivially exposes S and an opaque evaluator is disallowed.

## Option C — full-proof-root binding and global consistency

Hash the complete source certificate w and claim x into a canonical session digest r_w=SHA256('session'||cid||x||Serialize(w)), not just its PoW output. Derive K_w=H(r_w) and attempt D=S XOR K_w. This improves session separation and prevents some cross-certificate label splices within an independent row, but distinct qualifying ORIGINAL witnesses still obtain independent keys. A single ciphertext opens for one witness and fails for another unless pre-funding correction rows are supplied. Those rows revert to Option B or R357. Source authenticity must be cryptographically enforced BEFORE raw key release; a post-decryption check does not repair this.

## Source-authentication regression

A SHA prefix is a publicly synthesizable **index**. Given k_p, an adversary can choose a synthetic bitstring h with prefix p and evaluate Leaf(k_p,h) without its SHA preimage, parent header PoW, Merkle proof, contextually admitted Syscoin child, chain work, claim relevance or LC depth. Merely attaching a public verifier cannot prevent raw key evaluation. The exact compact-target inequality is not a prefix test anyway. To use the source certificate itself as a hidden credential would require an additional authenticated source-to-secret correlation in the pre-funding capsule; GGM does not instantiate it.

## Bounded executed local checker

A Python3 standard-library checker instantiated the binary SHA256 GGM with a 9-bit zero prefix and synthetic SHA256d of two 80-byte pseudoheaders. It found two distinct matching nonces (786 and 1149), checked distinct leaf keys, two per-leaf rows opening the SAME frozen synthetic 32-byte S, public common-seed recovery without ANY witness, evaluation from a made-up digest without a preimage, and divergence of full-proof-session keys absent correction rows. Two executions were byte-identical. Checker SHA256: `e4c7882b826891351a7fb86a89ab0813c7776d14f0be4a4caa5c8af5bf02ef9b`. Each JSON output SHA256: `43b71277d165b561d770c868572112eedcbf1c1e9c59262aa8d28f842e7165e3`. Complete derivation, checker and both outputs are in a **LOCAL-ONLY** reproducibility archive `/mnt/data/R358_sha_prefix_constrained_key_20261118.tar.gz`, SHA256 `bab82e53817aee35e7a15629fe511b73676903c900138042067d47691c995046`. No Bitcoin/Syscoin consensus admission, real native signature or quantum simulation was performed. Local archive availability in a later runtime is not assumed; this note is the GitHub handoff.

## Exact unfinished equation and regression decision

Reject transparent public SHA-prefix-constrained PRF release: public seed permits arbitrary digest evaluation, a common mask leaks immediately, and leaf masks need unavailable future-certificate rows. Do not retry by lengthening prefix, hashing more inputs, changing domain separation or enlarging fixtures. The next candidate must specify polynomial classical Build_orig(x_W,S)->C, public serialized Open_orig(C,w)=S for EVERY qualifying ORIGINAL w, AND a full-public QPT FALSE/hard-TRUE reduction to an ACTUAL original source certificate or independently justified hash/native break. It must account for malicious setup/coins, sibling selective opening, native VK/activation/slot binding and one valid challenge opening all fixed N-of-N preauthorizations without an online signer. There is still no such instantiated operation.

Retain the three original OR grounds (strictly greater same-anchor BTC cumulative work, finite authenticated specific-burn fault, and LC-depth-qualified relevant Syscoin inconsistency/tag fault), including strict post-PQ modern contextual admission, exact tag and semantic history checks, and R316's corrected stale-tag coverage interpretation. R225 fixed-outpoint portability, R327 black-box ideal extraction, R289 split-mask splicing and R356/R357 explicit-source-path failures remain regressions. No PR progress comment, Core/production edit, merge, deployment, or automation change.
