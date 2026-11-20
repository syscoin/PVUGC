# SAI85 — Hash-locked preimage-indexed release table and SHA input-prefix cover (NONQUALIFYING)

## Continuity and distinct construction choice

This resource-bounded offline iteration read the live open/draft PVUGC#1 research/pq-wkem-validation-20260918 head 131810f09b47cd586add4f3d4cb4669643b49633, SAI84 note blob 51c9f4b8fbf4766eb067318ef0485f64f28ac126, and issue comments since 2026-11-18T19:24:30Z (none). Core #609 read-only PR metadata head was b3b4f643383a2149807a25fe38d26b5f058daa60; no new Core source or tests were inspected. No web search or external research. Existing FE paper analysis and R225 endpoint issue are not superseded.

SAI84 attempted a unique globally simulated accepting proof and required an unconstructed proof canonicalizer. This iteration instead instantiates a **hash-only classical Build/Open for an already enumerable finite original-witness set**, and analyzes whether SHA-prefix constrained PRF compression would make Build practical. This is not another local affine/coefficient/tensor basis, independent arbitrary puzzle, or ideal FE gate. The exact failure is source-future enumeration and non-PPT Build, not correctness for the enumerated set.

## Finite enumerable-world Build/Open: actual equations

Let x be one exact fixed claim statement and U_x a bounded set of candidate ORIGINAL certificate encodings. Require a canonical encoding and deterministic PPT verifier R_x for all three approved OR grounds: qualified greater same-anchor Bitcoin work; finite authenticated particular-burn fault; qualified incompatible Syscoin history or independently authenticated contextual tag fault. Source proof binding includes the exact claim/activation/outpoint/burn/amount/recipient, baseline, BTC anchors/window, source relevance and light-client depth, resets/deadline, strict post-PQ AuxPoW checks, safe native message/VK and capsule ID. This construction requires the builder to **enumerate the entire set** W_x = {w in U_x : R_x(w)=1}. It cannot do that in the real bridge before future histories exist.

Use domain-separated independent SHA oracles H1,H2, output length k, public sid and a uniformly sampled k-bit K. With frozen k-bit payload S set D=S XOR K. For every w in W_x publish exactly one map entry

    t_w = H1(sid||w)
    c_w = K XOR H2(sid||w).

Publish C=(sid,x,D,unordered map {t_w:c_w},native VK,manifest). Public Open(C,w): compute t=H1(sid||w); if no entry return bottom; otherwise return D XOR c_t XOR H2(sid||w). For every enumerated ORIGINAL w it returns exactly the same frozen S. This is genuinely source-indexed via a hidden preimage of the hash-table tag, not via a user's untrusted acceptance bit. A wrong-input tag collision produces a random result, not the correct S, except with independent hash collision/key-guess probabilities. A supplemental source verifier may reject such collisions but is not the secrecy boundary.

The key proviso is decisive: any later valid w not in the precomputed table cannot open. A subset table is incomplete even when its included witnesses are genuine. This is why the finite construction does NOT satisfy practical Build_orig(x,S), and must never be deployed or represented as a completed witness-KEM. For variable-size native signatures, H2 can be counter-expanded as a hash-only pad; no such native signature was implemented in this fixture.

## Restricted joint classical public simulation, FALSE and hard TRUE

In an explicitly enumerated finite world with independent random oracles H1,H2, fix W_x, native verification key and any correlations of S with that VK. Before any H1/H2 query at an accepted full witness encoding, independently random H1(w),H2(w) make all unordered tags t_w and ciphertexts c_w uniform independent strings (up to hash collisions), while D=S XOR K is independently uniform. The full *single-table* public distribution (x,sid,VK,D,tags,ciphertexts) can therefore be simulated without S by uniformly sampling D and table pairs. This remains exact on the FALSE set W_x=empty. An accepted-witness hash query could be recognized by running R_x(w) and would itself supply ORIGINAL evidence; independent tag collision, native forgery and key guessing must be counted separately.

**This is not the requested independent PPT hard-TRUE reduction.** A simulator for the *real table* still needs to construct/enumerate W_x, requiring exponential processing and often unknown future source history; it has no practical joint-public source sampler. Also excluded are malicious generator tapes, N sibling capsules/selective openings, native proof-of-correct-compilation and coherent QPT queries. A ROM pre-query coupling is not a proof for concrete SHA. A malicious participant could publish incorrect or missing entries; useful completeness cannot be audited from an incomplete table. With N independent setup keys, one honest component can only protect an accepted native N-of-N path if that honest component's own disclosure mechanism is secure and no bypass exists.

## Exact SHA-input GGM-prefix feasibility theorem

Suppose an n-bit header *input* domain has N=2^n candidates, each independently satisfies a SHA-based target predicate with probability p=2^(-d) in an explicitly idealized random-oracle model. The accepting set W is a random subset of input leaves. In a standard GGM prefix-constrained key, a complete binary subtree seed is safe to publish only when **every input leaf under it** is accepted; otherwise an invalid input would decrypt.

Each accepted leaf whose sibling is unaccepted must therefore have its own singleton key in any exact prefix-subtree cover. Across N/2 independent sibling pairs, the event exactly one is accepted has probability 2p(1-p). Consequently, for the required singleton count X:

    X ~ Binomial(N/2, 2p(1-p)),
    E[X] = Np(1-p),
    Pr[X < (1-delta)E[X]] <= exp(-delta^2 E[X]/2).

When Np is superpolynomial, an exact GGM input-prefix cover is superpolynomial with overwhelmingly high probability; at substantial difficulty p is tiny, almost every accepting input is isolated. This result concerns *standard prefix-tree representations in an idealized RO*, NOT all possible SHA-specific ciphertexts or generic witness encryption. It is a feasibility check of Build, not a proposed standalone compression optimization.

Indexing the constrained key by **SHA output**, rather than its source header preimage, yields a compact target-zero prefix but is cryptographically wrong: anyone can choose an arbitrary output satisfying the numeric target and derive a key without an authenticated source header. Binding the actual SHA input, contextual AuxPoW ancestor and relevant history within the public release primitive is indispensable; an external honest-code verifier is insufficient.

## Actually executed bounded source fixture

A Python standard-library checker made a synthetic 80-byte Bitcoin-header-shaped input (76 fixed bytes, 17-bit nonce) with SHA256d work target <2^249, which has independent-random-output probability 1/128. This is NOT an authenticated Bitcoin fork, contextual retargeted AuxPoW, strict SYS tag check, full PoB, a native ECDSA signature, a quantum test, or production source validation. S is a synthetic fixed 32-byte capability; the fixture seeds/salt are public reproducibility constants.

It enumerated 131072 header encodings, found 993 target-passing candidates, and constructed 993 32-byte-tag/32-byte-pad entries (63552 bytes excluding metadata). Three different passing headers all opened the identical S; a nonmember did not open. Enumerating public header candidates recovered a genuine target-passing header after 216 tested inputs, illustrating that the **builder had already mined/enumerated the accepted headers**. Exact input-prefix cover had 990 nodes: 987 singleton leaves plus three fully accepted sibling pairs. The RO expected singleton count at N=2^17, p=1/128 was 1016; empirical variance is expected. Two checker executions had matching semantic JSON fields except observed runtime. This experiment cannot verify security.

Provenance: local-only archive /mnt/data/SAI85_hash_locked_source_table_20261120.tar.gz, SHA256 e406e22a949e185d41a2c8e6b1f8a3a7eb35142c3a6b22668ecb878ec3456244. Actual checker SHA256 27ebdee347c0275beb0a9df305911933bf9652a706d9e5aa1712391800ef6922; outputs SHA256 deaa2aaa82ffbc10508ee8d9c4f5dc8a7d2c93d86650ac68ab37eb839fa9c002 and c4ed28901b170cbcc45df02ac3ba9a92f0392e0d661b4eeeb6b568c7c6c5e8c2. Full derivation, checker, outputs and manifest remain LOCAL-ONLY in this exact archive; no claim they were uploaded as executable repo code.

## Stopping point and next constructive equation

The finite-domain hash table is an honest explicit Build/Open and restricted classical public tape simulator, but it cannot meet the ORIGINAL **PPT/future-evidence/universality** requirement. Without an independently constructed succinct preimage-constrained public release primitive, neither prefix-GGM, public output-target bits, finite explicit tables, online source signers, nor a proof-of-correct-compilation around the table fixes it.

Still required: a practical classical PPT Build_orig(x_W,S) before future ORIGINAL evidence exists, public Open_orig(C,w)=S for **every** qualifying ORIGINAL w, and a concrete full-public QPT recovery/native-forgery -> actual qualifying ORIGINAL witness or independent hash/native break reduction, with a usable one-honest setup and activation-specific native authorization. This run DOES NOT close that missing advance; no progress comment, notification, main/production write, Core modification, test assertion about network admission, deployment, or automation modification.