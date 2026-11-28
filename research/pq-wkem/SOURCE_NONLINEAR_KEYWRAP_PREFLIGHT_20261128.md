# Nonlinear recipient-key wrapping preflight (2026-11-28)

Research-only selection/repair notes, not a qualifying advance.

## Provenance and selection

Actual start: syscoin/PVUGC PR #1, open/draft/unmerged, branch research/pq-wkem-validation-20260918, head 10c22c7104840fb2e166773c04a376dc755da494. Read metadata, recent substantive discussion through R225, head commit filename, and exact-version SOURCE_CLAWS_CDS_PREFLIGHT_20261128.md (blob d54927badf42954dcd90815c3c17522e75f881f6). Rechecked head before preservation; this new note path returned 404. No web, new Core claims, external agents or checker execution.

Missing original operation remains joint classical-PPT generation of a source-dependent public evaluator for the fixed native cancel contribution, with every ORIGINAL witness opening the same capability and arbitrary unauthorized recovery/forgery reducible to a certificate or independent QPT break.

Selected mathematical change from the immediately preceding two-sampler XOR CDS: do not xor two local masks. Instead make one local output a recipient decryption key and the other a *nonlinear multi-recipient ciphertext*. The right message can have a different valid ciphertext row for each compatible left key. This breaks the specific length-three XOR graph-closure equation: correctness at three edges does not imply decryption at a fourth with independently keyed hash wrapping. Require left keys to depend on actual source preimages rather than on public join labels or transferable wire labels. Test actual feasibility of generating the right message, not just security of a hypothetical private sender. The goal is not a hash-pad optimization; it is to replace the shared-offset CDS mechanism with an asymmetric, nonlinear raw-output interface.

## 1. Exact proposed interface and honest algorithm

Retain the canonical full statement x (all three ORIGINAL OR branches, claim and native context). For a proposed split w -> (u,v), set R_x(u,v)=V_x(Join(u,v)), including actual authenticated source checks and relevant scope. Let a = Key(C_L,u) be a lambda-bit recipient key. Eval_R(C_R,v) returns a list of t(v) rows (salt_j,z_j,tag_j), with polynomial t. The Build target is one lambda-bit seed k masking the frozen sigma, with

    E = sigma XOR Expand(H("payload",ctx,k))
    z_j = k XOR H("wrap",ctx,salt_j,a_j)
    tag_j = H("auth",ctx,salt_j,z_j,a_j)

using unambiguous encodings and disjoint hash domains. A left recipient possessing a computes a candidate k_j from each row, checks the tag and opens E, using the native checking key/message if necessary. For every accepted pair there must be a row encrypted to its a (or an accidental hash collision; not a correctness strategy). Different accepted pairs can use different rows and none needs to share a pad with an incompatible pair. The native signature is not used as a substitute for source authentication. For simplicity take a single fixed k; opening the exact fixed native contribution from that k remains the requirement.

This is implementable symmetric encryption given a finite explicit list of recipient keys known when wrapping. The actual missing operation is generating Eval_R and its rows from arbitrary future v without knowing/enumerating compatible future u at Build, and without revealing k or an authorized recipient key to a public evaluator on v alone. Standard symmetric wrapping does not provide that operation.

## 2. Recipient multiplicity condition (preflight, not a new security foundation)

For fixed setup coins, fixed hash function and right input v, let A_v be the set of distinct raw keys Key(C_L,u) for all canonical u with R_x(u,v)=1. Suppose m distinct members a_1,...,a_m have been selected. Fix the same right row list for all of them (if honest Eval_R is randomized, consider one shared draw and account for the correctness error below).

For row j, recovering k requires H("wrap",ctx,salt_j,a_i)=z_j XOR k. If the hash values for the m distinct inputs in this row are distinct, at most one a_i can recover k from that row. Thus t >= m for simultaneous correctness in the absence of a collision in the considered wrap calls. Auth tags can only restrict success further. This bound does not assume the right list was chosen independently of the keys, k, or oracle outputs. It is a deterministic statement about the final list. In particular, choosing salts adaptively cannot avoid the bound without finding a collision. It also does not require unique decryptability for arbitrary malformed ciphertexts, or rely on a checker's internal state.

In an ideal lambda-bit wrap RO, if the setup, candidate witnesses, and all the tested evaluations jointly generate at most Q distinct classical wrap queries, the probability of any collision on those inputs is at most Q(Q-1)/2^(lambda+1), including adaptive queries. This is a classical honest-correctness calculation, not a QPT security proof. If witnesses are hardwired with oracle-dependent advice, or produced by an unbounded search outside that accounting, use only the deterministic conditional implication; do not silently apply the union bound. If m polynomially many accepted inputs each have correctness error <= eps over the same setup and right-evaluator draw, a union bound gives simultaneous correctness probability >=1-m eps. In the bounded-query case, choosing m=t+1 distinct keys then contradicts this lower bound except with collision probability. This argument does not assert that an efficient algorithm can generate t+1 actual original witnesses for any particular bridge statement, or that all possible splits have high multiplicity. It is a feasibility test for candidate raw keys, including whole-preimage hash keys where distinct accepted left inputs are meant to have distinct outputs.

The preceding XOR-CDS graph argument no longer applies to this ciphertext list. However the exact price of avoiding it in this concrete realization is one wrap per distinct compatible recipient key. If the right input is merely a fixed public baseline and left inputs range over different future certificates, the candidate must either support that multiplicity, or deliberately collapse many preimages to common recipient keys. A fixed-length list of ordinary hash wraps is not a succinct solution for arbitrary future recipients.

## 3. Attempted key-directory repair and public-trace check

Try collapsing recipients only by authenticated compatibility class, while keeping keys inaccessible from the class digest. This would permit one wrap per class, unlike raw whole-preimage keys. It avoids the prior explicit-prefix scan only if a label is *not* a decryption key and cannot publicly derive it.

Concrete desired algorithms:

    (C_L,C_R,E) <- Build(x,sigma)
    a <- LocalKey(C_L,u)
    rows <- LocalWrap(C_R,v)
    k <- SymOpen(a,rows)

LocalKey must agree on a class key for every required compatible u without knowing those u at Build. It must not let an arbitrary publicly supplied class digest derive the key. LocalWrap must generate the right row without revealing that key. For a static list, Build must know all relevant class keys or have an alternative public-key encryption algorithm; a seed for a publicly evaluable hash PRF on class labels fails the label-only scan of the preceding note. A hidden PRF seed with an unpublished evaluator is not a public algorithm.

For dynamic rows, a concrete attempt would be a publicly computable directory returning the needed recipient key from v, followed by ordinary symmetric wrapping (or translation of an existing encrypted k). But if LocalWrap actually computes any a_j as an intermediate, public code inspection by a holder of v recovers a_j and decrypts that row. Even if the symmetric wrapping is implemented without ever storing k in plaintext, possession of the raw key for the resulting row suffices. This is a public-algorithm trace simulation by the adversary itself, not an extractor requiring volunteered adversarial state. If v already determines a full valid ORIGINAL certificate efficiently, this particular attack would not violate hard-TRUE security; the directory must establish that fact, not assume it. For v that is only locally valid, this realization does not cryptographically require the missing u.

The only way forward within this repair is to construct a genuinely public encryption or ciphertext translation mechanism which operates on opaque class keys without computing them, whose decryption requires the source-preimage-dependent LocalKey, and whose correctness holds for all compatible pairs. Ordinary symmetric hash wrapping takes the secret key as input and does not implement it. A table of precomputed rows indexed by all future source evidence is not classical PPT Build. An ideal private LocalWrap is not a solution either.

One can make LocalWrap depend jointly on (u,v), rather than v alone, and derive a hash key from the complete transcript. This removes recipient multiplicity for an individual right evaluation. It does NOT yet provide the ciphertext translation: the new public evaluator would have to turn E into a wrap of k under that transcript-dependent key if and only if the entire authenticated source predicate holds, with no access to k on invalid inputs. The old split-mask or fixed correction table cannot be inserted here, because it would reintroduce the source-label problem. Public validation followed by deriving the plaintext from a public seed is not cryptographic control.

## 4. Decision and next operation

Reject this concrete multi-recipient hash-wrap realization before implementing larger fixtures. It escapes the preceding XOR identity but neither explicit rows nor public computation of their recipient keys implements the necessary original-source release. Do not generalize the recipient-count argument to arbitrary broadcast encryption, arbitrary nonlinear decoders, or all hash-based source-specific WE. Do not treat it as a theorem against the original bridge. No tests were run; this is a static algorithm/feasibility preflight.

A genuinely different next candidate would have to instantiate the following ciphertext transformation, not merely name it:

    C <- JointBuild(x,k)
    W <- PublicTransform(C,u,v)
    k <- SymOpen(LocalKey(C,u),W)

with all raw intermediate outputs publicly available, no hidden evaluation service, and with every original certificate accepted. If the transform evaluates a valid recipient key in the clear, analyze security as a single full-input source-dependent evaluator, not as a private two-party protocol. A construction could also abandon the asymmetric wrapping architecture entirely. The missing simulator must jointly account for C, transformed outputs at adversarially chosen inputs, source commitments and retained coins, auxiliary information, native VK/message, all related capsules and coherent hash access. Recovery of k or an accepted native forgery need not invoke the declared transform or supply a transcript. No such simulator or reduction is provided here.

Retain the actual three ORIGINAL grounds (qualified strictly greater exact BTC work, finite authenticated missing/invalid burn, qualified SYS inconsistency/tag fault) and every-witness same safe cancellation. No scope, maturity, source-consensus or native endpoint changes. No new material security correction to prior claims and no ordinary PR comment.
