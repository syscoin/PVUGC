# R402 — implicit source-work SHA walk and frozen-sink convergence (NONQUALIFYING)

## Continuity and construction selection

Read the open draft syscoin/PVUGC PR #1 branch research/pq-wkem-validation-20260918 at head e4bafe3a5b263cd06bd5099bec6587ee487a1d7f, R401 note blob fffaf156f611ffb869f2d8c150341caa61f36933, and exact R400 note. Comments since 2026-11-19 00:00 UTC were empty. Did not inspect Core #609 source or run Core tests.

R401 defeats a polynomially enumerated public state graph: anyone with the published start token walks all public edges to the terminal label. This new attempt removes that *particular* problem by replacing the explicit graph with exponentially many implicit edges whose byte descriptors correspond to candidate source-work histories. Discovering an accepted path might now genuinely require source work. The new unresolved step is a builder-frozen COMMON sink for all independently qualifying future paths, not another public BFS.

## Implicit source hash-walk (ISHW) candidate

Let x_W retain the ORIGINAL disjunction of (1) same-anchor strictly greater exact Bitcoin work, (2) authenticated finite specific-burn fault, or (3) relevant authenticated Syscoin fork/tag fault at agreed LC depth without greater Syscoin work. All claim/outpoint, withdrawal, burn, amount/recipient, baseline, anchors/windows, relevant source height, strict contextual modern AuxPoW, deadline/reset, safe native message/VK, and capsule ID constraints remain required. The experiment does not implement this original relation.

For canonical future source descriptors w=(e_1,...,e_d), define an unrestricted public walk from public initial L0:

    L_i(w) = SHA256("R402/edge" || L_(i-1)(w) || Canonical(e_i))
    K_w = SHA256("R402/sink" || L_d(w))

A first attempted Build, with a particular accepted source path w_A available, forms

    D = S XOR K_(w_A)
    C = (x_W, L0, D, SHA-walk program)
    Open(C,w) = D XOR K_w  [after a normal honest source check]

This Build is NOT the requested Build: the source future w_A is unknown at setup; more importantly another legitimate source witness w_B does not recover S. A public wrapper checking source validity does not repair the decryptor against arbitrary processing of C.

### Restricted two-path lemma

Take two distinct equal-length descriptor sequences from the same L0 and assume injective serialization. At the first divergent descriptor, the SHA inputs differ. Equality of their outputs is a collision. If their labels differ, the first later reconvergence is again a collision because its predecessor labels differ. If final walk labels differ, equal sink KDFs require a collision. Therefore, **absent an actual hash collision**, two different source sequences produce different sink pads. A hard-to-search implicit graph can avoid R401's public BFS, but mere SHA iteration does not supply the source-independent frozen sink.

This is a limitation of this specific hash-walk construction, NOT an impossibility theorem for hash-only witness encryption or FE.

## Attempted repairs and the complete-public view

1. PUBLIC reset to K=SHA256("reset"||x_W) forces all witnesses to agree, but K is available to everyone, exposing S=D XOR K before ORIGINAL evidence exists.
2. PRIVATE builder-seed reset K=SHA256("reset"||s||x_W) may mask S but leaves Open without any way to compute K from future w. Publishing s exposes S; retaining an evaluator for s violates offline public release.
3. A polynomial finite table of D_j=S XOR K_(w_j) works only for prechosen witness paths, not every future qualified original certificate, and source-generated exemplars are not necessarily available during setup.
4. A public source-checking program which outputs S when R_x(w)=1 can only be cryptographically safe if an independently instantiated protected compiler hides the embedded secret against arbitrary examination of its public bytes. Calling it FE, iO or AuthNext does not implement it. An outside Merkle/ZK verifier does not protect recoverable plaintext shares.

Thus the required joint-public FALSE simulator and hard-TRUE QPT recovery/native-forgery-to-ORIGINAL proof do not exist for this candidate. Random-mask simulation for an unopenable private reset does not supply a correct source witness opener. This attempt creates no source-dependent cryptographic release foundation.

## Executed bounded check and provenance

An actual standard-library Python checker was run twice with successful exit codes and byte-identical JSON. It mines two different FOUR-link SHA256d-linked synthetic suffixes from the same anchor at an 8-bit toy target. They satisfy only the checker-defined local linkage/target rule; no original Bitcoin/Syscoin source certification or actual AuxPoW is implemented.

The fixed synthetic 256-bit payload encrypted with the first path's hash-walk sink opens with that path, NOT the second. A public reset opens without any source. A private reset is not publicly evaluable. Exact executed checker SHA256:
08b5789ff778f6edd56a730c87fb79db6230d5f395021a7a714a324dde546b42
Both JSON outputs SHA256:
baaddb10a6c784416b268752a26bc7e0aa8f780efaa50d8ab681d39006f694ae

The accompanying check.py is the executed source. run.json is identical to both captured run1.json/run2.json. Seeds used for the private-reset demonstration were intentionally omitted from output. All values are synthetic public test data. There were no Core, real parent-chain, LC maturity, Bitcoin Script/native signature, FE, or quantum security tests.

## Exact handoff

NONQUALIFYING. The implicit graph avoids the explicit-polynomial-BFS attack but fails all-future-witness frozen-key convergence. The missing operation is STILL an actually serialized classical-PPT public merge gated by the complete authenticated ORIGINAL relation, not an external if-check or an opaque secret program, with all valid witnesses returning one safe native cancellation capability and an independent joint-public FALSE/hard-TRUE QPT reduction (including malicious source coins, honest-setup contribution, related capsules and selective openings).

Do not iterate SHA-walk depth, hash domains, public semantic reset or finite future certificate tables. Preserve the R289 splice, R316 tag-delay qualification, R401 BFS, and R225 activation portability as regressions. This is not a breakthrough and warrants no ordinary PR or user progress comment; no production/Core, automation, funds, or deployment actions.
