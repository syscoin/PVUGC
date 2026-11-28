# Forward SHA-merging diamond: ORIGINAL-source release screen (NONQUALIFYING)

## Continuity and deliberate change

Read current open/draft PVUGC #1 at head 0760f4de1d6751f3001c1f6c218d6000bc57271a on research/pq-wkem-validation-20260918 (base tree 6a47953f5935ea42ff79e18f6ab03d196ba45903). Read the exact latest hash-chain predecessor note, blob b9205735d6906d36e6722b0d718b2c7a1169e2ce. Top-level comments after 2026-11-18 18:00 UTC were empty. Core #609 metadata showed af4d78335c6b9b180e3f652909cd2ce3934d07a8; no Core source or tests were reread. No external literature or web search.

The preceding WOTS-predecessor capsule required hidden state held by the source signer. A malicious signer retaining private coins could recover the capsule secret before any ORIGINAL certificate. This pass attempts a *different* method: a PUBLIC FORWARD SHA merger from arbitrary source bytes to ONE fixed endpoint, without signer-retained secrets, a forced common future witness, polynomial/affine masks, or label/circuit guessing. Test its Build and Open together against full-public FALSE security and honest all-witness feasibility. Do not confuse this candidate with source admission or a general-purpose FE scheme.

## Candidate algorithms, first positive property

Take an n-bit compression H_n based on a domain-separated SHA output. Setup chooses L distinct public entry nodes ell_1,...,ell_L and tries to merge them with a binary diamond. Each stored edge is (u,salt,v) such that H_n("next"||u||salt)=v; each pair of children has a common parent, and all paths terminate at one public root r. For any source certificate byte string w, compute v=H_n("src"||x||canonical(w)). A public linking search tries nonces t until H_n("next"||v||t) is one of the ell_j, then follows the public diamond edges to r.

Any two successful links, including links from different authentic certificates, end at the SAME r. No signer's retained secret is needed. This is the single limited constructive feature. It does NOT make the link relevant to the qualified ORIGINAL Bitcoin/Syscoin OR relation.

## Joint-public release and repair disposition

1. If Build chooses D=S XOR H("pad"||r) and publishes (r,diamond,D), the entire PUBLIC capsule yields S=D XOR H("pad"||r), including for FALSE instances, with no w. Public-root convergence does not produce secret release. The simplest full-public simulator is contradicted by an immediate classical distinguisher/recovery.

2. Try secret K, public Y=H_n(K), D=S XOR K, and arrange for every source w to reach Y. The forward authenticating link delivers Y, not K. Publishing a reverse edge containing K releases it without a source witness. Demanding a private reverse edge that only original evidence unlocks is exactly the missing source-dependent protected Build/Open operation, not an independently supplied SHA primitive. H_n preimage resistance alone cannot implement ReverseAuthorized(C,w).

3. In a random-function model with L distinct entry points, every independent linking nonce hits some entry with probability p=L/2^n. In q trials the exact probability is 1-(1-p)^q. The value of p does not depend on whether the input source label is a genuine certificate or invented bytes. With L=8 and n=256 the expected number of trials is 2^253, exponentially large for any future original witness. Keeping honest linking polynomial requires L of near-exponential size, breaking practical Build. Replacing an ordinary publicly chosen domain tag by the word "accepted" adds no authentication: anyone can hash that tag without proving it applies to w. A public software if-check cannot rescue a secret extracted from public hashes.

4. Building even ONE chosen-input SHA merge by finding salts s_0,s_1 with H_n(u_0||s_0)=H_n(u_1||s_1) generically takes birthday-scale Theta(2^(n/2)) hash work; at full 256-bit output this is not classical PPT. The toy checker uses a truncated hash expressly to make collisions feasible. Replacing collisions by a Merkle tree removes this setup cost only for prelisted leaves; arbitrary unpredictable future source certificates are not included, and publicly updating the root changes a supposedly frozen capsule.

These are narrow failures of the explicitly given forward-merging representation, NOT an impossibility theorem for all hash-only witness encryption, a SHA attack, or a quantum security proof. No favorable parameter regime for this candidate simultaneously satisfies full-public security, all-witness practical opening, and PPT offline Build.

## Reproducible bounded computation

The committed check.py uses 12-bit truncated SHA256d and eight prelisted leaves. It constructs seven actual pairwise salted collisions and checks every public path has a common root. Four synthetic byte strings independently find entry links, including one deliberately labelled invalid and two junk strings; all reach the same root. The printed root is 645, and the left/right birthday pair trials are 190,59,68,136,25,87,85. The four link trial counts are 401,1216,1220,369. This establishes only the displayed toy arithmetic, not source authentication, native verification, FE, SHA256 collision resistance or quantum security.

Two executed checker invocations both exited zero and generated byte-identical JSON output. Checker SHA256: 7376d5180711857d3aa5e1e8c98ea261939f0afcb656f4d0a0dea8bacc1c63b4. Both outputs SHA256: 84ef2c741a94be1dfda8360e4e6614227967830f6facb4c225a92fecfd319a00. Full checker and both outputs are committed in this directory. No Core tests, original source certificates, Bitcoin VM, native signature, FE implementation or QPT test were run.

## ORIGINAL security obligation retained, no advance

The protected authorization remains for ONE notary initiation and ANYONE with one qualifying ORIGINAL source certificate. The three OR grounds remain (1) qualified strictly greater exact Bitcoin chainwork; (2) finite authenticated withdrawal-specific burn refutation; (3) qualified strict-PQ Syscoin history inconsistency/tag fault at LC depth. R316 was only stale-reference coverage; correct strict tag parsing and actual semantic ancestry must be enforced. No greater Syscoin work, winning-fork selection, second challenger, or extra signer requirement is introduced.

Still missing an actual classical PPT Build_orig(x_W,S)->C, public Open_orig(C,w)=the SAME frozen safe native cancellation capability for EVERY R_orig(x_W,w)=1, and a complete-public FALSE/hard-TRUE arbitrary-QPT unauthorized recovery/native forgery -> actual ORIGINAL certificate or independently justified hash/native break. Malicious setup, retained source coins, auxiliary/sibling multi-capsule composition and R225 native activation binding remain mandatory. No threshold aggregation, ideal FE program, online signer or exponential witness table was produced.

A successor must realize a publicly serialized cryptographically source-gated *non-forward-only* release transition, with security from its entire public bytes, not from hiding a computation behind a software verification wrapper. Reject another public terminal or hidden unrecoverable terminal without a concrete new mechanism. No breakthrough/progress comment or notification. No production/Core/workflow changes, deployment, asset transfer or automation change.
