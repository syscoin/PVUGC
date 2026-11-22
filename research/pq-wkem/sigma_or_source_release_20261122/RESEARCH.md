# Source-Sigma OR transcript completion: a tested candidate that does not release the planted secret

## Continuity and actual question

At start, open draft syscoin/PVUGC#1 branch research/pq-wkem-validation-20260918 was at 19c7702b8e57abb410f8d75bb1e72a87e0b7cd3c, the planted-OR-proof screen. Also read the exact recent adaptive-activation scope and public-frontier notes. Queried ordinary PR issue comments after 2026-11-20 UTC: none. No Core source or production was read or changed, and no real source certificate was processed.

The previous planted OR proof fails when its source proof and public metadata are conditionally independent of the planted hidden secret. This pass considers an actual *secret-dependent, publicly serialized proof transcript* rather than another independent proof: use the special-soundness algebra of a Sigma OR protocol to let a future source witness holder reopen a simulated arm. The mathematical change evades the independence premise in the narrow sense that the setup transcript does depend on the secret. The question is whether opening the source branch transfers the planted secret r, rather than only the source witness w, without giving that secret to everyone. This is a candidate screen and not an ORIGINAL hash-only FE/WKEM breakthrough.

## Exact target that is still missing

The bridge ORIGINAL predicate R_x(w) is a disjunction of (1) qualified same-anchor strictly greater exact Bitcoin chainwork, (2) finite authenticated missing/invalid burn authorization for the exact claim, and (3) qualified incompatible strict-post-PQ Syscoin histories or independently authenticated relevant tag fault at full required LC depth. Do not add greater Syscoin work, a winning fork, an N-of-N challenge quorum, a proof of no future fork, or rely on identical delayed tags to disprove conflict. x binds protocol/chain IDs, exact claim/outpoint, burn, amount, recipient, reserve and replay, baseline, BTC anchors/window, source height, deadline/reset, complete safe cancel transaction and VK, and capsule/session ID. At setup N parties are needed; afterward ANY ONE watcher with original evidence must locally release every fixed required contribution. For unknown future claim-specific activations, an honestly constructed initial capsule must already be a universal adaptive protected signer, unless a slot-global veto is approved.

## One explicit algebraic Sigma-OR transfer attempt

The following small cyclic group is only a mathematical *control for response equations*, NOT a discrete-log assumption, candidate hash-only foundation, practical setup, source verifier, Bitcoin protocol, or security parameter. For public Y_j=g^(x_j), a Sigma transcript (a_j=g^(t_j),e_j,z_j=t_j+e_j*x_j mod q) verifies g^(z_j)=a_j Y_j^(e_j). Let setup know secret r with public Y_r=g^r, and let the toy source statement have public Y_w=g^w for a witness w setup does not know.

The setup samples a secret-arm nonce t_r and challenge e_r, publishes a_r=g^(t_r), z_r=t_r+e_r*r. For the source arm it picks e_w0,z_w0 and SIMULATES without w:

    a_w = g^(z_w0)*Y_w^(-e_w0).

Publish a_w,e_w0,z_w0 and the OR challenge E0=e_r+e_w0. This differs from the prior proof-only candidate because the setup also publishes a real transcript correlated with r.

A later watcher knowing source witness w can reconstruct the simulated source arm nonce and reopen it at a different challenge:

    t_w=z_w0-e_w0*w,
    e_w1 != e_w0,
    z_w1=t_w+e_w1*w.

The resulting overall E1=e_r+e_w1 differs from E0, and both OR transcripts verify. However the setup branch challenge e_r and response z_r are UNCHANGED. Special soundness extracts

    (z_w1-z_w0)/(e_w1-e_w0)=w (mod q),

NOT the planted r. If the setup also publishes a valid secret-arm response z_r1 at e_r1 != e_r, anyone can immediately calculate

    r=(z_r1-z_r)/(e_r1-e_r) (mod q)

without an original source witness. Concealing z_r1 and allowing only genuine original source witnesses to unmask it is exactly the missing public protected release mechanism; a public proof verifier feeding an external accept bit does not implement that gate. Thus a public transcript of this form either keeps the planted secret untouched when w reopens the source arm, or leaks it unconditionally when the required extra secret-arm response is published. This verdict is **limited to these concrete transcript equations**; it is not a generic FE impossibility result.

The toy also assumes one fixed public Y_w during setup. The original fork/burn relation has potentially many future different witnesses, no universal fixed discrete-log statement about their bytes, and needs one frozen safe capability for all of them. Even a successful planted toy transfer would not by itself instantiate that broader relation. No arbitrary OR proof automatically converts knowledge of w into r.

## Executed checker and provenance

A Python3 standard-library checker was run twice in the working container and produced byte-identical JSON. It uses p=607, q=101, g=64, and 32 reproducible pairs (r,w). It verifies both OR transcripts, witness-dependent source reopening, the extraction of w rather than r from its changing challenge, and how a second publicly disclosed response of the SECRET arm algebraically exposes r. Neither discrete-log hardness nor any source-authenticated hash/PoW work is tested. Local check.py SHA256 5bb5be6b3f6db3250cf3aec3d5184163abd6eb98745ac964f6a54e7db3e8eb8f; two local JSON output SHA256 467affcc53c1761a3bdf86d0b7c741e319d0380f20206f082bc273afbcf964ff. The local independent archive SHA256 was 0b7bd6cee1763187defea0be9c13ff99ee4c86644eaa842e67f3f5c984fad600. All are synthetic controls, not cryptographic security tests. The checker and one captured output accompany this research-only note.

## Exact unfilled operation

The still-unbuilt function is serialized classical-PPT CompileUniversal(P0,sk_i;rho_i) -> C_i and PublicEval(C_i,A,W,T,w) -> the same deterministic safe native signature_i for every ORIGINAL qualifying w for that selected activation. Its joint public distribution must resist any arbitrary QPT algorithm, including malicious source/participant coins, native verifying keys, sibling capsules, selective openings and adaptive activation, unless such an algorithm can be turned into ACTUAL ORIGINAL certificate acquisition or independently justified hash/native break. The Sigma OR transcripts above do not provide a public source-dependent response gate or its joint simulator. No progress comment, user notification, activation, deployment, other repo write, or automation change is warranted.