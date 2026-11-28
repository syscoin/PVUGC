# SAI99 — simulated canonical proof-token route, early construction screen (NONQUALIFYING)

## Provenance and explicit unfinished operation

Read actual open/draft syscoin/PVUGC PR #1 head ceaca833c5b5c139cbbd5299bac6b9e2ea46fc17 on research/pq-wkem-validation-20260918, updated 2026-11-21 15:04:06 UTC; exact SAI98 note research/pq-wkem/sai98_global_root_mixer_screen_20261121/RESEARCH.md, blob bf31aea31ada276f62bfb345fd4611bac8a2470c, and targeted latest PR issue comments (none since 2026-11-18 19:24 UTC). SAI98's published local matrices can be mixed to recover the secret without one original witness. This attempts a structural alternative: one global witness-independent hidden proof token rather than separately composable public transitions. No Core #609 source or tests were reread.

The required operation remains a practical classical-PPT, serialized hash-only Build_original(x_W,S)->C and public Open_original(C,w)=S for EVERY qualifying ORIGINAL witness, with full-public FALSE/hard-TRUE QPT security and malicious one-honest setup. Three OR branches, modern contextual AuxPoW, claim-prefix, maturity, source relevance, and exact native cancellation remain unchanged.

## Candidate: setup-simulated canonical authenticated proof token

Try public Setup(1^lambda)->(pp,tau), Token(pp,x,w), Sim(tau,x), Check(pp,x,y). Require Token(pp,x,w)=y_x for all original R_x(w)=1, and Sim(tau,x)=y_x even before any original certificate exists. An honest participant computes y_x, K=SHA256('SCT-pad'||sid||canonical(pp,x)||y_x), D=S XOR K, publishes C=(pp,x,sid,D,agreed proof/manifest bytes), and erases tau,y_x. Open computes Token on a supplied original witness, verifies the token and yields D XOR SHA256(...||token). Every-witness common-value correctness follows IF the unique-token equalities hold. The sid/native authorization must be inside the token's statement to avoid sibling-capsule selective-opening portability.

A classical ideal-hash proof plan would couple the full public package to an all-random pad until the adversary queries the specific hidden y_x. Without such a query a uniformly masked frozen S cannot be recovered except guessing. To turn this into ORIGINAL resource security requires extraction from ANY public adversary learning y_x to an ACTUAL qualified original certificate or an independent hash break, and a joint QPT simulation correlated with native checking keys, setup proofs, adversarial source coins and sibling capsules. Neither a reduction nor an implementation is claimed.

## Attempted hash-only instantiation by deterministic transparent source proof

A natural approach is hash of a deterministic transparent proof transcript for the original verifier. Those transcripts normally commit to a witness-dependent trace. Consider two distinct original certificates w0,w1 whose authenticated SHA/AuxPoW traces t0,t1 are different. If the full proof transcript includes a binding Merkle root H(encode(t_i)), identical transcripts would imply equal roots. Different authenticated traces opening the same root imply a hash collision or a broken binding assumption. Thus merely removing prover randomness cannot make the transcript *identical* for every heterogeneous original witness. Omitting the trace binding and publishing only 'accept=1' cannot cryptographically restrict access to authentic source evidence.

A secret simulation trapdoor by itself also does not repair this: after erasure, watchers still need a classical public deterministic method to derive that exact hidden y_x from ANY original w. Taking that derivation as an axiom is the missing source-specific witness-PRF / common-value release mechanism renamed, not an independently instantiated primitive. Conventional SHA preimage/collision assumptions and ordinary proof soundness do not supply it. The attempt is therefore REJECTED at symbolic pre-screen; no larger synthetic test or program was justified.

## Exact handoff

Any substantive return to this architecture must actually implement all of: (1) practical public Setup, Token and Sim producing one y_(x,sid) for all ORIGINAL witnesses; (2) hidden-y joint public distribution and a concrete QPT recovery-to-ORIGINAL extractor; (3) malicious setup/capsule correctness and native claim/outpoint binding, including no nonuniform auxiliary shortcut. Otherwise move to an independently structured serialized global source gate, not another transcript/hash/commitment change.

NONQUALIFYING: no ORIGINAL Build/Open, no independently instantiated FE/WE/WPRF, no source work or QPT theorem, no Core test, no native signature, no user notification, PR comment, production edit, deployment, funds transfer or automation change. This is not a generic impossibility claim.
