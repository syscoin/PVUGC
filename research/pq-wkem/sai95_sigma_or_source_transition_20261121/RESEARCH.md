# SAI95 — Frozen sigma-OR proof transcript as a proposed non-black-box source-release carrier (NONQUALIFYING)

## Continuity and selection

Read the live open/draft syscoin/PVUGC PR #1 at 11a842079773038be3265fdbb36f90acdb861892, branch research/pq-wkem-validation-20260918. Latest SAI94 note blob: da499fe6e9ae3f0d45f92f138487798b956be7aa; SAI93 source-edge note blob: 64d11ba2daf035deb06bb5816dbfc27e7e4b7804. Targeted top-level comments after 2026-11-21T09:26:00Z: none. The inspected Core #609 *metadata* head is b3b4f643383a2149807a25fe38d26b5f058daa60; no current Core source/test read or run. No original Bitcoin/Syscoin source certificate or native signature was generated.

SAI94 eliminated one class of locally-patched hash-oracle public gates under its STRONG every-oracle correctness premise. Rather than repeat hash-prefix pads, feature masks, GGM edge labels, or oracle programming, this iteration examined a different proposed source-to-secret mechanism: special-soundness extraction across *two accepting sigma-OR transcripts with the same first commitments*, using an authenticated future source witness to construct the second transcript.

**Conclusion for this specific attempt: a genuine source witness can change the source (B) response, but the resulting extractor obtains the already-supplied source witness, not the independent setup secret needed to unmask the cancellation.** A complete-public two-world coupling demonstrates that no public decoder based only on these transcript bytes and the source witness can recover the intended payload in a small exact algebraic model. This is a rejected candidate, not a generic impossibility theorem, a hash-only FE scheme, or ORIGINAL source-release progress.

## Target and attempted compiler

Let A_y(s) denote knowledge of the one honest setup participant's hidden credential or hash preimage s. Let B_x(w)=R_original(x,w), the *unchanged* qualified bridge challenge disjunction: strictly greater exact work in relevant competing Bitcoin history; finite authenticated withdrawal-specific missing/invalid burn; or qualified strict-PQ Syscoin history inconsistency / independently authenticated tag fault at the required LC depth. These remain OR grounds, not a challenge quorum. x binds exact claim/outpoint, withdrawal/burn/amount/recipient, baseline and relevant history, BTC anchors/work/windows, LC maturity, deadline/reset, native cancel message/VK and capsule/session identifier.

Assume A_y has a three-move proof with first message a_A, challenge e_A, response z_A, and special soundness when two *different* challenges at the same a_A are both accepted. Setup knows s, generates one A proof response and a simulated B branch transcript, and publishes a complete sigma-OR transcript:

    T0=(a_A,a_B,e_A0,z_A0,e_B0,z_B0),
    e_global0=e_A0 XOR e_B0.

Setup chooses K=KDF(s) and D=S XOR K for its fixed safe cancellation capability S. The suggested Open should take a future original w, make a *different* accepted OR transcript with the *same* a_A,a_B, extract s, and return S=D XOR KDF(s). No source-generated s, canonical future fork, second notary, on-chain proof, or online signer is supposed to be needed.

A fixed Fiat-Shamir hash of identical statement, first messages and domain ordinarily gives only ONE global challenge. To avoid rejecting this idea solely on transcript mechanics, the analysis **grants** the candidate a second global challenge, e.g. from an additional domain/session nonce, and tests whether it can recover s even under that favorable concession. This concession is not itself a secure noninteractive transcript compiler.

## Exact branch-rewriting algebra

In a linear sigma protocol over F_2, with public M, y=M*w, one can commit to a=M*r and answer e in {0,1} via z=r+e*w. Verification is

    M*z = a + e*y.

A simulator without w can pick (z0,e0), setting a=M*z0+e0*y. A later holder of any witness w for y can convert that simulated response for the SAME a to a new challenge e1 by computing

    z1 = z0 + (e0+e1)*w.

The new response verifies. Given the two transcripts at different challenges,

    z0+z1 = w.

This is a concrete positive suboperation: B's real witness permits rewriting B's simulated transcript at a fixed commitment. But within the OR transcript, the holder leaves A unchanged at (e_A0,z_A0), varies the global challenge by varying only e_B, and therefore the pair extracts w **from B**, not setup secret s **from A**. Forcing a second challenge e_A1 != e_A0 at the SAME a_A would instead require a second valid A response; by A special soundness, that response already encodes knowledge of s. No independent ORIGINAL fork, burn fault or Bitcoin work certificate supplies such a response. Publishing a second A response or a freely callable A response generator leaks s without a source challenge. Cryptographically gating the generator on B_x is exactly the unresolved release primitive, not a repair that can be assumed.

## Exact joint-public indistinguishable-world correctness obstruction (TOY MODEL ONLY)

Take A as the binary 3x4 matrix that selects secret coordinates 1,2,3. Let delta=(1,0,0,0), so A*delta=0. Choose two setup secrets s1=s0+delta, same public y=A*s0=A*s1, and randomness r1=r0+e_A0*delta. Then the entire published A transcript is identical:

    A*r1 = A*r0,
    r1+e_A0*s1 = r0+e_A0*s0.

Publish the same simulated B transcript in the two worlds. Define synthetic payload bits S1=S0+1 and toy masks K_i=ell(s_i), ell(v)=v[0]. Because ell(delta)=1, D0=S0+K0 = S1+K1=D1. Consequently all published A/B transcript fields, their public verifier matrices, the B instance and ciphertext are BYTE-IDENTICAL across worlds, while the desired payload bits differ.

Any future B-witness-based second transcript uses only these shared public fields and the supplied w. It too is byte-identical across worlds, regardless of which of the several valid B witnesses was supplied. An opening algorithm on this distribution cannot return the correct S in both worlds; averaging uniformly over them caps its success at 1/2. The toy DOES NOT instantiate a native VK correlated with the target signature, an actual hiding hash commitment, a real SHA/AuxPoW relation, or a QPT simulator. It is an exact algebraic correctness counterexample to the selected transcript-release method, not a security result about FE in general.

A zero-row contradictory B system produces a FALSE fixture with no witness and no second B response. Hiding a payload when B is false is insufficient: the TRUE fixture also lacks any source-dependent route to the independent setup secret. Public proof validity cannot be substituted for a secret-release operation.

## Why an actual strict-PQ AuxPoW fork does not provide the missing A response

Modern contextual AuxPoW and canonical tag rules allow at most one valid modern Syscoin child per authenticated *parent commitment*, subject to hash/Merkle binding and the original coinbase being authenticated. Two conflicting legitimate Syscoin histories may be certified by DIFFERENT valid Bitcoin parents. The strict one-parent commitment rule does not create two responses to one setup commitment; if one requires two distinct children from exactly the same authenticated parent, one has silently restricted branch 3 to an impossible/fault condition outside ordinary valid-fork evidence. Parent tag observations may reference a common earlier ancestor while actual child histories already differ; source qualification follows authenticated history coverage, not bare latest-tag inequality (corrected R316). A shared known baseline ancestor is public, not an unknown s. This candidate neither disputes fork detection nor imposes greater Syscoin work.

## Executed checker and bounded provenance

Local Python3 standard-library check.py was executed successfully. In a four-bit F_2 source toy, all 16 assignments were checked: four valid B witnesses can rewrite the frozen B branch at an alternative challenge; twelve invalid assignments cannot. For two different valid witnesses, the extractor recovers that B witness. The A challenge and A response stay unchanged. The two different-payload worlds have exactly equal public capsule bytes. A contradictory B relation accepts none of 16 attempted rewrites. No signature, proof-system cryptographic security, real source, honest N-of-N ceremony, Core test or QPT experiment was run.

Local-only reproducibility bundle /mnt/data/SAI95_sigma_or_source_transition_20261121.tar.gz, SHA256 7faff41d85837ae412eb21f25895113649b451935d84246871023aff40fa5083. It contains complete local RESEARCH.md derivation, check.py (SHA256 e9b5d115dbe0c25075d8c3177746a8a1a5fed2c5947c347427a6065cb0c432b5), captured output.json (SHA256 545e0400088ea1ff6dbe8e7f56ec589077fc8928f219d6d2284d927af94dcb1c). These executable bytes are NOT claimed to be GitHub-published in this note.

## Repair attempt and exact unfinished obligation

Try setting the A challenge to SHA256 of the full authenticated source certificate: that merely chooses e_A1. It does not manufacture z_A1 for the SAME a_A without s. Letting the simulator choose a NEW a_A1 forfeits the special-soundness extractor; exposing all responses at the old a_A reveals s to anyone. Feeding a source proof into a normal external verifier has the same bypass, and proving correct setup cannot fix the missing response generation.

A true repair must implement a practical serialized *non-black-box source-conditioned* response operation that outputs a valid second A response for every original qualifying w, while the entire public package resists unauthorized computation. Such a response function, composed with the already-public special-soundness extractor and D, would itself instantiate the original public Build/Open functionality; neither this checkpoint nor a generic sigma-OR proof provides it.

Still missing: classical-PPT Build_original(x_W,S)->C, public Open_original(C,w)=S for EVERY original qualifying witness, exact claim/native/chain binding, full-public FALSE and hard-TRUE QPT recovery/accepted native forgery -> actual original certificate or independently justified PQ hash/native break, malicious one-honest N-of-N setup, sibling/selective-opening/source-coin composition, practical evidence availability and timing. No security assumption is replaced with a renamed release oracle.

**NONQUALIFYING.** No PR progress comment, user breakthrough notification, deployment, production or Core write, merge, or automation change.
