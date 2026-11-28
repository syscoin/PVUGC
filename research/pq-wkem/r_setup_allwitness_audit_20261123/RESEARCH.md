# One-honest FE ceremony: universal-correctness audit vs pointwise FE correctness (NONQUALIFYING)

## Source and research boundary (2026-11-23)

Live draft **syscoin/PVUGC#1**, branch `research/pq-wkem-validation-20260918`, inspected head `fedc144e63982ae1b3733374fe84b315d7c70ee8`, latest source-ID-tree screening note `research/pq-wkem/r_source_id_tree_screen_20261123/RESEARCH.md`. Immediate previous head `120c33b575bf0d651ab45c033b2a7c8aa0c03f0d` screened a proof-uniqueness shortcut. No top-level issue comments were returned since Nov 20. Core PR #609 metadata was checked only (then-head `af4d78335c6b9b180e3f652909cd2ce3934d07a8`); Core source, native tests and source certificates were NOT run/read this execution.

The new user-approved first release can use ordinary native BTC signatures, but the release foundation stays hash-only and must work for EVERY qualifying ORIGINAL source witness with the unchanged three OR branches, strict post-PQ contextual AuxPoW, exact claim/outpoint/burn/amount/recipient, anchors/windows/depth/reset/deadline/capsule and safe native message/VK binding. The live original-source FE compiler/decapsulator and full-public QPT security reduction are MISSING.

This pass continues the FE one-honest setup prerequisite from `research/pq-wkem/fe_gate_assessment_20261118/RESEARCH.md`: can a malicious participant satisfy a ZK proof of *correctly running an FE compiler* yet publish a capsule that is unopenable for at least one genuine future challenge?

## Candidate: commit-before-beacon compiler-randomness ceremony

Propose a **conditional** ceremony, not a replacement for FE. Fix public pre-manifest `M_0` committing to chain IDs, the exact source policy/verifier version, funding graph, all N native keys, authorized initiation, full withdrawal/cancel path policy, public cryptographic algorithms, session ID, and a noncircular future-activation rule before randomization.

1. Each participant `i` independently commits `h_i=H("seed"||M_0||i||s_i)` to a hidden compiler seed `s_i` and commits to a random beacon share `b_i`. All commitments are binding before opening any beacon shares. The honest participant contributes a fresh uniform `lambda`-bit `b_h`.
2. Reveal all beacon shares; abort without funding on a missing/invalid reveal. Let `B= b_1 xor ... xor b_N`. Before `b_h` is revealed, `B` is uniform conditional on already committed corrupt shares. Bind each compiler tape by domain separation:
   
   `rho_i,j = H("FE-rand" || M_0 || i || j || s_i || B)`.
   
   Distinct `j` denotes setup, encryption, function-key generation and any relevant encryption signing stage, not reused randomness.
3. Each party creates a FE capsule and a privacy-preserving proof for the exact finite relation `pk_i=Sig.PublicKey(sk_i)`, `Verify(pk_i,m,sigma_i)=1` for known-message mode, matching seed commitment, deterministic `rho_i,j`, exact FE.Setup/Enc/KeyGen and policy-circuit byte commitments. In dynamic signing mode protect `sk_i` and prove the actual restriction on allowed messages/activation/claim. No secret seed, signature or signing key is opened.
4. A public checker verifies all N proofs, canonical manifest bytes, exact native script/graph commitments, data availability and required preauthorization *before* irrevocable funding; refusal aborts, never triggers a fallback spend. All N native signatures are needed for protected edges; any watcher with one valid ORIGINAL challenge would later evaluate all public capsules, not contact any party.

**Proof boundary:** In the *classical random-oracle model*, if corrupt parties must bind their `s_i` and all identities/`M_0` before the honest beacon and cannot grind an unbounded number of sessions, a fixed precommitted malicious seed cannot force a selected compiler tape before seeing `B` except via prediction/prequery. With at most `Q` relevant prequeries and uniform honest `lambda`-bit beacon, the elementary probability of a prior exact input hit is at most `Q/2^lambda` (plus binding/collision errors). This is NOT a QROM proof, NOT a concrete SHA guarantee, and NOT a full-public simulator of FE ciphertexts. Selective aborts after beacon revelation and resets must be accounted for, with the source claim/session/restart bound fixed. The corrupted party can still reveal its own secrets or intentionally abort.

## The crucial stronger correctness obligation

Typical pointwise probabilistic correctness:
`forall w:R_x(w)=1, Pr_rho[Open(Build(x,S;rho),w)=S] >= 1-epsilon`
does NOT imply the needed **simultaneous** property:
`Pr_rho[forall w:R_x(w)=1, Open(Build(x,S;rho),w)=S] >= 1-negl(lambda)`.

**Exact counterexample:** Let `R_x(w)=1` for all `w in {0,1}^lambda`. A maliciously accepted generator chooses a uniform excluded point `b` and returns the required `S` for all `w!=b`, but `bottom` for `w=b`. For *every fixed* `w`, the scheme is correct with probability `1-2^-lambda`, yet for *every setup tape* there exists a qualifying future witness it will not open. Even perfectly uniform, audited compiler coins and a proof of correct generator execution do not repair this. Giving N of N other people honest capsules does not overcome the one malicious unopenable required contribution. The toy check exhaustively verified the lambda=8 identity, not an ORIGINAL source instance.

**Correctness repair requirement:** Make the accepted compiler relation enforce `forall accepted rho, forall original w with R_x(w)=1, Open(C,w)=S`, or provide an independently proven all-witness (uniform-over-w) negligibly failing FE algorithm with a suitable failure bound. A union bound over exponentially many allowed future source witnesses is invalid for a merely pointwise claim. A setup proof of correct execution is only useful after the compiler's *strong* correctness theorem is established.

A concrete possible **local-audit subcomponent** for a garbled Boolean circuit is to prove in zero knowledge that all four rows of every AND/Ch/etc. gate encrypt the output label for their specific input-label pair. This is polynomial in gate count and yields an induction establishing **universal circuit evaluation correctness for consistent input labels**, independent of future source witness enumeration. For a 2-input AND gate:
`T[a,b]=H("gate"||L_in1,a||L_in2,b) xor L_out,a&b`
for each `a,b in {0,1}`. Checking all four equalities verifies the local function for both bit choices; induction over the DAG checks all valid label paths. **This local audit does not instantiate a zero-knowledge proof**; revealing all input/output labels destroys release security. More fundamentally, it does not supply source-derived coherent input labels that are unavailable to fabricated histories and mixed witnesses. That is the *still missing protected source gate*.

The executable local check additionally demonstrates the gate-label bypass: under a synthetic false-source policy allowing only input `(0,0)`, publishing both garbled input labels allows direct evaluation of forbidden `(1,1)` and disclosure of the output-1-masked secret without an original source witness. This is not a new attack on a complete source FE scheme; it is a regression disqualifying naive clear-label setup audits.

## Executed evidence and exact limits

Python 3 standard-library `check.py` executed successfully on 2026-11-23 UTC, output captured in `output.json`. It exhaustively checks 256 possible excluded witnesses for lambda=8, computes fixed-committed-seed SHA outputs for 65,536 synthetic public beacons, verifies all four hash-XOR AND-gate rows, detects one deliberately corrupted row, and demonstrates the false-source public-two-label key recovery.

- `check.py`: SHA256 `a84da4d05fd1a9c1ee4d4bd7c5c09c6f4e81e251b70c243cc65154e2c0d86e80`; git blob `fba36967e606556d8226cd5107f32635246fc306`.
- `output.json`: SHA256 `194355a503b82281ae80c35c44f1173bdcbc995e92a69c6d49918976203739e8`; git blob `5a81b6055c8f3c9f3d5236cb5757205cc1a2ebae`.
- Checker is synthetic only: **no FE compiler, no ZK protocol, no QPT proof, no real source certificate, no native cancellation signing, no Bitcoin/Core tests**. Its empirical SHA beacon dispersion is NOT a proof for concrete SHA.

## Disposition and honest next equation

**NONQUALIFYING.** This is a distinct malicious-setup/useful-completeness component and a concrete audit design, not a substantive resolution of ORIGINAL hash-only release. Do not notify the user as a breakthrough, post a progress comment, or interpret local test counts as security evidence.

The missing independent foundation is still an actual classical-PPT **serialized** `Build_orig(x_W,sigma_cancel)` and public `Open_orig(C,w)=sigma_cancel` for EVERY qualifying ORIGINAL witness, whose *whole public package* including native VK, setup proofs, sibling capsules and auxiliary/corrupt setup state admits a FALSE/hard-TRUE QPT recovery/accepted-native-forgery-to-ORIGINAL-certificate reduction or an independently justified hash/native break. A proof of garbling correctness, transparent setup, a revealed acceptance bit or a hidden FE master key is not the missing primitive.

No PR comment, production edit, deployment, Core modification or automation change during this pass.
