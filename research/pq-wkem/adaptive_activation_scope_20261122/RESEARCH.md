# Adaptive activation-scope FE gate — nonqualifying security checkpoint

## Exact continuity
Read the open draft syscoin/PVUGC PR #1 on research/pq-wkem-validation-20260918 at 70c8e6519e6f6cc470fef499463c26475a0c7bda, and exact public-frontier note blob 82755666b0573e7d04400c1062f73735ba1040fb. Latest queried ordinary issue comments since 2026-11-18 18:20 UTC were empty. Prior FE assessment at commit 69d4a071e0c68fce7c43c5233bd4839b66efb58a, RESEARCH.md blob 6cd435772422fdb740d36af25fd7a0f751f8737e, supplied the conditional fixed-vs-dynamic signing distinction. No Core source tests, actual Bitcoin/Syscoin certificates, external literature or web searches were performed.

This run examines a precise necessary security component, NOT an implemented hash-only witness KEM. The previously attempted global hash-garbled finite automaton exposes a public polynomial frontier and cannot substitute for a guarded release operation.

## New quantified requirement
At funding, all N parties participate ONLY in an initial setup. One notary may later initiate a permitted withdrawal with claim, burn assertion, source baseline and cancellation outpoint UNKNOWN during setup. A fixed-statement Compile(x_W,sigma_W) CANNOT be built at funding if x_W has not yet been chosen. Publicly compiling an activation-specific capsule later without a secret would already constitute the missing restricted signer; an online N-of-N signing step violates the liveness goal. There are two alternatives: (a) an explicitly approved slot-global frozen native veto whose cancellation message is fixed at funding, or (b) the stronger adaptive universal FE program below. Do not silently broaden claim-specific cancellation into a slot-global veto.

Freeze at funding a claim-INDEPENDENT policy P0 containing the funded graph and UTXO, keys, authorized initiators, source-verifier version, bounded witness length/LC-depth and proof windows, activation rules, claim schema, safe whole-UTXO cancellation, reset and timeout behavior, and a noncircular session/manifest identifier. The missing per-party publisher/evaluator would be

  C_i <- CompileUniversal(P0,sk_i;rho_i)    ONCE, before any future activation.
  Sig_i <- PublicEval(C_i,A,W,T,w)         later, from only public bytes.

The protected program computes

  U_i(sk_i;A,W,T,w) =
      DeterministicNativeSign(sk_i,SighashAll(T,CompletePrevoutContext(A)))
      if AllowedActivation(P0,A,W)
       AND H(Serialize(W)) equals the nonwitness claim commitment of A
       AND input(T) equals the actual claim-bound outpoint (txid(A),v)
       AND SafeWholeUTXOCancel(P0,A,W,T)
       AND R_ORIGINAL(Freeze(P0,A,W,T),w)
      else bottom.

Freeze binds exact protocol/chain/claim IDs, asserted burn, amount, recipient, reserve, replay authorization, baseline, verified source commitment, Bitcoin anchors/window, relevant source height, LC depth, deadline/reset, exact safe cancellation transaction/message and VK, and capsule ID. R_ORIGINAL is the required OR of (1) qualified BTC competitor of strictly greater exact same-anchor work; (2) finite authenticated missing/invalid burn authorization for THIS claim; (3) qualified Syscoin inconsistency/independently authenticated tag fault at specified LC depth. No greater Syscoin work, winning fork, fabricated arbitrary old fork, or challenge quorum. Post-PQ contextual AuxPoW must enforce modern child ID and exact canonical tag; equal stale tags do not disprove a fork; different parents for the same child alone do not establish one. Tag-fault carrier authentication must be separate from the check being disproved.

For any ONE frozen allowed (A,W,T), every qualifying ORIGINAL w must produce the SAME safe deterministic native signature under participant i's key; no same hidden preimage or forced common source history. Different activations have different signatures. Every required participant capsule must implement this SAME universal predicate, so one watcher locally obtains all native N-of-N signatures. There is no online participant signing or threshold aggregation. Hash-only FE CompileUniversal and PublicEval ARE NOT INSTANTIATED. Ordinary Bitcoin ECDSA may be used for the first release only under its classical native security; this does not establish full post-quantum system security.

## Exact adaptive security obligation
After seeing the entire joint public package (C_i, all construction proofs, native VK, graph, source commitments, other capsules and auxiliary data), the attacker may choose any allowed activation A and target transaction T, query/synthesize relevant source evidence, retain malicious source/setup coins, and selectively open sibling capsules. Security must concern *arbitrary computation on those bytes*, not only prescribed PublicEval. An extractor E must turn any unauthorized accepted honest-participant signature for the same selected activation into an ACTUAL ORIGINAL certificate for that activation or an independently justified native/hash break:

  Pr[ unauthorized accepted honest signature for selected (A,W,T) ]
    <= L Pr[ E returns (A,W,T,w*) AND R_ORIGINAL(Freeze(P0,A,W,T),w*) ]
       + eps_native + eps_hash + eps_joint_sim.

The loss L, source work/query counts, auxiliary distributions, and completeness/malicious-setup assumptions require exact independent proof. The honest FE participant has no retained bypass secret. Previously legitimately authorized signatures on the same native message are not unauthorized forgery. A classical first-accepting-query log does not automatically lift to coherent QPT evaluation or concrete SHA. No full-public joint simulator, QROM extraction, source-to-signature proof, or even public guarded hash-only gate has been supplied. This is a TARGET inequality, not a theorem.

## Why fixed-target security does not imply adaptive-activation security
Take an ideal correctly protected base signer only as an *abstract* control and add a bad wrapper: sample tau uniformly from 2^k possible activation identifiers, publish tau, and permit unguarded release at A=tau. For every A0 fixed BEFORE publication, Pr[A0=tau]=2^-k. An attacker reading the public capsule chooses A=tau afterward and succeeds with probability one. Thus even a negligible selective leak per prechosen claim says nothing about an adversary-selected later activation. This is a quantifier counterexample, NOT a real FE attack or an assumed existence theorem. An executed exact standard-library enumeration for k=16 finds 1/65536 selective exposure and 65536/65536 adaptive exposure. See check.py and output.json; these are deliberately non-cryptographic.

## Repair status / exact unfinished equation
The structural repair is to bind one universal, bounded activation+ORIGINAL-source predicate inside the *protected* compiler and demand adaptive multi-claim joint-public security, instead of claiming a fixed-x FE theorem composes after a new claim is selected. A public proof of correct compiler execution or a Merkle capsule root does NOT create the compiler. A public external verifier followed by an FE accept-bit is directly bypassable; a public invalid-trace pad or local label-join remains subject to previous attacks. Pre-signing every possible future txid/claim requires superpolynomial enumeration unless the native spend is genuinely frozen under an explicitly approved slot policy.

The STILL MISSING step is an actual classical-PPT, serialized, hash-only CompileUniversal(P0,sk_i)->C_i and PublicEval(C_i,A,W,T,w), with cryptographic SOURCE-gated SAME-signature opening for every qualified ORIGINAL w and full-public FALSE/hard-TRUE QPT recovery/native forgery reduction including malicious setup, adaptive activations and sibling capsules. This iteration only prevents an unjustified selective-to-adaptive promotion. Do not report it as original-foundation progress or notify the user.

## Executed local checker
Python 3 standard library; exit 0, precise scope only selective/adaptive quantifier enumeration, no FE, no native/Bitcoin/source checks. check.py SHA256 9489a6ae7c69bcd22b40e09f6d74b3bcba29eef4398842ceb78ddb717951787e; captured output.json SHA256 d0b1cce35e1792d76921680bda66eaa66b4a555cd213fdd049945ecf9aa65efb. No PR comment, Core/production edit, deployment, or automation change.