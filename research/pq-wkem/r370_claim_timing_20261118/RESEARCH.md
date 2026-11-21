# R370 — Late claim timing and FE source-release interface (NONQUALIFYING)

## Continuity
Read live draft syscoin/PVUGC PR #1 at research/pq-wkem-validation-20260918, start SHA 93eb717895d6b450fc543b87136ce594562b2c37 (R369), note blob 0ec817dd6e81c40f7efc05fe074bf29140095921, and R368 note blob 40ffcf726ed151308961c3ed1e7190d346c6bb41. Recent PR issue comments since 2026-11-18T18:00:00Z were empty. Core #609 metadata head b3b4f643383a2149807a25fe38d26b5f058daa60 was read, not Core source. No Core tests, actual source certificates or FE were run. This is not an ORIGINAL-source release advance and warrants no progress comment or user notification.

## Constructive timing / quantifier repair to the prior conditional FE plan
N signers meet once at t0 and protect/erase signing secrets. A one-notary claim W is chosen later at t1. If W and activation outpoint u_W were unknown at t0, then the exact cancellation digest m_W=NativeSighash(T_safe,u_W,...) and sigma_i(W)=Sign(sk_i,m_W) were unknown as well. A claim-scoped FE capsule holding a frozen sigma_i(W) cannot be correctly completed at t0 for an arbitrary future claim. A new Build after t1 needs online protected secrets, a concrete keyless Build, or a preauthorized dynamic program. Assuming a new N-of-N round violates the required one-time setup.

A conditional public-program repair changes the order of quantifiers: at t0 compile one reusable C_i=Compile(sk_i, policy_template, sid) independently for each participant i. The public policy must contain BOTH:
- InitOpen_i(C_i,W_body,A_W,alpha) which signs ONLY an approved claim-bound activation using alpha, an authorization credential of ONE permitted notary, after checking its allowed burn/amount/reserve/recipient and safe covenant graph;
- CancelOpen_i(C_i,W_body,A_W,T_safe,w) which signs ONLY safe cancellation of that authorized activation after checking the ORIGINAL authenticated OR witness w with exact claim/source/Bitcoin windows, LC maturity, tag fault, deadline/reset and native-message binding.

One notary can initiate, and any challenger with one qualifying ORIGINAL certificate can obtain the N signatures without online N participants. But these programs are SPECIFICATIONS, not implemented FE, and are stronger/more general than a per-claim frozen-signature capsule. A separately proven fixed-slot graph and explicitly slot-global veto may avoid dynamic signing, but cannot silently substitute claim-specific authorization. A simple publicly checked accept bit supplied to a protected scalar FE gate is bypassable.

## Noncircular source binding
Fix an independent sid before compilation. W_body contains source and claim semantics but not its own activation txid/outpoint, nor its own final capsule hash. Define

  script_W = Script(PUSH32(H(sid||W_body)), DROP, pk_1,...,pk_N, N-of-N)
  A_W = SerializeAuthorizedActivation(..., P2WSH(script_W), ...)
  u_W = (txid(A_W), output_index)
  x_W = (sid,W_body,u_W,authenticated baseline,anchors,windows,LC depth,deadline,reset,...)
  m_W = NativeSighash(T_safe,u_W,script_W,prevout_value,...)
  manifest = H(exact compiled capsules and graph)

Then authenticating x_W, m_W and A_W inside the protected program is acyclic. Instead putting H(x_W) into script_W when x_W includes u_W creates the cycle script->A->u->x->script. Putting H(C) into x_W while C contains x_W gives another cycle. A session ID fixed in advance plus a subsequent manifest prevents these syntactic cycles, but no public source-gated FE is thereby constructed.

A fabricated A_W with the expected script must still be rejected unless it is an authorized graph transition. In the actual graph, activation/output malleability and fee paths must be consistent with native sighash semantics; an unsafe SIGHASH flag is not a substitute for a proved covenant. Honest-key erasure cannot be proved from a transcript. Proofs that capsules were compiled as specified cannot make an insecure compiler secure or ensure useful correctness under arbitrary malicious tapes.

## Executed bounded checker / provenance
A Python3 standard-library dependency checker ran twice with byte-identical output. It detected both self-reference cycles, found an acyclic per-claim dependency order, flagged pre-setup fixed-signature timing contradictions for late claims, and derived distinct synthetic SHA256d activation outpoints for two distinct claim bodies.

  check.py SHA256 c2fb5f7853f215b29f7c9c6dca7da67d1b3aeff7671b7a7010d44bb305873240
  out1.json and out2.json SHA256 e42f89f8a9d429725518599c6931377fda1161803548115082a956706e3987f3
  local archive R370_claim_timing_20261118.tar.gz SHA256 8bd465eb9a678ab2b4272815da452da903e6e5c4bb5ad09d2b9f2ac076965e2e

The checker/output are LOCAL ONLY, and their persistence is not assumed. This is a symbolic dependency audit with deliberately synthetic serialization, NOT a Bitcoin parser, BIP143 or script test, actual source validation, FE algorithm, QPT proof or security theorem. The previous FE note separately recorded its own limited native-signature check.

## Missing ORIGINAL foundation remains
There is no classical practical SERIALIZED hash-only public Compile/Open for qualified original BTC greater-work OR specific authenticated burn fault OR Syscoin qualified inconsistency/tag fault, with the SAME safe cancel capability per instance for every original witness and full-public FALSE/hard-TRUE arbitrary-QPT security under malicious setup/source coins/sibling capsules. Even the reusable two-policy signer above is conditional, not a construction. The strict activated contextual AuxPoW chain ID/exact tag rules, R316 tag-coverage correction, original source maturity and claim binding are preserved.

No PR comment, Core edit, production change, deployment, or automation change. NONQUALIFYING; no user progress notification.
