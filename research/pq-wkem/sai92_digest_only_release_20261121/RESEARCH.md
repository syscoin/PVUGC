# SAI92 — digest-only source-terminal gate: exact fresh-oracle substitution (NONQUALIFYING)

## Continuity and candidate

Started at the live open/draft syscoin/PVUGC PR #1 branch research/pq-wkem-validation-20260918, head cf9d8d8e2c483eb9716b49e1a63884d056383a3f (SAI91), with note blob 857f511fd8467d7043f1d37e0623ec94688f2638. SAI90 and SAI89 exact notes were read (blobs da98d29b8a2970c31790bea36f38f2b195e5fda7 and 065037c5ee6aa0c236a0713df4008950eb950021). Targeted ordinary PR comments after 2026-11-18T19:24:00Z returned []. No Core #609 source reread or Core test run.

SAI91 considered a degree-bounded polynomial rebase of a witness-specific hash terminal. This iteration checks a distinct proposed repair: an arbitrary public nonlinear terminal decoder whose only source-dependent secret-bearing input is a digest t inside the valid PoW target interval, while complete source verification is performed as an unprotected outer check. No degree restriction, polynomial correction, or known finite witness table is assumed. A useful construction must recover the same setup-frozen safe S from every original-valid witness but not from a fake digest without an original source certificate.

Candidate syntax (NOT SECURE):

    C = Build(x_W,S;r)
    t = TerminalHash(w)
    if VerifyOriginal(x_W,w): return TerminalDecode(C,t)

## Exact restricted random-oracle attack

Fix an independently authenticated, source-relevant header prefix p and fresh candidate nonces n_j. The ONLY remaining condition in this deliberately restricted final-header model is that H(p||n_j) belongs to T, the admissible target-digest set in a finite digest space D. Full claim ancestry, contextual AuxPoW and other original checks are held fixed in the model; this is not a proof that raw digest bounds suffice for the full bridge.

Model H as a random oracle and condition on the new candidate inputs not having been queried by Build or correlated with its published C. Let a=|T|, d=|D|, Y_j=H(p||n_j), and J be the first success among at most m trials. For any t in T:

    Pr[Y_J=t and J<=m]
      = sum_(j=1)^m ((d-a)/d)^(j-1) / d
      = (1/a) * (1-((d-a)/d)^m).

Hence Dist(Y_J | J<=m) = Uniform(T).

An attacker sampling t_fake uniformly from T, WITHOUT producing a header, coinbase, Merkle path, AuxPoW or source ancestry, supplies exactly the same digest distribution. For any public terminal-only function F(C,t) whose effective source-dependent input is only t (no internal authenticated source proof or preimage witness):

    Dist(F(C,Y_J) | J<=m) = Dist(F(C,t_fake)).

If honest valid-source terminals release S with probability at least 1-eps in this distribution, synthetic low-target digests also release S with at least that probability. The attack does NOT invert SHA or forge the source evidence. It bypasses an unprotected external verifier by calling the secret-bearing digest decoder directly.

This is a classical restricted IDEAL random-oracle statement, not a theorem about concrete SHA or coherent QPT access. Miner-selected correlated nonces, Build's oracle prequeries, and contextual validity conditions outside this model require separate analysis; in particular, the proof must NOT be cited as a general no-go for source-specific FE, Merkle witnesses, iO or the ORIGINAL relation. The inference concerns a digest-only terminal mechanism, even a nonlinear one, and is orthogonal to SAI91's interpolation dimension bound.

## Repair attempt and indispensable missing operation

Passing the COMPLETE original evidence into a cryptographically guarded program avoids the forged-digest substitute in its desired functional specification:

    Gate(C,w) = S if R_original(x_W,w) else bottom.

Merely checking R_original before invoking a still-public digest-only decoder does not repair the vulnerability. A public unprotected source verifier, source Merkle root, or accepted proof bit is not a hidden-label delivery or secure key gate. A ZK verification wrapper does not generate a secret-bearing public evaluator. The SAI86 virtual semantic-state architecture can still serve as a constructive reference, but this iteration implements neither its exponentially large secret edge table nor a polynomial publicly accessible secure update.

The indispensable next equation is an actual serialized classical-PPT

    PublicAuthenticUpdate(C,token_(i,q),b,authenticated_source_prefix)
       -> token_(i+1,delta_x(q,b))

whose terminal produces the SAME frozen safe native cancellation capability for EVERY original-valid witness, plus a joint-public FALSE/hard-TRUE arbitrary-QPT recovery-or-forgery reduction to an ACTUAL original certificate or independently justified hash/native break. This cannot be implemented merely by making a common digest, exposing a PRF seed, outsourcing the check to an optional wrapper, or presampling future source hashes.

## Executed bounded check and provenance

The accompanying Python3 standard-library checker exhaustively enumerates every oracle transcript of m=1,...,5 trials over a size-eight digest space with T={0,1,2}. It verifies that the conditioned first-success digest distribution is precisely (1/3,1/3,1/3) in all five cases, and that every one of the eight binary success predicates over T has identical valid-source and fake-digest success probability. The no-success fractions are (5/8)^m. This checks finite combinatorial identities, NOT SHA security or full-source authentication.

Local initially executed script SHA256 ff9ca45f3559f9142a03328ffd21d53c57c7032275d3451d491480d82ef08e3f. Captured output SHA256 776ae5904d5f46afb026be141e24f03d32b49a8ad2df6f81cf46869342068927. This note, checker, and output are being published as research-only files; no Core tests, Bitcoin/Syscoin original certificates, native signature, compiled FE, ZK proof, or QPT security check ran.

The ORIGINAL bridge target is unchanged: one-notary initiation and ANY qualifying ORIGINAL challenge, independently via greater exact competing BTC work, finite authenticated withdrawal-specific burn fault, OR strict-post-PQ qualified Syscoin history incompatibility/tag fault at the required LC depth. Strict tag/contextual admission, real relevant child ancestors, anchors/claim/UTXO/burn/amount/recipient/reset/deadline, safe native message and capsule binding, one-honest preauthorization, and no bypass edges remain mandatory. R316 stale tag equality is not evidence the strict light client misses authenticated fork conflicts.

NONQUALIFYING. This is an anti-spin regression excluding only the digest-only release path; it is NOT a source-gated WE/FE construction, a reduction proving hard-TRUE security, a progress announcement or a reason to disable the existing automation. Do not post a PR progress comment or notify the user.
