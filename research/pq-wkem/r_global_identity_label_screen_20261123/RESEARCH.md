# Global-certificate-ID hash labels — source-conditioned gate screen (NONQUALIFYING)

## Provenance
One bounded offline screen of a candidate differing mathematically from the previous *public matrix automaton*: nonlinear SHA-derived labels bound to the hash of an entire future source certificate. Read open/draft syscoin/PVUGC PR #1 at start SHA `9f7c702675b3719a745b660098bd1e34c26d275b` on `research/pq-wkem-validation-20260918`, current preceding `research/pq-wkem/r_source_matrix_automaton_20261122/RESEARCH.md` blob `37abc1718fbed8bef0cccbdb587cd4f6edaa020e`. The latest top-level issue comments since 2026-11-21T00:00Z were empty. Core #609 metadata head observed `af4d78335c6b9b180e3f652909cd2ce3934d07a8`; no Core code/test read was necessary. No web or other repositories.

## Attempted source-linked transition
Goal: prevent public suffix-space extraction of polynomial-width linear programs and prevent R289's mixing of partial garbled evaluations from distinct source certificates. Fix x_W to protocol/chain/claim/UTXO/withdrawal/burn/recipient/amount/reserve/replay/baseline/BTC anchor/window/relevant height/LC fork depth/reset/deadline/native safe message, VK, and capsule ID. Keep the OR of (1) same-anchor strictly more exact BTC cumulative work, (2) finite authenticated particular-claim burn fault, (3) authenticated relevant Syscoin inconsistency/outer-carrier-tag fault at required depth. No extra Syscoin-work condition.

For a candidate original witness w choose public full-certificate identity

    mu(w) = SHA256("PVUGC full-source" || sid || CanonicalSerialize(w)).

Instead of reusable local labels L_(v,b), propose a secret seed a and labels

    L_(v,b,mu) = SHA256("PVUGC label" || a || mu || v || b).

Different certificates will normally have distinct mu, so labels taken from distinct certificates are syntactically incompatible. That is the *proposed* modification, not a security theorem. The goal is a polynomial serialized protected evaluator whose labels enforce one global authenticated w and converge to one frozen S for every qualifying ORIGINAL w.

## The decisive serialization/security screen
The essential public label-generation operation has only three specified realizations:

1. Publish a or publicly expose L_(v,b,mu) for arbitrary mu,v,b. A malicious evaluator chooses one mu and obtains both b choices for every v, so global identity does not force consistent assignments, nor does a public if-check prevent direct label or invalid-point queries. Previously demonstrated local mixing/invalid-trace regressions apply unchanged. A caller-chosen mu is not a source certificate.
2. Publish only H(a). Future challengers cannot compute L_(v,b,mu) for arbitrary qualifying w without a secret-keyed evaluator; this fails public every-witness completeness.
3. Publish a secret-key-protected evaluator which accepts full w, independently authenticates R_x(w) *inside* the protected computation, then supplies labels for mu(w). That is the ORIGINAL source-dependent FE/release gate, simply moved to input encoding. It is not implemented by naming a constrained PRF, zero-knowledge wrapper, ideal SourceOpen, or hash commitment. Neither serialization nor a full-public joint simulator is supplied.

Additionally, deriving the release pad from mu itself makes it witness-specific. Distinct qualifying original certificates generally have different mu, so the builder must also provide a protected map that yields the SAME S across all such mu. A public KDF of mu cannot accomplish this while preserving the frozen secret; a source-authenticated secret-dependent convergence circuit is the missing operation.

FALSE-instance release cannot be concluded from the absence of an admissible w: the *complete public bytes* (native VK and message, policy graph, setup proofs, siblings, corrupted participant coins, source histories) may reveal S without any prescribed Open call. No actual FALSE joint-public simulator was constructed. Hard-TRUE recovery from the whole package likewise has no extraction to an actual original certificate, and there is no coherent-QPT proof. The one-honest N-of-N ceremony can separately prevent bypass edges but cannot secure an insecure public label generator.

## Screening outcome
The global-identity change does eliminate the literal reuse of labels across *different predetermined mu*, but cannot serve as the source authentication/release mechanism if the attacker chooses mu and both bit labels. The only apparently sound option assumes precisely the missing hidden-global evaluator, so **reject without implementing another fixture/parameter sweep**. This is a scope-preserving negative screen, not a generic hash-only impossibility, an FE construction, or a breakthrough.

Exact missing equation remains

    C = Build_inc(x_W, sigma_cancel; rho), 
    Open_inc(C, w) = sigma_cancel for EVERY ORIGINAL R_x_W(w)=1,

with a concrete classical-PPT serialized Build/Open and a complete-public FALSE/hard-TRUE QPT unauthorized recovery/native forgery -> ORIGINAL qualifying certificate or independent justified hash/native break, including malicious setup and sibling selective openings.

No checker, FE, Core, original certificate or native signing tests were run in this particular screen, and no numerical claims are attached. No progress PR comment, public release, automation change or production edits are warranted.
