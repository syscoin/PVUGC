# Full-certificate-tweaked gate transport — 2026-11-27

Nonqualifying static construction/repair iteration; no WKEM, QPT theorem or deployment claim.

## Continuity and selection

Actual start: syscoin/PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, head d744d707ef5463410abfe994ffede4f5827a2525. Read PR metadata, recent substantive comments through R225, exact head commit filename and SOURCE_CONSTRAINED_FSS_TERMINAL_CORRECTION_20261127.md (blob 91cf0e25b14b3e512004377991d1a257aeccf341), plus SOURCE_OR_PROOF_CHALLENGE_TRANSFER_20261127.md and SOURCE_PAIRED_INSTANCE_LIFT_CYCLE_20261127.md at that head. Re-read unchanged PR head; new path returned NOT_FOUND/404. No new Core-source claim.

Missing operation: witnessless classical-PPT serialized Build of one frozen safe native cancellation capability and public Open on EVERY qualifying ORIGINAL certificate, jointly with full-public QPT simulation/reduction. Candidate change: rather than fixed garbled labels shared across incompatible witnesses (R289), make every occurrence label and every gate-row correction depend on a digest of the COMPLETE canonical certificate. The intended anti-splice property is distinct label namespaces, not a final honest-code check. The new attempted operation is compact public transport of encrypted gate rows from setup to arbitrary future namespaces WITHOUT exposing untweaked labels. This differs from the last FSS single-terminal correction: transport must preserve local gate correctness throughout the computation. Public reversible tweaks are rejected immediately, since normalization preserves the old splice unchanged. Examine nonreversible seed expansion instead.

## 1. Serialization and transport equation

Let V_x be the complete original claim-bound verifier with all three independent grounds and actual authentication/relevance/maturity. Grant a correct Boolean circuit compiler with explicit fan-out/occurrence consistency; no Core implementation is claimed. For canonically encoded bounded input w, let t=H_cert(ctx,w), with context binding statement, capsule, protocol and exact native endpoint. For each wire i and bit a sample secret lambda-bit root s_(i,a), and define

    L_(i,a)(t) = H_label(ctx,i,a,t,s_(i,a)).

For each binary gate g with input wires i,j and distinct output k, and each row a,b, define

    M_(g,a,b)(t) = H_row(ctx,g,a,b,t,L_(i,a)(t),L_(j,b)(t)).
    D_(g,a,b)(t) = M_(g,a,b)(t) XOR L_(k,g(a,b))(t).

Use injective encodings and independent hash domains in the random-oracle diagnostic. The ordinary encrypted-row equation is exact: given matching labels and D, unmask the correct output label. Repeated occurrences of a wire must carry its same label within one namespace. Fresh namespace labels remove literal reuse of a label from another certificate, but this is NOT a QROM anti-splice proof and does not protect against a public encoder allowing both labels in one namespace.

Build knows all root seeds but no future certificate. Proposed public transport: sample a public per-row seed d_(g,a,b), serialize it as descriptor, and let

    Dhat_(g,a,b)(t) = H_corr(ctx,g,a,b,t,d_(g,a,b)).

The seed may be chosen adaptively during setup or derived from an untweaked row. The descriptor and computation are PPT; correctness needs Dhat=D. Grant for this preflight an ideal raw-input encoder supplying exactly the input labels at t for ANY canonical w, including invalid w. This is expressly NOT a constructed encoder: if it admitted only qualifying inputs, it would already implement the missing source gate. A terminal accepted-state mask would have to release the exact frozen sigma_cancel. First determine whether public gate transport itself works; do not scale or implement a fixture until this passes.

## 2. Fresh-namespace correctness

Fix a classical setup transcript including all queries and root/descriptor choices. Consider a subsequent classical evaluation on a namespace t for which Build made no label/row/correction query with that namespace field. Fix t independently of the unqueried domain contents, conditional on freshness. This is an explicit diagnostic condition, not an assertion about every actual source distribution or adversarial t. A future independently generated unpredictable namespace is a relevant completeness test; namespaces covered during setup are outside this calculation.

For any gate and row, reveal the two input labels, M and Dhat, then sample the output-label answer. The latter is fresh uniform independent of those values and the setup transcript. Hence

    Pr[Dhat XOR M = L_out | setup, fresh t] = 2^(-lambda).

Even equality of a public correction seed and a secret label root as strings does not change this: input encodings and domains differ. The same result holds if Dhat is any adaptive public computation of the setup transcript, t, input labels and other oracle answers, PROVIDED it does not obtain or otherwise depend on the fresh output-label answer. Reveal its transcript first and sample the previously unqueried answer. If it obtains that answer, independence does not apply. For at most q correction guesses without querying that point or conditioning on successful checks, a union bound is q/2^lambda. This is an exact classical experiment, not a quantum adversary bound or a universal limitation of public descriptions.

For a gate with multiple rows giving one output bit (AND has three zero rows), choosing the output label after the corrections also does not fix this particular construction. Let Z_ab=Dhat_ab XOR M_ab. Conditional on all input labels and row hashes, independent fresh correction hashes make the three zero-row Z values independent uniform; all agree with exact probability 2^(-2lambda). Choosing L_out=Z_00 does not make the other two zero rows decrypt to that label. This checks the candidate claiming all rows correct, NOT a claim all rows are reachable on one honest certificate. Defining the output per actual row instead removes the fixed-root specification at later gates, as below.

Thus the seeded-correction transport fails the stated fresh-namespace completeness test even before public input access, terminal recovery or joint simulation. No conclusion about concrete SHA or arbitrary non-black-box constructions follows.

## 3. Repair preflights

Row-derived child labels: recursively define L_out(t,w) from the actual row and prior labels rather than an independent root. This gives well-defined honest evaluation with public random Dhat, retaining full path-specific state even when semantic bits agree. However the accepted terminal labels now depend on the whole future evaluation, and Build cannot predict them. If final key=H_final(ctx,L_accept(t,w)) with a single public mask, different valid evaluations need the SAME final key. Fresh distinct inputs of an independent final hash do not guarantee that equality. One correction does not reconcile the independent outputs (cf. last FSS note). A new correction generator must yield the common key without exposing it on forbidden paths. No such generator is implemented; no enumeration or ideal terminal evaluator is an allowed repair.

Root-row transport: recover input root seeds from namespace labels; unwrap a conventional setup row containing the output root seed, then derive L_out(t). This would make transport algebra exact if seed access were supplied. But any recovered s_(i,a) computes its label in EVERY namespace. In a raw-input encoder accepting arbitrary syntactically valid candidate inputs, any bit with both possible values supplies both reusable root labels. Structural regression for a generic compiler: V'_x(w)=V_x(w) OR (z(w) AND NOT z(w)), where z is a freely variable raw-input bit, preserves exactly V_x's acceptance predicate. With both reusable z labels and ordinary root rows, feed z=1 to the AND occurrence and z=0 through NOT. A true output label propagates through OR with any available V output label despite the contradictory branch never being true for any consistent input. This is a regression against the repair and generic local-consistency claim, not a forgery against an exact Core verifier or an actual deployed capsule. Seed access restricted to already qualifying witnesses would reintroduce the missing source gate.

Public reversible transport: L(t)=L(0) XOR H_tweak(ctx,i,t), or another publicly invertible recoding, lets observers normalize, mix and reapply tweaks. R289 applies unchanged; reject without another fixture. Authenticating a public tweak does not make its labels nontransferable.

## 4. Joint simulation and next operation

Sampling independent public correction seeds is not a simulator for correct real capsules: a holder of a valid original witness and its stipulated labels checks a row and distinguishes by the fresh-namespace computation. Programming fresh correction outputs at each future evaluation is not an implemented classical serialized Build/Open; it would need a joint QROM argument including malicious retained source coins and related capsules. No programming is performed here.

The precise missing local operation is a publicly usable descriptor T_g so Eval(T_g,t,L_i,L_j) gives the correct nontransferable L_k at matching rows for future namespaces, without publishing normalization/seed recovery, while descriptor and raw-input encoding are jointly simulatable and cannot yield inconsistent accepted paths. The terminal SAME-capability equation and actual source-dependent input encoder are additionally unsolved. A successful local transport alone would not satisfy the original release obligation.

Do not continue by enlarging row counts, a different hash basis, seed trees or independently pseudorandom label marginals. A different correlated transport rule or a route avoiding transport altogether must instantiate actual source-conditioned release and its simulator. This is not a general impossibility result for source-specific computational hash release.

All original OR grounds, R316 actual LC maturity correction, R225 endpoint choice, one-honest malicious setup/pre-funding correctness, auxiliary/sibling QPT composition, exact native recovery versus accepted forgery and timely admissibility/inclusion remain unchanged. Static derivation only; no cryptographic checker, tests, subagents, web or literature. Expanded local derivation was saved; this file preserves the equations and their limitations. No ordinary PR progress comment.
