# Source-conditioned release by conjugated verifier transitions — 2026-11-26

Research only: static construction/repair screen; not a qualifying original release advance.

Continuity: actual PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, start and prewrite head 9ae9719981e29dac517328bf71841d5ce868e792. Read metadata, last returned substantive issue comments through R225, exact latest SOURCE_FEASIBLE_STATE_MIGRATION_20261126.md (blob e9ad2e0f7261160ce62e734cf20177e9b0281290), SOURCE_FIXED_TRANSCRIPT_EXPLANATION_20261126.md, SOURCE_DUAL_COPY_RESOLUTION_ROUTING_20261126.md, SOURCE_PAIRED_INSTANCE_REDUCTION_20261126.md and SOURCE_SPECIAL_SOUNDNESS_RESPONSE_20261126.md. New file returned NOT_FOUND/HTTP 404 at the prewrite head. No new Core claim.

## Selection before implementation

Missing operation: offline classical-PPT Build(x,S) must create a public capsule from which EVERY qualifying ORIGINAL witness w releases the SAME frozen native cancellation contribution S, with arbitrary full-public recovery/forgery security. R_x(w) denotes the complete bounded relation, including all three original OR grounds, actual source authentication, relevance, claim, maturity, window and native-message binding; no actual new source compiler asserted.

Rather than choosing a hidden native assignment bit by bit (previous feasible-state migration), use the original witness itself to drive a public sequence of nonlinear state transitions. Conjugate the entire verifier configuration at each time, including all stored input and intermediate memory, by a separately keyed hash-Feistel permutation. The honest opener follows an exact original computation, without an independent native search, separately accessible wire labels, an affine source evaluator, or a common proof transcript. Attempt to hide the accepting terminal state from those who cannot follow a valid execution. The mathematical change is a global state transport with a path-independent terminal configuration, not another coefficient basis or fixed hash probe. Assess serialization and arbitrary state-injection before implementation. Do not assume the public transition functions can be safely obfuscated.

## 1. Explicit candidate and missing lift

Fix a polynomial time bound T and fixed-length m-bit machine configurations for a deterministic verifier of R_x. Input bits can be consumed by public time-indexed functions F_i(s,b); computation-only steps ignore b. Include the entire work tape in s. Pad to a fixed length and time; on the last step erase all remaining memory and map the completed accept/reject flag to two distinct fixed public configurations a and r, respectively. Thus for every qualifying witness, starting from fixed public s_0 and following the specified bits of w, the final clear state equals a. This normalization is part of the candidate, not a claim about the existing Core verifier.

Build samples independent keys k_i for i=0,...,T. Let P_i be a hash-based Feistel permutation of the entire m-bit configuration, with even width (pad if needed); e.g. an eight-round balanced Feistel with round masks ExpandH("lift-round",ctx,i,j,k_i,right,m/2). Distinct hash domains for round masks and payload pad. This is an invertible explicitly evaluable construction; no claim that eight rounds under concrete SHA supply a QPT PRP proof is needed for the attacks below. Build computes:

    L_0 = P_0(s_0)
    G_i(L,b) = P_{i+1}(F_i(P_i^{-1}(L),b))
    E = S XOR ExpandH("lift-pad",ctx,P_T(a),|S|).

Open starts with L_0, consumes the full original w, computes L_{i+1}=G_i(L_i,b_i), and unmasks E with L_T. An ordinary full original verifier can fail closed for invalid honest inputs but is not credited with security. If G_i is evaluable, correctness for EVERY original witness follows by induction: L_i=P_i(s_i) and hence L_T=P_T(a). Native signature distribution and checking-key correlations are not implemented in this shell. With an independent synthetic uniformly random S one can also use a domain-separated hash check of S for the attack game.

Actual classical-PPT Build can serialize the G_i as ordinary circuits with the keys embedded. But those are public; an adversary reads the last permutation key and obtains P_T(a) directly. Correctness thus does not establish security even on FALSE x. No label splicing, original witness, oracle programming, or hash break is needed. Publishing only the transition function's description without its keys is not an algorithm. Do not implement the key-exposing version or replace Feistel by another publicly keyed nonlinear permutation.

## 2. Independent defect of the proposed global-state lift, even if key hiding were granted

For this screen only, give the proposal MORE than its actual hash-only construction: a public evaluation interface for each G_i that perfectly hides its internal permutation keys. This is not proposed as an available primitive. Unlike the direct constant-read attack, the following attack does not inspect any representation of the evaluator. It tests whether global state conjugacy itself would solve the full-public problem.

At i=T-1, the normalized F maps every arbitrary input configuration with accept flag 1 to a, and every arbitrary input with flag 0 to r. All m-bit strings are legitimate encodings under the permutation, regardless of actual reachability. For each uniformly chosen label L, P_{T-1}^{-1}(L) is uniform on configurations, exactly for EVERY fixed permutation. Thus G_{T-1}(L,0) returns P_T(a) or P_T(r) with probability 1/2 each, even on a FALSE source statement. This is not two inconsistent original witnesses and does not use a fabricated history as an accepted witness. The evaluator is invoked at a state that was never reached from L_0.

After q independent uniform labels, failure to sample the accept label is exactly 2^{-q}. Failure to see BOTH possible outputs is 2^{1-q} for q>=1. Each of the two outputs yields a candidate native capability by the public unmasking equation. If S is an exact accepted frozen native signature, run the public native check on each candidate: either an accepted candidate suffices for the forgery objective, and the true S is among the candidates except with probability 2^{-q}. For the synthetic exact-recovery game, the native hash check identifies S except for a hash collision; for a two-message hiding game, the publicly chosen distinct candidate payloads allow distinguishing except for accidental pad matches (under a random-oracle pad idealization). Even without a check, randomly selecting one candidate gives nonnegligible recovery. No ordinary EUF claim is used to identify exact same-message signatures. This classical attack extends directly to the full-public QPT setting because a QPT adversary can execute it classically.

The same problem arises if the final acceptance flag is represented by k publicly checked bits instead of one: random-input acceptance probability is whatever fraction of ALL clear configurations maps to a, not the fraction of reachable configurations. Increasing k or searching for a rare syntactic terminal state is not the sought original evidence dependency. In particular, a random inaccessible terminal state could block honest opening just as an independent puzzle does. The explicit probability above applies to the stated final-normalization design, not every possible hidden state machine.

This attack differs from the preceding hidden-coordinate migration, which had a native greedy search independent of w. Here honest w determines all transitions efficiently; the injected final state bypasses the entire prefix. It also differs from local garbled-label mixing: only whole m-bit inputs and outputs are used, with one evaluation of a global transition per trial. Hiding the transition's implementation, even if possible, is not sufficient.

## 3. Constructive repair attempt: sparse authenticated state lift

Try eliminating surjectivity rather than another permutation. Let each encoded state at level i be

    L_i(s) = (P_i(s), H("lift-auth",ctx,i,P_i(s),t_i)),

with independent hidden t_i and lambda-bit tag (truncate/domain-separate as required). Replace G_i by the actual verify-then-translate map:

    parse (u,v)
    if v != H("lift-auth",ctx,i,u,t_i): return FAIL
    u' = P_{i+1}(F_i(P_i^{-1}(u),b))
    return (u', H("lift-auth",ctx,i+1,u',t_{i+1})).

Start with the tagged state L_0(s_0). Unmask E using the ENTIRE tagged accepting state L_T(a), not just its first component. This exact repair preserves the same induction and eliminates the section 2 uniform-label injection at the level of idealized secret-key evaluation: with a fresh uniform tag on any fixed u, probability of passing is exactly 2^{-lambda}, even before an accept test. That observation concerns random injection only, not adaptive/QPT MAC security or arbitrary reachable-state manipulation.

The explicit serialized classical-PPT version still reveals t_i and k_i. An attacker computes the correct final label directly. Could remove explicit t_i by publishing public hash-chain authenticators: start with a public seed h_0 and derive h_{i+1}=H("lift-chain",ctx,i,h_i,u_i,b_i,u_{i+1}). If the verifier checks only that the next tag matches this equation, any attacker can choose arbitrary previous u,h and compute a tag; it is not evidence of rooted reachability. If it checks the complete chain from the fixed initial state, the chain does supply a globally consistent trace (with all transitions genuinely checked), but it no longer implements the secret-key translation or common terminal tag. The final chain tag depends on the full path, so different qualifying original witnesses need not agree; publishing a common-mask correction per accepting chain would require solving the original transport operation. Deriving h_T solely from the public normalized a makes it publicly computable. No code implementing the unhidden-key versions is warranted.

An explicit encrypted-edge table could instead carry (u',v') under H("lift-edge",ctx,i,L_i(s),b) for every transition from every clear state. Build can produce these rows knowing the keys, and local evaluation can use the exact full-state label without recovering those keys. But the complete table has 2^m configurations per layer and is not PPT for the original verifier. Restricting it to an efficiently enumerable set of reachable states also permits public traversal of those same edges, providing a witness or establishing no accepting endpoint in that finite graph. Do not count exponential tables or ideal hidden transition evaluators as a repair.

## 4. Exact unresolved equation / handoff

A genuinely different continuation would have to implement an authenticated, sparse, nonlinear state lift with serialized public transition code and secret terminal encoding, while:
- using actual complete original evidence to generate the authenticated states, not an independent secret token;
- preventing arbitrary invocation at unreached states and transfer between independently generated traces;
- allowing every original witness to reach one and the same secret terminal encoding, without a table of accepting traces or independent hidden opening;
- giving a joint full-public simulator/reduction for all transition code, initial encodings, native checking data, auxiliary correlations and related capsules.

For example, a new construction would need an actual classical PPT Eval_i(C,L,b) realizing the sparse-state transport without revealing a seed from which arbitrary L_i(s) is constructible. Merely postulating this operation, a hidden-key gate, or a full-trace membership check followed by native recovery is not a solution. The concrete constructions here are rejected before implementation. No parameter sweep or tests. Not a general impossibility theorem; no QPT MAC, PRP, or concrete SHA proof is claimed.

No original source compiler, native endpoint, malicious setup, joint simulation or arbitrary hard-TRUE recovery theorem. R316 maturity and R225 endpoint scope unchanged. No external literature, new Core inspection, local code execution, delegated agents, or ordinary PR comment. Notification gate not met.
