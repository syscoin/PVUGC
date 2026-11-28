# Paired-seed routing with shared correction words — 2026-11-27

Nonqualifying static construction preflight, not a WKEM, deployment claim, or change to the source relation.

## Continuity and selection

Actual syscoin/PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, starting head b062a613343c51b6e57e17ab8e66c111b1d11520. Read actual metadata, recent substantive issue discussion through R225, exact start commit metadata and SOURCE_AUTHENTICATED_PREPROCESSING_20261127.md (blob 5f8d14eeabfaef2164704ff7852fe91f2c752d31), SOURCE_OR_TRANSCRIPT_TRANSFER_20261127.md and SOURCE_CLAW_NATIVE_CHAIN_20261127.md at the exact start. Rechecked unchanged head and absence of the present path (404 NOT_FOUND). No new Core facts or verifier changes.

Missing operation: a classical-PPT serialized public encoder and opener must make the actual frozen cancellation capability available from every qualifying ORIGINAL certificate and unavailable without one. The closest R289 attack combines independently accessible wire labels from inconsistent traces. The proposed mathematical change is to carry a single *paired-seed state* along the entire certificate, rather than separately usable labels for each input occurrence. Rejection paths should synchronize the two seeds, whereas all accepting paths should normalize to a common hidden terminal difference. Explore a DPF-like shared nonlinear hash expansion and correction, generated before the future source certificates exist. This is a preflight of an explicit correction equation, not an assumption of two noncolluding servers, an ideal evaluator, or a new independent puzzle. Do not implement a larger complete-state graph or another label-mixing fixture.

## 1. Exact candidate and its intended repair

Let R(x,w) be the entire finite bounded original predicate, with all three independent OR branches, authenticated histories, relevance, maturity and exact claim binding. Let a deterministic streaming computation process canonical padded certificate bits b_i. Its internal state includes the information required to verify the original relation, not just an asserted validity bit. Write P=(s_0,s_1,t_0,t_1) for a pair of lambda-bit seeds and binary control flags, and let G_i,b(s) be a domain-framed hash expansion. In this candidate all data accessed by Open, including both components of a reached P, are public to its evaluator. No privacy from one evaluator is assumed.

A public per-layer, per-bit correction C_i,b is used as follows (addition of seeds is XOR):

    u_a = G_i,b(s_a) XOR (t_a * C_i,b), a in {0,1}
    D' = u_0 XOR u_1
       = G_i,b(s_0) XOR G_i,b(s_1) XOR ((t_0 XOR t_1)*C_i,b).

The flags can be updated from additional hash expansion bits and public flag corrections as in a tree traversal. We grant the candidate arbitrary correct flag updates for the preflight; they cannot remove the displayed necessary seed equation. When seeds and flags synchronize, identical subsequent hash expansions and corrections preserve synchronization. This is a useful absorbing rejection invariant. At a known terminal accepting state the intended difference is a fresh lambda-bit K chosen by Build; the output payload is E=sigma_cancel XOR H_mask(ctx,K). A valid witness is meant to drive the pair to that accepting difference and recover exactly the same sigma_cancel. An unauthorized trace is meant to end synchronized or with no usable difference. There is no honest-code check after unmasking.

For a tree with explicitly enumerated prefixes, Build knows P at every visited node and can impose a chosen next difference D_target on any edge with t_0 XOR t_1=1 by choosing

    C(P,b) = G_i,b(s_0) XOR G_i,b(s_1) XOR D_target.

When t_0 XOR t_1=0, a correction cannot change the next difference at all; for an already synchronized reject state this is appropriate. A full prefix tree needs corrections for exponentially many future prefixes. State merging is required for PPT setup on the original source, not merely an efficiency improvement to an already secure original encoder. The whole-pair design avoids independent per-wire input labels in its *intended* interface, but must also withstand arbitrary use of both public seeds and arbitrary correction inputs.

## 2. Attempt to share a correction across distinct active prefixes

Try one C_i,b for all active prefixes at a given layer with the same next bit. Take two prescribed incoming pairs P,Q with control XOR equal to 1 and the same prescribed target difference D_target. Subtract the two required equations:

    G_i,b(s_0(P)) XOR G_i,b(s_1(P))
      = G_i,b(s_0(Q)) XOR G_i,b(s_1(Q)).

In the independent-output random-oracle idealization, for prescribed distinct unordered seed pairs fixed independently of these expansion outputs, this equality has probability 2^(-lambda). If one seed is shared, the two unshared outputs must coincide; if none is shared, the XOR of four independent outputs must vanish. If the two unordered pairs coincide the equation is redundant; that is actual state normalization (or an accidental seed-pair collision), not a correction mechanism for distinct states. If the prescribed target differences differ, the same equation holds with their XOR on the right. The probability argument in that case also needs those differences fixed independently of the expansion outputs. No adaptive QROM theorem is claimed here. The algebraic compatibility condition itself is exact.

A standard single-path point-function tree can set corrections around its one distinguished path while keeping other paths synchronized. Here Build does not have a distinguished qualifying witness, and must support every distinct future qualifying original witness. Setting independent correction words on each active prefix restores the tree construction but not polynomial setup. Sharing corrections by program counter is not enough. Shared flags or flag-dependent public corrections only choose from a bounded set of words, and each collision class of active pairs must satisfy the same compatibility equation. We did not implement a seed-pair generator guaranteeing those identities for the actual source verifier.

## 3. Try source-dependent correction without enumerating prefixes

Use a canonical digest d=H_state(ctx,i,complete verifier state) as a public correction address. A transition must depend on the actual source state, including needed prior certificate information; using just i and b discards it. Try a public correction function C_i,b(d,P) that computes the correct normalization word from the *whole* reached pair, rather than accepting independently mixed intermediate wire labels. One algebraic implementation is

    C_i,b(d,P) =
      G_i,b(s_0(P)) XOR G_i,b(s_1(P)) XOR N_i,b(d),

where N is a target difference associated with the next state. On any active pair, evaluation yields exactly N_i,b(d). At an accepting terminal transition N must equal K. This is exact regardless of the hash expansion.

This puts the source-dependent correlation into N, rather than into G. If N is public on arbitrary digest addresses, the desired terminal value is available from the accepting-state address without a witness whenever that address is computable; canonical accepting-state erasure makes it especially easy to compute. If N is public but restricted to being callable only after a valid transition, ordinary public code checking d or a source proof cannot enforce that restriction on direct calls to its underlying mask-correction computation. If instead N is a hidden PRF of a *full* state digest, independent outputs do not normalize distinct accepting states to K, and no serialized evaluation key for just the correct addresses has been constructed. A GGM prefix cover works for known simple subsets of addresses, not for the preimage set of actual qualified source histories under H_state. If N is assigned K at all accepting digests by a specially constrained public key, generation and full-public security of that key would already implement the missing original-source-dependent gate.

Consider a second repair: normalize early to one common pair whenever paths have the same verifier state, so a state-indexed rather than prefix-indexed edge table suffices. This is possible for an explicitly finite deterministic automaton with known states. However the original predicate needs, among other things, authenticated hashes, predecessor equality, chain context and exact work, and the source state space is not provided as a polynomial-size read-once automaton. A digest is a short *description of an address*, not a polynomial number of possible addresses. A read-many program with only program counter and bounded local state and arbitrary public per-occurrence transitions admits inconsistent input reads. The R289 splice applies unchanged if independent occurrence labels are reintroduced; reject that variant without fixtures. This does not establish a lower bound for every possible compiler of the source predicate. It identifies the absent implementation of the proposed correction mechanism. Merely hashing an address does not provide a secret-gated edge translation.

## 4. Joint simulation and disposition

For the explicit synchronized path invariant the hash expansion is public, and the builder can simulate honest traversal given all correction data. That is not a simulator of a real secret-bearing capsule: the shared-word version has incompatible correctness requirements unless its correlated seeds have a new construction, the public-normalizer version exposes its terminal difference, and the hidden-normalizer version has no public correction algorithm. Independent expansion randomness cannot be invoked as a full-view hybrid when the required correction identities correlate all active pairs. In particular a simulation that programs G on every accepting prefix is not a PPT classical Build for concrete hashes. No extraction from arbitrary QPT native-signature forgery, same-message variation, malicious source-coin retention or correlated auxiliary input has been proved. No independent source proof has been substituted for release.

The next viable paired-routing candidate would need actual polynomially serialized nonlinear pair normalization for the ORIGINAL source states, hiding the terminal common difference from arbitrary calls, with a joint simulator of the correlated pairs and correction words. Do not postulate the normalizer or repeat this candidate with more flags, another hash basis, or a larger complete-state graph. No code or tests were run: the static correction equations rejected the candidate before implementation. No external research, web, subagents, PR comment or qualifying notification.

All original OR branches, claim relevance and maturity, R316 coverage correction, R225 activation-bound or explicit slot-global endpoint, pre-funding malicious setup and availability, one-honest N-of-N separate from challenge, and network/inclusion assumptions remain unchanged. No generic NP impossibility or deployed-source assertion.
