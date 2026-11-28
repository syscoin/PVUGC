# Paired-seed tree release: construction preflight (2026-11-28)

Research only; nonqualifying. The original source predicate, release capability and trust boundary are unchanged.

## Selection and provenance

Actual start: syscoin/PVUGC PR #1, open/draft/unmerged, same-repository branch research/pq-wkem-validation-20260918 at beaad18899b63f256f09e666dca69463f7311f6d. Read its metadata, recent substantive discussion (through R225), head commit filename, and exact SOURCE_ROOT_BOUND_LABEL_TRANSFER_20261128.md (blob 6731d8001bd1c271a732fad4f0c3132193ca1c49). The preceding attempt lacks joint root-specific input transfer and public row translation. No new Core source assertions, web use, other repository access, code execution or agents.

Missing operation: a witness-independent polynomial-size serialized capsule must cause every full authenticated ORIGINAL witness to yield the same hidden native cancellation contribution. The change selected for preflight is a *paired, full-prefix seed evolution* instead of separately transferable input/intermediate labels. Each evaluator follows a single full witness from the two root seeds; the proposed secret is a difference of terminal masks rather than an accepting gate label. This would avoid R289's direct independently selectable wire-label interface if it worked. The proposal uses only symmetric hash expansion, not a group, LWE, a private evaluator, or a source-side secret. Do not assume that conventional single-key function-secret-sharing security survives revealing both keys.

## 1. Specify the candidate before scaling

Let V_x(w) be the complete unchanged bounded ORIGINAL predicate. Use canonical fixed-length witness encoding with length N (including padding checks). Domain-separate all hashes by context and capsule identifier. For clarity write XOR throughout and consider one lambda-bit payload; longer fixed native contributions could use a KDF if the key release were secure.

The capsule would contain two root seeds s0,s1, two root control bits t0,t1 with t0 XOR t1=1, a polynomial list of public correction words CW, and one final word T. The honest Open expands both states on each bit of the same w. For branch b at depth i define

    (u_j,v_j) = Expand(i,b,s_j)  // lambda-bit seed and one control bit
    s'_j = u_j XOR (t_j * W[i,b])
    t'_j = v_j XOR (t_j * B[i,b])

for j in {0,1}. Multiplication by a bit selects the word or zero. A shared, public, depth/branch-indexed correction W,B is applied identically by both evaluators, conditional on their own control bit. With q_j the resulting terminal seeds and z_j their control bits, define

    F_j(w) = H(end,q_j) XOR (z_j * T)
    OpenRaw(C,w) = F_0(w) XOR F_1(w).

The intended invariant is synchronized pairs at rejected terminals (so raw output is zero), and z0 XOR z1=1 at every accepted terminal, with a common D=H(end,q0) XOR H(end,q1) that the builder knows. Set T=sigma XOR D. Then every accepted witness obtains exactly sigma. No final honest-code check could compensate for failure of the hidden correlation. This is a candidate recurrence, not an implemented Build.

The candidate does not export two choices of a garbled label for an individual wire. However, both evaluator states and all correction words are necessarily visible or computable from C and a selected prefix. The proof must therefore model both keys jointly and arbitrary access to state-update code, not an honest transcript. Secret sharing of the two root keys between unavailable parties would change the trust model and is excluded.

## 2. Try to generate shared corrections by forced synchronization

For a parent with t0 XOR t1=1, merging the two child seeds requires

    s'_0 XOR s'_1 = u_0 XOR u_1 XOR W[i,b] = 0,
    t'_0 XOR t'_1 = v_0 XOR v_1 XOR B[i,b] = 0.

Thus the unique correction that synchronizes that child is

    W[i,b]=u_0 XOR u_1, B[i,b]=v_0 XOR v_1.

For an already synchronized parent, synchronization is preserved automatically for either branch with any common correction. For a still-distinct parent with opposite control bits, the correction to collapse a branch depends on that parent's two expanded seeds. This is useful for one specially selected path: the builder can compute the expanded states on that path and synchronize the off-path child at every level. But for ORIGINAL acceptance there are many possible surviving prefixes, not one selected witness. The builder must handle them all and does not know future valid witnesses.

If two distinct still-live parent pairs need to collapse the same branch at the same level, a single depth-indexed W,B can work only if their two raw XOR differences are equal. For four fixed distinct fresh hash-expansion inputs in an ideal classical random oracle this equality has probability 2^(-lambda-1) for the combined seed/control word. This is a local calculation, not an adaptive QROM bound or a claim about correlated inputs. In the general candidate, states may be adaptively correlated, so a successful construction would need to generate and prove such correlations, not invoke the fresh-input probability as a universal impossibility. A vanilla shared correction word does not construct them.

Also, a rejection decision based on whether a prefix admits any extension is not itself an available efficient operation. Local finite checker failures could synchronize earlier, but there is no assumption that deciding live prefixes for the complete source relation is PPT. The terminal V_x check alone does not construct the desired synchronized seed pair.

Try instead making W,B a public function of the full prefix and its two current states. At a rejected transition it can simply evaluate the two raw differences above. This achieves local synchronization without a secret key. Unlike the previous root-specific garbling attempt, no hidden row translation is required for that local operation. But synchronization is merely a way to cancel a public output, not a way to create a hidden accepting output. The terminal calculation must be addressed independently and jointly before treating this as a repair.

## 3. Attempt the terminal calibration

For every accepted witness with opposite terminal control bits, the exact output is

    OpenRaw(C,w) = D_w XOR T,
    D_w = H(end,q0(w)) XOR H(end,q1(w)).

One global T works iff D_w is the same D for every qualifying ORIGINAL witness. A builder can calibrate to one supplied witness, but that is not the required witness-independent Build and does not establish all-witness correctness. For two fixed accepted terminal pairs with four distinct fresh independent terminal hash inputs, their D_w values coincide with probability 2^(-lambda). Choosing T after computing one difference cannot change their relative XOR. Again this is only the fresh-output preflight; a deliberately correlated transition construction would have to invalidate its premises.

Consider forcing the same ordered pair (a*,b*) at every accepted terminal using a reset rather than relying on accidental hash equality. For fixed terminal parents with opposite control bits, common XOR correction preserves one seed up to its raw expansion: the evaluator whose control bit is zero is not adjusted. A single W cannot reset both seeds arbitrarily. A broader reset with two independent masks can force a fixed pair, but the simplest public implementation would publish a*,b*, or derive them from the public verifier's accepting state. Then anyone computes D=H(end,a*) XOR H(end,b*) and sigma=T XOR D without ORIGINAL evidence. Checking V_x(w) in the reset implementation does not hide these constants. If a*,b* are instead hidden and obtained by decrypting a public reset word using the actual witness-dependent state, one needs a serialized correction generator that produces that same pair for *all* qualifying states without revealing it on unrelated states. No such generator was supplied by the seed expansion or synchronization.

A second attempt is to make the terminal correction T_w depend on the current pair. Correctness requires

    T_w = sigma XOR D_w       (accepted w).

The two public evaluators can already compute D_w from their chosen state. If the proposed expression for T_w embeds sigma as a public constant or uses a public common reset mask, it exposes the payload directly. If it uses an undisclosed seed for sigma-dependent correction, it has not implemented public Open. It would be circular to assume a function releasing T_w at every accepted prefix while its own public encoding hides sigma. Replacing XOR with a KDF at the output does not generate the required correlation.

The ordinary single-target correction-tree construction cannot be invoked here as a black box: it requires the target path at setup, and publishing both keys reveals their paired control differences along branches. A polynomial collection of explicitly supplied target paths is an easier finite release set, not the original unknown future evidence relation. Enumerating all accepted terminal pairs or all distinct correction contexts is not a demonstrated PPT Build. No implementation of a new public correlated hash expansion that satisfies the missing all-accepted-terminal invariant is claimed.

## 4. Decision and precise next handoff

Reject this explicit shared-correction candidate before implementing a toy source fixture. Its local rejection synchronization can be computed with public inputs, but it provides no hidden common terminal difference. The missing operation in this direction is a *jointly generated nonlinear terminal correlation*:

    (C,D) <- BuildCorrelation(x,VK,M;rho)
    Q_w <- PublicPairEvolution(C,w)
    H(end,Q_w[0]) XOR H(end,Q_w[1]) = D     for every V_x(w)=1.

BuildCorrelation must be an actual classical-PPT algorithm independent of the future witness, with a non-circular false/hard-true security reduction. Publishing T=sigma XOR D is not the missing part. A future paired-state approach should explain how its concrete serialized correction words jointly generate the correlation without enumerating accepting states or making D a directly evaluable function of a public accepting-state identifier. Do not merely change the PRG, correction field, or hash placement in this recurrence.

Even obtaining this invariant is not a full proof: the adversary sees both evaluator keys, arbitrary auxiliary input and source coins, the native VK/message, related capsules and T, may access hashes coherently, and need not follow a canonical trajectory. An independent-label or single-key FSS simulation is not a joint simulator. A hard-TRUE recovery/native forgery reduction cannot assume the attacker discloses its selected witness, states or query log. All three source branches, qualification, setup correctness/erasure, graph binding, replay and native signature scope remain required. No generic-NP or hash-only impossibility claim. No qualifying advance, ordinary PR comment, or user notification.
