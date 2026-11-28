# 2026-11-23 — two-share DPF source compiler and lazy correction screen (nonqualifying)

## Continuity and candidate selection

Read actual PVUGC PR #1 metadata: open/draft/unmerged, head 6019928c6d6ec01f846d6b371b584c9e424b7904, branch research/pq-wkem-validation-20260918. Read recent substantive comments including R225, the exact head note SOURCE_SINGLE_PROOF_EXPLANATION_SCREEN_20261123.md (blob f82a070361e2d883af46958647f219726ddb24db), and SAI113 source-bound GGM ticket note at this head. Filtered changed filenames for FSS/DPF/GGM precedents; no entire PR diff or historical archive reconstruction. Read starting Git commit/tree 061e298ccf24e25dc8595d608eb6bd94fa0efed0. No new Core source claim, external literature, production changes, or deployment. R316 is only a stale-reference coverage regression.

Missing operation remains classical-PPT Build_inc(x_W,sigma_cancel) -> serialized C and public Open_inc(C,w) -> the same exact native safe cancellation signature for every qualifying ORIGINAL w. R(x_W,w) is the unchanged three-ground OR, including anchored greater exact BTC work, authenticated finite burn-authorization refutation, and qualified relevant mature Syscoin history inconsistency or properly typed tag/carrier fault. Context includes all claim, source, window, replay, maturity, native message/VK and endpoint bindings. It is not the PoW output inequality alone.

Structural delta from R289's independently selectable occurrence labels: try two *whole-input* functions with a common payload difference, not a per-gate garbling or split-mask circuit. Each share evaluates on a complete canonical padded source certificate, not on individual wire labels. Use paired-seed distributed point function (DPF) recursion and shared correction words. The split of a single valid trace into inconsistent local labels is not the proposed operation. SAI113's public output-range key is also not used: the domain is original input bytes, not a claimed PoW digest. Both keys must be public, and ordinary one-key DPF privacy is explicitly insufficient.

## Candidate release and exact proof obligation

Let F_0 and F_1 be evaluated by two public classical algorithms on the same encoded w. Attempt to generate their serialized keys from x_W and a uniform lambda-bit k with

    F_0(K_0,w) XOR F_1(K_1,w) = k   if R(x_W,w)=1
                              = 0^lambda otherwise.

Build publishes (ctx,K_0,K_1,E), E=sigma_cancel XOR KDF(ctx,k,len(sigma_cancel)). Open uses the pair difference (and may check R as an optimization, never as the secrecy gate). For the candidate exact-zero construction take k nonzero. This gives the required every-witness common value IF the actual two-key generator exists. Evaluating different complete strings w0,w1 would not algebraically splice local labels, but this observation does NOT show security; arbitrary algorithms see both keys, internal states, masks and correlations. The necessary joint reduction would simulate both keys and E with native context/auxiliary information without k or sigma_cancel, or extract an ORIGINAL certificate from arbitrary recovery. Two marginal PRF claims do not suffice. Nothing here programs a QROM or invokes independent-label results for source-dependent labels.

## Explicit DPF recursion

Investigated standard paired GGM seed/control-state recursion in the XOR output group. At a prefix p the pair of states is (s_0,t_0),(s_1,t_1), with lambda-bit seeds and one-bit controls. In child direction j, a public hash-expander returns G_j(s_b) and control bit g_j(s_b). A common correction word (a_j,b_j) is applied to both shares:

    s'_i = G_j(s_i) XOR (t_i * a_j)
    t'_i = g_j(s_i) XOR (t_i * b_j),    i in {0,1}.

Here multiplication by a bit is selection of zero or the correction. If the pair is identical, all future deterministic symmetric transitions are identical and the XOR output cancels. If t_0 XOR t_1=1, the correction that kills the child by making its complete pair identical is uniquely forced:

    a_j = G_j(s_0) XOR G_j(s_1)
    b_j = g_j(s_0) XOR g_j(s_1).

For a single known distinguished input the usual point-tree idea is to kill the off-path child and keep the on-path control parity unequal. At the distinguished leaf a common final correction makes the payload difference k. That Build requires the distinguished input; extending by a sum of one-point keys requires already knowing/enumerating all accepting leaves and is not a source-dependent PPT generator for the ORIGINAL relation. We did not implement such an easier relation.

For a compressed multi-point compiler with shared correction words per depth/direction, two active prefixes p,q requiring a killed child in direction j force the same correction to equal their two seed-expander differences. In an independent ideal random-expander model for four distinct seed/direction inputs this is an XOR collision of four uniform lambda-bit values. Over Q distinct queried inputs in one direction, the probability that ANY four distinct outputs have zero XOR is at most 3*binom(Q,4)*2^-lambda (the factor 3 is conservative; the zero-XOR event itself is the same for the three pairings). If two unordered seed pairs share exactly one seed, equality of differences requires a collision of the remaining two outputs, bounded by binom(Q,2)*2^-lambda. These are bounds over all sampled distinct oracle inputs, so cover classical adaptive selection of those inputs. Equal unordered pairs and within-pair seed equality are exceptions, not covered by the four-distinct argument. No QROM or concrete SHA bound follows.

Intentional pair aliasing can avoid a correction collision, but if two prefixes at the same depth have the same complete state pair up to exchange of share indices, deterministic symmetric future transitions with depth/direction-only corrections and XOR decoding give identical suffix functions. In particular the two prefixes must have the same residual acceptance language for exact zero versus nonzero k. This is not a general lower bound for FSS: it restricts this specific state-sharing implementation. For source verification with future hash-state/ancestry dependence there is no demonstrated compact representation of the needed residual languages, and Build does not know the future certificates.

## Repair: remove eager pruning and make correction words prefix-dependent

Eager pruning has an additional public-view issue: in the exact-pruning variant where pair identity occurs iff a prefix has no accepting extension, an arbitrary classical capsule holder can find a witness whenever one exists. Starting at the root, evaluate both child state pairs; at least one is nonidentical, choose it, repeat until the leaf. Induction on prefix viability yields an accepted complete input in O(m) paired steps for m input bits. This does not rely on any adversarially supplied state. It does NOT establish an invalid original certificate or unconditional impossibility. It does contradict a joint hard-TRUE hiding argument on a distribution whose ORIGINAL certificates are independently hard to find, because the capsule itself provides a polynomial witness search. Exact dead-prefix pruning is therefore not the appropriate public representation. The implication does not apply if nonidentical prefixes can still have no accepting extension.

Attempted repair uses only witnessed prefix transitions, allowing a nonidentical pair even when no accepting suffix exists; exact zero is required only at the terminal leaf. Correction words become prefix-dependent. This removes both the forced shared correction equality and the exact viability-search implication. To make Build polynomial, avoid a per-prefix table by allowing Open to compute the correction jointly from its two current states and public prefix. This sacrifices independent share evaluation but is a permissible candidate public Open if the full capsule remains secure. For parity one, any desired next seed/control difference (D_pj,e_pj) can be enforced by the explicit public operation

    a_pj = G_j(s_0) XOR G_j(s_1) XOR D_pj
    b_pj = g_j(s_0) XOR g_j(s_1) XOR e_pj.

Thus the local correction equation can be solved without setup knowing every valid source prefix. The problem is now the SAME common payload invariant and its hidden source dependence, not selecting the transition word. In the terminal XOR decoder with fixed final word c, one needs

    H_out(s_0(w)) XOR H_out(s_1(w)) = k XOR c

for every accepted w with control parity one, while the entire pair evaluator and c remain public. A fresh unpredictable difference per accepted input cannot decode one precommitted k. Publishing c_w for each accepted leaf is the disallowed exponential witness enumeration. Choosing c_w at evaluation time requires a secret-dependent value not yet constructed.

Concrete repair options screened before coding:
- Carry a common difference d through the recursion, possibly blinded by a public prefix mask B(p). The proposed next difference is D_pj=d XOR B(pj), where d is recovered from the current pair XOR and B(p). The root pair and B(empty) are public, so anyone computes d immediately. If k is a public function of d and ctx, release is bypassed; if k requires a second hidden invariant, this repair has not constructed that invariant.
- Use a late final correction that reads the original verifier's Boolean result and assigns the appropriate pair difference. If the target difference or mask is in the public evaluator, the caller can compute the accepted branch directly; an ordinary if-check is not cryptographic release. If only a target hash is public, matching the target via seed selection is an additional preimage search unless the original certificate already supplies that preimage under a separately constructed relation. The original witness does not automatically contain a seed preimage for a Build-chosen hash. No independent source puzzle is allowed.
- Hide exact pair-state equality behind an extra common PRG cover share. With both keys public, separately represented additive cover shares can be removed by the caller. Mixing the cover into the PRG inputs instead removes the exact same-input cancellation property; a new hidden correlation would be needed. Neither change generates the missing terminal mask.

These repairs were screened analytically; the relevant direct public-access attacks are not improved by larger fixtures, different hash placements or more correction-word bits. No checker or benchmark was executed. This is not a claim that all nonlinear joint state evaluators, concrete hashes, or scoped WE are impossible. The candidate fails to instantiate the terminal equation, and no complete-public simulator or extraction reduction was supplied. A shared correction bound alone is not research completion.

## Handoff

A genuinely different continuation would need a public source-prefix-dependent state transition whose hidden invariant is not a publicly recoverable root/difference, and whose terminal extractor works for every full qualified ORIGINAL certificate without requiring the same certificate or a Build-programmed independent puzzle. It must simultaneously specify how Build produces that correlation without witnesses and how the paired-state public view is simulated or reduced to independently justified QPT source/hash/native hardness. Late pruning, exact same-input FSS correctness and independent one-key privacy are not substitutes. No further DPF prefix/parameter sweep is warranted without this missing correlation.

Preserve all ORIGINAL scope and one-honest setup, capsule correctness before funding, native signature/accepted same-message forgery, related-capsule and auxiliary dependence, malicious retained source coins, slot-global versus activation-bound endpoint choice, and real source admission. No actual native signature, authentic original evidence, implementation of Build/Open, QPT theorem, or deployment. No ordinary PR comment or user notification. Completion unmet.
