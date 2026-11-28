# Late-bound Merkle-root garbling: public hash rekey trial — 2026-11-26 UTC

Status: nonqualifying construction/repair iteration; no original source release or full-public security theorem.

Continuity: actual PR #1 was open/draft/unmerged, head 53fac3f562efd18ffee2dae977368c6a5dd13567 on research/pq-wkem-validation-20260918. Read current PR metadata, latest five substantive discussion entries (through R225), latest commit's changed filename, and exact SOURCE_DPF_TERMINAL_CORRECTION_20261126.md (blob 01b33cd11967a7a8ef72ab977774c39f0c62fb37). Re-read head before write and confirmed this new path returned 404. No Core reinspection needed: no new source-rule or deployment claims.

## Selection before construction

Missing original operation: given a future complete certificate w of any of the three original OR grounds, public Open must obtain the same frozen cancellation contribution S; Build is offline before w exists. Preserve all authentication, maturity/relevance, context/native bindings, and original claim scope. The R289 local label splice is the closest attack; R303 independent labels do not implement source-derived labels. R327 and the latest DPF terminal correction do not implement the source-dependent public evaluator either.

Try binding EVERY intermediate wire label to one late-chosen Merkle commitment r to the entire original certificate (including its length, canonical encoding, claim context, and an optional opener-chosen salt for internal commitment freshness). This is not a replacement for the original source commitment. Each input occurrence would require a genuine Merkle opening at its exact index; output labels would carry the identical r. The intended mathematical change is a noninvertible, independently domain-separated hash transformation of a hidden base label at the chosen r, rather than merely including a public root in a gate selector or reusing root-independent labels. Different roots should require separate independent labels. Unlike R289, the proposed gate interface has no direct cross-root label conversion.

Reject the invertible tweak L_r = L XOR H(ctx,r,i,b) without experiments: possession at one root translates to every root. Investigate the noninvertible tweak and whether one serialized public row can be rekeyed for all future roots without exposing a transferable base label. This is not another low-degree evaluator/basis sweep. The following trial deliberately grants the unconstructed initial Merkle-opening-to-label operation; failure even with that grant rejects the row mechanism, not the original source problem. No initial-source release is claimed.

## 1. Explicit unary late-bound row trial

Let N=2^lambda and use distinct hash domains for row pad and label. For a single unary transition from input label A to output label B (uniform distinct lambda-bit strings), Build publishes

    T = H("row",ctx,A) XOR B.

For a root r, the proposed input and output tokens are

    K_r = H("label",ctx,r,A)
    Z_r = H("label",ctx,r,B).

The desired public row algorithm receives T, r, K_r, public context and hash access; it must output Z_r without revealing either transferable base label. Extend to circuit gates by using distinct hidden base labels for each (wire,bit) and rows for the gate's truth table. If it worked, use a root-bound final wire for each accepting branch; the remaining terminal correction would still have to map every accepting root to the SAME S. This row is intentionally a necessary suboperation, not a completed Build/Open.

Attempt A: derive a root-specific ciphertext by changing the row pad to H("row",ctx,r,K_r) and retaining T. It no longer cancels H("row",ctx,A); correctness is lost. To restore correctness, Build would need the root-specific delta

    Delta_r = H("row",ctx,A) XOR H("row",ctx,r,K_r)

and a way to return Z_r rather than B. Publishing Delta_r as an unconditional public routine is not justified by the hash; Build cannot enumerate arbitrary future roots. The obvious root-independent correction exposing A or B revives root rebinding. A table per root is exponential in the allowed commitment length and cannot be required of a practical classical PPT Build.

Attempt B: eliminate static B and define the output token recursively as

    K_next = H("advance",ctx,r,T,K_r).

This IS a public classical hash computation and a syntactically serializable row. But a logical wire reached by two distinct allowed predecessor tuples now has two generally distinct tokens at the SAME root. Downstream tables cannot be keyed by the single logical wire label as originally required. If both advance-domain inputs are distinct fresh points, equality occurs with probability 2^-lambda in the ideal oracle. A gate with multiple rows must either merge tokens or retain all distinct provenance. The latter is not a polynomial-size table for general verifier circuits; even a chain of two-to-one merges can retain 2^d distinct path identities unless a merge is actually implemented. Defining K_next only from public (r,wire,bit) supplies a public counterfactual output, not an authenticated merge. No claim that all succinct provenance encodings are exponential.

## 2. Joint ideal-oracle experiment for the unary row

Explicitly idealize H as a random oracle with lambda-bit output. Context/domain encodings are injective. Sample (A,B) uniformly as an ordered distinct pair. The trial's public view is (r,T,K_r), and target Z_r. For this local experiment r is fixed independently of A,B, and there is no correlated auxiliary material besides that stated. The following is an exact alternative generation of the joint real distribution, not a marginal-only hybrid:

    sample T,K,Z independently uniformly from {0,1}^lambda;
    sample an independent random oracle O;
    program O("row",ctx,A) = T XOR B,
            O("label",ctx,r,A) = K,
            O("label",ctx,r,B) = Z.

All three points are distinct. Conditional on A,B the programmed outputs are independent uniform; hence the joint distribution agrees exactly with ordinary Build plus K and target Z. The capsule T and supplied K are independent of A,B in this generation. The experiment exposes the complete oracle interface (including coherent queries) and not the hidden addresses.

For a baseline where the three points are NOT programmed, the target Z is independent of the entire public view and oracle. Any algorithm's probability of returning Z is exactly 1/N if it always returns a lambda-bit answer, at most 1/N otherwise.

For an arbitrary q-query quantum algorithm in this isolated experiment, telescope the programmed and unprogrammed unitary query executions, using the baseline prefix and programmed suffix at each replacement. If p_j denotes baseline query-state squared mass at the three changed addresses just before query j, the vector norm difference is at most 2 sum_j sqrt(p_j). Baseline states depend on O,T,K,r but not A,B,Z, so E p_j <= 3/N. Jensen and averaging over the classical sampled data give an upper bound 2q sqrt(3/N) on mean norm distance; the success probability difference is at most that bound (pure-state trace distance <= vector norm distance; mixed initial states can be purified independently). Thus the concrete proposed row, even granting K_r, has

    Pr[public evaluator returns Z_r] <= 1/N + 2q sqrt(3/N).

For classical queries the corresponding first-hit coupling yields the stronger bound 1/N + 3q/N: until the first changed-address query the executions agree, and the baseline query list is independent of A,B. The result is an upper bound, not a tight security estimate. If independent sampling with replacement is desired, condition on A != B or account separately for probability 1/N.

This explicitly rules out correctness of Attempt A with JUST its serialized T and K_r in this model. It does not analyze arbitrary additional correlated setup hints, actual SHA, correlated native checking keys, other gates/capsules, or a new primitive. No full-public QPT release reduction follows from this local experiment.

## 3. Public classical late-root evaluation exposes the base label if it queries it

Try to repair the row by publishing an arbitrary additional root-independent hint D generated by a classical PPT Build. Retain the exact label target Z_r=H("label",ctx,r,B), with B a fixed hidden base label selected at setup. Consider a root r fresh for this domain and a label oracle location ("label",ctx,r,B) not queried at setup or by any external input-generation routine except as explicitly part of the authorized inputs. In particular no authorized input is already the desired output label. Use a genuinely fresh random internal salt if needed for the local experiment; this is not a change to original source maturity rules. For an independently uniform rho-bit r, the probability a q_B-query classical setup has even queried the label domain at r is <=q_B/2^rho; for a correlated source root no such bound is asserted. Condition only on a fresh location in the remaining argument.

Suppose classical public Eval(D,T,r,K_r) returns the exact Z_r with probability 1-epsilon. Unless its initial view already depends on the fresh value Z_r, lazy sampling implies

    Pr[success AND no query of ("label",ctx,r,B)] <= 2^-lambda.

This follows by leaving that random-oracle cell unsampled until first query: conditioned on any execution that does not query the cell, the entire observable transcript and answer are independent of its uniform value. This remains true if D contains arbitrary setup correlations not involving that fresh cell. Hence Eval queries the cell with probability at least 1-epsilon-2^-lambda. No QPT extraction assumption is needed for this step: honest Eval is classical and public, so an attacker can run its serialized code while recording its own ordinary query arguments. The query contains B verbatim.

If the attacker does not know which query contains B, it can collect every candidate from this domain at r and use a *public label-check* if present. Without a check, it can retain the polynomial list of candidates; for a constant-size splice requiring two such labels, it tries all polynomially many pairs using the public terminal/native check if present. For large circuits with many unknown candidate choices, a polynomial global selection algorithm does not follow from this argument. If Eval has genuine earlier knowledge of Z_r through some other source-dependent input, that dependency must be explicitly constructed and jointly simulated, not excluded by fiat.

Once B is known, the attacker computes H("label",ctx,r',B) for any r'. This contradicts the intended nontransferability of this particular late-root label design. The failure does NOT require recovering the full capsule secret from a single wire, nor does it claim all public computations of random-oracle functions expose a fixed transferable secret. It applies to this choice of root-specific label as an ordinary hash at a fixed secret base-label address, with public classical evaluation and fresh output value. It also does not assume access to an adversary's private state: the attacker is instrumenting its OWN honest execution.

Example of the local consistency consequence, not a source fixture: in a compiler with a final AND of wires x and NOT x, choose independent salted internal commitments to x=1 and x=0. Suppose the two honest locally accepted computations respectively provide the true label for x and the true label for NOT x, and each meets the freshness and public-evaluation premises above. Learn their base labels from their respective evaluation queries (or retain the constant number of polynomial candidate lists as above), rebind both to one r*, then invoke the accepting AND row with the two root-compatible tokens. The Merkle openings were each genuine for their OWN roots; no Merkle collision is needed. A row that cryptographically checks the entire committed computation rather than these tokens would not be the proposed row mechanism. If there is a terminal same-S correction already supplied for r*, this splice gives its accepting input; if not, full secret recovery is not established. This is the R289 consistency problem reappearing after the proposed repair, not a demonstrated break of an implemented original bridge capsule.

## 4. Handoff

The exact next equation is NOT just a better random-oracle label formula. The intended public gate must support late root binding without (a) an instrumentable root-independent secret argument that gives cross-root rekeying, (b) independent root pads that no setup row can cancel, or (c) exponential provenance variants. A possible different mathematical route would use root-dependent hidden state that has no fixed transferable base-label preimage and an explicitly constructed convergent transition across different valid predecessor tuples; its full serialized public evaluator and joint simulator remain absent. Do not retry with a longer label, merely a different H nesting, an invertible tweak, or independently randomized per-root tables.

Even successful gate rekeying would leave the first original-witness-to-input-label release, the final same-capability correction over all accepting roots, native VK/message correlation and same-message forgery reduction, and malicious multi-party setup and sibling-capsule security to construct together. Merkle binding is not itself an input-label release. The local QROM experiment above is independent-label only; never import it into the correlated full public capsule without a joint simulator. No generic NP impossibility result or original relation simplification. R316/R225 qualifications and all three original OR grounds retained. No code/checker run, no delegated agents, no external literature, no consensus verification, no native signature generation, no completed original release or qualifying result. No ordinary PR comment.
