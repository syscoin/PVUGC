# 2026-11-24 — Atomic source-address DPF release and receiver-root repair (NONQUALIFYING)

## Selection and provenance

Actual starting and last checked pre-write head 903c8ceda4b22ec385ca1e79bcd1df077431bc07, syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, open/draft/unmerged. Read actual PR metadata, recent substantive comments through R225, exact head commit filename and SOURCE_WITNESS_EQUIVOCATION_EXTRACTION_20261124.md (blob 6b15848b6250b85b29e70321cfe0ae7ea39036a0), and SOURCE_DUAL_MODE_OR_TRANSPORT_20261124.md at the exact starting head. Checked this note path absent (contents 404). No web, external literature, new Core source claim, entire PR diff, production action or ordinary PR comment.

Missing ORIGINAL operation: derive the same frozen native cancellation capability from every qualifying original certificate, via an actual serialized Build/Open, without independently issuing hidden input labels or letting an invalid mix recover the output. Candidate change from split-mask/garbled correction: use a *single complete original-certificate address* to evaluate two correlated hash-tree point-function shares. This intentionally eliminates any need to combine partial labels from different verifier gates. The source-controlled receiver-root repair below tests whether these shares can be issued before any future original certificates exist. The construction is not another private-coefficient polynomial or a parameter sweep. Selection rejects before implementation.

## 1. Explicit atomic address construction

Use an injective fixed-length n-bit encoding of the original witness (including typed evidence branch, length and context as necessary); validation still requires the original unchanged relation R_x, all three independently sufficient grounds, relevance and maturity. For this calculation alone consider a single target address a and a fixed ell-bit native signature S. The attempted generalization to all qualifying witnesses is the issue being screened; this single-address baseline is NOT an acceptable substitute.

A binary seed expansion G(s) yields two pairs (s^L,t^L),(s^R,t^R), each a lambda-bit seed and one control bit. It may be modeled as domain-separated hash expansion. XOR is bitwise. Sample roots s_0,s_1 independently; initial controls t_0=0,t_1=1. At level i of generation expand both current seeds. Let k=a_i (keep), l=1-k (lose); define the common correction words

    d_s = s_0^l XOR s_1^l
    d_t^j = t_0^j XOR t_1^j XOR [j=k], for j in {L,R}.

For each party b and either child j, the transition on the parent state (s_b,t_b) is

    s'_b = s_b^j XOR (t_b * d_s)
    t'_b = t_b^j XOR (t_b * d_t^j).

Here multiplication by a bit is either zero or the full word. Generation follows k, storing the common corrections for each of the n levels. For final seeds on a, define

    d_f = S XOR H_out(s_0*) XOR H_out(s_1*)

where H_out expands to ell bits and is domain-separated. The two serialized keys comprise respective roots and the common correction words plus d_f. On any address v, Eval_b follows v using the given root and corrections, yielding H_out(s_b') XOR (t_b' * d_f). XOR of the two evaluations is S at a and all-zero otherwise.

Proof: when parent control parity is one, child parity is [j=k] by the d_t formula. The lose-child seeds are equal by the d_s formula; lose-child controls are equal by parity zero. Equal seeds and controls remain equal under every subsequent identical transition, even if both controls are one. Along the keep path control parity remains one; the terminal XOR is S by d_f. Thus correctness of the point function is exact (no pseudorandomness claim needed). Independent partial wire labels have been eliminated in this baseline.

## 2. Full public view is not the one-key security experiment

If both keys are published, they give an immediate straight-line recovery of a without a source certificate. At each level expand the current pair and apply the public corrections to both children. Exactly one child has control parity one. Follow that child. Induction above identifies precisely a; after n levels evaluate both shares and XOR to obtain S. This takes two seed expansions per level plus word operations, regardless of the hardness of finding a from x. The attacker need not supply an internal representation or query log. A public capsule containing either a publicly computable equivalent of both states or both actual keys has this same attack.

If a encodes an original witness and generation already knows a, the attacker recovers an ORIGINAL certificate, so the address extraction alone does not contradict the user's recovery-implies-certificate phrasing. But Build cannot then be an x-only hard-TRUE setup, and hard-TRUE hardness is lost relative to that public capsule. More importantly correctness fails for any other qualifying witness encoding a' != a. If a is instead a public statement address, the attacker obtains S without original evidence. Giving the keys for polynomially many separately generated addresses does not cure the problem; every published pair has its own parity trace. No claim is made that arbitrary function-sharing constructions have this exact parity property.

## 3. Attempted change: let the ORIGINAL witness supply the second root

To preserve atomicity without exposing the parity trace, publish only the first root and the corrections; obtain the second root during Open from H_root(ctx,encode(w)), with the second initial control fixed to one. The two domains H_root and G are independent in the following explicit classical random-oracle screening experiment; this is not a concrete SHA or QROM theorem. This would not require a common source digest, since different witnesses could in principle supply different receiver roots. The actual question is whether independently issued public correction words can be correct for the many future receiver roots.

Consider a qualifying w fixed independently of the fresh Build coins, with the full relevant original source context. In the experiment Build has not queried H_root at the exact context/encoding of w; it has made at most q distinct seed expansion queries including first-root expansion. The actual receiver root r is uniform conditioned on that transcript, and with probability at least 1-q/2^lambda its G expansion has not been queried. The public first correction d_s and first root s_0 are fixed given the transcript. To implement the exact DPF lose-child coalescence for either possible first keep bit, the receiver must satisfy

    G_seed^l(r) = G_seed^l(s_0) XOR d_s.

At a fresh r, each child seed is uniform lambda bits. Even allowing the keep bit to be chosen after seeing both children, the probability that either required equality holds is at most 2/2^lambda. Thus the chance that the receiver root satisfies the necessary first-edge coalescence equation is at most (q+2)/2^lambda, plus the probability Build queried the precise H_root input. This is a necessary invariant for this particular DPF correctness mechanism, not a bound on every possible scheme that lacks that invariant. It excludes the proposed independently derived receiver root even before terminal correctness or security of S. Conditioning on a future witness chosen adaptively using the capsule would require a different experiment; the user's every-witness completeness still includes independently supplied qualifying witnesses wherever such a distribution exists. No claim that real PoW certificates are sampled uniformly, or that these oracle assumptions hold for concrete SHA.

Changing the receiver derivation to an actual publicly recoverable preissued root restores the parity-trace attack. Giving each receiver separate correction words requires an actual Build algorithm to generate and deliver those words for original witnesses not known at setup; the ordinary point-function generation computes them from the selected address and both roots. An exact root-independence repair cannot simply leave the d_s equation unspecified. Nor can a public acceptance if-check after XOR recovery supply cryptographic enforcement.

## 4. Handoff

The atomic complete-address change removes the particular local label-combination attack but does not construct the original source release. A genuine continuation along this direction would have to derive *receiver-dependent correction words with a jointly simulatable public representation* from x and setup coins, such that each future original certificate supplies the matching receiver state without disclosing an unauthorized evaluation path. It must preserve actual full-certificate admission and correctness for all branches. This is a missing equation, not an assumed primitive. Do not scale the one-point baseline, enumerate certificates, publish receiver root tables, or change hash placement/seed lengths under the same premises. The standard two-key point function and the independent-root repair are rejected at selection; no larger fixture or code execution is warranted. This does not rule out general nonlinear function sharing, non-black-box hash constructions, or source-specific WE.

No actual native signature generated, source validation implemented, QPT reduction proved, or malicious setup / sibling capsule composition completed. No code or tests executed; exact static transition derivation and conditional oracle screening only. Original three OR grounds, R316 maturity/coverage correction, R225 endpoint choice, authentic carrier validation, graph binding, erasure, DA and network assumptions unchanged. No notification warranted.
