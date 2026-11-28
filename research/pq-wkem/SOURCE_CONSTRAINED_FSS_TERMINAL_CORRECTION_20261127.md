# Source-constrained FSS terminal correction — 2026-11-27 UTC

Nonqualifying bounded static construction/repair iteration. No WKEM, QPT security, or deployment claim.

## Continuity and selection

Actual start: syscoin/PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, head bf05e76b2df79ec871bce0d3092f2eaf2ec7b6ca. Read PR metadata, recent substantive comments through R225, exact head commit's filename and SOURCE_COLLISION_PERIOD_LOCALIZATION_20261127.md (blob 0c4af7618aee24ef23b73167fc9bff4068f01bda), plus SOURCE_OR_PROOF_CHALLENGE_TRANSFER_20261127.md at the same head. Rechecked unchanged head; proposed new path returned NOT_FOUND/404. No new Core source claim.

Missing ORIGINAL operation: witnessless classical-PPT Build of a capsule carrying one frozen safe native capability, and public Open with EVERY qualifying ORIGINAL certificate, with arbitrary QPT full-public security. Candidate change: use function-secret-sharing (FSS) of a constant release key over the entire canonical certificate domain, with *source-constrained access* to the individual evaluations. Unlike garbled local labels or additive private coefficients, the share value at a complete certificate is a nonlinear hash-tree evaluation. The intended protection against R289's split-mask false splice is that mismatched full-certificate inputs yield unrelated terminal masks; only the two outputs for the SAME qualifying input should cancel. No shared witness or common preimage is presumed. This preflight checks whether the standard hash-tree terminal correction actually has that property, BEFORE implementing another large fixture. This is not a claim that a constrained FSS primitive with these properties exists.

## 1. Candidate serialization and precise obligation

Let V_x(w) be the complete ORIGINAL verifier with all three independent OR grounds, full authentication, relevance and exact claim/native binding. Use a bounded canonical bit encoding of w, with length/domain tags and unambiguous padding. Split checks into two predicates P_0(x,w), P_1(x,w), with conjunction EXACTLY V_x(w); for example authentication checks versus remaining claim-specific conditions, with appropriate branch typing. Both consume the entire same certificate, not independently chosen histories. This split is only a formal factorization of the original verifier, not a claim that either predicate has an efficient constrained-key representation.

Choose uniform K in {0,1}^lambda and E = sigma_cancel XOR KDF(ctx,K;length). A candidate Build would publish two hash-tree FSS evaluation keys, terminal correction D, and E, with source-constrained key representations. For each key i, the expansion on complete w ends at seed s_i(w), control bit t_i(w). The standard binary seed/control correction recurrence, written for a direction b, is

    (u,v) = G_b(s_i)
    s_i' = u XOR (t_i * C_seed[b])
    t_i' = v XOR (t_i * C_bit[b])

where G is domain-separated hash expansion, corrections are public words (indexed by level, or by a public prefix in a more expensive variant), and bit multiplication selects zero or the word. This is classical PPT given a polynomial-size table and root. The terminal share is

    Y_i(w) = H_out(ctx,s_i(w)) XOR (t_i(w) * D).

The terminal hash is an independent lambda-bit random-oracle domain in the analysis, not a proof about concrete SHA. The mask expansion domain is separate again. Aim for t_0 XOR t_1 = 1 at each accepted leaf. Then the desired exact recovery equation is

    Y_0(w) XOR Y_1(w) = K
    iff H_out(ctx,s_0(w)) XOR H_out(ctx,s_1(w)) = K XOR D.

Open would evaluate both source-constrained keys on a qualifying ORIGINAL w and unmask E. The *actual* constraints must prevent extraction of forbidden evaluation state from the serialized keys, not be ordinary public if-checks. Merely publishing both roots plus corrections and running a source test before evaluating gives every adversary the ungated evaluation program. That is not the proposed repair. A possible concrete constrained-key format for prefix-restricted domains is a list of allowed prefix subroots plus the corresponding public continuation corrections. This really hides unlisted roots under a one-way tree expansion assumption, but it only supports the explicitly covered subtrees; it does not implement arbitrary source predicates.

One can try to make the constant-function FSS first, then constrain both keys separately. Grant exact control-bit parity for the entire domain in that approach, and grant correct evaluation state at every admitted leaf even if generating its correction table is difficult. The following terminal obstruction still holds. It is independent of the PRG security of G and independent of whether the preceding tree uses a level or prefix correction table.

## 2. Exact terminal relation

For two accepted inputs w,w', define the unordered pairs A={s_0(w),s_1(w)}, B={s_0(w'),s_1(w')}, retaining the distinction between equal-seed pairs and two distinct seeds. Correctness with one public D requires the same XOR of terminal hashes on both pairs. If either pair has equal seeds, that XOR is zero and K=D; the public capsule opens without any source certificate. This is an exact attack, even if the seed itself is private.

For two distinct-seed pairs, if the unordered pairs differ but have one common seed, equality implies a collision between the other two H_out values. If they are disjoint, equality gives a four-distinct-input XOR relation. The latter is not an ordinary hash collision and must not be claimed to follow from collision resistance alone.

Here is a precise bounded classical sampling check of this candidate in the independent random-oracle model. Consider any adaptive classical sequence of at most q distinct inputs to H_out, including Build's calls and the four terminal seed queries in evaluations at two chosen valid certificates. The certificates can be fixed beforehand, or selected by the classical experiment on its prior public transcript; all H_out accesses by that experiment count. Conditional on prior answers, each newly queried distinct input has a fresh uniform answer. The probability of any two-distinct-input equality or any four-distinct-input zero XOR among the queried answers is bounded above by

    (binom(q,2) + binom(q,4)) / 2^lambda.

Proof: charge each bad subset to its last queried member, and for each choice of the other one or three previously queried members the last answer is fixed by their XOR. Sum the conditional probabilities. The bound also applies if G's independent oracle is fixed before the experiment. This is not a quantum query bound and is not a union bound over exponentially many witnesses. It is a preflight for a classical Build and two classical evaluations; it remains valid with arbitrary adaptive classical seed selection within that query budget. It does not depend on the adversary volunteering a representation.

Consequently two such correctly opening leaves, barring the bounded bad event, either expose K=D or use precisely the same unordered pair of distinct seeds. This eliminates the intended design in which different valid full certificates produce fresh independent terminal seed pairs while a single public correction reconciles all of them to K. The exact matching-pair alternative is materially different from the prior global collision-period candidate: it has no global Simon period requirement and no additive low-degree private evaluator. However it creates a new source-access obligation below.

## 3. Attempted repair with the same unordered pair and hidden orientation

Let a,b be independent distinct seeds and choose

    D = K XOR H_out(ctx,a) XOR H_out(ctx,b).

At every valid w, the two constrained evaluations would return (a,b) or (b,a) as their terminal seed pair, with opposite control bits. The two shares indeed sum to K. No public equality-test or hash commitment to a,b is needed for correctness. Orientation could vary between witnesses, so no fixed assignment of one seed to each source predicate is necessary.

But if arbitrary local evaluations on any inputs reveal both seeds, even at DIFFERENT and individually incompatible certificate inputs, the adversary computes K directly from the public D and those two hashes. The control bits and full-input identity are irrelevant to that equation. In particular, simply assigning a to the first local key and b to the second, with independently satisfiable local predicates, fails even on a false original instance with disjoint local domains. This is not the old affine-coefficient attack: the inner hash can be ideal and nonlinear. It is a specific loss of the supposed cross-input anti-splicing invariant at the terminal correction. The final mask is then opened directly, without extracting an original certificate, inverting a hash, or requiring native signature malleation.

There is a logically possible orientation repair which should not be conflated with that attack. For example, for a conceptual constant-function share pair, set s_0(w)=a if P_0(x,w), b otherwise; set s_1(w) to the complementary seed. If only P_0-domain evaluations of key 0 and P_1-domain evaluations of key 1 are accessible, all allowed evaluations on a FALSE instance give a. On a TRUE instance any w in the intersection gives b via key 1, while key 0 gives a. Thus disjoint domains do NOT inherently imply exposure of both seeds; a proof claiming so would be wrong.

The exact missing public operation in this repair is a serialized, source-constrained key 1 whose accessible evaluation reveals b if and only if the full input satisfies P_0 AND P_1, without having b as a readable constant or an accessible forbidden-path seed. Build knows b but not any future qualifying certificate. Writing the orientation rule into executable code with literal a,b exposes both; ordinary public guards on the seed tree do not hide them. A seed-tree prefix-cover representation would need to implement source-dependent orientation using real subtree keys: with a polynomial explicit cover of the accepting domain, any covered prefix can be completed and checked by anyone, so it is not a solution for hard-TRUE source relations. If orientation is itself an opaque evaluator, the original release operation has simply been reintroduced. There is no implementation of that operation here.

Note the direct correspondence of this repaired interface to the missing primitive: publish a as well, and use b as the key for an independent native mask. The promised access to b for every valid original w, and inability to access it otherwise, is already the desired witness-dependent release. Assuming this correspondence does not instantiate it. Nor does it give a joint simulator for the seed-tree keys: a simulator that samples unrelated seeds at accepting leaves violates the terminal equation in section 2; one that installs both actual labels in public reachable state permits the direct attack. A nonqualifying local evaluator cannot be promoted to a secure FSS merely by making its single-key marginal pseudorandom.

## 4. Scope and next selection

No general limitation on FSS, hash-only source-specific WKEM, or arbitrary public correlations is proved. The bounded hash experiment is not a full-public QROM security argument. The correctness obstruction concerns a single terminal correction and the specified independent terminal hash outputs. The direct recovery attack concerns capsules where both labels can actually be obtained from serialized keys; it does not cover all possible orientation encodings. No attempt was made to extrapolate the classical probability bound to QPT or to adversarial source-generation distributions.

The next candidate must avoid the fixed-correction reconciliation entirely or implement genuine source-conditioned access to the terminal representation with a joint simulator. Do not expand this preflight into additional hash bases, larger trees, additional correction-word counts or label-count optimization. Merely making FSS share keys look independently pseudorandom is not a repair. No public release compiler, original-source Open, FALSE/hard-TRUE proof, or native forgery reduction has been obtained.

All three original independent OR grounds, R316 LC maturity correction, R225 endpoint scope, pre-funding correctness/malicious one-honest setup, full auxiliary/sibling-capsule exposure including retained source coins, exact native recovery versus accepted forgery, and timely admissibility/inclusion remain unchanged. No new source consensus assertion. Static derivation only; no local code, checker, test, subagent, web, or literature invoked. No ordinary PR progress comment.
