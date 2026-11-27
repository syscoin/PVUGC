# Unkeyed transition transport and cross-IV projection — 2026-11-27 UTC

Research only: nonqualifying construction/repair screen.

Continuity: syscoin/PVUGC PR #1 open/draft/unmerged; actual branch research/pq-wkem-validation-20260918; start and prewrite head f5014dd640f006731ea101ddfe5a4a04fbff1da5. Read actual PR metadata, latest returned substantive comments through R225, latest commit filename and exact SOURCE_COMPLEMENT_TREE_RELEASE_20261127.md (blob 9d17aff1c017872f759bc7d5acc849f6ba866b71), SOURCE_CONJUGATED_TRANSITION_LIFT_20261126.md, SOURCE_QUERY_RENDEZVOUS_20261127.md, SOURCE_NATIVE_PATH_EMBEDDING_20261127.md, SOURCE_SPECIAL_SOUNDNESS_RESPONSE_20261126.md, SOURCE_OFFLINE_MPC_RECONSTRUCTION_20261126.md and SOURCE_PAIRED_INSTANCE_REDUCTION_20261126.md. New path absent (NOT_FOUND/HTTP 404). No new Core source or deployment claim.

## Selection before implementation

Missing operation: offline classical PPT Build(x,S) must serialize a capsule returning the SAME frozen safe native cancellation contribution S on EVERY qualifying ORIGINAL certificate w, with arbitrary full-public FALSE and unauthorized hard-TRUE recovery and accepted-forgery security. R_x(w) denotes the full bounded original relation, retaining all three independently sufficient BTC-work, finite authenticated burn-refutation, and Syscoin-history/tag grounds, actual source authentication, relevance, maturity, claim/window and native context. No new source compiler asserted.

The previous conjugated transition trial G_i=P_{i+1} F_i P_i^{-1} needed public evaluation of secret-key-containing G_i; revealing their code disclosed the keys, and even an ideal hidden permutation admitted terminal-state injection. Instead try a projective action that INTERTWINES with the original PUBLIC unkeyed transition. The mathematical change is to require the same unmodified public transition to act on a secret-transformed initial state, so Build publishes no transition keys, encrypted edge tables, ideal evaluator, or independently selectable wire labels. Open follows one complete original computation. This also avoids the previous independent sender/receiver query-list resampling premise: the entire computation starts at a capsule-dependent state. Check correctness and the final-state image before implementing. This is an output-key transport candidate, not an attempt to replace source admission with an easier relation.

## 1. Explicit projective transition candidate

Fix a time-padded deterministic verifier F_i(s,b), i=0,...,T-1, with full configurations s (including all work memory and retained input) and consumed input symbol b, fixed initial state s0, and final normalization to distinct public configurations a (accept) and r (reject). A source certificate w specifies the input symbols. The source statement and all F_i are public.

Build would sample a private seed k and compute an efficiently evaluable sequence of maps P_{k,i} on the configuration spaces with the following intertwining property:

    F_i(P_{k,i}(s),b) = P_{k,i+1}(F_i(s,b)).

The identity could be required only on honest reachable configurations and their admissible next symbols, rather than on every s. The intended actual algorithms, if such maps can be generated, are

    Build(x,S;k):
        L0 = P_{k,0}(s0)
        K  = P_{k,T}(a)
        E  = S XOR ExpandH("projective-transition-pad",ctx,K,|S|)
        publish (x,ctx,L0,E) and exact native checking context

    Open(C,w):
        L = L0
        for each original verifier step i with symbol b_i(w):
            L = F_i(L,b_i(w))
        return E XOR ExpandH("projective-transition-pad",ctx,L,|S|).

Include a full original verifier check in honest Open, but do not attribute secrecy to it. Correctness follows by induction from the intertwining equations for the actual original w: L_i=P_{k,i}(s_i), so L_T=P_{k,T}(a) for EVERY accepted w. Distinct witnesses may traverse unrelated configurations, with no requirement of a common proof/preimage. No secret transition code appears in this shell. The secret maps are used only by Build, so unlike the prior conjugated-transition trial there is no hidden-key public evaluator requirement. We have not constructed these maps for the actual verifier.

There is an independent exact failure of the normalized version even if one grants the maps. For the last public transition, normalization means

    image(F_{T-1}) subseteq {a,r}.

Every honest Open, including one starting from the transformed L0, ends in this public two-element set. For any qualifying w, correctness forces K in {a,r}. In particular, no secret seed, nonlinear transformation, injectivity or hidden representation changes that conclusion. The adversary tries BOTH public terminal configurations in the unmasking equation. One is the frozen S on a correct hard-TRUE instance; native checking recognizes an accepted candidate, which suffices for the accepted-forgery goal, and uniform choice among the two gives at least 1/2 exact-recovery probability even without uniqueness of native signatures. This does not obtain original evidence and uses no collision, preimage search, or source hash prediction. More generally an efficiently enumerable public terminal image of polynomial size gives polynomial candidates and inverse-polynomial exact recovery. This argument is about the specified unkeyed projection with normalized last transition, not about arbitrary capsules or arbitrary verifier normalization inside a nonpublic state space. It suffices to reject the simple candidate without implementing it.

If the identity is stipulated globally and the normalizing transition can output a on some arbitrary input state, then even on a FALSE instance P_{k,T}(a) is in the public image: substitute that input into the intertwining identity. Under the weaker reachable-only condition this additional FALSE claim does not follow. The hard-TRUE attack already suffices. This is different from the preceding terminal injection attack: no hidden evaluator is even queried at an unreachable state. The attacker enumerates the public output image directly.

## 2. Repair: omit the public reset and transport an actual hash path

Try an enlarged terminal image by replacing normalization with a running hash state carrying the complete original computation. Let A(w) denote an injectively encoded sequence of blocks associated with the full trace and original evidence; include context in the encoding. Instead of requiring a common final clear configuration, attempt a projective hash:

    source state:    y(w) = F_{A(w)}(IV)
    projected state: z(w) = F_{A(w)}(p_k),

where F_B(s)=Compress(s,B) and F_{A(w)} is the ordered iteration. Honest Open can compute z(w) from a public projected initial state p_k and the complete original evidence, without any secret transition keys. Build would need a secret-key algorithm for the SAME z(w), or a common function of it, without knowing future w. This is a state-transport equation, not a public hash of independently supplied pad labels. Source digests for distinct accepted witnesses are not assumed equal.

Screen even the favorable local case in which Build knows a single authentic digest y for one unknown block B and F_B(IV)=y, and a prospective Open possesses B. This is NOT the original challenge relation or a claim that all original witnesses provide a preimage of one fixed digest. It isolates the concrete source hash operation:

    Build knows y; choose and publish p != IV;
    Build must predict z = Compress(p,B);
    Open with B computes z.

In the ideal compression-function model with lambda-bit output, fix IV and B independently of the oracle, sample y=Compress(IV,B), give y to Build, and let classical Build make adaptive oracle queries and choose p != IV and a prediction K. Conditional on its transcript and the event that it never queried the exact address (p,B), the output at (p,B) is still uniform. The address may be selected adaptively from the transcript: after conditioning on that transcript and fixed B, this exact address is unqueried and distinct from (IV,B). Therefore Pr[K=z AND (p,B) unqueried] = 2^-lambda Pr[(p,B) unqueried]. Equivalently success is at most Pr[queried (p,B)] + 2^-lambda. This is a classical ideal-function correctness screen, not a QROM reduction, not a distributional claim about actual SHA states or source-block entropy, and not a claim that the sender cannot know any baseline blocks. It exposes the missing cross-IV prediction when setup lacks the original block. Choosing p=IV makes the output y public. Guessing actual input blocks is the prior address-coverage problem; no larger query fixture is warranted.

For a sequence of blocks the last call need not be fresh (cycles or overlap with prior queries are possible), so the one-block proof is not asserted as a general multiblock bound. There is nevertheless a precise possible repair target: secret state transformations commuting with every relevant block transition. If Q_k satisfies F_B(Q_k(s))=Q_k(F_B(s)) for all relevant states/blocks, then setting p_k=Q_k(IV) gives z(w)=Q_k(y(w)). Build can compute Q_k(y) for a known digest; Open computes the same by the unkeyed transitions. This is an actual correctness identity, with the following additional requirements still unimplemented:

    (i) a hash-only PPT generator of Q_k with the real transition intertwining;
    (ii) projection Q_k(IV) and all public context do not expose Q_k(y);
    (iii) all original qualifying w, including different terminal digests,
          yield one common native key via an actual public extraction rule.

If Q_k is publicly computable from its published projection, the attacker simply evaluates Q_k(y) without B. For example the explicit commuting register F_B(s)=s XOR H(B), Q_k(s)=s XOR k (illustrative wrapper, NOT actual source hash), has p_k=IV XOR k and hence Q_k(y)=y XOR IV XOR p_k, entirely public. Reject this familiar affine special case before implementation. Conversely, postulating a nonpublic Q_k compatible with actual compression does not provide a hash-only compiler or an independent hardness assumption. One must generate it and prove the joint public distribution. Replacing actual source hashes with an invented commuting hash action would not establish original certificate admission.

The enlarged register version of section 1 can use public verifier state s together with u updated by u'=H(ctx,i,u,s,b). It no longer has a two-element terminal image, but different accepting original traces need not yield the same u. Keeping a final public normalization of the entire enlarged state returns to section 1. Erasing only the verifier state leaves the unresolved common-key extraction on the high-entropy register. Setting the extraction to a public function of a known clear terminal digest removes the original witness dependency. Merely adding a proof that the terminal register was correctly computed does not compute the secret transform of its unknown digest.

## 3. Joint distribution and handoff

The candidate addresses neither full-public security nor malicious setup simply by removing keyed transition serialization. A legitimate continuation would require an actual unkeyed public transition lift whose large terminal image can be evaluated along every authentic original trace, together with a secret projective action giving a common output without the public reset-image leak. It must include an actual public extraction rule for distinct terminal digests, preserve the real source verification and claim scope, and jointly simulate the projection, native context, related capsules, malicious source-coin auxiliary input and ciphertext. Arbitrary QPT recovery/accepted forgery must yield an original certificate or independently justified hash/native break; knowledge of a state label, or the fact that a receiver can follow a correct path, is not such an extraction. A secret action with precisely the desired release property cannot be introduced as a primitive.

Reject the small-image normalized form, public shift and independent-address prediction forms without more implementations. Do not retry another hash IV, state width, register hash, or coefficient basis merely to test the same failure. A future candidate must actually implement a source-dependent projected computation on a large terminal image and its common-output correlation/simulator together. No proof of generic impossibility, concrete SHA/QROM claim, native signature implementation, R316/R225 scope change, or original release advance. Static derivation only; no scripts, tests, subagents, external literature or new Core reads. No ordinary PR comment. Notification gate not met.
