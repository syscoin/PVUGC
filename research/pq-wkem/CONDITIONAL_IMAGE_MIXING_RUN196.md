# Run 196: conditional-image mixing for whole projected matrix channels

**Status:** new algebraic/statistical bound and newly executed finite checks. Not a completed WKEM, not full-capsule hiding, and not an arbitrary-QPT source extractor. This is new work; no previously denied note, checker, or orphan fragment is being republished.

## Starting point and lineage

Connected GitHub reads verified `syscoin/PVUGC#1`, branch `research/pq-wkem-validation-20260918`, at `0c36e9b9e4f3f1546533f3564cf3015ec7ebb890`, open/draft/unmerged. Latest ordinary comment read: `5894497334`.

Exact-version inputs read before research:
- `CMV_MINRANK_LACONIC_QPT_SOURCE_BRIDGE_RUN152.md`, especially Sections 4-7;
- `literature-20260924/rank_field_extensions.py`, blob `e3c51bff4a8f3817f70b1368190b8b35893cafa2`, encoder/specification lines 1-200;
- `literature-20260924/DEEP_DIVE_RANK_SCALAR_DESCENT.md`, blob `5d061495800bad32733298d25f1f1ac6e55779c2`, Sections 2-3.

The Run-195 local archive was found and read at SHA-256 `6f573db01c89938c9c8d693fd5c06a9f5a5007960fa7229d0245887d78a78665`. It is a reported/uncommitted research parent, not a published theorem. Its checker was not rerun or reused here. The new question is whether a whole projection, including nonlinear statistics, can be bounded without counting its characters. No prior publication denial is treated as resolved.

Primary records checked: [CMV v1](https://arxiv.org/abs/2510.03752v1) and [Hair-Sahai v1](https://arxiv.org/abs/2609.18275v1). Their security theorems are not imported: random planted MinRank and classical generic-group security respectively do not prove this statement-derived construction secure. No full-paper re-audit is claimed in this upload/continuation session.

## 1. Conditional-image theorem

Let S have an independent binary matrix basis M_1,...,M_D, each a by b, and let every nonzero matrix in S have rank at least d >= 1. Independently sample uniform u_l in F_2^a and v_l in F_2^b, for l=1,...,r. Output all D bits

    Y_i = sum_l u_l^T M_i v_l.

Set V=[v_1 ... v_r], c=b-d, and let U_D be uniform D-bit data. Then

    TV(Law(Y), U_D) <= Pr[rank(V) <= c].

**Proof.** Condition on V, without publishing it. Y is a linear map L_V of the independent uniform left factors, so it is uniform on im(L_V). A vector z annihilates that image exactly when M_z V=0, where M_z=sum_i z_i M_i. Independence of the basis makes z!=0 equivalent to M_z!=0. If rank(V)>b-d, no nonzero M_z can annihilate every column of V, since dim ker(M_z)<=b-d. Thus L_V is surjective and Y is exactly uniform on this good event. The unconditional distribution is a mixture of that uniform distribution and the bad-event distribution. Convexity of TV proves the bound.

This bounds **every statistic of Y**, not only a parity or a standardized mean. It has no factor equal to the number of source words or witnesses. It does not require computing the minimum rank efficiently; d is a proved lower bound used in the analysis.

For r>c the exact bad-event probability is

    2^(-br) sum_{j=0}^c [b choose j]_2 product_{i=0}^{j-1}(2^r-2^i).

The rank-j count follows by choosing its column space and a surjective map onto that space. The elementary bound [b choose j]_2 < 4*2^(j(b-j)) yields

    TV <= min(1, 4(c+1) 2^(-d(r-c))).

Indeed j(b+r-j) increases for 0<=j<=c<min(b,r). Empty products handle j=0. There is no approximation in the probability sum.

## 2. What it resolves in the current research direction

Run 195's small standardized mean shift was not by itself a bound against nonlinear tests. The conditional-image theorem supplies an actual distributional bound when the effective right-kernel codimension c is small enough and r exceeds it.

For a decoy projection with effective column width b=s+c_projective and proved minimum rank d=s, the whole one-block marginal is negligible if s(r-c_projective)=omega(log lambda). Even the weaker bound d=s-1 suffices with c replaced by c_projective+1.

The latter is the conservative source-specific interface available without classifying the full minimum-rank locus. A subspace of dummy-assignment coefficient functions annihilating every degree-<=R Boolean polynomial also satisfies the weighted-table equations for the contradictory constant relation 1=0. The published characteristic-two source-gap argument therefore gives minimum binary rank >R, i.e. d>=R+1=s-1. This implication retains that published algebraic extension as an explicit dependency; it is not the original authors' PQ theorem.

Consequently fixed projective codimension and unbounded r give negligible **whole-projection** distance when R=Theta(log lambda). This strengthens a mean-only observation but does not solve the growing-codimension regime c_projective=Theta(r), in particular c_projective approximately 2r: there the bound is vacuous.

Fixed outside assignment coordinates can give duplicate or zero columns. Remove those by a public full-row-rank column map J: M=BJ. Since J V remains uniform, use B's effective column width, not artificial zero padding. This step must be exhibited for a concrete projection.

## 3. Critical scope: projection is not the full ciphertext

Y here is all coordinates of a chosen matrix-space projection at **one** CMV block position. The full Run-152 tuple has t^2 positions sharing factors. Conditioning on other positions can reveal information about V or the left factors, so the theorem cannot simply be applied separately and summed.

Applying it honestly to the assembled full-block source uses its actual effective column width (normally t*b), not b. Its available minimum rank need not grow by t. That typically makes the good-event condition incompatible with honest rank decoding r<t. Thus this is not full-public-output false-instance hiding or an arbitrary-QPT extractor.

The statistical bound survives arbitrary quantum postprocessing and any fixed public parameters or quantum advice independent of the fresh factors, by tensoring the same auxiliary state and applying trace-distance contraction. It does not cover ciphertext-correlated auxiliary information, other capsule blocks, native-key wrappers, adaptive capsules, or retained builder randomness. These must be proved separately.

## 4. New exact finite marginal calculations

The new checker independently constructs the published weighted-table syntax over GF(16) and GF(32), with distinct extension-field sample elements and ord(gamma)>n. It sums assignment encodings against all degree-one/two coefficient monomials, vertically descends them, verifies matrix-basis independence, and exhaustively enumerates the entire resulting projection space.

For (n,R)=(4,1), the image dimension is 10 and its nonzero binary ranks are 3:155 and 5:868. For (5,2), the dimension is 15 and the complete spectrum is 4:651 and 6:32116. These are finite fixtures, not a general rank-classification theorem.

Using Run 152's exact coefficient 2^(-r rank(M)), integer Walsh inversion gives the complete probability vector at each r=1,...,6. In these two fixtures the exact total variation distances are

    TV_4(r) = (217/256) * (5*2^(-3r) - 4*2^(-5r)),
    TV_5(r) = (217/512) * (21*2^(-4r) - 20*2^(-6r)).

The checker verifies these formulas against full probability vectors for the stated r values, including nonnegativity, normalization, and the conditional-image upper bound. No general-n formula is asserted.

Both fixtures have TV=217/512 at r=1. At r=6 the exact distances are 1110823/68719476736 (approximately 1.61646e-5) and 4665283/8796093022208 (approximately 5.30381e-7), respectively. They bound every nonlinear test on these finite projections, not on the full capsule.

Independent small binary-matrix fixtures enumerate 255 conditioned linear images, checking uniformity on the image, the dual-kernel criterion, and the mixing bound directly without Fourier inversion. The finalized checker passed syntax validation and two executions with identical output. It uses no network, signing keys, blockchain transactions, or production code.

## 5. Exact security and resource ledger

- Honest sampler: classical randomized polynomial time in explicit matrices and r. The exhaustive checker is a small-instance validation oracle, not the general encoder.
- Adversary: arbitrary quantum postprocessing of the specified classical projection; only the explicitly stated independent auxiliary-state model is covered.
- Hardness assumptions for the conditional-image theorem: none. No LWE, SIS, MinRank hardness, ideal group, random oracle, or extraction assumption.
- Reduction: straight conditioning and linear algebra, then trace-distance contraction; no rewinding, advice cloning, QROM programming, or source extraction.
- Source-specific application: depends on the published order-parameterized characteristic-two source-gap lemma and a concrete effective-column map. The two finite image ranks were independently recomputed.
- Still UNPROVED: full-capsule false-instance QPT hiding; arbitrary true-instance recovery/forgery to ORIGINAL witness; malicious N-of-N setup/abort/erasure composition; retained-state keyless building; native-key auxiliary correlations; practical complete parameters.

## 6. Handoff

Do not repeat fixed-codimension character counts or infer security from mean displacement. A dimension-free whole-projection bound is now available there. Continue with the actual shared-factor, multiple-block channel or growing effective codimension; identify a statistic that survives there or prove a joint conditional-image/operator-mass theorem. Keep WE-like offline release mandatory and all witness/proof computation off chain. The stopping condition remains unmet.
