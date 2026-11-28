# Full-witness GGM namespaces and two-seed correction transport (2026-11-25 UTC; NONQUALIFYING)

## Selection and provenance

Actual PR syscoin/PVUGC #1, open/draft/unmerged, branch research/pq-wkem-validation-20260918, start and pre-write checked head 39be105aeac3db6a965f01f794a7ad81da0faf84. Read PR metadata, recent substantive discussion (through R225), exact head commit and SOURCE_FIXED_TRANSCRIPT_OFFSET_20261125.md (blob f310cd8566ee03ca0a963f92d4d8a83923510259). New path checked absent (404). No web/literature, Core source claims, whole PR diff, native signing, or executed cryptographic checker. Static construction and algebra only. No lattice/group foundation.

Missing operation: from any ORIGINAL certificate w, publicly derive globally consistent intermediate labels in the same namespace, then obtain the identical hidden cancellation capability. Closest attack is constrained-PRF/garbled-correction cross-witness splice (R289 and handoff). Rather than making another local correction or assigning public namespace tags to existing labels (which does not stop an adversary using the base labels), try independent GGM trees indexed by the *entire* witness, with constrained input keys and a two-seed correction-word tree to transport the hidden output across namespaces. This changes the mathematical input correlation: wrong-bit labels at a fixed namespace are outside the published subtree, not merely renamed. The question is whether the correction tree can supply all namespace-specific row masks without giving away the roots or enumerating the namespaces. The following is a construction attempt, not a claim that the previous splice is repaired end to end.

## 1. Explicit input namespace and reference construction

Let R_x(w) be the original bounded verifier, with a canonical fixed-length n-bit padded witness. No changes to its three OR grounds, context, depth, authentication, claim relevance or endpoint. For notation, take any lambda-bit seed-expanding, domain-separated hash PRG G(s)=(s_L,s_R); QPT PRG security would need to be independently justified. All keys below are fresh per context. Treat Boolean wires as a fixed circuit with two labels per wire. For each wire i and value b choose an independent GGM root k_{i,b}. Define L_{i,b}(w) as the leaf at index w. For an input wire i, put its corresponding witness bit first in its tree order (then the other coordinates in canonical order). Publish only the child seed of k_{i,b} at first-bit b for each b. Thus the public input-label algorithm can derive L_{i,w_i}(w), but cannot simply traverse that same root for the wrong bit of the same w. Do not publish an ancestor of either constrained subtree. For internal wires use a fixed coordinate order. This is a standard seed-expansion algorithm, not an implemented ORIGINAL-dependent KEM. Namespace includes the full bit string (not just a public hash digest that can be selected independently of w). Labels for different w are different PRG leaves, not public permutations of shared base labels.

For a binary gate g=(i,j,o,f), the explicit reference table for each w and row (a,b) is

    D[g,a,b,w] = H_row(ctx,g,w,L[i,a](w),L[j,b](w)) XOR L[o,f(a,b)](w).

Use a fixed lambda-bit row hash. For output wire o* publish for every w

    E[w] = S XOR XOF(ctx,w,L[o*,1](w),len(S)).

Here S is the same frozen safe cancellation capability. With all D and E explicitly listed, every genuine w gives the correct one-label evaluation and every accepting w yields S. This is an exponential reference encoding (O(2^n) rows), not a PPT Build, and no joint security theorem for it is claimed. In particular security of constrained input keys in isolation does not prove security after publishing all row and output correlations. A row must be decryptable only with the correct labels for its exact w. Simply making D independent of w and having evaluators convert their labels to a common root reinstates the prior mixing attack, so that variant is screened out without another fixture.

The new candidate is to replace the exponential D/E arrays with a small two-seed correction tree, rather than publish internal roots or per-namespace public masks. It must transport a specific common output leaf pad on every accepting w while retaining independent namespaces.

## 2. Two-seed correction-tree trial

Consider the following explicit hash-only seed transport used for a pair of seed states. For party j in {0,1} at prefix p, state is (s_j(p),t_j(p)), t a bit. Expand s with domain-separated G into two children (u_j^d,v_j^d), d in {0,1}, where u is a lambda-bit seed and v a control bit. At level ell let correction words be (A_ell^d,B_ell^d), shared for all prefixes of that level. The serialized evaluation rule is

    s_j(pd) = u_j^d XOR t_j(p)*A_ell^d
    t_j(pd) = v_j^d XOR t_j(p)*B_ell^d.

Here multiplication by a bit either retains the word or returns zero. An equal pair (same seed AND same bit) stays equal on all descendants. A pair with differing control bits is called active. For an active prefix, an intended inactive child must satisfy

    A_ell^d = u_0^d XOR u_1^d
    B_ell^d = v_0^d XOR v_1^d.                (1)

An intended active child requires

    B_ell^d = 1 XOR v_0^d XOR v_1^d.          (2)

For a single active prefix at each level (one chosen point), Build can expand its two private seed states, set the words for the losing child by (1), set the other control word by (2), and choose the remaining seed word arbitrarily. Then both evaluators can traverse any index using a linear-size serialized table; the two outputs coincide away from the chosen point. This is a real two-seed transport procedure for a *known single point*, not the original witness set. It avoids the local splice by having one paired state for each entire prefix. The candidate extension is to create a paired tree for the whole accepting source language, in which equal subtrees are nonaccepting and all accepting leaves have active controls. This would give the input to a single fixed payload correction, below. We attempt to keep one common pair of words per level and not enumerate all prefixes.

## 3. Exact simultaneous-correction obstruction and repair attempt

Suppose there are two different active prefixes p and q at the same level, and for the same branch d each has an intended inactive child. The shared seed word has to satisfy both

    A_ell^d = u_0(p,d) XOR u_1(p,d)
            = u_0(q,d) XOR u_1(q,d).        (3)

For four distinct independently sampled fresh random-oracle expansion inputs at that step, their uniform seed outputs make the two right sides independent uniform words. The probability of (3) is 2^-lambda (before choosing A). The two control equations impose additional constraints. This probability statement is only for the specified fresh-independent-expansion trial; it does not cover adversarially correlated seeds, repeated inputs or arbitrary hash constructions. Even if both branches at both prefixes remain active, their required B words in (2) can disagree. The single-point algorithm does not supply these correlations for multiple active prefixes.

Repair 1: allocate words per prefix, not per level. This restores the algebra locally. Build must know which children to deactivate, expand both private states for every active prefix and store the corresponding words. If active means 'has an accepting extension', public possession of both initial seeds and corrections also gives a direct classical greedy search: start at the active root, test both control pairs, choose an active child until the final leaf. Every such leaf is then an ORIGINAL witness. Thus an efficient Build implementing that exact activity invariant on hard-TRUE original instances would already be a witness-finding algorithm. This is not an attack on a proof by itself: the greedy algorithm would actually output a valid witness. It is a reason not to assume that the builder can compute the viable-prefix frontier without knowing future source evidence. Alternatively leave all prefixes active until the last layer and set leaf activity using R_x(w); the explicit Build now needs exponentially many prefixes. No polynomial bound on the original witness frontier is known or assumed, and no restricted source relation is substituted.

Repair 2: compute prefix-specific words from a public seed and prefix instead of listing them. In the explicit independent-expansion construction this is not an implementation of (1)/(2): the correction generator must match XORs of private PRG children at all constrained prefixes. Publishing both seed roots makes those XORs computable but does not give a small independent correction generator with hidden correlations. Choosing the generator first and subsequently choosing seeds to realize every required constraint is a different setup problem, not solved by the hash PRG assumption. The construction does not prove that all correlated seed choices or all possible generators fail. An independent algorithm producing those correlations, with its joint public simulator, would be needed before considering this repair viable.

## 4. Common-payload endpoint: even solving the internal controls is not enough

Use a fresh domain-separated XOF F on seed state, output length len(S), and a single public final word J. Define y_j(w) = F(ctx,s_j(w)) XOR t_j(w)*J; the paired output is y_0 XOR y_1. If the states are identical, the output is zero. For an accepting active leaf, the common payload requirement is exactly

    J = S XOR F(ctx,s_0(w)) XOR F(ctx,s_1(w)).                (4)

With one accepting point, Build knows its seed states and sets J accordingly. With two accepting leaves whose four final seed inputs are distinct and fresh in the F domain, the two required words are independent uniform strings conditional on S and prior expansion states; one J satisfies both with probability 2^-len(S). This is a correctness failure for the specified trial, not a full-public attack or a general impossibility. Per-leaf J repairs correctness only by reintroducing the exponential array. Defining final seed states to converge to one common hidden pair for every accepting leaf would avoid (4), but requires exactly the new transport of a fixed hidden value under different original witnesses. A public constant seed pair would expose the pad regardless of witness. Allowing only an honest Open-code R_x check after computing the pad is forbidden.

The two-seed trial therefore does not supply the D/E replacement from section 1. Its failure is at the simultaneous private-state transport and common-value correction, not the superficial bit-label availability. The fixed-message two-seed algorithm is explicitly only a known-point mechanism; the original relation has no builder-known canonical point. No QROM reduction is obtained by calling its seeds random. In particular the public correction words depend on private seeds, so isolated independent-leaf PRG guarantees do not justify a joint simulator.

## 5. Exact handoff

Do not retry namespace renaming, a larger GGM/DPF fixture, public prefix-mask generation that assumes access to both hidden states, or another degree/basis/syndrome variant. A genuinely new candidate must provide serialized PPT algorithms that solve both (3) or its replacement (without computing a viable-prefix frontier) and (4) or its replacement (without revealing S on FALSE), jointly across the full witness domain. A small correction-tree construction for a point or interval, or a simulation of independently sampled leaves, is not that candidate. Alternatively find a different source-dependent operation that avoids namespace transport entirely. In either case show why the full public adversary cannot combine incompatible intermediate states; no volunteered trace, representation, query log, or secret evaluator.

All ORIGINAL source and endpoint requirements remain, including three independently sufficient OR grounds, R316 maturity/coverage correction, R225 slot-global or genuinely activation-bound message, one-honest erasure and malicious setup, canonical contexts, auxiliary/sibling capsules and selective openings, exact recovery versus accepted native forgery. No new consensus claims. No implementation of full Build/Open, QPT theorem, or practical WKEM. No ordinary PR comment or user notification.
