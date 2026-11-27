# ORIGINAL-certificate-directed lossy fixed-point transport — 2026-11-27

Nonqualifying construction/repair iteration. No WKEM, bridge deployment, or concrete SHA security claim.

## Continuity and selection

Actual start: syscoin/PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, head 694552ea00bfe2dc4e03ba495fafa04b8798bb29. Read PR metadata, recent substantive comments through R225, exact head changed filename, and SOURCE_INVERTED_BROADCAST_TREE_20261127.md (blob 8f1077081c4493382dbb7c2c6ec16d0276bc9866). Also read the exact-head OR proof challenge transfer, full-certificate tweak gate transport, batch OT receiver tape, paired-instance lift cycle, and transition certificate delegation notes to avoid repeating those variants. Rechecked unchanged head; proposed new path returned NOT_FOUND/404. No new Core-source assertion.

Missing operation: a serialized witnessless classical-PPT Build and public Open from EVERY qualifying ORIGINAL certificate, producing the same frozen safe native capability, with full-public FALSE/hard-TRUE QPT recovery and native forgery arguments.

Selection: use a planted hidden common *attractor* in a public nonlinear, noninjective transition system, rather than independent output labels, a seed-tree enrollment, precomputed signatures, additive private coefficients, or a reversible masked permutation. The intended mathematical change is that distinct complete witnesses can follow distinct state trajectories and coalesce through irreversible coordinate overwrites. No inverse frame, reusable wire label, or per-witness terminal hash reconciliation is required by the intended design. The closest reversible-frame and inconsistent-label attacks do not apply literally to this transition algebra. Test whether the actual serialized maps allow the needed source-directed convergence, and derive the corresponding joint simulator, before implementing a larger verifier or fixture.

## 1. Concrete serialized candidate

Let V_x be the complete ORIGINAL claim-bound verifier, including all three independently sufficient grounds and their authentication, relevance, LC maturity, and exact claim/native bindings. Grant the ordinary deterministic evaluation of V_x; no implementation or Core audit is claimed.

Fix the context ctx (including the capsule ID and exact native VK/message) before sampling the internal secrets below. Let N=2^lambda. Use independently domain-separated random functions A_j,B_j from lambda bits to lambda bits, for polynomially many indices j, and a separate F from pairs of lambda-bit strings to the exact cancellation capability length L. Domains include ctx and indices with unambiguous encodings. This is an explicit ideal random-oracle diagnostic, not a claim about concrete SHA.

Build samples independent uniform a,b in {0,1}^lambda. It computes and serializes

    c_j = a XOR A_j(b)
    d_j = b XOR B_j(a)
    E   = sigma_cancel XOR F(a,b).

No qualifying witness is needed to produce these bytes. Erase a,b after setup. Define the public transition maps on state (u,v):

    T^A_j(u,v) = (c_j XOR A_j(v), v)
    T^B_j(u,v) = (u, d_j XOR B_j(u)).

These are idempotent noninjective coordinate updates: each discards one entire input coordinate. All maps fix (a,b). In particular T^A_j composed with itself equals T^A_j, not the identity; there is no inverse map that cancels a previous frame. No source-independent literal planted state is published. There can be other fixed points; no uniqueness is needed for the intended opening, which requires reaching the actual sampled pair.

Intended Open: from the complete canonical ORIGINAL witness w, run its verifier and derive an initial state and a polynomial schedule of these coordinate updates, potentially adaptive to both the full source certificate and the resulting state. Apply them and return E XOR F(u_final,v_final). The intended correctness is that EVERY qualifying w reaches (a,b), even if its initial state and schedule differ. No final honest-code if-check can be the only protection. The exact missing operation in this candidate is a source-directed path to the sampled common attractor. We analyze even arbitrary adaptive algorithms with access to all maps, not just a fixed schedule or a particular circuit trace.

This is a genuinely serialized Build and a proposed evaluation rule, but not a completed Open. The following joint-distribution check rejects the independent-plant version before any implementation of a verifier schedule.

## 2. Exact joint coupling and simulation diagnostic

For this candidate only, take the external original source data, any complete qualifying w, ctx, native VK/message and sigma_cancel to be fixed or jointly sampled independently of a,b and of the fresh transition/KDF oracle domains. They may be correlated with each other and the oracle in the disjoint original-source domain. In particular, the test grants the evaluator a qualifying ORIGINAL witness as auxiliary input; it need not find it. This is an admissible completeness diagnostic for independently available evidence. No claim is made about source data maliciously generated using the planted secrets or arbitrary related capsules.

Define two coupled experiments:

* Sample a,b uniformly; sample c_j,d_j and E independently uniformly at their respective lengths; sample independent uniform base functions A^0_j,B^0_j,F^0.
* In the REAL experiment use the base functions except overwrite the following points:

      A^1_j(b) = a XOR c_j
      B^1_j(a) = b XOR d_j
      F^1(a,b) = sigma_cancel XOR E.

  All other function values are unchanged.
* In the BASE experiment leave the functions unchanged, and publish exactly the same c,d,E.

The REAL joint law is exactly the Build law, including the hidden pair and oracle, under the stated independence. Conditional on a,b and sigma_cancel, each original random-function value defining a correction is independently uniform in its disjoint domain; XOR is a bijection to the correction, and the rest of the oracle is independent. This is a sampling identity, not a proposal that real setup can program SHA. The BASE experiment uses independent uniform serialized corrections and mask and unprogrammed oracle functions, with unchanged external original and native data.

Classical adaptive diagnostic: run any q-query algorithm in BASE, including its full original witness and chosen source-guided transitions. Its complete base transcript is independent of a,b. For a query of type A or B the probability of hitting the overwritten point is 1/N; for an F query it is 1/N^2. The probability of any such hit is at most q/N by a union bound on BASE queries. REAL and BASE executions are identical until the first such hit under the coupling. In BASE, an output pair equals the independent sampled pair with probability at most 1/N^2. Therefore

    Pr_REAL[output pair=(a,b)] <= q/N + 1/N^2.

This also bounds a classical schedule with arbitrary adaptive choices and arbitrary source-dependent initial state under the diagnostic independence. No claim of extraction from adversarial query logs is used; this is a distributional proof of failure of intended completeness.

For completeness, the same coupling has a direct QROM distinguishing estimate in this restricted experiment. Treat the domain-tagged functions as a single standard XOR oracle with consistent output padding; the overwritten set S(a,b) contains one input for each A and B domain and one for F. For fixed base functions, serialized bytes and independent external data, the base pre-query state |psi_t> is independent of a,b. If p_t is its squared query amplitude on S(a,b), then E_(a,b)[p_t] <= 1/N: sum over domain-tagged addresses, each having probability at most 1/N of being marked. This remains true for coherent queries spanning indices and domains; there is no factor equal to the number of domains when q counts queries to this combined oracle.

The two oracle unitaries agree off S and differ there by operator norm at most 2, hence their action difference on |psi_t> has norm at most 2 sqrt(p_t). Purify the evaluator's measurements/randomness. Telescope its real and base oracle sequence using base states before the replaced call and real unitaries afterward. By the triangle inequality and Jensen, the expected final Euclidean norm difference is at most 2 q / sqrt(N). For any final measurement, including one that compares the output to a,b in the joint experiment, the absolute probability difference is at most this bound (and trivially at most 1), using the pure-state trace-distance bound and averaging the fixed experiments. In particular

    Pr_REAL[output pair=(a,b)] <= 1/N^2 + 2q/sqrt(N).

This proof uses explicit random-oracle coupling, not rewinding, classical extraction from a quantum adversary, or a proof of hash security from collision resistance. It is a restricted joint simulation of this failed candidate, not a simulator for a functioning WKEM. It does not cover arbitrary maliciously correlated source coins, setup validity, related capsules, or native forgery.

## 3. Consequence for original release, and actual attempted repair

The candidate has a genuine hidden common fixed state and noninvertible public maps. However the same independent-plant simulation that hides that state from an unauthorized evaluator also hides it from the honest evaluator GIVEN an independently available qualifying original certificate. Thus the proposed source-directed convergence is not supplied by the source verifier, no matter how the schedule is selected. Changing update order, adding indices, iterating to a guessed fixed point, or supplying a more detailed verifier trace does not change this result. Do not implement a larger fixture.

Even returning sigma_cancel without finding the planted pair is not an established alternative: under the BASE experiment the independent mask E gives no information about sigma_cancel beyond the external native/source view; the above joint distinguishing bound transfers any efficient success test to this BASE experiment up to its stated loss. Recovery that is already feasible from that external view would be an independent endpoint issue, not a source-controlled release. For the specific proposed Open, a correct decryption without the planted pair also could arise from an accidental KDF output equality; for uniformly random independent L-bit F values a fresh such guess has chance 2^-L, and this does not establish every-witness completeness. No native unforgeability reduction is asserted.

A possible repair is to give each qualifying ORIGINAL witness a way to compute either one of the two planted coordinates (not necessarily the same coordinate for all witnesses). Then the rest is a real public transport: given a, compute b=d_j XOR B_j(a); given b, compute a=c_j XOR A_j(b); apply F and unmask E. This is exact and does not require a common full state from every witness, a known starting trajectory, or inversion of any map. It is not permissible to assume the coordinate access.

Try setting a equal to a public original anchor or a deterministic hash of the claim commitment, with b still random. Build can instantiate this repair without a witness, but every observer knows a and the same one-step B update recovers b and the exact frozen capability, on FALSE or hard-TRUE alike. The symmetric case with public b fails identically. A coordinate equal to a secret selected at setup but with no actual source-dependent public correlation returns to the independent-plant diagnostic. A coordinate computed from one known original witness neither ensures every-witness access nor prevents malicious retained source coins from making that access public before a relevant challenge. None of these variants passes the release obligation. These are exact attacks or conditional correctness failures, not an attack on the real source verifier.

For a genuinely different repaired construction one must change the distribution of the actual public transition descriptors so that the ORIGINAL evidence supplies correlated access to a planted coordinate (or a new irreversible convergence rule that does not need such access), while preserving a joint simulator for observers without qualifying evidence. In particular the independence used above must not simply be asserted for an evaluator given w in the repaired distribution. A useful target would be a polynomial classical sampler producing nonlinear transition maps, not an oracle programmed at future witness points, whose planted state can be reached with every original witness and whose full public descriptor admits a reduction from arbitrary unauthorized recovery to an actual original certificate or an independent justified QPT break. The present construction has not implemented that sampler. Merely adding a V_x acceptance branch to the public map description, followed by a literal hidden state, is not cryptographic access control.

## Scope and handoff

Do not repeat this candidate with more coordinates, random map families, longer trajectories, or a different hash domain. Its problem is source-conditioned convergence, not fixed-point hiding or optimization. The restricted coupling is useful to test the actual new construction but not a notification-gate advance. No general impossibility of source-specific computational hash-only release follows.

All three original OR grounds and actual relevance/maturity, R316 LC correction, R225 native activation scope, one-honest malicious setup and pre-funding correctness, full auxiliary/sibling composition, native exact recovery versus accepted forgery, and timely admissible evidence/inclusion remain unchanged. Static derivation only; no cryptographic checker, code execution for crypto, tests, subagents, web, or external literature used. No ordinary PR progress comment.
