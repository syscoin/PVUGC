# MINK-TWO-OPEN-LINEAR-20261102-R17

STATUS: one-mask/two-openable receiver-key construction for R16's one-edge, one-honest-slot 3COL proof. Exact finite algebra proved, straight-line quantum-polynomial-time (QPT) simulation conditional on the PREVIOUS specified-distribution decisional-QPT-LWE assumption. This is NOT generic witness encryption, a complete full-public SOURCE simulator, a hard-TRUE ORIGINAL-witness extractor, 128-bit security validation, or a Bitcoin deployment claim.

## Predecessor / exact source / objective

Read draft/open/unmerged syscoin/PVUGC PR #1 at 61f396640a3a4a0da7287964c6a2b86837ffe26b, branch research/pq-wkem-validation-20260918; R16 source research/pq-wkem/mink_multisource_commit_20261102/RESEARCH.md, Git blob 07d3893f0b8e7911bf7ab44c1dfbea6029a3cb9a; latest substantive ordinary PR comment 6580102747.

R16 uses two independently uniform D-bit receiver values T1,T2, T0=0 for each vertex/slot/round. Its all-slot FALSE graph simulator is missing. Its one-honest-slot programming shows three possible openings, although a fresh one-edge 3COL test only ever opens ONE color per endpoint. We retain R16's statistical binding, one-honest QPT-LWE masking and one-time classical edge challenge while compressing the receiver challenge to ONE D-bit value. We additionally establish an explicit conditional adaptive-single-edge transcript comparison, including revealed opening seed correlations. No SOURCE release algorithm is modified.

## Exact algorithms, distribution, checking keys and interface

Let D be EVEN. R16's public key consists of N matrices A_1,...,A_N and authenticated designated-last share transcripts; at least one A_h is honestly uniform and its associated hidden seed independently uniform. Each per-commitment seed tuple S=(S_1,...,S_N) consists of independent uniform kappa-bit seeds, sampled after public A is frozen, never reused. Define F_A(S)=XOR_j Stream_(A_j)(S_j), where each Stream is R16's 14-stage, fixed-public-matrix ordinary-LWE generator. Illustrative UNASSESSED parameters: q=2^16, n=256, m=4096, errors independently uniform [-512,511], kappa=45056, D=286720. One stream's QPT pseudorandomness is CONDITIONAL on ordinary decisional QPT-LWE with precisely this distribution, and costs at most 14 times its distinguishing advantage. Corrupt public A_j may be arbitrary functions of previously public A_h, but not of the future hidden seeds.

On each pair of bit coordinates let M(x,y)=(y,x XOR y). Both M and I XOR M are invertible over GF(2). Set L_0=0, L_1=I, L_2=M. Receiver challenges are now ONE public U in {0,1}^D, drawn exactly uniformly in real execution by the honest designated-last receiver share after all prior corrupt shares are fixed. Set T_c=L_c(U) for c in {0,1,2}. For each vertex v of proper-color c, select fresh independent seed tuple S_v and publish C_v=F_A(S_v) XOR L_c(U_v). Verify an opening (c,S) by C_v XOR L_c(U_v)=F_A(S). Verify one edge by checking both endpoint openings and different colors. Only ONE classical edge is opened from this commitment set. N slot AND-verification, authenticated context (relation ID, claim/UTXO, branch, source anchors/window, verification-key identifier), and per-round fresh secrecy requirements are unchanged.

Honest setup/evaluation are classical PPT for polynomial dimensions. A QPT verifier may perform coherent calculations on all PUBLIC classical keys/commitments and hold independently prepared or public-transcript-correlated quantum advice, but the edge/opening API sends a single CLASSICAL edge and returns classical endpoint opening data. No superposition opening-oracle access, no advice revealing fresh seed tuple entries or fresh secret graph label permutation, and no second opening of the same commitment is allowed. Related SOURCE capsules with secret-correlated auxiliary information are outside this theorem.

## Theorem A: unconditional statistical binding, unchanged R16 bound

For each distinct a,b, the linear difference L_a XOR L_b is exactly one of I, M, I XOR M, all invertible. Consequently (L_a XOR L_b)U is exactly uniform D bits for uniform U. An adversary opening C in distinct colors a and b with any two seed tuples S,S' necessarily satisfies

    (L_a XOR L_b)U = F_A(S) XOR F_A(S').

For EVERY fixed (possibly malformed) A and each ordered pair of seeds, this has probability exactly 2^(-D) over the honest receiver U. There are at most 2^(2N*kappa) ordered seed pairs and three unordered color pairs. Therefore

    delta_bind <= 3 * 2^(2N*kappa-D).

The union bound is existential over all candidate openings and holds against UNBOUNDED computation, including quantum computation eventually returning classical seeds. Freeze A before honest U. Across Q bounded authenticated sessions, V vertices and ell independently fresh rounds add at most Q*V*ell*delta_bind. The R16 completed-accept FALSE-3COL soundness proof remains: after all C freeze, one fresh hidden honest uniform edge among E edges accepts a false graph with probability at most 1-1/E, so

    Pr[all-slot completed acceptance of FALSE 3COL]
    <= (1-1/E)^ell + V*ell*delta_bind

per session, regardless of malicious OTHER slots. Aborts are not counted as successful funding; no completion-conditioned uniformity or censorship liveness claim is made.

## Theorem B: two valid colors and exact post-opening distribution

Fix any a!=b. Sample independent entire seed tuples S_a,S_b and compute Y_a=F_A(S_a), Y_b=F_A(S_b). Define the simulator's PUBLIC receiver key and commitment

    U* = (L_a XOR L_b)^(-1)(Y_a XOR Y_b),
    C* = Y_a XOR L_a(U*).

Both (a,S_a) and (b,S_b) verify exactly. The simulator can do this in classical polynomial time without a true graph coloring or SOURCE witness.

If Y_a,Y_b are independently uniform D-bit strings, the linear map (Y_a,Y_b) -> (U*,C*) is an invertible bijection, hence (U*,C*) is EXACTLY uniform over two independent D-bit public values. Replacing the two independent pseudorandom F outputs by uniforms is a straight-line QPT hybrid under the unchanged R16 specified LWE assumption. The published checking key includes U* and all A, not just a marginal C.

For POST-OPENING security, fix one chosen revealed color c in {a,b}, reveal the actual seed S_c, and replace only the OTHER independent hidden value F_A(S_d) by an independent uniform Y*. Now, CONDITIONAL on S_c and the full public A/transcript, U* is exactly uniform and C*=F_A(S_c) XOR L_c(U*). Therefore the complete joint distribution (A, authenticated earlier shares, U*, C*, c, S_c) is EXACTLY the real honest receiver-key/commitment/opening distribution in this hybrid. This does not assume a SourceOpen oracle. Its prerequisite is independence of the unrevealed seed from the adversary's prior quantum advice and selective-opening transcript.

## Theorem C: adaptive SINGLE classical edge simulation for ONE honest CRS slot

For a true 3-colorable graph G of V>=2 vertices and E>=1 edges, the honest prover fixes one proper coloring but draws a fresh secret uniform permutation of three color labels per proof round. A QPT verifier processes the entire public commitment/key transcript, then selects exactly one CLASSICAL edge e=(u,v), after which one pair of openings is returned.

Simulator for the honest slot chooses an ordered pair (a,b) uniformly among the six distinct ordered color pairs for the round. At EVERY vertex it runs Theorem B to prepare both colors a and b. After seeing the adaptively selected e, it opens u as a and v as b. Thus any selected edge accepts even when G is false. No rewind or prediction of the actual edge is needed.

Proof opportunity, with actual conditions and hybrid count: fix a candidate edge e0, and consider only the SUBNORMALIZED transcript event in which the QPT verifier's classical chosen edge equals e0 (on other events output a fixed symbol). In real execution, the two endpoint colors are uniformly one of six distinct ordered pairs due to the fresh private permutation. Replace F_A(S) for the V-2 unopened vertices by independent uniforms. In simulation, replace one HIDDEN alternate F_A(S) for each of the two revealed endpoints; by Theorem B this gives exactly the real opened endpoint distribution EVEN INCLUDING revealed S. Replace BOTH hidden F_A values at each of V-2 unopened simulated vertices. Their (U,C) pairs then become independent uniforms. The resulting reference joint classical transcript is identical, including keys, commitment values, public context, revealed seeds and the fixed-edge selection predicate. The count is (V-2)+2+2(V-2)=3V-4 independent stream replacements for this e0.

A verifier's selection predicate can be arbitrary coherent QPT POSTPROCESSING of the public classical view before returning a classical e, so the fixed-e0 argument is straight-line. The E disjoint chosen-edge events sum without quantum rewinding. Conservatively, for one round

    Adv(real full honest-slot transcript, simulator transcript)
    <= E * (3V-4) * eps_stream,
    eps_stream <= 14 * Adv_QPT-DLWE_specified.

An additional independently justified public-CRS setup simulator error, if any, must be added; it is NOT silently assumed zero. Multiple independent rounds/sessions require fresh seeds and a sequential hybrid accounting for adversarial classical transcript conditioning. The proof does not cover adaptive MULTI-edge exposure, quantum coherent queries to the opening oracle, secret-correlated seed auxiliary input, or unknown-one-honest fully malicious setup; in particular it does NOT fake the other malicious AND-verifier slots when a Build-consistency statement is FALSE.

## Bandwidth and optimality within this binding approach

At D=286720 bits, R16's receiver T1,T2 cost 2D=71680 bytes per vertex/slot/round. One U costs D=35840 bytes, a 50% receiver challenge saving. The D-bit prover commitment C is unchanged, so total public receiver+commitment falls from 3D=107520 bytes to 2D=71680 bytes (33.3% smaller). All public A matrices, proof openings, SOURCE caps, setup and native signature costs remain. For exact uniform D-bit pairwise receiver differences, entropy of a receiver seed must be >=D; therefore this single-D-bit key is minimal for this particular statistical argument. The proof remains far too large to claim practical performance.

## Exact residual obligations / non-claims

The predecessor's false SOURCE example A=0,b=(10,0,...) still leaks its protected capability and is NOT repaired. A malformed all-zero verifier slot can still refuse to accept a false intermediate Build consistency proof; AND verification across N malicious slots is NOT simulatable from only the honest h receiver key. There is no polynomial-time arbitrary ORIGINAL-NP Build/Lift with every valid ORIGINAL witness recovering the SAME precommitted capability, no joint SOURCE checking-key/capsule/native vk/auxiliary/related-capsule simulator, and no reduction from arbitrary QPT unauthorized hard-TRUE key recovery or accepted native forgery to an ORIGINAL witness or independent PQ break. No QPT hardness estimate for illustrative LWE parameters, no complete N-of-N one-honest abort proof, no keyless builder security, and no conditional Bitcoin-native endpoint implementation have been established.

The exact executable checker.js is a finite GF(2) and toy-image test, not a QPT experiment. It checks all pairwise linear maps/inverses for D=2,4,6,8, programmed two-openings, revealed-seed ideal conditional law, unopened joint uniform ideal law, actual bad-key enumerations and all false K4 edge answers. Output captured verbatim in checks.json. Independent local Python checker passed 16101 assertions twice with identical outputs; it is local-only. No web research or independent agents were used.
