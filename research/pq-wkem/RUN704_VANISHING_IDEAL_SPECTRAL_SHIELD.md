# Run 704 — Relation-vanishing spectral shield: exact false-instance full-view simulation

Research-only, 2026-10-22. Started from verified syscoin/PVUGC#1 open draft at 51672b61ca111dcd243964d5ce9fa6fedfe95876. Follows Run 593 typed matrix SOURCE, Run 701 3CNF SOURCE, Runs 695/696 same-eigenvalue correctness and randomized recovery, and the local-only Run 703 native exact-key adapter. No practical or arbitrary-NP PQ WKEM is claimed. Polynomial ideals and Nullstellensatz certificates are established algebra; this checkpoint is their exact composition with the existing public spectral release and a QPT false-instance simulation, not a claim of inventing polynomial ideals.

## Explicit honest algorithms and entire public output

Fix the ORIGINAL relation/context x (including claim/UTXO, branch, source anchors/window and native verification context) and a complete normalized SOURCE z=(u,h) from the Run 701 3CNF compiler. Let each PUBLIC r_i(u) vanish on every accepted SOURCE, e.g. Booleanity u_j^2-u_j or violated-clause indicator r_c(u)=product_{l in clause c}(1-l(u)). Let M_x(z) be the Run 701 typed-gate baseline operator, built with private independent random factors, of dimension N=2bm+1, independent of the intended K conditional on public context.

For every i, publish a multiplier-space specification P_i (a finite-dimensional polynomial space with fixed monomial basis). Secretly sample independently uniform matrix polynomials Q_i in P_i tensor Mat_N(F_q); do not expose Q_i, private M factors or coins. Publish ONLY the aggregated polynomial coefficient array:

    C_x(z)=M_x(z)+K I_N + sum_i r_i(u) Q_i(u),

plus x, the native verification key pk, the Run 703 native key-binding tag tau (if used), field, spaces P_i and decoder parameters. All public coefficient slices, polynomial degrees and evaluation rules are part of the full view, not an ideal oracle. A deterministic public lossless codec may be applied to the aggregate without changing conclusions. Honest N-of-N erasure/abort security remains an independent unimplemented premise.

Encode a valid ORIGINAL witness w using Run 701, obtaining accepted z. All r_i(u) vanish, so C_x(z)=M_x(z)+K I_N EXACTLY. Run 593/695 therefore give the same rank deficiency for EVERY valid witness; Run 696 Krylov/Berlekamp-Massey/Frobenius receives exactly its previous matrix and recovers K as before. Different valid witnesses may generate different matrices. Native PK/tag candidate filtering and offline signing are unchanged (Run 703 was verified locally but not committed). This is a correctness-preserving modification; it does not itself establish hard-true key security.

## Theorem A: exact public polynomial transcript key independence for a concrete class

Define W_x={sum_i r_i Q_i: Q_i in P_i tensor Mat_N(F_q)}. It is a finite-dimensional linear subspace of the COMPLETE public coefficient-array space. Independent uniform Q_i push forward to a uniform distribution on W_x: every fiber of a linear map has the same cardinality.

Suppose that for fixed x there exist scalar polynomials p_i in P_i such that the FORMAL polynomial identity sum_i r_i(u)p_i(u)=1 holds. This is a bounded multiplier-space unit/Nullstellensatz certificate, not an assumption that can be made for arbitrary false inputs with polynomial cost. Then, for any fixed baseline matrix polynomial M, any K and K', the ENTIRE public coefficient-array distributions of M+KI+sum r_iQ_i and M+K'I+sum r_iQ_i are identical.

Proof: set Delta=K'-K and Q_i'=Q_i-Delta p_i I_N. This is a bijection of independent uniform mask coins because p_i lies in P_i. Then M+K'I+sum r_iQ_i' = M+KI+sum r_iQ_i, coefficient for coefficient, for ALL z (even invalid/non-Boolean). Thus complete ciphertext laws and all classical or coherent public-evaluation channels are equal, with total variation distance zero. No selected-query restriction, QROM programming, rewinding or supplied SOURCE representation appears.

The statement remains exact given arbitrary quantum auxiliary state correlated with K, pk or tau, provided that state does not reveal or correlate with the freshly sampled hidden mask coins and that M sampling conditional on public context is independent of K. It is not malicious-setup/retained-mask security.

## Theorem B: straight-line native-security reduction, only for those FALSE x

Give a QPT simulator a native challenge (pk,tau) and any correlated allowed auxiliary quantum state, but not K. It samples M and Q_i according to honest setup, inserts dummy K*=0, and forwards (x,C*,pk,tau) to any full-public-transcript attacker. For x satisfying Theorem A, conditional on the native challenge this is EXACTLY the real joint public distribution, since the shielded spectral C is independent of K. If the attacker recovers K or emits a native forgery, the simulator outputs that object unchanged.

Therefore FALSE-instance additional key information leaked by C is zero, and false-instance unauthorized key recovery/native forgery reduces without loss to the **augmented native** problem with actual pk AND tau exposed. This is NOT a reduction of augmented native security to standard SLH-DSA EUF-CMA; the hash tag may be correlated with the secret and must be included in its exact QPT game. It does not prove the generic ORIGINAL witness-extraction direction. Fresh independent masks extend the same exact coupling to jointly exposed multiple false capsules, even with a shared K, pk and tau; reuse of masks or any true capsule is unproved.

## Independently instantiated certificates (not a new WE assumption)

False 2-variable formula with four clauses (u or v), (u or not v), (not u or v), (not u or not v). Their violated-clause polynomials are (1-u)(1-v), (1-u)v, u(1-v), uv. They sum to 1 IDENTICALLY as a polynomial. Four independent constant matrix masks suffice; relative to Run 701's affine SOURCE operator, only uv is a newly needed public monomial coefficient slice. The full public coefficient distribution is exactly key-independent for this false x, even with native pk and tau correlations except the augmented-native challenge itself.

More substantively, the jointly contradictory clauses (u), (not u or v), (not v) have residuals r1=1-u, r2=u(1-v), r3=v. No constant combination equals 1: the uv coefficient forces the multiplier of r2 to vanish, conflicting with the u and constant coefficients. However the NONCONSTANT degree-one identity

    1 = r1+r2+u*r3 = (1-u)+u(1-v)+uv

holds identically. Take P1=P2=span{1}, P3=span{1,u}; exact key-shift coupling subtracts Delta*I from the Q1 constant, Q2 constant and the u coefficient of Q3. The public aggregate still adds at most uv relative to the affine SOURCE coefficients. These are complete globally inconsistent systems, not independent locally openable clauses.

For a TRUE 2-clause formula (u or v), (not u or v), both valid ORIGINAL assignments (0,1) and (1,1) compile through actual Run 701 typed gates; their intermediate matrices differ but the added masks vanish exactly and K remains an eigenvalue of both. The supplemental full Python checker verified these same-matrix equalities and rank deficiency in F_101. Its output was 71 assertions, with two different valid SOURCE matrices, no accepted false SOURCE in both false examples, and exact all-coefficient key-shift coupling. The compact committed Node checker rechecks a q=3 exhaustive census of all 81 four-mask full polynomial transcripts PER key for keys 0,1,2; distributions coincide exactly. It also checks 17 matrix-valued full coefficient couplings and the nontrivial degree-one identity.

## Generality, size and honest limitations

Every false Boolean 3CNF has an exponential-size certificate in sufficiently large polynomial multiplier spaces. Write Boolean indicator e_a(u)=product_j[u_j if a_j=1 else 1-u_j], and note sum_{a in {0,1}^t} e_a=1. Choose one violated clause c(a) for every assignment a; e_a*r_{c(a)}=e_a modulo the Booleanity ideal (u_j^2-u_j). Summation and elementary polynomial reduction yield 1=sum_c r_c p_c+sum_j(u_j^2-u_j)s_j, with deg p_c<=t and deg s_j<=t+1. This demonstrates existence for EVERY false 3CNF, without a witness or refutation supplied at Build time, but coefficient/support sizes can be exponential in t. For a total-degree D public polynomial in t variables, naive storage is N^2*binom(t+D,D) field elements. Polynomial-size false hiding for arbitrary NP is NOT established. Even one extra dense N=30001 matrix costs around 29.7 GB at 33 bytes per field element; these toy fixtures do not give practical 128-bit parameters.

What is PROVED under the stated model: every-valid-witness exact spectral correctness survives; an independently instantiated bounded certificate gives perfect independence of the ENTIRE false ciphertext from K; this yields a lossless straight-line QPT false-instance native-challenge simulation, including public pk, tau and separately keyed false-capsule aggregation. This is a genuine partial reduction without a renamed WE/oracle assumption.

What is STILL UNPROVED: polynomial-size masks/certificates for all false Syscoin relations; hard-true unauthorized key recovery or accepted native forgery -> accepted SOURCE/ORIGINAL witness (Run 259 applies ONLY AFTER SOURCE is supplied); independent augmented-native QPT hardness with pk+tau; malicious or retained-coin setup/abort; multi-capsule true-branch leakage; 128-bit resources; Bitcoin P2MR/native-SLH activation and complete transaction graph. A public evaluator given an easy true witness is expected to recover K; the missing hard-true case is fundamentally different.

Next CONSTRUCTIVE handoff: find polynomial mask spaces that cover a meaningful authentic SYS/BTC false-evidence subrelation, without sacrificing this exact shift-coupling, and then derive or replace the hard-true carrier with an independently justified arbitrary-QPT recovery-to-SOURCE reduction. Do not count further compression or a generic-model theorem as completion.

Dependencies: verified Run 701 note blob 94628f7a9248d6336476a9867552c5ef66d2e6cd; Run 593 typed gate 29b9168bfff6043810284cd1960400579f224e31; Run 259 SOURCE-binding c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2; prior Run 703 native adapter is local-only after GitHub safety denial. This is research, not production code.
