# Boolean-ideal-masked rank-pencil release — 2026-11-27 UTC

Research only; nonqualifying construction/repair iteration. No practical original-source release or full-public security theorem.

Continuity: actual syscoin/PVUGC PR #1 open/draft/unmerged; branch research/pq-wkem-validation-20260918; start and prewrite head 7631390ce7dfb1bb7c4ee4e63d8e3aef135b364f. Read actual metadata, latest returned substantive comments through R225, head commit filename and exact SOURCE_SIGNED_MATCHING_AGGREGATE_20261127.md (blob 0eb714db44c275492640b032cedf325f76ab3164), SOURCE_SPECIAL_SOUNDNESS_RESPONSE_20261126.md, SOURCE_FEASIBLE_STATE_MIGRATION_20261126.md, SOURCE_COMPLEMENT_TREE_RELEASE_20261127.md and SOURCE_PAIRED_INSTANCE_REDUCTION_20261126.md. New path returned NOT_FOUND / HTTP 404 at the prewrite head. No new Core claims.

## 1. Selection before construction

Missing operation: an offline classical-PPT capsule mapping EVERY qualifying ORIGINAL source certificate to the same frozen safe native cancellation contribution S, with arbitrary full-public QPT recovery and forgery security. R_x denotes the complete bounded relation including all three independently sufficient greater-BTC-work, authenticated finite burn refutation, and qualified Syscoin inconsistency/tag-fault grounds and their admission, relevance, maturity, claim/window and native bindings. No actual source compiler is claimed.

Try a different operation from the previous additive private-coefficient evaluator and signed matching aggregate: a public linear matrix pencil whose *rank drop* selects a hidden pad bit. The opener supplies a whole globally consistent Boolean verifier trace in one evaluation, not independently selected garbled occurrence labels. The desired bit is not a common proof string, hidden evaluation coefficient, dummy preimage, or sum over a large graph. Public coefficient matrices are dense random equivalents of small formula-to-matrix representations. Unlike the paired proof-search trial, there is no explicit public source-mode branch selector or independent selector opening: the two public objects have identical types and the honest algorithm uses ordinary linear algebra. Analyze whether a public simulator can hide their distinction on FALSE/hard-TRUE statements. In particular try a high-degree randomized Boolean-ideal mask to avoid the obvious non-Boolean interpolation/fingerprint of an unmasked determinant. The mask is not an additive evaluator that is required to hide private coefficients; the intended decoding invariant is singularity.

## 2. Concrete serialized Build and Open shell

Work over F_2. Let z contain the complete padded source input and deterministic computation trace of a bounded Boolean circuit for R_x. Denote the local Boolean constraints by factors f_i(z), with value 1 iff constraint i holds, including final acceptance. Use gates of bounded fan-in and their trace-output variables, so each factor is a small multilinear polynomial over F_2; repeated variable powers are reduced on Boolean inputs. Public constants can be implemented by dedicated trace variables with local equality-to-constant constraints. Each individual factor is satisfiable, and hence nonzero as a formal multilinear polynomial, even when the global conjunction is unsatisfiable. If a factor is identically zero the verifier has a publicly immediate contradiction; that trivial case is not needed for the attack.

Between adjacent factors insert fresh pairs of variables u_i,v_i, each pair unique and absent from all f_j, with factor B_i=1+u_i v_i+v_i u_i. Define the ordered formula

    P(z,u,v) = f_1 B_1 f_2 B_2 ... B_(m-1) f_m.

Every scalar Boolean evaluation of B_i is 1, so P is exactly the verifier conjunction. The added variables may be set to zero by honest Open; they do not change the original evidence. The order of multiplication matters in the repair analysis below; no commutative expansion is required at Build. Include one further variable t, always set to 1 in honest Open.

For every bit j of a random lambda-bit pad key K, construct two polynomials p_j,i for i=0,1 with

    p_j,i = 1 + b_j,i t P + H_j,i,     b_j,i = [i=K_j].

Start with H=0. Build uses a polynomial-size arithmetic branching program (ABP) to represent the given formula. Explicit recursion: constant/variable is one directed labeled edge; sum uses disjoint parallel copies joined by constant-one edges; product uses disjoint sequential copies joined by a constant-one edge. Preserve the b=0 branch as a zero-weight edge and pad both graphs to the same number of vertices. This construction has linear size in the formula tree description, not its potentially exponential expanded monomial list.

Topologically order the vertices. Let U(z,u,v,t) be the strictly upper triangular labeled adjacency matrix (sum of parallel labels), with distinguished source a and sink c. The path sum e_a^T(I-U)^(-1)e_c is exactly the formula polynomial, since the inverse is the finite sum of powers of U. Publish coefficients of the affine linear pencil

    M_j,i = A_j,i [[ I-U_j,i, e_c ],
                   [ e_a^T,   0  ]] D_j,i,

where A,D are independently uniformly sampled invertible constant matrices over F_2 of the appropriate size. Uniform sampling may use sequential independent columns outside the span of previous columns; no secret field arithmetic is needed at Open. Do NOT publish A,D, the ABP or b separately. A,D have determinant one over F_2. Schur elimination gives det(M_j,i)=p_j,i, with sign immaterial. This is actual public matrix evaluation and not a private polynomial evaluator. Include exact context and a synthetic payload ciphertext E=S XOR ExpandH("rank-pencil-pad",ctx,K,|S|).

Open computes the full original trace from w, sets separators to zero and t=1, evaluates each published pencil at these Boolean values, and uses Gaussian elimination to find the unique singular matrix per bit. It recovers K_j as its index and decrypts E. This is classical polynomial-time and returns the same S on every qualifying original w, regardless of differing traces. This is a shell conditional on the bounded verifier representation, not an implemented source compiler or native endpoint. On an invalid Boolean trace both polynomials are 1, so neither matrix is singular. That pointwise property alone is not security.

## 3. Initial full-public fingerprint and proposed repair

For H=0 the unselected determinant is identically 1; the selected determinant is 1+tP. Random row/column equivalence does not hide determinants. The formal polynomial P is nonzero: each local factor is nonzero, every separator simplifies to 1 in the commutative polynomial ring, and that ring is an integral domain. Over a sufficiently large characteristic-two extension field, an arbitrary public party evaluates both pencils at independently random field values. By the elementary degree/root bound for a nonzero multivariate polynomial (induction on the number of variables), tP is nonzero with probability at least 1-deg(tP)/|F|. Thus it identifies the bit without any Boolean satisfying witness, even on globally FALSE statements. Field extension arithmetic is polynomial in the extension degree; the adversary uses the published F_2 coefficients unchanged.

Repair the direct comparison with the constant determinant by masking BOTH sides independently with high-degree Boolean-ideal polynomials. Let h range over ALL scalar variables, including t and separator variables. Choose polynomial-size random formulas Q_j,i,h (e.g. sums/products of random affine forms), and set

    H_j,i = sum_h (h*h+h) Q_j,i,h.

The factor h*h+h appears adjacently in this ordered formula. This is a real mathematical change: the unselected determinant is no longer formally constant and the ordinary extension-field fingerprint above does not directly identify it. On scalar Boolean traces every mask vanishes, preserving exact honest correctness. Build compiles the expanded *formula description* into the same ABP shell, with same-size padding as needed. It does not reveal the masks separately. No assumption that this distribution hides the two pencils is made. An attempted simulator would need to conceal the selector in the whole pair, not merely the scalar determinant values on invalid Boolean inputs.

## 4. Full-public noncommuting-idempotent substitution defeats this repair

The scalar Booleanity mask vanishes not only at scalar bits but also at arbitrary idempotent matrices X_h over F_2, because X_h^2+X_h=0. Unlike scalar Boolean bits, idempotent matrices need not commute. Substitute X_h for each variable in the PUBLIC affine pencil, interpreting a constant matrix coefficient C as C tensor I_d, and a variable coefficient C_h as C_h tensor X_h, so that the entire output is an ordinary block matrix over F_2. Row/column equivalence remains exact:

    M_j,i(X) = (A_j,i tensor I_d) M_raw_j,i(X) (D_j,i tensor I_d).

The strictly upper triangular block adjacency still has a finite path-sum inverse. Block Schur elimination reduces the rank of this matrix to (number of ABP vertices)*d plus the rank of

    p_j,i(X) = I_d + b_j,i T P(X).

All H_j,i(X) vanish IDENTICALLY because the left Booleanity factors are zero, for arbitrary choices of Q and arbitrary random equivalences. This holds even when the masks have high degree. The attacker need not recover A,D or any hidden polynomial coefficients. Constant terms are interpreted as constant multiples of I_d; ordered multiplication of path weights implements the original formula order exactly.

Here is a polynomial-size construction of idempotents such that P(X) is nonzero, including on FALSE instances. Choose any nonzero monomial from each local multilinear f_i, and choose u_i v_i from each B_i. Concatenate these ordered words to form W. The chosen local words contain no repeated variable within a monomial; fresh separator symbols are disjoint from all local variables and each other. Thus W is reduced (no equal adjacent symbols). Its length L is polynomial. In the formal free associative algebra with relations h*h=h, this reduced word has coefficient 1 in P: for any expansion term to reduce to W it must choose u_i v_i from every separator (those unique variables occur nowhere else); this forces the local words between separators to be the chosen reduced local monomials. Distinct chosen local monomials cannot merge across separators. The coefficient is therefore nonzero even if the f_i are globally inconsistent. Empty monomials cause no problem; the same argument applies. If m=1 and the selected monomial is empty, the construction below uses a single state.

Construct d=L+1 dimensional row-vector transition matrices X_h on states 0,...,L, with e_k X_h defined as follows:

    if k<L and W[k+1]=h:  e_(k+1)
    else if k>0 and W[k]=h: e_k
    else:                  0.

The index notation W[1..L] is one-based. Since W is reduced, a move to the next state on h is followed by a stay on the same h. Staying and the zero state are stable. Thus X_h^2=X_h for every h. The entry (0,L) of an ordered word product is 1 exactly when that word reduces to W: a symbol must advance to the next prescribed letter, repeat the last letter, or be killed. For L=0 all X_h are zero and this entry selects the empty word. Therefore P(X) has (0,L) entry 1 by the preceding coefficient argument. This constructs the idempotents directly from the public verifier formula; no search for a satisfying witness or coefficient extraction from a hidden pencil is needed. The attack uses the same fixed P representation on both sides, chosen in Build as specified.

Finally choose an idempotent matrix T making I_d+T P(X) singular. For column-vector algebra let v be a standard basis vector such that P(X)v is nonzero (e_L works with the construction above). Choose a row linear functional phi such that phi(v)=phi(P(X)v)=1. Over F_2 either these two nonzero vectors coincide, or they are linearly independent, so these equations are solvable by Gaussian elimination. Put T=v phi. Then T^2=T, and T P(X)v=v. Hence (I_d+T P(X))v=0. This construction also works when the mask includes t's Booleanity factor.

For every bit, evaluate the two public block pencils at these idempotents, including T. The unselected block Schur complement is I_d, so it is full rank; the selected one is singular. Ordinary polynomial-time rank computation identifies K_j exactly, and the complete K decrypts E with NO original certificate. Dimensions are polynomial in the bounded formula description and the length of W. This is a straight-line classical full-view attack, stronger than needed to refute QPT security of this shell, and works for global FALSE or unauthorized hard-TRUE cases. It does not assume volunteered adversary representations, native-key extraction, hash collisions, concrete SHA properties, local garbled-label access, or any bound on additive secret-coefficient degree. It accesses only the public pencil coefficients and the actual public relation description. Consequently no full-view simulator hiding the selected payload can exist for this construction; extra native VK/message, context, related capsules or auxiliary inputs do not remove the attack. This is a synthetic pad-release failure, not a statement about a particular deployed signature scheme.

## 5. Repair boundary and next equation

One could additionally mask by commutator-ideal terms (h k+k h) Q, which vanish on scalar Boolean inputs but do NOT vanish on the noncommuting idempotents used above. That changes the mathematical premise of section 4, so the exact attack is not asserted for that more general distribution. It also removes the proof that the selected block Schur complement has the known rank: its unknown mask now contributes. Merely adding commutators is not a construction with a security reduction. Need an actual serialized matrix distribution with arbitrary-operator invariants jointly hidden, not merely matching scalar determinant evaluations or polynomial identity on the Boolean cube. Another concrete possibility is to arrange all products in a canonical multilinear Boolean normal form before compilation, but the naive expansion can have exponential size and offers no general PPT Build. The user constraint prohibits assuming a new primitive that already guarantees the common-value release; matrix equivalence hardness alone is not established by these masks.

Do not retry larger pencils, another random basis, or additional powers of Booleanity masks: the explicit attack annihilates them exactly. A proposed further repair must eliminate the noncommuting-idempotent distinguisher while retaining actual public evaluation, every-original-witness release and a joint arbitrary-QPT simulation. No such repair or security theorem was found. This is not an impossibility result for all matrix pencils, all commutator-masked distributions, or hash-only witness encryption. No actual source verifier, real native signature construction, malicious offline N-of-N setup, or related-capsule proof. R225 endpoint and R316 maturity scope unchanged. Static derivation only; no checker execution, tests, external literature, subagents, new Core inspection or ordinary PR comment. Notification gate not met.
