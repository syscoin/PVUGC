# Witness-selected decoding and its public coefficient attacks

**No completed efficient generic PQ WKEM is supplied.** This continuation constructs two candidate encoders, proves their common-key correctness, and rejects them using public recovery algorithms. Only the supplied conversation and the requested GitHub record were consulted. Starting head: `a9aaa1a68dbdbbc239d33867967e4f342c45aba6`. No outside literature, priority claim, production change, or secure parameter recommendation is involved.

## 1. Candidate: witness-selected acyclic hash masking

Let E be a finite-dimensional public coefficient space of functions of Boolean witness w, and I a known subspace vanishing on every valid witness. For example, I can be the span of bounded-degree multiples of the verifier constraints. Sample independent secret field blocks s_i and publish

    C_i(w) = b_i(w)s_i + sum_j a_ij(w) H_j(s_j) + Z_i(w),  Z_i in I.

The coefficient functions b_i,a_ij and hashes H_j are public. Setup needs no witness. Suppose every valid witness makes b_i(w) nonzero and the graph j->i for a_ij(w)!=0 acyclic. Then a witness holder evaluates the functions and solves in a topological order:

    s_i = [C_i(w)-sum_(j already recovered) a_ij(w)H_j(s_j)] / b_i(w).

Different witnesses may select different orders, but all recover the same secret vector and derived key. The computation has no returning MPC participant.

### Public recovery theorem

For unresolved set U, search for i in U and a public dual functional lambda satisfying

    lambda(I)=0,
    lambda(a_ij)=0 for j in U,
    lambda(b_i)=1.

This is ordinary linear algebra on published coefficient vectors. Subtract already computable hash terms from C_i and apply lambda to recover s_i exactly.

If a valid witness w* exists, any source of the graph induced by U under w* supplies the conceptual functional evaluation-at-w* divided by b_i(w*). Thus the linear system is feasible. The public algorithm does not need w* to find a solution. Each recovered block is exact; induction recovers all blocks in at most their count many stages.

The theorem is pointwise in the secrets and mask coins. It does not invert H, require training encryptions, or depend on a mask distribution. It defeats the intended true-but-hard extraction property for this candidate, rather than merely exploiting an invalid-witness API.

### A false-instance family

For odd cycle length L over an odd prime field, use constraints

    q_i(w)=w_i+w_(i+1)-2*w_i*w_(i+1)-1=0.

There is no Boolean satisfying assignment. At degree two I=span{q_i} has zero intersection with the affine-function space, because each quadratic monomial is unique with nonzero coefficient. Choose b_i=1 and dependencies a_ij=1-w_0 for j<i, a_ij=w_0 for j>i, a_ii=0. Public peeling starts at an endpoint and recovers every key block despite the false source relation.

### General linear closure

The implementation also treats public vector equations

    Y=L*s+sum_j N_j F_j(s_{T_j})+M*r.

Once every input to F_j is recovered, evaluate it and subtract its contribution. A functional killing M, all unknown nonlinear columns and all other unresolved linear-secret columns isolates a new secret coordinate. Any coordinate returned is exact, even if the algorithm later stalls. A witness-assisted simultaneous linear block solve is included: each row of its left inverse supplies such a functional, whose existence can instead be tested publicly. Public invertible row mixing does not change the result.

This does not recover a pure unknown nonlinear preimage from its hash, nor apply to every nonalgebraic, hidden-space or exponentially represented ciphertext.

## 2. Non-triangular candidate: masked permutation powers

Work over F_(2^b), b odd, with 0<k<b and gcd(k,b)=1. Then d=2^k+1 is coprime to 2^b-1. Choose public affine r(w), secret s, and Z in a known degree-two constraint-vanishing space I. Publish the coefficients of

    C(w)=(s+r(w))^d+Z(w).

Frobenius acts only on coefficients of Boolean multilinear functions, so this polynomial has degree at most two in w even when the integer exponent is enormous. Every valid witness recovers the same s by applying the ordinary permutation-exponent inverse to C(w), then adding r(w).

### Public recovery on every true instance

Let Q be the public quotient map modulo I. Write

    t=Q(1), u=Q(r), v=Q(r^(2^k)), D=Q(C-r^(2^k+1)).

Then exactly

    D=s^(2^k+1)t+s^(2^k)u+s*v.

On a true instance t!=0. If u=a*t and v=b'*t, evaluation at any valid witness implies b'=a^(2^k). A normalized functional recovers (s+a)^d after adding a^d, and the power inverse recovers s.

Otherwise Gaussian elimination finds lambda(t)=0 with (A,B)=(lambda(u),lambda(v)) nonzero. It gives

    A*s^(2^k)+B*s=lambda(D).

This is linear over F2 in the b binary coordinates of s. If A=0 or B=0, it has at most one solution. Otherwise its nonzero kernel elements satisfy x^(2^k-1)=B/A. Since gcd(2^k-1,2^b-1)=1, there is at most one nonzero kernel element, so at most two candidate roots. Binary Gaussian elimination obtains them without enumerating the field.

Filter candidates by membership of C-(candidate+r)^d in I. On a true instance two distinct survivors would evaluate at a valid witness to distinct inputs of the same permutation giving an equal output, impossible. Thus recovery is exact without knowing that witness.

### Asymptotic false-instance guarantee

Use the false three-pigeons/two-holes Boolean relation. I is the degree-two span of row normalization equations, within-row pair exclusions and same-hole pair exclusions. The four affine classes 1,x_0,0,x_1,0,x_2,0 remain independent modulo I.

For uniform affine r, its three nonconstant coefficients after row reduction are independent uniform a_0,a_1,a_2. The vectors (a_i) and (a_i^(2^k)) are dependent exactly when all their nonzero entries are equal. There are 1+7(q-1) such triples out of q^3, for q=2^b. Therefore t,u,v are independent, giving direct exact field-linear recovery of s, except probability

    [1+7(q-1)]/q^3.

The recovery probability tends to one as the field grows. This is a failure of the candidate's ordinary false-instance secrecy, not only of its stronger extraction claim.

## 3. Three-bit-exponent repair tested

For d=sum_(i in J) 2^i with |J|=3 and gcd(d,q-1)=1, the same candidate has degree at most three in w. Expand

    (s+r)^d=sum_(B subset J) s^(sum_(i in B)2^i) * product_(i in J\B) r^(2^i).

Subtract the known B=empty term, quotient by I, then eliminate the public coefficient vectors of secret monomials with |B|>=2. The remaining equations are linear combinations of Frobenius powers of s, hence binary linear equations. Full binary rank b is a public certificate of exact recovery. No universal claim that this rank condition always holds is made.

Tests use d=1+2^64+2^128 in F_(2^257), represented by the independently checked irreducible polynomial X^257+X^12+1. On the false five-pigeons/four-holes relation, I includes all allowed localizing products through degree three. Its quotient has dimension 56 and Q(1)!=0. Two public field-coordinate equations gave binary rank 257 and recovered s in two fixed fixtures and one independently generated public-only fixture.

The public-only fixture contains ciphertext data and a key-check hash, not s, the reference key, random tapes or mask coefficients. A separate consumer recovered the exact 256-bit derived key. This is a classical public computation, not a quantum algorithm or an attack on a third-party system. A check that I contains 1 would not remove this fixture.

## 4. Validation and scope

The final suite has 29 passing test groups, zero failures/errors, and passed an isolated replay with matching source hashes and counts. Selected scopes: 39 acyclic true capsules, 60 odd-cycle false capsules, 8 additional full-key false recoveries from 32 field blocks; 80 row-mixed joint-hash closure cases; 60 two-bit-power true recoveries and 60 false recoveries; 33,280 exact false-family coefficient triples; 3 two-bit-power and 2 three-bit-power false recoveries over the 257-bit field. Counts overlap in scope and replays are not additional coverage.

The separate public-only regression also replayed with the same single recovered key, binary nullity zero and verified commitment. Its SHA-256 is
`e0350d20acb3628d0cc1ef5fe11d6c4af9a04f095b598178a55cc4e7ff1a0d96`.

The complete source, longer proof, frozen public fixture, source-hashed results and progress log are in the conversation artifact `wkem_witness_selected_decoder.zip`. This documentation commit does not claim those code files are also committed.

Source SHA-256:
- decoder_audit.py: `b0456b187ba539d9b3c7a521699b103735f14a4615c6f71673a396d14be8027b`
- frobenius_mask.py: `453b6c1f14c53207cd259b019912e964f968f365520482794d9c1366ceb917a1`
- public_regression.py: `5bb69f36f6dc28e1403db33aaec448de41acd1ccbaece85aa80e8d61c697a061`

Both candidate encoders are rejected. The first exposes a public adaptive elimination; the second exposes public Frobenius linearization. Keeping the encoder's internal wires inside MPC cannot remove these identities from its published outputs.

**Still unconstructed:** the requested efficient generic PQ WKEM, a valid inner compiler, its full-output hardness and source-extraction reduction, and its secure setup and parameters. No new assumption asserting that missing result is substituted for its construction. These findings do not prove a universal impossibility for computational WE.
