# Checkpoint 8 continuation: quotient encodings and fixed-probe extraction

**Status: proved representation and restricted extraction lemmas, NOT a complete
WKEM, general key-recovery reduction, or PQ security claim.**

This continuation starts from PR #1 head
`9489a2a246018ae673a148c18a302fcf235dfceb`. Checkpoint 8 was a comment describing
local quotient tests; no corresponding code was committed at that head. The
quotient module here reconstructs and independently checks that statement. The
original third-party papers were not downloaded or re-reviewed. GitHub was used
only for the requested project reads/writes. No novelty/priority claim is made.

## 1. Exact public-quotient normal form

Let V=F_q^m and let S be a publicly specified linear subspace. Let
pi:V -> F_q^(m-dim S) be any public surjection with kernel S, and let sec be a
public linear right inverse. Both are computed by Gaussian elimination.

Let (K,A,F) have any joint distribution, including a nonlinear precursor F.
Sample U uniformly in S, independently of (K,A,F), and publish C=F+U.
Here A denotes allowed pre-mask auxiliary information; it need not be independent
of K or F.

Then the distributions

    (K,A,C)
    (K,A,sec(pi(F))+U')

are identical, where U' is a new independent uniform element of S. Indeed,
F-sec(pi(F)) lies in S, and translating a uniform subspace vector by any fixed
member of S preserves its law. Conditioning on K,A,F proves the joint claim.
Also pi(C)=pi(F) deterministically.

Thus C can be publicly compressed to pi(C), and a ciphertext with the identical
conditional distribution can be reconstructed from pi(C), A and fresh public
sampling randomness. This transfers any experiment on this classical public
output to the quotient and back, including QPT postprocessing, with no statistical
loss. This is a representation equivalence, not a hiding proof.

The independence assumption matters. If A reveals U, the original view can reveal
F even though its quotient does not. The tests contain an exact example. Later
public processing of already simulated data is allowed, but one cannot retain
unmodeled side information about the original hidden mask.

Even for an arbitrary nonuniform/correlated mask supported in S, the deterministic
map C -> pi(C) still works. Such a mask cannot defeat an attack already using only
the quotient. Only the reverse simulation needs independent uniform masking.

## 2. The moment quotient is explicit

Use the compiler in PROOFS.md. V is the vector space of squarefree polynomials of
degree at most D. S is the span of all reduced localizing polynomials

    X_T q_s(X), |T|<=D-2.

Do not add the affine equation mu_empty=1 to S. The homogeneous moment solutions
form S^perp under coefficient/moment pairing.

When the affine slice is nonempty, its origin mu0 and directions nu1,...,nuell
satisfy

    mu0_empty=1, nu_i_empty=0,
    (mu0,nu1,...,nuell) is a basis of S^perp.

Consequently a valid quotient coordinate system is

    Q(F)=(Lambda_mu0(F),Lambda_nu1(F),...,Lambda_nuell(F)).

For a valid witness w with affine coefficients sigma,

    F(w)=Q(F)_0 + sum_i sigma_i Q(F)_i.

This is an exact public evaluation identity. It does not make Q(F) hard to analyze.
When the affine slice is empty, the normal form using mu0 is unavailable; the
general linear quotient still exists. The implementation rejects this normalized
case rather than invent a satisfying witness.

## 3. An explicit nonlinear polynomial proposal reduces to the old rank capsule

Consider matrix-valued polynomials

    F(X)=G(K)+sum_(h=1)^r a_h(X)b_h(X)^T+Z(X),

where a_h has t coordinates, each a polynomial of degree <=D-1; b_h has t
coordinates, each affine linear; multiplication is squarefree-reduced; and every
entry of Z lies in S. For the two-way simulation, those entries are independent
uniform elements of S, independent of the precursor and allowed auxiliary data.
Let L_h be the t-by-a_D matrix of left polynomial coefficients and let R_h be the
(n+1)-by-t matrix of right polynomial coefficients. By construction,

    Lambda_mu(a_h b_h^T)=L_h B(mu) R_h.

Therefore the normalized quotient of F is EXACTLY

    C=G(K)+sum_h L_h B0 R_h,
    P_i=sum_h L_h B_i R_h, i>=1.

This is the shared-factor rank-projection capsule already considered, not a new
cryptographic encoder. All existing attacks on its public quotient transfer to
the polynomial proposal. Under uniform constraint masking, every attacker on the
polynomial proposal can also be simulated given the quotient. Polynomial
nonlinearity plus extra uniform constraint multiples does not add a missing
hiding layer.

For a valid witness the polynomial matrix evaluates to G(K) plus rank <=r,
so its correctness identity is genuine. The tests check that identity without
promoting it to key-hiding or extraction security.

## 4. Exact distribution of a fixed linear probe

Specify independent uniform factors

    L_h in F_q^(t x a), R_h in F_q^(b x t), h=1,...,r,
    H(B)=sum_h L_h B R_h,
    C=G(K)+H(B0), P_i=H(B_i),

with G a public F_q-linear encoder and K uniform in F_q^k. For fixed test matrices
Z0,...,Zell in F_q^(t x t), put

    T_Z=<Z0,C>+sum_i <Zi,P_i>,
    a_Z=G*(Z0),
    D_Z=sum_i Zi tensor B_i.

Pairings are entrywise without conjugation. Up to consistent vectorization,

    T_Z=a_Z . K + sum_h u_h^T D_Z v_h,

where u_h=vec(L_h) and v_h=vec(R_h^T) are independent uniform vectors.
For every nontrivial additive character psi,

    E psi(T_Z-a_Z.K) = q^(-r rank(D_Z)).

For one factor pair, averaging over u makes the expectation zero unless
D_Z v=0, which occurs with probability q^(-rank D_Z). Multiply the r independent
expectations. This proof works over every finite field. The executable supports
only small prime fields.

Multiplication of D_Z by any nonzero field scalar preserves rank. Fourier
inversion therefore gives the entire scalar noise distribution:

    Pr[noise=0] = 1/q + (1-1/q) q^(-r rank D_Z),
    Pr[noise=b] = (1-q^(-r rank D_Z))/q, b!=0.

Thus T_Z predicts the field-valued key functional a_Z.K with the first probability.
If a_Z=0 the test is not key-sensitive; a structured public token is not by itself
a key-recovery attack.

**Probability scope:** Z must be fixed independently of these fresh factor
samples. Computing Z from public source matrices/statement is allowed. Choosing Z
adaptively after observing the sampled ciphertext is not covered by this fixed
character law. The full joint distribution is not shown pseudorandom.

## 5. A proved, restricted recovery-to-witness reduction

Assume B0,B_i are the normalized degree-D moment compiler matrices. If

    Z0 != 0 and rank(D_Z)<D,

choose any cell (a,b) with Z0[a,b]!=0. The (a,b) block of D_Z, divided by Z0[a,b], is

    E=B0+sum_i (Zi[a,b]/Z0[a,b]) B_i.

E is an admissible affine moment matrix, is nonzero because its constant moment
is one, and rank(E)<=rank(D_Z)<D. The committed semantic extractor consequently
returns a satisfying Boolean witness. This is an explicit polynomial-time
reduction in the representation sizes. The code checks and reconstructs the
result; it does not assume the coefficients are Boolean.

This algebraic implication remains valid for ANY supplied Z, even one selected
adaptively. It is only the probability inference from observed bias that requires
the independence premise of Section 4.

Combining Sections 4 and 5, a fixed key-sensitive linear probe with character bias

    bias > q^(-rD)

necessarily supplies an extractable witness. Equivalently, its field-guessing
probability exceeding

    1/q + (1-1/q) q^(-rD)

supplies the same conclusion. On a false instance no such above-threshold fixed
probe exists.

The inequality must be strict. For Boolean x,y with x+y=3 over F5 and D=3, the
nonempty normalized moment vector is (1,4,4,3), of rank exactly three. The scalar
test Z0=1, r=1 has bias 1/125, but no Boolean witness exists. Exhaustive factor
sampling confirms the boundary exactly. The extractor correctly refuses it.

This is NOT the requested reduction from arbitrary key recovery. No algorithm is
provided for converting an arbitrary nonlinear/quantum decryptor into such a
fixed probe, and the entire spectrum can have significant aggregate weight.

## 6. Why negligible fixed linear biases do not establish secrecy

There is an unconditional general counterexample to that inference. Let

    Y=L R, L uniform t-by-h, R uniform h-by-t, h<t.

For every fixed nonzero test Z,

    E psi(<Z,Y>)=q^(-h rank Z) <= q^(-h).

Nevertheless rank(Y)<=h always. A public rank test distinguishes this from a
uniform t-by-t matrix. For a uniform matrix U,

    Pr[rank U<=h] <= 4 q^(-(t-h)^2).

Proof of the latter bound: union-bound over (t-h)-dimensional kernel subspaces.
There are at most 4 q^(h(t-h)) such subspaces, and a uniform matrix annihilates any
fixed one with probability q^(-t(t-h)). The Gaussian-binomial constant is <4,
since product_(j>=1)(1-q^-j) >= product_(j>=1)(1-2^-j)>1/4. For an elementary lower
bound use the first three factors times `1-sum_(j>=4)2^-j`, which is 147/512>1/4.

For q=2, h=128, t=256, each fixed character bias is at most 2^-128, while the
nonlinear rank test has distinguishing gap at least 1-4*2^-16384. No new primitive
or computational assumption is involved. This is a counterexample to a proof
inference, not asserted to be the actual moment compiler's ciphertext.

The exact small test uses t=4,h=2: all 65,536 factor pairs are enumerated, all
65,536 character coefficients match the formula, and exactly 7,576 of the 65,536
uniform output matrices have rank <=2. This demonstrates why Section 5 cannot be
silently advertised as security against arbitrary processing.

## 7. Reproduction and precise progress

Run from the repository root:

    python -m unittest discover -s research/pq-wkem/tests -v
    python research/pq-wkem/validate_quotient_probe.py

The latter writes a separate latest result rather than overwriting the captured
report. The new tests cover:

- 59 complete subspaces and 968 subspace/offset pairs over F2 and F3;
- nonlinear precursors and a negative auxiliary-mask-disclosure example;
- 18 moment-quotient configurations;
- 90 bilinear moment identities;
- 18 complete matrix-polynomial/rank-projection identities and 54 witness checks;
- all 256 binary matrix-valued modes with one and two independent factor pairs;
- 24 odd-field modes on all 6,561 factor pairs;
- 64 sampled modes at t=3, on all 4,096 factor pairs;
- all 78,125 factor pairs for the false F5 strict-boundary instance;
- all 65,536 factor pairs and Fourier modes for the nonlinear-rank-test example.

Counts concern different algebraic checks and repeated fixtures, not independent
cryptographic security trials. Fixed-seed Python RNGs choose reproducible public
test fixtures only. There is no cryptographic randomness implementation, KEM API,
key encapsulation security level, production change, or third-party exploit.

Completed: exact quotient restoration, concrete equivalence of a nonlinear
polynomial proposal to the previous projection encoder, exact fixed-probe
probabilities, and explicit extraction for above-threshold fixed probes.

Not completed: a secure generic PQ encoder, its full-distribution hardness
reduction, an adversary-based extractor for arbitrary successful key recovery,
practical parameters, or distributed setup. Checkpoint 8 is no longer stranded as
an uncommitted claim; it is reproducible here. The holy-grail WKEM is not completed.
