# Full-transcript Fourier recovery-to-ORIGINAL extraction

Research record: `fourier-recovery-extraction-20261026`.
Repository: syscoin/PVUGC, draft PR #1.
Starting head: `d47fb4cdf4e426ea00749a7e61f2b67850071df0`.

## Verdict and exact delta

The scalar-only polynomial shield from the immediately preceding review cannot
have hard-true key secrecy: on a true instance, 1 is outside the explicit mask
span and a public linear separator recovers the scalar key. A secret PRG seed or
hashing the already recoverable key does not change that conclusion.

There IS a different reusable component in the current project: the
Fourier-filtered SOURCE carrier. Its complete single-column key-dependent
Fourier support consists exactly of ORIGINAL witnesses. This note derives a
**coherent code-access extractor from an arbitrary full-transcript quantum
adversary**, rather than requiring it to supply a SOURCE representation.

The exact result is a resource-accounted extraction inequality. It does NOT
establish a practical PQ WKEM, a standard-LWE instantiation, or hard-true
security at polynomial honest cost. The current decoder still needs exponential
length in nonlinear-gate count. In particular, polynomial in the emitted
capsule length is not automatically polynomial in the security parameter or
source size. That distinction applies to the extractor as well as setup.

This is a new derivation extending the predecessor's support theorem; it is not
a claim that its earlier note already proved extraction. The predecessor
explicitly left arbitrary bare-key/native-forgery extraction open.

## 1. Exact dependencies and chosen candidate

Only these live exact-version project items were used as mathematical
continuity inputs:

* `research/pq-wkem/affine_gate_elimination_20261026/README.md`, blob
  `356d5be2f809f60ef6bc77110ac39513ca69a106`, at starting head.
* Its `check_affine_source.js`, blob
  `596c3b86a4fb8320be96513b83f2a0c5be1e6ad8`, at starting head, for the actual
  homogeneous wire/factor convention and tiny mixed-affine fixtures.
* `research/pq-wkem/VTDH_STANDARD_LWE_QPT_LIFT_RUN122.md`, read at starting head,
  to check whether its previous LWE hybrid supplied an alternative missing
  SOURCE-opening step. It does not; its own scope is only the pad layer.

No external literature, web research, older archive reconstruction, or complete
PR diff was used. Run 259 is not invoked: the Boolean SOURCE below has direct
information-theoretic decoding from a qualifying Fourier index.

## 2. Algorithms and complete public distribution

Fix an ORIGINAL deterministic Boolean verification circuit R_x(w), with t
witness input bits, exact affine gates, g AND/NAND gates, and an output-accept
pin. Its internal wires are determined by its inputs. Statement and context
include the relation identity and intended claim/branch/anchors. The source
circuit is fixed independently of the fresh release key. A newly generated
checking key is included in the bound PUBLIC capsule/context, not silently
omitted from the adversary's input. If the ORIGINAL source circuit depends
nontrivially on that same secret key, a further distribution-preserving
source/key embedding is needed; this note does not assert it.

Use the predecessor's homogeneous GF(2) SOURCE matrix C. Each wire has two
labels with v_(i,0)+v_(i,1)=v_0. Each nonlinear gate has four allowed assignment
labels with odd total when v_0=1; incidence equations tie the label marginals
to the wire labels. Affine gates and public pins are exact linear equations.
Let B be any full row basis of ker C, let d be its number of rows, and b=B e_0.
(B is called R in the predecessor; B here avoids confusing it with the
ORIGINAL relation.)

For each nonlinear gate independently sample an error block with law

    Pr[E_f=0000]=1/3,
    Pr[E_f=1000]=Pr[E_f=0100]=Pr[E_f=0010]=Pr[E_f=0001]=1/6.

All other error coordinates are zero. Let P_z be the distribution of
Q=B E+b z for z in {0,1}. All these samplers are explicit and classical.

Build for an arbitrary emitted length L:

1. Sample a fresh native secret/seed K of k bits and its public checking key
   pk, according to the native key distribution. K is independent of the
   fixed ORIGINAL source and the fresh release randomness.
2. Sample independent uniform X in GF(2)^L and independent E_1,...,E_L.
3. Compute Q_j=B E_j+b X_j for every j.
4. Use a public fixed linear reconciliation map F of rank r, chosen without
   looking at X or E, and publish W=F X. Sample an independent two-universal
   linear hash H: GF(2)^L -> GF(2)^k and publish T=K+H X.
5. Publish V=(x,context,C or its deterministic description,B,pk,F,H,W,T,
   Q_1,...,Q_L,allowed auxiliary data). No secret setup factors are exposed.

The public encoding may be losslessly compressed. Secret-dependent auxiliary
checks are not ignored: they must be part of the native challenge model and
must be simulatable by the extraction setup sampler. The simplest instantiation
here uses only pk(K), with no additional secret-key tag.

Encode/Recover is unchanged: a valid ORIGINAL w produces its complete one-hot
SOURCE v_w. Solve alpha_w B=v_w^T using public linear algebra. Then

    alpha_w Q_j = X_j + v_w^T E_j.

Its binary channel has bias rho=(2/3)^g for every valid w. A successful fixed
reconciliation decoder reconstructs X from these observations and W; return
K=T+H X and check pk. Distinct witnesses need not produce equal alpha or
intermediate matrices. They recover the same K. This proof does not implement
a new finite-length reconciliation code; it preserves the existing recovery
interface and its error conditions.

The honest algorithms are polynomial in their actual emitted length and
circuit description. No polynomial-in-circuit-length completeness claim is
made for the currently required L.

## 3. Exact witness-supported difference law

Let S_x be the set of a in GF(2)^d for which v=a^T B is the one-hot SOURCE of a
valid ORIGINAL witness and v_0=1. Since B has independent rows and the circuit
is deterministic, there is a bijection from S_x to satisfying complete circuit
states. Write s_x=|S_x|; s_x<=2^t. ExtractOriginal(a) computes v, reads input-wire
bits, and verifies the ORIGINAL circuit before returning w.

For a probability law P, use the unnormalized character expectation

    P_hat(a)=E_{Y~P}[(-1)^(a.Y)].

The gate-error Fourier coefficients at selected-label counts h=0,...,4 are
1, 2/3, 1/3, 0, -1/3. If v_0=1, every gate has either one or three selected
labels. A three-label gate makes the coefficient zero. If all gates have one
label, their incidence and affine constraints give an ORIGINAL witness.
If v_0=0, shifting by b has no effect on the character.

It follows EXACTLY, including true instances, that

    P1_hat(a)-P0_hat(a) = -2 rho  for a in S_x,
                           0     otherwise.                 (1)

In particular S_x is empty on a false ORIGINAL instance, hence P1=P0 as
complete classical laws. The previous whole-false-view simulator is retained.
No computational assumption occurs in (1).

## 4. Single-column quantum extraction lemma

Fix all other classical transcript components. Let an arbitrary quantum
adversary followed by a reversible success check have success probability
f(y) in [0,1] when the selected column is y. The success check is either exact
key equality to the setup key (known to this proof's extraction sampler), or
native verification on a fresh authorized-scope message. It does not check
whether the adversary supplied a SOURCE representation.

Let U_y be a unitary implementation of this adversary and success check,
including a purification/deferred implementation of its internal measurements.
Keep y as a read-only control register. Let Pi project onto success, and set

    Z_y = U_y^dagger (I-2 Pi) U_y.

The workspace begins in a density matrix sigma. It can contain ONE copy of
arbitrary quantum advice, even entangled with an untouched reference, provided
its distribution is the same for all substituted y. Fresh noise-dependent
advice is excluded. All public deterministic computations are circuits; no
random oracle or oracle-programming theorem is used.

Extractor:

1. Prepare the uniform superposition of y in GF(2)^d.
2. Apply the controlled U_y, phase-flip the success subspace, then apply the
   controlled U_y^dagger.
3. Apply d Hadamards to the y register and measure a.
4. Run ExtractOriginal(a); return the verified ORIGINAL witness or failure.

This is COHERENT CODE ACCESS, not merely a classical-input black-box call to
an unknown service. The extractor needs the reversible circuit implementation
of A and its inverse. It uses the advice state once; it neither clones it nor
assumes a reusable supply of copies. Inverse circuit execution is stated as an
access requirement, not asserted to follow from arbitrary oracle access.

Define

    f_hat(a)=2^-d SUM_y (-1)^(a.y) f(y),
    Z_hat_a=2^-d SUM_y (-1)^(a.y) Z_y.

The measured probability of a is

    p_a=Tr(sigma Z_hat_a^dagger Z_hat_a).

For nonzero a, Tr(sigma Z_hat_a)=-2 f_hat(a). Weighted Cauchy-Schwarz gives

    p_a >= |Tr(sigma Z_hat_a)|^2 = 4 f_hat(a)^2.             (2)

Every a in S_x is nonzero because (a^T B)_0=1. Hence the probability p_ext of
returning an ORIGINAL witness is at least 4 SUM_(a in S_x) f_hat(a)^2.

For delta=E_{P1} f-E_{P0} f, Fourier inversion and (1) give

    delta=-2 rho SUM_(a in S_x) f_hat(a).

A second Cauchy-Schwarz application proves, whenever s_x>0,

    p_ext >= delta^2 / (s_x rho^2).                         (3)

The algorithm does NOT enumerate S_x, know s_x, find a heavy coefficient
classically, or postulate that A volunteered an internal representation.
The set S_x is used only in the analysis and the efficient final SOURCE test.
This is the new upstream extraction arrow absent from a supplied-mode lemma.

## 5. Lifting to the entire capsule, checking key and helper

Let p_real denote A's key-recovery or fresh-native-forgery success on Build.
Define hybrid G_j for j=0,...,L: columns 1,...,j use independent P0 samples;
columns j+1,...,L use P_(X_i); retain the REAL pk, X-derived W,T, public H,F,
context, and allowed auxiliary data. Thus G_0 is real. No checking-key or
helper correlation is removed without an explicit hybrid.

The extractor chooses j uniformly, samples the setup key K, X, H and every
other component exactly as in G_(j-1)/G_j, and substitutes a variable y for
column j. It can compute the success predicate because it generated K or
because native verification is public. Its input ORIGINAL source remains the
same; a key-dependent source would need the additional embedding stated in
Section 2.

Condition on the sampled context xi. If X_j=0, the adjacent laws coincide and
delta_xi=0. If X_j=1, their success difference is the delta of Section 4. The
same extractor has conditional witness probability at least
(delta_xi)^2/(s_x rho^2). Average over xi and j. Telescoping and Jensen give

    p_Ext >= (p_real-p_G_L)^2 / (L^2 s_x rho^2).             (4)

For use as a one-sided security bound, retain only a positive success gap.
The quantum state sigma may vary with xi; (2) applies separately before this
averaging, so no advice-copying step is hidden in Jensen.

In G_L, all Q columns are independent of X. Since X is uniform and W=F X,
H_min(X|W)=L-r. A two-universal H gives statistical distance at most

    epsilon_H = min(1, (1/2)*sqrt(2^(k-(L-r))))

between (H,W,HX) and (H,W,U_k). This also holds with allowed quantum side
information independent of the fresh X/noise, conditioned on the public
source and setup key. Thus replacing T=K+HX with uniform changes ANY quantum
success probability by at most epsilon_H, while preserving the REAL pk(K)
and all allowed native challenge material.

Construct a native adversary B_A: given its ordinary/explicitly augmented
native challenge, sample independent P0 columns, X,W,H and uniform T, run A
once, and forward its key-recovery result or fresh signature. No unknown K or
ORIGINAL witness is needed to simulate this ideal view. Let p_native be THIS
adversary's success, not a silently assumed zero baseline. Then

    p_G_L <= p_native + epsilon_H.

Combining with (4), for eta=max(0,p_real-p_native-epsilon_H),

    p_Ext >= eta^2 / (L^2 s_x rho^2),                       (5)

or equivalently

    p_real <= p_native + epsilon_H
              + L rho sqrt(s_x p_Ext).                    (6)

This proves an explicit recovery/forgery-to-ORIGINAL-or-native-break reduction
for the specified FULL public distribution and coherent code-access model.
It is not a proof that every true instance is computationally hard. True
instances with an easy public witness must be openable, as intended.

The extractor uses O(T_A + poly(|x|,Ld,k)) quantum/classical gates, including
one coherent A execution and its inverse, plus SOURCE verification. Its
success loss in (5) must be kept when converting a concrete witness-search
hardness bound. No unit-cost access to an exponentially long capsule is used.

For false x, (1) already makes every column hybrid exact and (6) is unnecessary:
p_real <= p_native+epsilon_H. The old false-instance proof is not weakened.

## 6. When this gives a meaningful computational security conclusion

Let D_x=s_x rho^2. D_x need not be computed by the algorithms. The bound
D_x<=2^t(4/9)^g is public; for example g>=t implies D_x<=1. Under polynomial L,
polynomial D_x, a matching hard-true ORIGINAL search distribution/advice model,
and native QPT security, (5) would rule out a nonnegligible excess recovery
success. That is a conventional reduction consequence, not a new assumption
that a hidden value is releasable only by a witness.

**Those requirements are not simultaneously instantiated as a practical
scheme here.** The current honest projection decoder needs approximately
rho^-2=(9/4)^g columns per constant amount of reliable information, with
additional coding/security overhead. Generic g therefore makes honest length
exponential. The extraction loss may also be prohibitive. The theorem is
polynomial in ACTUAL public input length, not automatically QPT in a security
parameter for exponentially long inputs.

Moreover, in the illustrative g>=t regime, exhaustive ORIGINAL input search
already takes at most 2^t<=2^g, less than the leading (9/4)^g honest column
count. Thus this note must NOT be presented as a practical hard-true security
parameter set, or as proof that the current exponential object is economically
competitive with finding a witness directly. No extra dummy gates/padding are
proposed as an efficiency repair.

A useful surviving target is now precise: retain an efficiently extractable
key-sensitive mode structure while obtaining polynomial-rate honest recovery.
A different error law that changes (1) would need a NEW support and extraction
analysis. A bare LWE wrapper or the Run-122 VTDH pad cannot be assumed to supply
that structure or its full joint simulation.

## 7. Scope ledger and internal validation

**Honest setup/opening:** classical, explicit algorithms; polynomial in
emitted length, NOT generic polynomial-resource honest completeness.

**Adversary:** arbitrary quantum circuits with allowed quantum advice and
classical public inputs. Extractor has coherent circuit/inverse access. No
classical rewinding, QROM programming, generic-group assumption, or claimed
standard-LWE reduction.

**Source and native key:** fixed source independent of fresh release seed;
all pk/helper/pad correlations exposed. Secret-correlated side information is
allowed only with a matching, simulatable native challenge and extraction
sampler. Arbitrary advice correlated with fresh release noise is NOT covered.

**Multiple capsules:** the theorem immediately treats independently generated
other-key capsules as simulatable side input. For several fresh same-source,
same-key capsules, replace all their columns; use their total count in place
of L and the sum of their hash-hybrid errors. A different-source shared-key
capsule would yield a witness for one of those sources, not automatically the
intended target: independent claim/branch keys remain necessary. Adaptive
selective opening that reveals target-correlated release coins is NOT proved.
Opening an independent non-target key with its independent coins can be
included as simulatable side information; no blanket selective-opening claim.

**Native forgery:** an arbitrary accepted fresh native signature is covered by
the success predicate, not only explicit seed recovery. A Bitcoin transaction
graph must independently show that an unauthorized spend needs such a fresh
signature rather than an already preauthorized edge. The graph, ceremony,
erasure, abort/liveness and conditional native-PQ endpoint are not proved here.

**Taxonomy:** exact full-distribution equation (1), not isolated probes, handles
all public processing within the game. Neighboring-seam, global-frame,
fingerprint, public evaluation and cross-view algorithms are arbitrary choices
of A in (2)-(6). Known secret masks/biased noise/malicious setup violate the
honest sampler premise and remain separate. Context/branch separation is not
replaced with a secrecy claim. The reflection proof genuinely treats coherent
quantum A and mixed advice; it is not a classical bound with a Grover speedup.

## 8. Executed finite validation (support, not proof by testing)

The independent Python checker performs exact rational/GF(2) checks of the
published mixed-affine SOURCE convention, a unique-true example, two-gate true
and false examples, the exact Fourier difference law, arbitrary Boolean or
rational acceptance functions, and the full two-column helper/pad hybrid.

It also numerically simulates controlled four-dimensional unitary adversaries
with mixed advice, verifies the Born-rule Fourier measurement probabilities,
and checks inequality (2) and its witness-set bound. These are SMALL CLASSICAL
MATRIX SIMULATIONS, not quantum hardware runs or a test of arbitrary QPT
security. Floating-point checks use explicit tolerance; distribution and
hybrid calculations use exact fractions. The native check in the finite
helper test is deliberately insecure to verify that native success must be
subtracted; it is not a PQ primitive.

The full checker and captured output are preserved with hashes in provenance.
The derivation above, rather than the finite examples, is the claimed theorem.
Independent formal proof checking or external review has not been performed.

## 9. Core handoff

The scalar polynomial shield still cannot support hard-true secrecy. The
Fourier carrier now has an explicit full-transcript code-access extraction
inequality, including checking-key and reconciliation correlations, but no
practical hardness parameter set. Keep its false-instance simulator, SOURCE
compiler and this quantitative extractor together. The remaining constructive
problem is polynomial-rate witness-enabled recovery WITHOUT losing the
witness-supported difference law (or a separately proved computational
replacement). Do not relabel this result as completed generic PQ WKEM or as a
reason to disable the research automation.
