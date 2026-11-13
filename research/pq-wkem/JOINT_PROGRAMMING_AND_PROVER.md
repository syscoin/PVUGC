# Joint matrix programming and the missing witness prover

**Research results, not a completed generic-NP compiler or WKEM.**

This continuation starts from PR head
`d2d87c3e3171207c4253b34c8fbf3ecb3486f59f` and the supplied fixed-target and
harmonic-channel notes. Only supplied files and the requested GitHub record
were used; no outside literature lookup or priority claim is made.

## 1. A compatible joint sampler exists

Let q be prime, z* in F_q^n nonzero, and y in F_q^d nonzero. Setup knows z*.
Choose j with z*_j != 0, choose every other column of V uniformly, and set

    V_j = (y - sum_(i != j) V_i z*_i) / z*_j.

This samples uniformly from Vz*=y, in O(dn) field operations. With y uniform
including zero, V has an exactly uniform marginal. Excluding y=0 gives a
marginal at statistical distance q^-d from uniform. The pair (V,y) is not
independent: that distinction is essential.

For a fixed source-noise law independent of the remaining matrix coins, put

    w(a)=|muhat(a)|^2, Z=sum_a w(a),
    L_z=sum_(c in F_q) w(c z*), beta*=q^-d (Z-L_z).

Then exactly

    E Theta_y = w(z*) + beta*,
    E Theta_0 = 1 + beta*,
    E sum_(Va=y, a != z*) w(a) = beta*.

Proof: scalar multiples cz* have image cy deterministically. For any a outside
span(z*), a row conditioned on its dot product with z* still has uniform dot
product with a. Independent rows give probability q^-d for every image. Sum
the nonnegative weights. QED.

Thus a useful planted preimage and small other-preimage mass can coexist. The
previous independent-target nonexistence bound does not apply to this sampler.
Setup does not need an original NP witness, but there is NO implemented public
Prove(pk,x,w) transferring the planted vector to a future witness holder.
Publishing z* instead makes it usable without a witness.

## 2. The harmonic bound can extract the planted secret itself

Use the supplied harmonic channel with eta=alpha*sin(pi*floor(q/2)/q)/sqrt(2).
Its only key-sensitive modes have Va=-t*y, t in {+1,-1}. A surviving Fourier
label is normalized to -t*a, preserving its norm.

For fixed setup let ell(V)=sum_(Va=y,a!=z*) w(a), let Gamma be an arbitrary bit
predictor's correlation, and let P_z(V) be its unnormalized circuit-access
Fourier-sampling probability on the two labels that normalize to z*. The exact
character identity, Cauchy--Schwarz and Parseval give

    |Gamma| <= eta sqrt(P_z(V) w(z*)) + eta sqrt(ell(V)).

The reduction does not need z* to run: it samples a label, checks t and the
linear relation, and outputs the sign-normalized a. Success is the analyzed
event of returning z*. The reversible-circuit and auxiliary-input qualifications
of the supplied harmonic proof still apply.

Average over programmed setup. If beta_bar bounds E ell(V) and W_bar=E w(z*)>0,
then Cauchy--Schwarz over setup and Jensen imply

    E P_z >= (|E Gamma|-eta sqrt(beta_bar))_+^2 / (eta^2 W_bar).

This avoids a Markov loss and no longer needs the earlier enlarged extraction
radius. For the supplied N-channel balanced linear key code, the same core
hybrid has E Gamma=2(epsilon-2^-kappa)/N; substitute that value for whole-key
recovery. Additional key-dependent checkers or setup leakage are not silently
covered.

This is a reduction to recovery of a deliberately planted preimage. It is NOT
an established ordinary-LWE/SIS hardness reduction for that distribution, and
returning z* is NOT returning an original NP witness. A public proving-key
construction and its full joint-distribution security remain missing.

For example, when V is uniform, z* uniform in a public useful domain D, and
y=Vz*, the target lies in V(D). Against an independent uniform target the
statistical distance is at least 1-|D|/q^d, and |D|<=Z/gamma^2 when every element
is gamma-useful. Recognizing V(D) may be computationally difficult for large D;
this is not an efficient distinguishing claim. It prevents treating the uniform
V marginal as a statistical independent-target reduction.

## 3. Several programmed proofs force their affine closure

For prescribed z_0,...,z_(h-1), define

    D=span{z_i-z_0}, H=span(D,z_0), C=z_0+D.

The constraints Vz_i=y with y!=0 are consistent iff z_0 is not in D. Uniform
rows satisfying them are obtained by ordinary affine Gaussian elimination.
For every sampled matrix V(D)=0 and V(C)=y. Outside H the image is uniform.
Consequently

    E Theta_y = sum_(a in C) w(a) + q^-d (Z-sum_(a in H) w(a)),
    E Theta_0 = sum_(a in D) w(a) + q^-d (Z-sum_(a in H) w(a)).

Random completion cannot remove those forced spectral contributions.

For any finite-group noise, two distinct preimages a,b with |muhat(a)| and
|muhat(b)| at least gamma>1/sqrt(2) also satisfy

    |muhat(a-b)| >= 2 gamma^2-1.

Project their unit-modulus characters in L2(mu) onto the constant function:
the product of constant-component lengths is >=gamma^2; the product of
orthogonal-component lengths is <=1-gamma^2. Apply the reverse triangle
inequality. For odd q, the two distinct kernel elements +/-(a-b) imply

    Theta_0 >= 1+2(2 gamma^2-1)^2.

At gamma=19/20 this is 2.29605. Near-one kernel mass therefore cannot be
combined with two distinct such proof outputs. A many-to-one prover is not
excluded, but has not been constructed.

## 4. A separate relaxed-radius restriction on locally composed provers

Form R_OR(x;w_1,...,w_k)=OR_i R(x,w_i). For fixed setup and each fixed proving
tape, suppose every coordinate of a globally evaluable public prover F is a sum
of functions, each depending on a proper subset of the k witness blocks.
Functions inside a block may be arbitrarily nonlinear. This hypothesis concerns
the COMPLETE evaluator, not merely verifier equations or a formula valid only
on accepted inputs.

Fix a valid original witness w* and public default inputs. Let u_S place w* in
blocks S and defaults elsewhere. Every nonempty S is a valid OR input. Pairing
corners along a block absent from each local summand gives

    F(u_empty)=sum_(nonempty S) (-1)^(|S|+1) F(u_S).

The coefficients sum to one. If all valid outputs satisfy V pi=y and centered
Euclidean norm <=B_h, linearity and the torus triangle inequality give

    V F(u_empty)=y,
    ||F(u_empty)||_tor <= (2^k-1) B_h.

An algorithm evaluates F on the PUBLIC defaults. It need not know w*, V, the
other corners, or a decomposition into local terms. A uniform efficient inner
extractor that covers this radius would turn that algorithm into witness search.
On a QPT-one-way relation f(w)=x, the combined promises would contradict that
one-wayness, under the stated setup/extraction model.

With a common proving-tape distribution and completeness 1-epsilon for every
fixed valid input, the same conclusion holds with probability at least
max(0,1-(2^k-1)epsilon), by a union bound over the conceptual valid corners.
Bad setup probability is separate. Input-dependent tape laws are not covered
without further work.

The norm factor is sharp. On one-bit blocks, put

    p(u)=-product_i(1-2u_i)+2^k product_i(1-u_i).

Its degree-k coefficients cancel. On nonzero Boolean u it is +/-1, while at
zero it is 2^k-1. The vector (1,t*p(u)) with verifier V=(1,0), y=1 has norm
ratio approaching 2^k-1. Conversely the genuine k-way function
(1,t*product_i(1-u_i)) escapes the bound and has a small circuit. Therefore this
is NOT a size lower bound or a general nonlinear-compiler impossibility.

For k=5 the relaxed-radius factor is 31. This result differs from the earlier
PROVER_RANGE_BOUNDARY.md: it uses a norm radius rather than a small output-set
bound and permits arbitrary nonlinear work within each input block. It does
not refute every proposed joint-programming prover.

## 5. Actual validation and scope

The separately saved standard-library package has 22 passing test groups,
zero failures/errors. Selected scope counts: 949 exact conditional image
probabilities; 212 row-fiber bijections; 357 programmed spectral matrix checks;
415 affine-closure points; 9,072 two-proof kernel inequalities; 240 local maps
and 120 arbitrary-within-block maps; 200 norm/target checks; and nine exact F3
harmonic character identities with planted-mode bounds. Counts overlap and
replays are not additive evidence.

The F3 Fourier calculations use exact rational coefficients in Q(omega),
omega^2+omega+1=0. No quantum hardware or QFT implementation was run. Fixed
random seeds and small fields are validation fixtures, not security parameters.

An initial run had one wrong expected simplification which omitted the q-1
nonzero scalar multiples of a plant. That expectation was corrected; the failed
run is logged and not counted as a completed validation.

Local helper SHA-256:
`fc349fc7e64eab3edc8c3f159ea5eec1dcef32a615fcefa49b1e51bd3780666f`.
Local final test_joint.py SHA-256:
`226e7b3967ca069caa96082dbf070d4fbe5578e9d499f48ba6845e7b598ad3e0`.
The complete source-hashed results, other tests and longer note are in the
conversation artifact `wkem_joint_programming.zip`. This documentation commit
does not claim that those test sources have been committed.

**Unfinished:** the original-witness-to-planted-proof public compiler, the
full-output PQ hardness/extraction reduction with allowed auxiliary data,
malicious-secure setup, practical secure parameters, and a completed WKEM.
No production source is changed and no deployment protection is asserted.
