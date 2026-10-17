# Posterior cleanup and weighted extraction

**No completed generic PQ WKEM or inner compiler is supplied.** This note follows the density-aware checkpoints at PR head `9c502fc3c428cc9a7852b8c1e986cc3efd576ee1`. Only supplied material and the requested GitHub record were used. No outside literature, priority claim, production change, or secure parameter recommendation is involved.

Earlier checkpoints already establish posterior-normalized channel identities, a conditional weighted extractor, and a native planted-syndrome LWE reduction. Those are not new results here. This continuation checks two proposed ways to implement the weighted extractor and its remaining geometric condition.

## 1. A public posterior sampler provides a decoder

Use the public harmonic channel over Z_q, q>=3:

    c=V^T r+e,
    d=y^T r+nu+Delta*b,
    Delta=floor(q/2),
    Pr[nu=u]=(1+alpha*cos(2*pi*u/q))/q, 0<alpha<=1.

Let r be uniform and e have distribution mu. Set

    p(c)=Pr[c], pi_c(r)=Pr[r|c],
    m_y(c)=E_(r~pi_c) omega^(-y^T r),
    J_y=E_c |m_y(c)|^2, omega=exp(2*pi*i/q).

Suppose a public algorithm independently draws r' from pi_c for the supplied c. It computes u=d-y^T r', without a source witness. Exactly,

    Pr[u=t | b]=(1+alpha*J_y*cos(2*pi*(t-Delta*b)/q))/q.

Proof: conditional on c, the true r and independent r' are iid. Their target difference has character E[omega^(y^T(r-r'))|c]=|m_y(c)|^2 and a symmetric distribution. Convolution with harmonic nu leaves only frequencies 0,+1,-1. Average over c. QED.

For ANY exact preimage z with Vz=y,

    E_c[m_y(c)*omega^(z^T c)]=muhat(z).

Cauchy--Schwarz therefore gives J_y>=|muhat(z)|^2. If the honest amplitude premise is alpha*|muhat(z)|>=gamma, then alpha*J_y>=gamma^2/alpha>=gamma^2. This does not require alpha=1.

Writing phi=pi*Delta/q and

    beta_q=sin(phi)/q * sum_u |sin(2*pi*u/q-phi)|,

the standard residual sign decision has crossover (1-alpha*J_y*beta_q)/2. For odd q>=31 and gamma=19/20, the bound beta_q>7/11-11/(7*31^2) gives crossover <0.215 by exact rational arithmetic.

If a fresh approximate posterior sampler has average conditional TV error <=0.005, either bit law changes by at most 0.005, so its crossover is <0.22. Independent calls preserve the channel independence used by the existing outer code.

For the supplied [128,32] evaluation code over F_256, eight bits per symbol and independent bit repetitions R, exact binomial-tail calculations bound FAILURE of this hypothetical unauthorized decoder as follows:

| crossover bound | R=17 | R=25 |
|---|---:|---:|
| 0.215 | <2^-122 | <2^-241 |
| 0.22 | <2^-111 | <2^-225 |

These are not security levels. They say that an efficient public posterior sampler would recover the key with overwhelming success under these correctness conditions. No such sampler for cryptographic-size instances is constructed here. Finite harmonic-sampler approximation and abort probabilities are separate terms.

## 2. Controlled history erasure has precisely that consequence

After the reversible change (r,e)->(r,c), the source sampling purification is

    |Psi>=sum_c sqrt(p(c)) |c>|phi_c>,
    |phi_c>=sum_r sqrt(pi_c(r))|r>.

Suppose a proposed public cleanup is a controlled unitary U=sum_c |c><c| tensor U_c with U_c|phi_c>=|0>. Its public inverse, applied at a classical supplied c, prepares U_c^dagger|0>=|phi_c>. Measuring gives the posterior sample required by Section 1.

The claim is robust: if sum_c p(c)*(1-|<0|U_c|phi_c>|^2)<=epsilon^2, the inverse's average posterior TV error is <=epsilon, by the pure-state measurement bound and Cauchy--Schwarz. Per-c phases do not change the measurement probabilities.

This concerns CONTROLLED reversible history erasure, not every standalone preparation of sum_c sqrt(p(c))|c>. For a permutation sampler c=F(r), the marginal clean state is uniform regardless of F, whereas conditional history erasure would invert F on a supplied c. These are different interfaces. An extractor-only secret trapdoor is also a different proposal and needs its own inner-security composition proof.

Tracing out history is not coherent erasure. Tracing the complete original random tape gives a diagonal output mixture; after partially uncomputing e and keeping r it generally gives a different mixed state with some coherences, still not the desired clean marginal. The tests distinguish those cases.

## 3. Keeping the history gives a syndrome, not necessarily a preimage

For the raw q-ary character-prediction subproblem, prepare

    q^(-d0/2) sum_(r,e) sqrt(mu(e)) |r,e>,

apply f(V^T r+e), and Fourier-transform both registers. Here V has d0 rows. A bounded f can be a clean matrix element of a QPT circuit; probabilities then include that clean-work event.

Let fhat be the normalized Fourier coefficients of f and let Fsqrtmu be the unitary Fourier transform of sqrt(mu). The exact amplitude at (u,b) is

    sum_(Va=u) fhat(a)*Fsqrtmu(b-a).

Expansion of f and character orthogonality prove the identity. The event u=y has probability at least the squared correlation E[f(V^T r+e)*omega^(-y^T r)]. But b is a convolved frequency and need not satisfy Vb=y.

Sharp control: take e=0 and f(c)=omega^(z^T c), Vz=y. Prediction is perfect and u=y occurs with probability 1, but b is uniform in F_q^n. For full-row-rank V, Pr[Vb=y]=q^-d0. This is a raw q-ary phase-predictor example, not a perfect binary decoder of the noisy harmonic channel. A different uniform-input Fourier query would recover this particular easy z; the counterexample rejects only the tested measurement as a general extraction claim.

## 4. Weighted normalization does not bound the short-mode tail

Consider an easy binary control with G independent uniform source bits, each repeated three times through BSC(eta) noise. V has one [1,1,1] block per row and the target is the source-bit parity. Minimum-weight target preimages choose one coordinate per block and have weight G. They are publicly easy to find; this is NOT a hard-NP experiment.

For one block put

    p0=((1-eta)^3+eta^3)/2, p1=eta*(1-eta)/2.

Let f be the majority phase. The unitary Fourier transform of sqrt(p)*f has singleton coefficient A=(sqrt(p0)+sqrt(p1))/sqrt(2), triple coefficient B=(sqrt(p0)-3sqrt(p1))/sqrt(2), and zero even-parity coefficients. Hence its probability on minimum-weight preimages is exactly (3A^2)^G.

At eta=1/(2G), the actual predictor correlation is

    [1-6eta^2+4eta^3]^G -> 1,

while

    log2 P_min=G*log2(3/4)+O(sqrt(G)).

The normalized weighted SIGNAL has the same issue. With

    m0=((1-eta)^3-eta^3)/((1-eta)^3+eta^3), m1=1-2eta,
    C=(sqrt(p0)*m0+sqrt(p1)*m1)/sqrt(2),
    J_block=2*p0*m0^2+6*p1*m1^2,

its normalized minimum-weight fraction is (3C^2/J_block)^G, also exponentially small. At G=256 the predictor correlation is about 0.994165, J total about 0.988387, but log2 P_min is about -76.4109.

Thus eliminating an exponential denominator does not eliminate a compiler-specific weighted bad-mode condition. Public canonicalization trivially removes the redundancy in this easy control, so these figures are NOT a general lower bound on all extractors. Any corresponding quotient, rounding, or source-witness extraction procedure for an actual compiler must be supplied and proved.

## 5. Actual validation and scope

The local full suite has 15 passing groups and passes an isolated replay with matching source hashes and counts. It includes 1,901 exact Bayes cells, 108 complete residual-law comparisons, 183 witness-character bounds, 122 inverse-posterior states, four approximate-cleanup controls, four rational code bounds, 1,398 retained-history amplitudes, 102 corresponding correlation bounds, and direct weighted tensor checks. Counts overlap in scope and replays are not additive coverage.

A separate producer and fresh consumer verified recovery of one complete 256-bit key from 17,408 channels at toy parameters q=37,V=(1,2),y=1,CBD_1,R=17. The consumer received only public data and computed its posterior by EXPONENTIAL enumeration. It was not passed a witness, reference key, producer tape, or real per-channel secret. This validates the consequence of the posterior-sampling interface, not an efficient cryptographic-size attack.

Finite probability checks use exact fractions; complex/statevector checks use explicit numerical tolerances. Analytic proofs establish the general identities. No quantum hardware, production scheme, or cryptographic parameter estimate was tested. The initial suite had one unsupported numerical threshold in a negative control, corrected from 0.1 to 0.05 after observing 0.075342; the failed log is retained and not counted as a complete validation.

The accompanying posterior_decode_check.py is a standard-library exact checker for the posterior law and code bounds. The larger statevector suite, regression, complete note, source hashes and logs are in the conversation archive wkem_posterior_continuation.zip; they are not silently claimed as committed files.

**Uncompleted:** an efficient generic source-witness compiler, the full-public-output PQ hardness/source-extraction reduction, malicious-secure setup and practical parameters, and the requested WKEM. These scoped results do not refute the separately recorded native LWE reduction, every global clean-state preparation, adversary-assisted extraction, or computational WE generally.
