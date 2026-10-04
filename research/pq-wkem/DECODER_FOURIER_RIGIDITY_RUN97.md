# Run 97 — arbitrary-decoder Fourier identity and decoder-rigidity barrier

## Status

Starting verified PR head: f127e33fb43ed2898bcc0a67ddbc944c5f514ca9 on branch research/pq-wkem-validation-20260918. PR #1 was open, draft, and unmerged. The immediate scientific handoff is the local Run-96 q-ary-symmetric Hamming-spectral release theorem; Run 92 and Run 89 are present on the current research branch.

This run does not complete the practical PQ witness KEM. It corrects the strongest unresolved claim in the Run-96 handoff. There is an exact Fourier identity for the final classical response of an arbitrary QPT decoder, and under polynomial key-sensitive response-spectrum support there is a coherent QPT extractor for a low-weight normalized source relation. However, decoder success alone does not imply that support property: an explicit deterministic polynomial-time decoder family has constant recovery advantage while every response Fourier coefficient is exponentially small, every supported mode has growing Hamming weight, and the genuine weight-one witness mode has coefficient exactly zero.

Production code is unchanged.

## 1. Channel and exact arbitrary-decoder identity

Let F_q be a prime field, P in F_q^{r x m}, C = ker(P), h in F_q^m, and 0 < beta < 1. One bit capsule is

X = P^T s + E + b h,

where s is uniform and each coordinate of E is q-ary symmetric:

Pr[E=0] = (1+(q-1)beta)/q,
Pr[E=a != 0] = (1-beta)/q.

Every nontrivial additive character of one noise coordinate has expectation beta. For L independent capsules of the same bit, write Y=(y_1,...,y_L),

W(Y) = sum_j wt(y_j),
sigma(Y) = sum_j h^T y_j.

Let A be any QPT algorithm receiving the complete classical capsule tuple and finally outputting one classical bit. It may have arbitrary internal quantum state, auxiliary quantum input, measurements, and randomness. Define its real response function

f(x) = E[(-1)^{A(x)}] in [-1,1]

and normalized additive Fourier coefficient

fhat(Y) = E_x[f(x) omega^{-<Y,x>}],  omega = exp(2 pi i/q).

If b is uniform and A succeeds with probability 1/2 + epsilon, then

2 epsilon = (1/2) sum_{Y in C^L} fhat(Y) beta^{W(Y)} (1 - omega^{sigma(Y)}).      (1)

Proof: Fourier-expand f. Averaging P^T s_j kills every frequency outside C. Independent q-symmetric noise contributes beta^{wt(y_j)}. The bit shift contributes omega^{b sigma(Y)}. Averaging (-1)^b over b=0,1 yields (1).

This theorem is information-theoretic. It already quantifies over arbitrary QPT decoders because it uses only their final classical output probabilities. It assumes no LWE/SIS/MinRank hardness, generic group, QROM, rewinding, or extraction.

## 2. Conditional positive theorem: polynomial key-sensitive spectrum

Define

S_A = {Y in C^L : sigma(Y) != 0 and fhat(Y) != 0}.

Assume |S_A| <= M. This is a structural condition, not a new hardness assumption and not something inferred from success.

Taking absolute values in (1) and using |1-omega^a| <= 2 shows that some Y in S_A satisfies

|fhat(Y)| beta^{W(Y)} >= 2 epsilon / M.                  (2)

Hence

|fhat(Y)| >= 2 epsilon / M,                              (3)

and

W(Y) <= ln(M/(2 epsilon)) / ln(1/beta).                  (4)

Because sigma(Y) != 0, some component y_j has h^T y_j != 0. Scaling it by (h^T y_j)^{-1} preserves Hamming weight and gives

P y'_j = 0,    h^T y'_j = 1.

Therefore, if the source/Karp-Levin extractor works for every normalized codeword through the support threshold in (4), the mode yields an ORIGINAL source witness.

This gives a concrete positive interface: polynomial key-sensitive response-spectrum support plus non-negligible decoding advantage implies a polynomially bounded source relation.

## 3. Coherent QPT extraction under that condition

The coefficient in (3) is algorithmically extractable if the reduction has a coherently re-runnable implementation of the adversary, including preparation of any auxiliary state used by the run, and access to the resulting circuit's adjoint. Let U_A be a unitary dilation of that complete implementation and let Z apply phase (-1)^a to its designated output bit. Then

V_A = U_A^dagger Z U_A

has clean-workspace matrix element f(x). Prepare uniform x, apply V_A, apply the quantum Fourier transform over the capsule domain, then measure the Fourier register together with whether the workspace returned to zero. The joint probability of seeing Y and clean workspace is exactly

|fhat(Y)|^2.                                             (5)

Thus a coefficient of magnitude at least 2 epsilon/M is sampled in expected polynomial time when M/epsilon is polynomial. The candidate is publicly checked by testing P y_j=0, sigma(Y)!=0, the weight cutoff, then normalizing one component and invoking the source extractor.

The reduction model matters: it uses a coherent implementation of the adversary circuit, re-preparation/purification of its auxiliary state, and U_A^dagger. It is not a claim about one-way black-box access to an unknown quantum device, nor does it cover a one-shot unknown quantum-advice state that the reduction cannot coherently prepare again. This matches the access model of quantum Goldreich-Levin formulations that assume a unitary and its adjoint and run polynomially in the inverse heavy-coefficient threshold.

## 4. Barrier: success alone does not force heavy or low-weight response modes

The support premise above is not automatic. The following explicit family lives inside the binary q=2 version of the same q-symmetric shift channel.

For r >= 2, let m=3r+1 with coordinates

x = (x_0, z_1,...,z_r, u_1,v_1,...,u_r,v_r).

Take P=0 and h=e_0, so the weight-one normalized relation e_0 exists. Let

X = E_beta + b e_0

with independent binary symmetric noise, and define the deterministic polynomial-time decoder

A_r(x) = x_0 + sum_j z_j + sum_i u_i v_i  mod 2.        (6)

Its phase response is f_r(x)=(-1)^{A_r(x)}.

The linear factors force every supported Walsh frequency to satisfy y_0=1 and y_{z_j}=1 for all j. Each quadratic pair (-1)^{u_i v_i} has four normalized Walsh coefficients, all of magnitude 1/2. Tensoring r pairs gives exactly 4^r supported coefficients, each of magnitude

2^{-r}.                                                  (7)

Every supported frequency has Hamming weight at least

r+1,                                                     (8)

while the actual weight-one witness mode e_0 has Fourier coefficient exactly zero.

For binary q-symmetric noise E[(-1)^E]=beta. For two independent noise bits U,V,

kappa_2(beta) = E[(-1)^{UV}] = 1 - (1-beta)^2/2.         (9)

Therefore

E[(-1)^{A_r(X)+b}] = beta^{r+1} kappa_2(beta)^r,         (10)

and

Pr[A_r(X)=b] = (1 + beta^{r+1} kappa_2(beta)^r)/2.       (11)

Choose beta_r = 1 - a/r for fixed a>0. Then beta_r^{r+1} -> e^{-a}, kappa_2(beta_r)^r -> 1, and

Pr[A_r(X)=b] -> (1+e^{-a})/2.                            (12)

For a=1 this tends to about 0.68394, a constant recovery advantage. Yet the target spectrum has exponential size 4^r, every individual coefficient is exponentially small, all supported modes have weight at least r+1, and the genuine weight-one witness coefficient is exactly zero.

This is deliberately a toy source because P=0 makes the witness public. It is not a break of a cryptographic hard instance and not a full black-box impossibility theorem. It rigorously refutes only the analytic implication needed to correct Run 96:

successful decoding does NOT imply that the decoder's own Fourier response exposes a heavy or low-weight witness mode.

Coherent Fourier sampling can sample response frequencies efficiently because their total squared mass is one, but here it samples only the high-weight family and can never output e_0 from the decoder response because that coefficient is zero.

## 5. Consequence for the WKEM program

Run 96 conditionally provided the false-statement half:

false source weight-enumerator bound -> statistical hiding -> arbitrary-QPT false hiding.

Run 97 shows that the true-instance extraction half requires an additional theorem. A final construction must prove at least one of:

1. decoder rigidity/concentration: every successful decoder for the actual release has non-negligible Fourier mass on source-extractable normalized relations;
2. a different extraction channel that obtains an ORIGINAL witness without requiring the decoder's own Fourier response to contain it;
3. a direct independently justified QPT-hardness reduction from arbitrary early key recovery.

The polynomial-spectrum theorem above is a valid positive interface with explicit resource bounds, but the bent family proves that this structure cannot simply be assumed from decoder success.

## 6. Literature status

The current Jin ePrint page still states a Karp-Levin reduction from polylog(lambda)-size circuit SAT to GapMDP over a prime field of size lambda^{omega(1)}, approximation factor omega(log lambda), and generic-group extractable WE for the compressed circuits. The full PDF remained inaccessible through the available web-fetch path in this run. Therefore the exact code dimensions, normalization, low-support ORIGINAL-witness extraction threshold, and weight enumerator required by Run 96 remain unverified from the full proof. Jin's generic-group encryption theorem is not used here as a PQ reduction.

For quantum Goldreich-Levin, the accessible modern theorem used only as an access-model check assumes oracle access to a unitary and its adjoint and polynomial dependence on the inverse coefficient threshold. Run 97's extractor is derived directly for our response function; the literature reference is not used to replace that derivation.

## 7. Quantum-security ledger

Honest algorithms: unchanged; Run 96 remains classical PPT if its source reduction and repetition count are polynomial.

Adversary: identity (1) holds for arbitrary QPT decoders with arbitrary quantum auxiliary state and final classical bit output. The coherent extraction theorem is narrower: the reduction must be able to coherently prepare/re-run the adversary's auxiliary state as part of U_A.

Hardness: none for the new identity or counterexample. The sparse-spectrum theorem is structural/conditional and is not promoted to a cryptographic assumption.

Reduction model: coherent extractor uses the complete adversary implementation and its adjoint, including coherently re-preparable auxiliary-state preparation. No rewinding or QROM is used. Ordinary one-way oracle access or a non-repreparable one-shot quantum advice state is not claimed sufficient.

Established in this run: exact arbitrary-decoder response identity; coherent extraction under polynomial key-sensitive Fourier support; explicit deterministic decoder family proving success alone does not imply heavy or low-weight response modes.

Still UNPROVED: decoder rigidity for the actual source/release; arbitrary-QPT early FINAL-key recovery to ORIGINAL source witness or an independently justified PQ-hardness break; Jin's exact source parameters; malicious-secure setup/abort if eventually needed; concrete practical final parameters.

The stopping condition remains unmet.

## 8. Validation executed

The deterministic standard-library checker decoder_fourier_rigidity_run97_check.py was executed twice with byte-identical JSON. It verifies:

1. exhaustive instances of identity (1) on tiny binary linear channels and deterministic decoder truth tables;
2. exact Walsh spectra of the counterfamily for r=1..4: support 4^r, magnitude 2^{-r}, minimum support weight r+1, and zero e_0 coefficient;
3. exact success enumeration against (10)-(11) for small r using rational noise probabilities;
4. the asymptotic table for beta_r=1-1/r through r=256, showing constant recovery correlation while coefficients decay exponentially and minimum Fourier weight grows linearly;
5. synthetic sparse-spectrum arithmetic checking the threshold implications (2)-(4).

These are algebra/probability checks, not cryptographic hardness evidence.

## 9. Next handoff

Do not spend the next run merely applying Goldreich-Levin to the Run-96 decoder; the bent family refutes that route without an additional rigidity theorem.

The highest-value next work is to audit Jin's actual source code geometry (k,m,d,D, normalization, weight enumerator, and every-low-support ORIGINAL-witness extraction) and then test candidate decoder-rigidity transformations against the Run-97 bent family plus the earlier occurrence-switching/public-closure failures. In parallel, a direct QPT-hardness reduction that bypasses decoder Fourier coefficients remains acceptable if its exact assumption and quantum reduction are independently justified.

The practical generic-NP public offline PQ witness KEM remains open.
