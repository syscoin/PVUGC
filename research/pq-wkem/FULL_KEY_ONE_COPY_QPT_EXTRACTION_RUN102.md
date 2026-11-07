# Run 102 — full-key one-copy QPT extraction from channel spectral concentration

## Status

Starting verified PR head: `93ae96ba977d96e435c41c86ffeb037e8dbc2ff5`
on branch `research/pq-wkem-validation-20260918`.  PR #1 was open, draft,
and unmerged.

This run continues the Run-96/98/99/101 random-direction Hamming-spectral route.
It does **not** complete the practical generic-NP PQ witness KEM because the
required generic-NP source compiler has not yet been instantiated and audited.

The central result is nevertheless stronger than Run 101:

> For the exact final raw key, the channel-spectral extraction theorem can handle
> an arbitrary non-uniform QPT adversary with an arbitrary **mixed quantum
> auxiliary state using one copy of that state**.

The reduction does not need to clone, re-prepare, purify, or measure-and-rewind the
advice.  It uses a reversible dilation of the adversary circuit, a phase on the
classical output-key register, and the circuit adjoint.  A vector-valued Fourier
sampling inequality shows that the actual measurement probability of a low-weight
source frequency dominates the scalar Fourier mass forced by successful key
recovery.

This corrects the overly conservative Run-101 statement that coherent extraction
required re-preparable/purifiable auxiliary state.

The theorem is a direct circuit reduction, not a generic theorem converting arbitrary
classical reductions to the post-quantum setting.

No production path is changed.

## 1. Public raw-key capsule

Let

\[
C=\ker P\subseteq\mathbb F_q^m.
\]

For a uniformly sampled final raw KEM key

\[
K=(K_1,\ldots,K_\kappa)\leftarrow\{0,1\}^{\kappa},
\]

publish `L` independent random-direction capsules for each bit:

\[
h_{i,j}\leftarrow\mathbb F_q^m,
\qquad
c_{i,j}=D_{i,j}+K_i h_{i,j},
\tag{1}
\]

where

\[
D_{i,j}=P^Ts_{i,j}+E_{i,j}.
\]

All `s`, `E`, and `h` are independent.  A nontrivial additive character of one
q-ary-symmetric noise coordinate has expectation `beta`.

The final key for the theorem is exactly the uniform raw `K`, or a public injective
re-encoding of it.  A non-injective KDF/hash wrapper is a separate theorem obligation.

Write

\[
N=\kappa L.
\]

For a tuple of source frequencies

\[
Y=(y_{i,j})\in C^N
\]

define total source weight

\[
W(Y)=\sum_{i,j}\operatorname{wt}(y_{i,j}).
\tag{2}
\]

## 2. Exact full-key recovery identity

Let an arbitrary QPT adversary output a candidate key `Khat`.

For a uniformly random

\[
a\leftarrow\mathbb F_2^\kappa
\]

character orthogonality gives

\[
\mathbf 1[\widehat K=K]
=
2^{-\kappa}
\sum_{a\in\mathbb F_2^\kappa}
(-1)^{a\cdot(\widehat K+K)}.
\tag{3}
\]

Therefore, if

\[
p_{\rm rec}=\Pr[\widehat K=K],
\qquad
\Delta=p_{\rm rec}-2^{-\kappa},
\tag{4}
\]

then exact key recovery above random guessing is a signed response correlation.

For fixed public directions `h` and hash `a`, define

\[
f_{a,h}(c)
=
\mathbb E[(-1)^{a\cdot\widehat K}\mid h,c]
\in[-1,1].
\tag{5}
\]

Use normalized finite-field Fourier coefficients

\[
\widehat f_{a,h}(Y)
=
\mathbb E_{c\leftarrow U}
\left[
 f_{a,h}(c)\overline{\chi_Y(c)}
\right].
\tag{6}
\]

For each key bit put

\[
\sigma_i(Y,h)=\sum_{j=1}^L h_{i,j}^T y_{i,j}
\in\mathbb F_q
\tag{7}
\]

and, with `omega=exp(2 pi i/q)`,

\[
\Gamma_{a,h}(Y)
=
\prod_{i=1}^{\kappa}
\frac{1+(-1)^{a_i}\omega^{\sigma_i(Y,h)}}{2}.
\tag{8}
\]

The exact complete-key identity is

\[
\boxed{
p_{\rm rec}
=
\mathbb E_{a,h}
\sum_{Y\in C^N}
\widehat f_{a,h}(Y)
\beta^{W(Y)}
\Gamma_{a,h}(Y).
}
\tag{9}
\]

The zero frequency contributes exactly `2^-kappa`: for `Y=0`, the product in
(8) is zero unless `a=0`, and for `a=0` the response is identically one.

Thus all recovery advantage `Delta` is carried by nonzero source frequencies.

## 3. Key averaging removes the apparent `q` dependence

For every fixed `h` and every fixed `Y`,

\[
\boxed{
\mathbb E_{a}
|\Gamma_{a,h}(Y)|^2
=
2^{-\kappa}.
}
\tag{10}
\]

This does not require `Y` to be nonzero and is exact for every prime `q`.

Indeed, for every unit-modulus complex number `z`,

\[
\frac12
\left|\frac{1+z}{2}\right|^2
+
\frac12
\left|\frac{1-z}{2}\right|^2
=
\frac12.
\tag{11}
\]

Equation (10) follows independently over the `kappa` key-bit factors.

## 4. Full-key channel-spectral-tail theorem

For an extraction threshold `B`, define source-only masses

\[
T_{\le B}
=
\sum_{\substack{Y\in C^N\\0<W(Y)\le B}}
\beta^{2W(Y)},
\tag{12}
\]

\[
T_{>B}
=
\sum_{\substack{Y\in C^N\\W(Y)>B}}
\beta^{2W(Y)}.
\tag{13}
\]

Define the adversary's averaged low-source scalar Fourier mass

\[
M_{\le B}
=
\mathbb E_{a,h}
\sum_{\substack{Y\in C^N\\0<W(Y)\le B}}
|\widehat f_{a,h}(Y)|^2.
\tag{14}
\]

Parseval gives at most one total squared response mass for every fixed `a,h`.

Using Cauchy-Schwarz over `(a,h,Y)` and (10), the high-weight contribution to
(9) has magnitude at most

\[
\sqrt{2^{-\kappa}T_{>B}}.
\tag{15}
\]

Hence put

\[
\delta
=
\Delta-\sqrt{2^{-\kappa}T_{>B}}.
\tag{16}
\]

Whenever `delta>0`, the low region contributes at least `delta`.  A second
Cauchy-Schwarz application gives

\[
\boxed{
M_{\le B}
\ge
\frac{2^\kappa\delta^2}{T_{\le B}}.
}
\tag{17}
\]

It is cleaner to normalize the source masses by the key-space size:

\[
R_{\le B}=2^{-\kappa}T_{\le B},
\qquad
R_{>B}=2^{-\kappa}T_{>B}.
\tag{18}
\]

Then

\[
\boxed{
M_{\le B}
\ge
\frac{(\Delta-\sqrt{R_{>B}})^2}{R_{\le B}}.
}
\tag{19}
\]

No assumption about one heavy Fourier coefficient or polynomial Fourier support
appears.

## 5. One-copy mixed-advice Fourier sampler

Run 101 left an unnecessary auxiliary-state restriction.  The correct reduction can
work directly with an arbitrary mixed advice state.

Fix classical `a,h`.  Model the adversary on classical capsule input `c` by a
reversible dilation

\[
U_{h,c}
\]

of its QPT circuit, acting on its arbitrary auxiliary density state `rho` together
with fresh zero work registers.  Intermediate measurements and discarded garbage are
deferred and retained in the dilation.

Let the output candidate-key register receive the phase

\[
Z_a|\widehat K\rangle
=
(-1)^{a\cdot\widehat K}|\widehat K\rangle.
\tag{20}
\]

Define the Hermitian unitary response operator

\[
V_{a,h,c}
=
U_{h,c}^{\dagger} Z_a U_{h,c}.
\tag{21}
\]

Then

\[
f_{a,h}(c)
=
\operatorname{Tr}(\rho V_{a,h,c}),
\tag{22}
\]

where `rho` here includes the fixed fresh work-register initialization.

Prepare a uniform superposition over the complete capsule vector `c`, retain `c` as
the read-only control, apply controlled `V_{a,h,c}`, Fourier transform the capsule
register, and measure frequency `Y`.

The operator Fourier coefficient is

\[
\widehat V_{a,h}(Y)
=
\mathbb E_c
\overline{\chi_Y(c)}\,V_{a,h,c}.
\tag{23}
\]

The probability of observing frequency `Y` is

\[
Q_{a,h}(Y)
=
\operatorname{Tr}
\left[
\rho\,
\widehat V_{a,h}(Y)^\dagger
\widehat V_{a,h}(Y)
\right].
\tag{24}
\]

Weighted Cauchy-Schwarz gives

\[
\boxed{
Q_{a,h}(Y)
\ge
\left|
\operatorname{Tr}(\rho\widehat V_{a,h}(Y))
\right|^2
=
|\widehat f_{a,h}(Y)|^2.
}
\tag{25}
\]

Therefore, after sampling fresh classical `a,h`, one execution of this coherent
sampler lands in the nonzero source region of total weight at most `B` with
probability at least

\[
M_{\le B}.
\tag{26}
\]

The same physical advice register is used through `U`, the phase, and `U^\dagger`.
It is not cloned, re-prepared, purified by the reduction, or measured and rewound.
The state may be consumed by the final frequency measurement; only one
non-negligible-success extraction attempt is needed.

The reduction does require the adversary's circuit description so that its reversible
dilation and adjoint can be implemented.  It is therefore a direct non-black-box
coherent-circuit reduction.  It does not claim to work when the adversary is exposed
only as an opaque forward-only CPTP oracle.

Standard non-uniform QPT adversaries are circuit families with quantum auxiliary
input/advice, so the theorem covers arbitrary such adversaries without assuming that
the advice is efficiently generatable.

## 6. ORIGINAL-source extraction theorem

Assume that for every true statement there is a polynomial threshold `B` such that:

1. every nonzero

   \[
   y\in C,\qquad \operatorname{wt}(y)\le B
   \]

   efficiently yields an ORIGINAL NP witness;

2. the normalized high tail is negligible,

   \[
   R_{>B}=\operatorname{negl}(\lambda);
   \tag{27}
   \]

3. the normalized low mass is polynomially bounded,

   \[
   R_{\le B}\le\operatorname{poly}(\lambda).
   \tag{28}
   \]

Let an arbitrary non-uniform QPT circuit adversary, with arbitrary mixed quantum
advice, recover the exact raw final key with

\[
p_{\rm rec}
\ge
2^{-\kappa}+\frac1{\operatorname{poly}(\lambda)}.
\tag{29}
\]

Then (19) gives inverse-polynomial `M_<=B`.  The one-copy sampler obtains a nonzero

\[
Y=(y_{i,j})\in C^N
\]

with total weight at most `B` with inverse-polynomial probability.  At least one
component is nonzero and itself obeys

\[
\operatorname{wt}(y_{i,j})\le B.
\]

Invoke the source extractor on that component.

Thus, under the three explicit **source-geometry** conditions above,

\[
\boxed{
\text{arbitrary non-uniform QPT exact FINAL-key recovery}
\Longrightarrow
\text{ORIGINAL NP witness}
}
\tag{30}
\]

with a one-copy quantum-advice reduction.

This is a source-conditional theorem.  It is not yet a generic-NP construction
because the required source compiler has not been instantiated.

## 7. Global correctness/recovery spectral floor

The same proof without splitting low/high regions gives

\[
\boxed{
\Delta
\le
\sqrt{2^{-\kappa}T_{\rm all}},
}
\tag{31}
\]

where

\[
T_{\rm all}
=
\sum_{\substack{Y\in C^N\\Y\ne0}}
\beta^{2W(Y)}.
\tag{32}
\]

Hence any successful full-key decoder necessarily implies

\[
\boxed{
T_{\rm all}
\ge
2^\kappa
\left(p_{\rm rec}-2^{-\kappa}\right)^2.
}
\tag{33}
\]

This is a useful sanity condition on any proposed true-instance source spectrum.

For independent capsule coordinates,

\[
\boxed{
T_{\rm all}
=
(1+S_C(\beta))^{\kappa L}-1,
}
\tag{34}
\]

where

\[
S_C(\beta)=\sum_{0\ne y\in C}\beta^{2\operatorname{wt}(y)}.
\]

Equation (34) is exact.

## 8. Two-temperature tail certificate

For `0<beta<beta'<=1`,

\[
\boxed{
T_{>B}(\beta)
\le
\left(\frac{\beta}{\beta'}\right)^{2(B+1)}
\left[
(1+S_C(\beta'))^{\kappa L}-1
\right].
}
\tag{35}
\]

This makes the true-instance extraction condition source-checkable from a weight
enumerator or an upper bound on it at a slightly larger bias.

The combined source target is now very explicit.

### False statements

Run 99 requires extractor-quality q-symmetric syndrome:

\[
HE_\beta^m\approx_{\rm stat}U,
\]

or an independently justified QPT-hard computational replacement.

### True statements

At the same operating bias:

* every nonzero relation through weight `B` must source-extract;
* `2^-kappa T_>B` must be negligible;
* `2^-kappa T_<=B` must be polynomially bounded;
* the honest witness channel must still decode every key bit reliably.

This is a two-sided source-code design problem, not a decoder-rigidity problem.

## 9. Relation to Run 97 and Run 101

Run 97 correctly refuted the inference

> successful decoder => one heavy low-weight Fourier coefficient.

Run 102 does not revive it.  Exponentially many individually tiny coefficients are
allowed.

Run 101 then showed that a concentrated **channel** spectrum forces aggregate
low-source scalar response mass, but it conservatively limited the coherent sampler
to re-preparable/purifiable advice.

Equation (25) is the repair: the actual vector-valued measurement probability
dominates the squared scalar response coefficient for an arbitrary mixed advice
state.  One copy suffices.

The remaining bottleneck has therefore moved back to the source compiler rather than
the decoder/advice model.

## 10. Relation to quantum search-to-decision literature

Sudo, Hara, Tezuka, and Yoshida, *Quantum Search-to-Decision Reduction for the LWE
Problem*, IEICE Trans. Fundamentals E108.A(2), 104--116 (2025), give a useful
precedent for the one-copy pattern.

Their generalized quantum Goldreich--Levin theorem uses a predictor unitary and its
adjoint once each together with an auxiliary quantum state.  Their Theorem 2 gives a
sample-preserving LWE search-to-decision reduction using the LWE distinguisher
unitary and its adjoint once each with the auxiliary state.

That paper does **not** solve the present source problem.  Its recovered object is
the ordinary LWE secret for a random LWE matrix.  Here the required object is a
low-weight member of the structured public relation code `ker(P)` that extracts the
ORIGINAL NP witness.

Bitansky, Brakerski, and Kalai, *Constructive Post-Quantum Reductions* (CRYPTO 2022),
show why one must not generically assert that a classical reduction remains
constructive with quantum auxiliary input: copying/restoring advice can be impossible,
especially for general search problems.

Run 102 does not use such a generic lifting theorem.  Equation (25) is a direct
one-copy circuit calculation for this particular public release distribution.

## 11. Exact validation

`full_key_one_copy_qpt_extraction_run102_check.py` is deterministic and
standard-library-only.  Two finalized executions have byte-identical JSON output.

It checks:

1. an exact binary full-key fixture with `kappa=2`, `L=2`, `m=1`,
   `beta=1/2`; the exact MAP decoder has

   \[
   p_{\rm rec}=121/256,
   \qquad
   \Delta=57/256;
   \]

2. the exact full-key spectral identity (9) over every key, direction, capsule,
   hash character, and Fourier frequency in that fixture;

3. the channel-tail lower bound (19) at several thresholds;

4. the global spectral floor (33) and product identity (34);

5. **3,072 exact rational mixed-advice operator-Fourier inequalities** over every
   assignment of four binary-input response operators from
   `{I,X,Z,-I}`, three advice states (`|0>`, `|+>`, maximally mixed), and four
   frequencies, with zero violations;

6. the `Gamma` mean-square identity for `q=2,3,5,7` and key dimensions through
   three bits;

7. the full-key two-temperature tail inequality.

The checker validates algebra/probability only.  It does not establish the missing
generic-NP source compiler or any lattice hardness assumption.

## 12. Quantum-security ledger

### Honest algorithm model

Setup/encapsulation and honest witness decapsulation remain classical PPT whenever
the source compiler, dimensions, and repetition count are polynomial.

### False-statement adversary

Run 99's statistical syndrome theorem, when its source condition holds for the full
public view, is information-theoretic and therefore secure against arbitrary QPT
adversaries.

### True-statement adversary

Run 102's extraction theorem handles arbitrary non-uniform QPT circuit adversaries
with arbitrary mixed quantum auxiliary input/advice.

It requires only one copy of that state.

### Reduction model

The source extractor is non-black-box at the adversary-circuit level: it implements
a reversible dilation and the adjoint `U_A^\dagger`.

It uses no advice cloning or re-preparation, no measurement rewinding, no amplitude
amplification, no random oracle, no QROM programming, and no superposition access to
an external oracle.

### Hardness distribution

No LWE, SIS, MinRank, generic-group, or newly named computational assumption is used
for the Run-102 extraction theorem.  Its remaining assumptions are explicit
source-code spectral/extraction properties.

### Exact conclusion

Conditional on the source properties (27)--(28) plus all-low-support ORIGINAL-witness
extraction, arbitrary non-uniform QPT exact raw-key recovery implies an ORIGINAL NP
witness with non-negligible probability.

### Still UNPROVED

1. a practical generic-NP public source compiler satisfying **both** Run 99's false
   syndrome-extraction requirement and Run 102's true low-tail/all-low-support
   extraction requirements;
2. the exact parameters and every-low-support extraction theorem for Jin 2026/2063;
3. concrete final resource estimates at a defensible security level;
4. a non-injective final KDF wrapper, if one is desired rather than taking the raw
   uniform `K` itself as the KEM key;
5. malicious-secure setup/abort and auxiliary-publication composition if a future
   source compiler introduces temporary setup secrets.

The stopping condition is not met.

## 13. Next handoff

The main quantum decoder/extractor obstruction is no longer the first priority.
The next high-value work is source-specific:

1. obtain the full current Jin GapMDP construction and extract exact
   `m,k,d,D,n_act`, the low-support ORIGINAL-witness extraction threshold, and a
   usable true/false weight-enumerator bound;
2. simultaneously evaluate Run 99's false syndrome-capacity condition and Run 102's
   normalized true spectral tails at the honest operating `beta`;
3. if the existing GapMDP source cannot satisfy both sides, search for a
   source-preserving compiler/transformation that creates this two-sided spectrum
   without reintroducing the public quotient/label failures already ruled out;
4. only after a concrete source passes those tests should the project spend effort
   on ceremony details and final resource optimization.

This is a stronger QPT extraction checkpoint, but not a completed WKEM.
