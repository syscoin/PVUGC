# Run 101 — random-direction orientation reduction and channel-spectral-tail extraction

## Status

This run continues the verified Run-99 random-direction/syndrome checkpoint on
`syscoin/PVUGC` PR #1.  The verified branch at the start of the run was
`research/pq-wkem-validation-20260918` at
`93ae96ba977d96e435c41c86ffeb037e8dbc2ff5`; the PR was open, draft, and
unmerged.

This is **not** a completed practical PQ witness KEM.

The main new result is a true-instance extraction interface that is stronger than
Run 97's "polynomial decoder Fourier support" condition.  Successful decoding does
not need to have sparse Fourier support.  Instead, if the **public channel's own
source spectrum** is concentrated below the source-extraction weight threshold,
then every successful decoder must carry non-negligible *total squared response
mass* on that low-weight source region.

For a coherently re-runnable QPT decoder, that mass can be sampled by the Run-97
coherent Fourier procedure, yielding a low-weight source relation and then an
ORIGINAL NP witness under the stated source-extractor condition.

A second exact result puts the Run-98 random-direction capsule into an
"orientation" normal form and gives a completely forward-only reduction from
arbitrary key recovery to distinguishing the base masked/noisy distribution from
uniform.  This reduction uses no adjoint, rewinding, random oracle, or QROM
programming.

The remaining gap is explicit: the spectral-tail extractor still needs coherent
re-runnability/adjoint access to the adversary for the Fourier sampling step, while
the forward-only reduction ends at a decision problem.  A general arbitrary-QPT
decision-to-ORIGINAL-witness theorem remains unproved.

No production path is modified.

## 1. Channel inherited from Runs 98–99

Let `q` be prime,

\[
P\in\mathbb F_q^{r\times m},
\qquad
C=\ker P.
\]

Let

\[
D=P^Ts+E_\beta\in\mathbb F_q^m,
\]

where `s` is uniform and the coordinates of `E_beta` are independent q-ary
symmetric variables with nontrivial-character bias `beta`.

For one encrypted bit, sample a fresh public

\[
h\leftarrow\mathbb F_q^m
\]

and publish

\[
(h,c),\qquad c=D+b h.
\]

For `L` repetitions of the same bit, all `D_j,h_j` are independent.

Run 99 proved that on false statements the deviation of `D` from uniform is exactly
the deviation of the q-symmetric noise syndrome from uniform.  The present run
focuses on the true-instance extraction side.

## 2. Exact orientation normal form

Apply the public invertible map

\[
(h,c)\longmapsto(u,v)=(c,c-h).
\]

If `b=0`,

\[
(u,v)=(D,D-h)\overset d=(D,U),
\]

where `U` is uniform and independent of `D`.

If `b=1`,

\[
(u,v)=(D+h,D)\overset d=(U,D).
\]

Thus for `L` repetitions the key-recovery problem is exactly

\[
\boxed{
b=0:\quad (D^L,U^L),
\qquad
b=1:\quad (U^L,D^L).
}
\tag{1}
\]

This is an exact distributional equality for every `P`, not an asymptotic or
hardness claim.

## 3. Forward-only arbitrary-QPT key-recovery -> base decision

Let `A` be any algorithm, classical or quantum, that outputs a classical guess for
`b` from the complete orientation transcript.  Suppose

\[
\Pr[A=b]=\frac12+\varepsilon.
\]

Define a distinguisher `B` for `D^L` versus `U^L`.

Given a challenge tuple `z`:

1. sample an independent uniform tuple `u`;
2. sample `t in {0,1}`;
3. if `t=0`, run `A(z,u)` and accept iff `A` outputs `0`;
4. if `t=1`, run `A(u,z)` and accept iff `A` outputs `1`.

When `z<-D^L`, the acceptance probability is exactly `1/2+epsilon`.
When `z<-U^L`, both branches feed `(U^L,U^L)` to `A`; their complementary
acceptance predicates sum to one, so the acceptance probability is exactly `1/2`.

Therefore

\[
\boxed{
\operatorname{Adv}_B(D^L,U^L)=\varepsilon.
}
\tag{2}
\]

This wrapper invokes `A` only in its ordinary forward direction.

A standard random-position hybrid then turns `B` into a one-sample distinguisher
between `D` and `U` with signed advantage exactly

\[
\boxed{\varepsilon/L.}
\tag{3}
\]

The reduction samples `D` itself on positions before the challenge and `U` on
positions after it, choosing the transition coordinate uniformly.

Equations (2)–(3) hold for arbitrary QPT `A` just as for classical `A`: no
measurement is reversed, no auxiliary state is cloned, and no oracle is programmed.
They isolate the remaining forward-only problem as

\[
\boxed{
D=P^Ts+E_\beta\ {\buildrel ?\over\approx}\ U
\quad\text{unless an ORIGINAL source witness can be extracted.}
}
\tag{4}
\]

Run 99 already shows that this decision problem is exactly noisy-syndrome
nonuniformity.

## 4. Exact arbitrary-decoder response identity with fresh random directions

The orientation reduction is useful operationally, but it does not itself extract a
source relation.  A second theorem uses the full Fourier identity.

Condition on the public directions

\[
\mathbf h=(h_1,\ldots,h_L).
\]

For the decoder's final classical output define the real response function

\[
f_{\mathbf h}(\mathbf c)
=
\mathbb E[(-1)^{A(\mathbf h,\mathbf c)}]
\in[-1,1].
\]

Let

\[
\widehat f_{\mathbf h}(Y)
=
\mathbb E_{\mathbf c\leftarrow U}
\left[
 f_{\mathbf h}(\mathbf c)\,
 \overline{\chi_Y(\mathbf c)}
\right],
\]

where

\[
Y=(y_1,\ldots,y_L),\qquad
W(Y)=\sum_j\operatorname{wt}(y_j).
\]

Define

\[
\sigma_{\mathbf h}(Y)=\sum_j h_j^Ty_j
\]

and, for `omega=exp(2 pi i/q)`,

\[
\kappa_q(a)=\frac{1-\omega^a}{2}.
\]

If the key bit is uniform and `A` succeeds with probability `1/2+epsilon`, then its
signed correlation

\[
\rho
=
\mathbb E[(-1)^{A+b}]
=
2\varepsilon
\]

satisfies the exact identity

\[
\boxed{
\rho
=
\mathbb E_{\mathbf h}
\sum_{Y\in C^L}
\widehat f_{\mathbf h}(Y)
\beta^{W(Y)}
\kappa_q(\sigma_{\mathbf h}(Y)).
}
\tag{5}
\]

The zero mode vanishes because `kappa_q(0)=0`.

For every nonzero tuple `Y`, at least one `y_j` is nonzero.  Since `h_j` is fresh
uniform and independent,

\[
\sigma_{\mathbf h}(Y)
\]

is exactly uniform in `F_q`.  Hence

\[
\boxed{
\mathbb E_{\mathbf h}
|\kappa_q(\sigma_{\mathbf h}(Y))|^2
=
\frac12.
}
\tag{6}
\]

Equation (6) is independent of `q`.

## 5. Channel-spectral-tail extraction theorem

For an integer source-extraction threshold `B`, define the **channel masses**

\[
T_{\le B}
=
\sum_{\substack{Y\in C^L\\0<W(Y)\le B}}
\beta^{2W(Y)},
\tag{7}
\]

\[
T_{>B}
=
\sum_{\substack{Y\in C^L\\W(Y)>B}}
\beta^{2W(Y)}.
\tag{8}
\]

Define the decoder's averaged low-source squared Fourier mass

\[
M_{\le B}
=
\mathbb E_{\mathbf h}
\sum_{\substack{Y\in C^L\\0<W(Y)\le B}}
|\widehat f_{\mathbf h}(Y)|^2.
\tag{9}
\]

### Theorem 1

If

\[
\delta
:=
2\varepsilon-\sqrt{T_{>B}/2}
>0,
\tag{10}
\]

then

\[
\boxed{
M_{\le B}
\ge
\frac{2\delta^2}{T_{\le B}}.
}
\tag{11}
\]

### Proof

Split (5) into low and high total-weight regions.

For each fixed `h`, Parseval and `|f_h|<=1` imply

\[
\sum_Y|\widehat f_{\mathbf h}(Y)|^2\le1.
\]

Cauchy-Schwarz over the joint `(h,Y)` space, followed by (6), gives

\[
|\rho_{>B}|
\le
\sqrt{T_{>B}/2}.
\tag{12}
\]

Therefore the low region contributes magnitude at least `delta`.

A second Cauchy-Schwarz application gives

\[
\delta
\le
\sqrt{M_{\le B}}\sqrt{T_{\le B}/2},
\]

which is equivalent to (11). ∎

This theorem does **not** require the decoder response to have polynomial Fourier
support.  Exponentially many individually tiny coefficients are permitted.  What
must be controlled is the **channel's** spectral mass.

## 6. Coherent QPT source extraction under the spectral criterion

Suppose additionally that:

1. `epsilon` is inverse-polynomial;
2. `T_>B` is small enough that `delta` is inverse-polynomial;
3. `T_<=B` is polynomial, so (11) is inverse-polynomial;
4. every nonzero source relation

   \[
   y\in C,\quad \operatorname{wt}(y)\le B
   \]

   efficiently extracts an ORIGINAL NP witness.

Under the same coherent-access model already isolated in Run 97, prepare fresh
uniform `h`, coherently implement the complete decoder including re-preparation of
its auxiliary state, phase-kick its output bit, uncompute it with the adjoint, and
Fourier-sample the capsule register.

For fixed `h`, the probability of observing frequency `Y` with clean workspace is

\[
|\widehat f_{\mathbf h}(Y)|^2.
\]

Averaging fresh `h`, the probability of landing in the low source region is exactly
`M_<=B`.  By (11), this is inverse-polynomial under the conditions above.

A nonzero tuple `Y` of total weight at most `B` contains a nonzero component
`y_j in C` with

\[
\operatorname{wt}(y_j)\le B.
\]

Invoke the source extractor on that component.

So, **conditional on coherent re-runnability of the adversary**, the spectral-tail
conditions give

\[
\boxed{
\text{successful QPT key recovery}
\Longrightarrow
\text{ORIGINAL source witness}.
}
\tag{13}
\]

This is strictly more general than Run 97's polynomial-support theorem.

It still does **not** cover a one-shot unknown quantum advice state for which the
reduction cannot coherently prepare the state or implement the full adversary
adjoint.  Therefore (13) is not yet the project's required arbitrary-QPT theorem.

## 7. Source-checkable product identity

Let the one-copy source spectral sum be

\[
S_C(\beta)
=
\sum_{0\ne y\in C}\beta^{2\operatorname{wt}(y)}.
\]

For `L` copies,

\[
\boxed{
T_{\rm all}
:=
T_{\le B}+T_{>B}
=
(1+S_C(\beta))^L-1.
}
\tag{14}
\]

Thus the sufficient extraction conditions can be checked from the source weight
enumerator, not from the decoder.

A particularly useful tail certificate uses a second bias `beta'` with

\[
0<\beta<\beta'\le1.
\]

Since `W>B` implies `W>=B+1`,

\[
\boxed{
T_{>B}(\beta)
\le
\left(\frac{\beta}{\beta'}\right)^{2(B+1)}
\left[
(1+S_C(\beta'))^L-1
\right].
}
\tag{15}
\]

This is a two-temperature source-spectrum bound.  It converts control of the
weight enumerator at a slightly larger bias into an explicit high-weight tail bound
at the operating bias.

Equations (11), (14), and (15) yield a concrete target for the missing generic-NP
source compiler:

* false instances: Run 99 requires q-symmetric syndrome extraction / tiny
  `S_C(beta)`;
* true instances: low-weight codewords must all source-extract, while the
  `C^L` channel spectrum at the operating bias must have polynomial low mass and
  negligible high tail.

This is a **two-sided weight-enumerator/source-extraction requirement**, rather than
a minimum-distance promise alone.

## 8. Why the Run-97 bent counterfamily does not refute Theorem 1

Run 97 constructed a toy binary source with

\[
C=\mathbb F_2^m,\qquad
m=3r+1,
\]

and a successful deterministic decoder whose entire response spectrum lies at
growing weight even though a weight-one witness exists.

For this code,

\[
1+S_C(\beta)
=
(1+\beta^2)^m.
\tag{16}
\]

With Run 97's

\[
\beta_r=1-\frac1r,
\]

the channel spectral mass is enormous.  In particular, if the source-extraction
threshold is the genuine weight-one witness threshold `B=1`, then `T_>B` dwarfs the
decoder correlation.

Therefore condition (10) fails.  Theorem 1 correctly refuses to certify that toy
decoder.

The new theorem does not assert the invalid implication

> successful decoder => heavy/low individual Fourier coefficient.

It asserts the different, quantified implication

> successful decoder + low channel spectral tail =>
> non-negligible **aggregate** low-source Fourier mass.

The deterministic checker retains the Run-97 counterfamily as a mandatory negative
regression.

## 9. Exact finite validation

The finalized deterministic checker is standard-library-only and was executed twice
with byte-identical JSON output.

It verifies:

1. the exact orientation equality for q=2 and q=3;
2. for every deterministic orientation decoder in the q=2 and q=3
   one-coordinate fixtures, the forward wrapper's `D`-vs-uniform advantage equals
   the decoder's key-recovery advantage;
3. every deterministic binary `L=2` distinguisher satisfies the exact random-hybrid
   `1/L` telescoping identity;
4. all **65,536** deterministic response tables in a binary `m=2` random-direction
   fixture; Theorem 1 applies to **13,312** of them and has **zero violations**;
5. the exact tuple product-spectrum identity and two-temperature tail certificate;
6. Run 97's bent family at `r=2,4,8,16`, where the new criterion correctly remains
   inapplicable;
7. a synthetic one-dimensional spectrum fixture showing the theorem's quantitative
   premises can be simultaneously satisfied.

The synthetic positive fixture is not a cryptographic construction or deployment
parameter set.

## 10. Literature checkpoint

### Hair–Sahai 2609.18275

The current public record states an unconditional NP witness-encryption construction
only in the **classical prime-order generic-group model**, together with a
logarithmic-gap homogeneous-MinRank reduction whose YES witness has a Boolean right
factor.

That result is useful for source/rank extraction research, but its generic-group
security is not concrete post-quantum security and is not used as a QPT assumption
here.

### Jin 2026/2063

The current public metadata states a Karp–Levin reduction from
`polylog(lambda)`-size circuit satisfiability to GapMDP over a prime field of size
`lambda^{omega(1)}` with approximation `omega(log lambda)`, then combines it with
the Barta–Ishai–Ostrovsky–Wu generic-group framework.

The full current ePrint PDF remained inaccessible through the available primary
fetch path in this run.  Consequently this run does **not** claim verified exact
`m,k,d,D,n_act`, complete weight enumerators, or an all-low-support
`-> ORIGINAL witness` theorem for Jin's source.

Those exact quantities are now directly testable against (11), (14), and (15) once
the full construction is available.

## 11. Quantum-security ledger

**Honest algorithm model.**
The random-direction setup/encapsulation and witness decapsulation are classical.
All finite-field sampling and checking in this run are classical polynomial time
when the source dimensions and repetition count are polynomial.

**Adversary model.**
The orientation reduction (2)–(3) is valid for arbitrary QPT key-recovery algorithms
with classical public inputs and classical output.  It is forward-only.

The spectral identity (5) also describes the final classical response of an
arbitrary QPT decoder.

The algorithmic extraction from aggregate Fourier mass is narrower: it requires a
coherently re-runnable implementation, coherent preparation/purification of the
auxiliary state used by each run, and the full circuit adjoint.

**Hardness distribution.**
No LWE, SIS, MinRank, generic-group, random-oracle, or new computational assumption
is introduced by Theorem 1.  The channel masses are exact functions of the public
source code and q-symmetric noise.

**Reduction model.**
The forward decision reduction uses no rewinding, extraction, QROM, superposition
oracle, or adjoint.

The Fourier source extractor is a straight coherent circuit reduction using the
adversary and its adjoint.  Its auxiliary-state limitation is explicit.

**Exact conclusion.**
Run 101 proves a decoder-independent channel-spectral sufficient condition for
low-weight source extraction in the coherent-access model and a separate
forward-only reduction from key recovery to base-channel distinguishing.

**Still UNPROVED.**

1. arbitrary-QPT key recovery with unrestricted one-shot quantum advice
   `-> ORIGINAL witness` or independently justified QPT-hardness break;
2. the actual generic-NP source compiler satisfying the required true-instance
   low-tail/all-low-support extraction properties and Run-99 false-instance
   syndrome-extraction property;
3. Jin's exact source parameters/full theorem;
4. malicious-secure setup/abort and auxiliary-input composition if a future layer
   introduces setup secrets;
5. final practical parameters and resource estimates.

The stopping condition is therefore not met.

## 12. Next handoff

The highest-value next steps are now sharply separated.

**Source geometry.**
Obtain the full current GapMDP compiler and calculate its exact/bounded
weight enumerator.  Evaluate

\[
S_C(\beta),\quad
T_{\le B},\quad
T_{>B}
\]

and the Run-99 syndrome-capacity condition at the same operating bias.  Check whether
every nonzero relation through threshold `B` extracts the ORIGINAL NP witness.

**Arbitrary-QPT extraction.**
Try to replace the coherent-adjoint sampling step by a forward-only
decision-to-search theorem for the public noisy-subspace distribution

\[
P^Ts+E_\beta.
\]

Equation (3) shows that solving that problem would immediately cover arbitrary
random-direction key recovery without relying on decoder Fourier rigidity.

Do not return to the already-refuted claim that decoder success alone forces one
heavy low-weight Fourier coefficient.
