# Run 134 — GapMDP gap alone does not certify q-symmetric syndrome hiding

## Status

Verified starting PR head: `76e5b632cf00b4372955b871aadd59ded84c5167` on branch `research/pq-wkem-validation-20260918`. PR #1 was open, draft, and unmerged. The latest substantive ordinary PR comment was `5850205385`, which publishes Runs 122–128 and leaves the statement-specific public source compiler as the live bottleneck.

This run gives a focused falsification of a tempting shortcut in the Run-99/102 handoff:

> A large GapMDP YES/NO distance gap, even an `omega(log lambda)` gap, does **not** by itself imply the q-symmetric syndrome-extractor property required by the Run-99 statistical release.

The obstruction is joint entropy/rate, not the largest individual Fourier coefficient. There are explicit linear-code families with the **same field, length, active-column count, and exact minimum distance** such that one family has negligible q-symmetric syndrome distance while the other has statistical distance tending to one. In the bad family every nontrivial Fourier coefficient can nevertheless be super-negligible.

This is information-theoretic and therefore applies against arbitrary QPT distinguishers. It does **not** show that Jin's actual 2026 GapMDP source fails; it shows that the currently verified public gap theorem is insufficient evidence. The exact rate, active-column structure, and weight/syndrome spectrum of Jin's actual reduction still have to be audited from the full current construction.

No production path is changed.

## 1. Run-99 release condition recalled

Let

\[
C=\operatorname{rowspan}(H)\subseteq \mathbb F_q^m,
\qquad \dim C=k,
\]

and let `E_beta` be iid q-ary-symmetric noise with nontrivial character bias `beta`:

\[
\Pr[E_i=0]=\frac{1+(q-1)\beta}{q},\qquad
\Pr[E_i=a\ne0]=\frac{1-\beta}{q}.
\]

Run 99 proved that the random-direction Hamming release hides a false-instance key statistically iff, up to a factor two for one capsule, the public noise syndrome

\[
Z=H E_\beta
\]

is close to uniform over `F_q^k`.

For every nonzero frequency `a`,

\[
\widehat Z(a)=\beta^{\operatorname{wt}(a^T H)}.
\tag{1}
\]

Therefore a false minimum distance `D` implies the pointwise bound

\[
|\widehat Z(a)|\le \beta^D\qquad(a\ne0).
\tag{2}
\]

The question is whether a very small right side can certify the **joint** distribution. The answer is no.

## 2. Two explicit code families with identical minimum distance

Fix integers `D | m` and a prime power `q >= m`.

### Low-rate family

Partition the `m` coordinates into

\[
J=m/D
\]

disjoint blocks of size `D`. Let `C_good` be the direct sum of `J` repetition codes: one generator row is the all-one vector on each block and zero elsewhere.

Then

\[
C_{good}\text{ is }[m,J,D]_q,
\tag{3}
\]

all `m` columns are active, and every nonzero codeword has weight an integer multiple of `D`.

### High-rate family

Let `C_bad` be a generalized Reed--Solomon code of length `m` and dimension

\[
k_{bad}=m-D+1.
\]

Because `q>=m`, such a code exists and is MDS, hence

\[
C_{bad}\text{ is }[m,m-D+1,D]_q.
\tag{4}
\]

Again all `m` columns can be chosen active.

Thus the two source spaces have exactly the same:

* field size `q`;
* length `m`;
* active-coordinate count `n_act=m`;
* minimum nonzero Hamming weight `D`.

They differ primarily in dimension/rate and weight enumerator.

## 3. The low-rate family is an exact q-symmetric extractor when `beta^D` is small

For one repetition block, the syndrome coordinate is the sum of `D` independent q-symmetric noise symbols.

Every nontrivial additive character therefore has expectation

\[
\gamma=\beta^D.
\]

The sum is itself q-symmetric with bias `gamma`. Its exact total-variation distance from uniform is

\[
\delta_1=(1-1/q)\beta^D.
\tag{5}
\]

The `J=m/D` blocks use disjoint noise coordinates, so the syndrome coordinates are independent. A standard hybrid bound gives

\[
\boxed{
\operatorname{TV}(H_{good}E_\beta,U)
\le \frac{m}{D}(1-1/q)\beta^D.
}
\tag{6}
\]

Consequently, when `m/D` is polynomial and `beta^D` is negligible, this complete syndrome is statistically close to uniform against an unbounded distinguisher, hence against arbitrary QPT adversaries.

## 4. The high-rate family can be almost maximally nonuniform with the same `D`

Put

\[
\eta=(1-1/q)(1-\beta).
\]

One q-symmetric noise symbol has Shannon entropy

\[
H(E_\beta)=h_2(\eta)+\eta\ln(q-1).
\tag{7}
\]

For **every** `k x m` linear map, including the Reed--Solomon generator,

\[
H(HE_\beta)\le mH(E_\beta).
\tag{8}
\]

Let

\[
\varepsilon=\operatorname{TV}(H_{bad}E_\beta,U_{q^{k_{bad}}}).
\]

The Fannes--Audenaert entropy-continuity inequality gives

\[
k_{bad}\ln q-H(H_{bad}E_\beta)
\le \varepsilon\ln(q^{k_{bad}}-1)+h_2(\varepsilon).
\]

Using `ln(q^k-1) <= k ln q` and `h_2(epsilon)<=ln 2`, define

\[
\Delta=k_{bad}\ln q-mH(E_\beta).
\]

Then

\[
\boxed{
\varepsilon
\ge
\max\left\{0,
\frac{\Delta-\ln2}{k_{bad}\ln q}
\right\}.
}
\tag{9}
\]

This lower bound depends on the output dimension/rate, not on the minimum distance.

So (2) can make **every individual nontrivial Fourier coefficient tiny** while (9) forces the whole syndrome distribution to stay far from uniform.

## 5. Asymptotic separation with an `omega(log lambda)` GapMDP gap

The separation can be made to match the qualitative gap regime advertised by Jin's current GapMDP result.

Let the security parameter be `lambda` and choose

\[
d=\lambda,
\qquad
g=(\log_2\lambda)^2,
\qquad
D=dg,
\qquad
m=2D.
\tag{10}
\]

Thus

\[
D/d=(\log_2\lambda)^2=\omega(\log\lambda).
\tag{11}
\]

Let the honest decoder need inverse-polynomial signal

\[
\tau=1/\lambda
\]

and choose the most hiding-friendly bias at that correctness floor,

\[
\beta^d=\tau,
\qquad
\beta=\lambda^{-1/d}.
\tag{12}
\]

Then

\[
\boxed{
\beta^D=(\beta^d)^{D/d}
=\lambda^{-(\log_2\lambda)^2}
=2^{-(\log_2\lambda)^3}.
}
\tag{13}
\]

So **every** nontrivial Fourier coefficient of both code families is super-negligible by the shared minimum-distance promise.

For `C_good`, `m/D=2`, and (6) gives

\[
\operatorname{TV}(H_{good}E_\beta,U)
\le 2(1-1/q)2^{-(\log_2\lambda)^3},
\tag{14}
\]

which is negligible.

For `C_bad`,

\[
\frac{k_{bad}}m=\frac{D+1}{2D}=\frac12+o(1).
\]

Meanwhile

\[
1-\beta=1-e^{-\ln\lambda/\lambda}
=O(\ln\lambda/\lambda),
\]

so

\[
\frac{H(E_\beta)}{\ln q}\to0
\tag{15}
\]

for any `q>=m` and also for larger fields. Equation (9) therefore gives

\[
\boxed{
\operatorname{TV}(H_{bad}E_\beta,U)\to1.
}
\tag{16}
\]

The checker records concrete ledger points. Already at `lambda=2^8`, its conservative entropy lower bound is above `0.938`, while the low-rate family's TV upper bound is below `2^-511`. At `lambda=2^20`, the bad lower bound exceeds `0.99995` while the good upper bound is below `2^-7998`.

This is the exact phenomenon the current research must not blur:

> `omega(log lambda)` distance gap + super-negligible maximum character does **not** imply full-output statistical hiding.

A rank/distance gap controls the first nonzero spectral location. Run 99 needs enough control over the **number and aggregate mass** of all spectral directions, equivalently the syndrome entropy/extractor behavior.

## 6. Consequence for the current Jin lead

The current public record for Zhengzhong Jin, *Witness Encryption for NP from SNARGs and Groups*, says the construction gives a Karp--Levin reduction from satisfiability for `polylog(lambda)`-size circuits to GapMDP over a prime field of size `lambda^{omega(1)}`, with approximation factor `omega(log lambda)`, and then obtains generic-group WE/extractable WE consequences.

That is a genuinely important source-semantic result. But the gap statement alone supplies only the analogue of:

* YES: some nonzero codeword has weight at most `d`;
* NO: every nonzero codeword has weight above `D`.

Run 134 proves that those two facts do **not** determine the Run-99 release distribution, even if `D/d=omega(log lambda)` and even if `beta^D` is super-negligible.

Therefore the following remain mandatory before using Jin's source in the Run-99/102 concrete-QPT route:

1. exact false-instance `m`, `k`, and `n_act` after all preprocessing;
2. the actual false-code weight enumerator, a direct syndrome-extractor theorem, or another bound strong enough to show `H_xE_beta` close to uniform at the honest operating `beta`;
3. the true-instance low-support theorem required by Run 102: **every** nonzero relation through the extraction threshold must yield an ORIGINAL source witness, not only existence of one short YES witness;
4. the resulting normalized low/high spectral tails;
5. any QPT computational replacement if statistical extraction fails.

The currently verified public abstract does not supply those details. This run therefore corrects any stronger reading of the earlier handoff. It does not claim Jin's actual construction fails them.

## 7. Relation to Hair--Sahai and the rank-mask branch

The same lesson matches Runs 79 and 82 in rank metric.

Run 79 already showed that a minimum-rank bound on every key-sensitive character is too weak when the public output has many spectral directions. Run 82 then exhibited an exponentially large near-gap family inside an actual Hair--Sahai false source space.

Run 134 is the Hamming/syndrome analogue in a cleaner coding-theory form: two codes can have the same exact minimum distance and same largest nontrivial character, yet opposite full-output statistical behavior.

Hair--Sahai remains useful for its source-preserving low-rank algebraic extraction. Its published security theorem is classical generic-group security, not a concrete PQ theorem.

## 8. QPT/security classification

### Honest algorithms

The code generation, noise sampling, syndrome evaluation, and finite checks are classical polynomial-time for polynomial dimensions.

### Adversary model

The good-family upper bound and bad-family lower bound are information-theoretic. They apply to unbounded adversaries and therefore to arbitrary QPT adversaries.

### Hardness assumptions

None are used in Run 134.

The Reed--Solomon family is used only as an explicit high-rate MDS code. No decoding hardness assumption is made.

### Reduction model

There is no cryptographic reduction, rewinding, extraction, random oracle, QROM programming, or quantum auxiliary-state issue in this run.

### Exact conclusion

A GapMDP minimum-distance promise, even with `omega(log lambda)` gap and super-negligible maximum nontrivial Fourier coefficient at the chosen `beta`, is insufficient to establish Run-99 full-syndrome statistical hiding.

### Still unproved

* Jin's **actual** source rate/enumerator/syndrome law at exact current-version parameters;
* a generic-NP source compiler satisfying both Run-99 false extraction and Run-102 true all-low-support ORIGINAL-witness extraction;
* a surviving concrete standard-assumption computational replacement if statistical extraction is impossible;
* the separate Hair--Sahai two-sided rank-mask unconditional distribution question;
* malicious erased-setup/abort composition and practical final parameters.

## 9. Deterministic validation

`gapmdp_gap_only_syndrome_run134_check.py` is standard-library-only. It was syntax-checked and executed twice with byte-identical output.

The finite exact fixture uses `F_7`, `m=6`, and `D=3`:

* `C_bad`: Reed--Solomon `[6,4,3]_7`;
* `C_good`: direct sum of two `[3,1,3]_7` repetition blocks, hence `[6,2,3]_7`.

The checker exhaustively enumerates every codeword and verifies exact minimum distance `3` for both. At `beta=1/2`, both have maximum nontrivial syndrome-character magnitude exactly `beta^D=1/8`, yet their exact complete-syndrome TVs differ. It also verifies that the good syndrome is exactly a product of two q-symmetric variables of bias `beta^D` and checks the hybrid bound (6).

A separate `beta=4/5` control verifies the entropy-derived lower bound (9) against the exact enumerated bad-family TV.

Finally, an asymptotic arithmetic ledger validates equations (10)--(16) at `lambda=2^8,2^12,2^16,2^20`.

These tests validate finite algebra/probability and the parameter arithmetic only. They do not establish LWE, SIS, GapMDP hardness, generic-group security, or Jin's unretrieved full theorem details.

## 10. Next handoff

Do not treat Jin's `omega(log lambda)` GapMDP gap as a completed Run-99 source instantiation.

The next high-value work is exact-source, not another wrapper:

1. obtain the full current Jin reduction and extract `m,k,n_act,d,D` plus the actual code construction after preprocessing;
2. compute or bound its q-symmetric syndrome entropy/weight enumerator at the smallest `beta` compatible with honest decoding;
3. verify the **every-low-support -> ORIGINAL witness** property needed by Run 102, not merely the YES existential short vector;
4. if the false code is too high-rate, search for a source-preserving non-isometric rate/spectrum transformation. Run 99 already rules out row-basis changes, monomial scrambling, zero padding, and matched-signal repetition as generic repairs.

The practical generic-NP public/offline PQ witness-KEM stopping condition remains **unmet**.
