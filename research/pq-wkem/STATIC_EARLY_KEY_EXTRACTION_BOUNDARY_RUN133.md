# Run 133 — static early-key extraction is the right true-instance game; recovery-to-extraction has a straight-line bridge

**Status:** security-definition/reduction checkpoint. This is **not** a construction of the required PQ witness KEM and it does not assume a witness PRF as an acceptable endpoint.

## 0. Verified handoff and exact scope

The connected GitHub record was read before this work. At the start of this run, `syscoin/PVUGC#1` was open, draft, and unmerged on branch `research/pq-wkem-validation-20260918` at head

`76e5b632cf00b4372955b871aadd59ded84c5167`.

The latest substantive ordinary PR comment visible on that head was comment `5850205385`, which records publication of Runs 122–128. Exact-head research records used here include Runs 79, 82, 99, 106, 108, 118–120, 125, 126, 128 and the 24 September literature assessment. The immediate local handoff is Run 132: the one-hot/linear-noise route is closed by a public `B+2` exact pseudowitness and short public kernel relations. Runs 129–132 are not on the PR head and are not republished by this run.

The purpose of Run 133 is to correct the **true-instance extraction game** and to isolate exactly what a future concrete rank/lattice construction must prove. A recurring ambiguity in the research ledger was whether “arbitrary QPT auxiliary information” meant auxiliary information may itself depend on the post-setup hidden key. That is too strong for the intended unauthorized-early-recovery goal and, for broad relation classes, is known to be unattainable. The statement is fixed before setup in this project, so the correct extraction target is **static in the statement/setup order**.

No production path is changed.

---

## 1. The exact core primitive induced by the project syntax

For an NP relation `R`, consider the usual witness-PRF-like syntax

\[
(fk,ek)\leftarrow \mathsf{Gen}(1^\lambda,R),
\qquad
F(fk,x)\in\mathcal Y,
\qquad
\mathsf{Eval}(ek,x,w)\in\mathcal Y.
\]

Correctness requires, for every valid witness,

\[
R(x,w)=1
\Longrightarrow
\mathsf{Eval}(ek,x,w)=F(fk,x)
\tag{1}
\]

except with negligible failure.

For the present project, `x` is chosen **before** setup. Setup knows `x` but no witness. After completed setup, nobody remains online. Therefore the relevant true-instance game has this order:

1. a static environment chooses `x` and allowed auxiliary state `rho_x` **before** fresh setup randomness;
2. setup generates public output `P_x` and hidden/erasable state that defines a single value
   \(K_x\in\{0,1\}^\lambda\);
3. the hidden state is erased according to the setup model;
4. a QPT adversary, given `(x,P_x,rho_x)` but no valid witness, outputs a classical candidate `K'`;
5. non-negligible probability that `K'=K_x` must imply either an ORIGINAL `R`-witness or an independently justified QPT-hardness break.

All public setup transcripts, proving keys, auxiliary encodings, and checking data belong in `P_x`; they are **not** silently omitted as “auxiliary information.”

What is excluded from the unauthorized-early-recovery game is side information produced *after seeing the fresh setup key* by an entity already holding a valid witness and computing the final key itself. Giving the adversary the final key as auxiliary input trivially makes “key recovery implies witness extraction” false.

---

## 2. Literature correction: static versus semi-static/adaptive extractability

Zhandry's witness-PRF paper already identifies precisely this quantifier boundary.

Its Definition 3.7 defines **extractable static** witness-PRF security. Its Remark 3.8 explains why semi-static/adaptive variants are not attainable for many relations: for a relation where instances and witnesses are easy to sample jointly but witness search from the instance alone is hard (the paper gives outputs of a one-way function as the example), a sampler can choose a true `(x,w)`, wait for `ek`, compute

\[
y^*=\mathsf{Eval}(ek,x,w)=F(fk,x),
\]

and provide `y*` as auxiliary information. A distinguisher/recoverer then trivially knows the target value, but that does not provide a way to recover `w`.

This matters here because the project **does not require that impossible game**. Its statement is fixed before setup. Thus:

\[
\boxed{
\text{the target should demand QPT static extraction with full public setup output,}
\text{ not key-correlated semi-static/adaptive auxiliary-input extraction.}
}
\tag{2}
\]

This is not a weakening of false-statement security or of arbitrary-QPT adversarial power. It is a correction of dependency order: arbitrary quantum side information about the preselected statement may be allowed, while information that is literally derived from the newly generated hidden final key is not part of “unauthorized early recovery.”

### Quantum qualification

Zhandry's 2016 definitions/theorems are stated for PPT adversaries. Run 133 does **not** silently upgrade them to QPT. Equation (2) defines the game this project needs; a usable construction must prove the corresponding quantum version explicitly.

A natural strong formulation allows `rho_x` to be an arbitrary polynomial-size quantum state generated before setup. The public `P_x` is then classical (unless a future construction explicitly says otherwise). A QPT extraction theorem must tolerate that pre-setup quantum side information. No existing theorem is imported here for that guarantee.

---

## 3. New reduction: exact key recovery gives the distinguishing advantage needed by extractability

There is a useful straight-line bridge that had not been stated explicitly in the project ledger.

Assume the primitive's output set `Y` has size `Q`, ideally `Q=2^lambda`. Suppose a QPT recovery algorithm `A_rec`, on the static view `(ek,x,rho_x)`, outputs a **classical** `Y`-value and satisfies

\[
\Pr[A_{rec}(ek,x,\rho_x)=F(fk,x)] = \varepsilon.
\tag{3}
\]

Construct a distinguisher `D` for the real-vs-uniform witness-PRF challenge `y_b` as follows:

1. run `A_rec(ek,x,rho_x)` once to obtain `y'`;
2. output “real” iff `y'=y_b`.

No rewind, clone, measurement rollback, random-oracle programming, or extraction from the internal quantum state of `A_rec` occurs.

When the challenge is real,

\[
\Pr[D=\text{real}\mid b=0]=\varepsilon.
\tag{4}
\]

When the challenge is independent uniform `U(Y)`, it is independent of the classical `y'`, regardless of the distribution of `y'`, so

\[
\Pr[D=\text{real}\mid b=1]=1/Q.
\tag{5}
\]

Therefore

\[
\boxed{
\operatorname{Adv}_D
=
\varepsilon-1/Q
}
\tag{6}
\]

(up to absolute value under the paper's convention).

For a `lambda`-bit range, the loss is exactly `2^-lambda`.

### Consequence

If a future primitive has a **QPT static extractability theorem** of the form

\[
\text{non-negligible real-vs-random advantage on a true fixed }x
\Longrightarrow
\text{extract an ORIGINAL }R\text{-witness or solve }\mathcal H,
\tag{7}
\]

for an independently justified QPT-hard problem `H`, then any non-negligible unauthorized exact final-key recovery probability immediately triggers (7) through the straight-line reduction (3)–(6).

This is stronger and cleaner than trying to design a separate “key-recovery extractor” from scratch. It also makes the quantum obligation precise: the **primitive's extractability theorem** must already be QPT-valid. The recovery-to-distinguishing wrapper itself is quantum-benign.

---

## 4. A core KEM composition theorem — conditional, not an endpoint

The preceding observation gives a simple conditional composition.

Assume a witness PRF for the **ORIGINAL relation** `R` with:

1. classical PPT `Gen`, `F`, `Eval`;
2. all-witness correctness (1);
3. false-instance pseudorandomness against QPT adversaries for the full public output;
4. QPT **static extractability** for true fixed instances with allowed pre-setup quantum auxiliary state and with all public setup artifacts included in the evaluation key/view;
5. a `lambda`-bit output range.

Then a core offline witness KEM is:

- setup on `x`: generate `(fk,ek)`, define `K=F(fk,x)`, publish `ek`, securely erase `fk`;
- decapsulation on any valid `w`: output `Eval(ek,x,w)`.

Every valid witness gets the same `K` by (1). False statements hide `K` by item 3. True-statement early exact recovery reduces by (6) to item 4.

If setup is distributed, `fk` generation/usage can in principle be implemented with the allowed N-of-N root / threshold-in-operator ceremony, but **that composition is not proved by this run**. A final construction still needs malicious-secure distributed generation, abort handling, transcript simulation, erasure, and proof that the transcript is within the extractability theorem's public view.

Most importantly:

\[
\boxed{
\text{assuming such a witness PRF does not solve the project.}
}
\]

It simply identifies the exact missing base primitive. The project rules correctly forbid relabeling witness PRF / WE / UWM-equivalent functionality as a new assumption.

---

## 5. Why this normalization is useful for the current Hair–Sahai / lattice work

Runs 79–82 and 125–131 have been trying to realize a common hidden value from statement-derived rank structure without assuming witness PRFs.

Run 133 gives the security test that any surviving candidate must pass:

### False `x`

The complete public output must make the canonical value QPT-pseudorandom (or statistically hidden). Run 130/131's rank-mask uniformization is one possible route, but its one-sided full-uniformity proofs face the effective-span capacity barriers and its unconditional two-sided distribution remains open.

### True `x`

Do **not** require a magical extractor that works even when auxiliary input already contains the freshly generated key. Instead require:

> for fixed `x` chosen before setup and the complete setup-generated public view, any QPT algorithm that recovers the canonical value with non-negligible probability yields an ORIGINAL source witness or a standard QPT-hardness break.

This is exactly where Runs 123/126's `Hash`/`Ext` mode would have to land. The Ext mode must not be able to resample the canonical value from public/extraction data, and its extracted object must feed the ORIGINAL source extractor.

The Hair–Sahai supplied-low-rank extractor remains useful only as the **last semantic arrow**:

\[
\text{supplied source-bearing low-rank object}
\to
\text{ORIGINAL witness}.
\]

The still-missing first arrow is

\[
\text{arbitrary QPT canonical-value recovery from full public view}
\to
\text{such a source-bearing object or PQ-hardness break}.
\]

Run 133 does not solve that arrow, but it removes an unnecessarily impossible auxiliary-input quantifier from it.

---

## 6. Jin 2026/2063: what extractability does and does not transfer

The current primary ePrint page for Zhengzhong Jin's *Witness Encryption for NP from SNARGs and Groups* (`2026/2063`, received 16 September and approved 19 September 2026) states:

- generic-group WE for NP from SNARGs with subexponential soundness and polylogarithmic online verification after preprocessing;
- a Karp–Levin reduction from polylog-size circuit SAT to GapMDP over a super-polynomial prime field with `omega(log lambda)` gap;
- unconditional **extractable** WE for circuits of size `polylog(lambda)` in the generic-group model.

This is highly relevant to the exact arrow above, but it does not by itself close the project's ORIGINAL-source-extraction requirement.

The generic-NP composition has the shape

\[
(x,w)
\xrightarrow{\text{SNARG prover}}
\pi
\xrightarrow{\text{small online verifier}}
1.
\]

If the small-circuit extractable WE returns a witness for the online-verifier circuit, the object obtained is an accepting **SNARG proof `pi`**. For ordinary false-statement WE security, SNARG soundness is exactly the property needed: a false source statement should not admit an efficiently produced accepting proof.

For this project's **true-instance early-key extraction**, however, the required arrow is stronger:

\[
\pi\text{ accepted}
\Longrightarrow
w\text{ for the ORIGINAL NP relation}.
\tag{8}
\]

Plain SNARG soundness does not imply (8). An argument-of-knowledge/SNARK extractor with an exact QPT theorem could potentially supply that arrow, but the ePrint abstract's generic theorem assumes a SNARG, not a knowledge argument.

Therefore the safe current classification is:

\[
\boxed{
\text{Jin's small-circuit extractability is a genuine useful component,}
\text{ but the generic SNARG lift does not by soundness alone yield ORIGINAL-witness extraction.}
}
\tag{9}
\]

### Verification limitation in this run

The current ePrint HTML/metadata and abstract were retrievable. The PDF endpoint itself was blocked by the available fetch path in this run, so I did **not** claim theorem-number/proof-level facts beyond the retrievable current primary text. In particular, the adversary model and any quantum-generic-group formulation of Jin's extractability theorem remain `UNVERIFIED` here. Generic-group security is in any case not a concrete post-quantum instantiation.

---

## 7. Witness-map cross-check: canonicalization is not a free simplification

Chakraborty–Prabhakaran–Wichs define a unique witness map (UWM) as mapping every witness of a fixed true statement to the same unique proof. Their 2023 work places UWMs between witness PRFs and iO and states that designated-verifier UWMs are equivalent in feasibility to witness PRFs.

That is almost exactly the syntactic canonicalization this project wants. It also explains why the missing “all witnesses -> one hidden value” step has resisted simple algebraic quotients:

- Run 129 showed the natural public linear Hair–Sahai anchor quotient is witness-free and therefore useless as a hidden capability;
- a cryptographically protected designated-verifier unique map is essentially witness-PRF-strength functionality rather than a cheap linear normalization.

Thus UWM language is useful for naming the target, but it is not a standard-LWE/SIS construction and cannot be used circularly as the base solution.

---

## 8. QPT / assumption ledger

### New Run-133 recovery-to-distinguishing theorem

- **Honest algorithm model:** classical or QPT recovery algorithm; final key/output is classical.
- **Adversary model:** arbitrary QPT recoverer is allowed.
- **Hardness assumption:** none for equations (3)–(6).
- **Reduction model:** straight-line, one invocation of the recoverer, no rewinding, no cloning of quantum auxiliary state, no RO/QROM programming.
- **Conclusion:** exact final-key recovery probability `epsilon` yields real-vs-uniform distinguishing advantage exactly `epsilon - 1/|Y|` for the comparison distinguisher.

### Static auxiliary-input boundary

- **Honest setup:** fresh after `(x,rho_x)` is fixed.
- **Allowed auxiliary state:** project target may quantify over arbitrary polynomial-size quantum `rho_x` generated before setup, but an actual cryptographic theorem must say so explicitly.
- **Excluded triviality:** post-setup auxiliary information computed from a valid witness and equal to the final key.
- **Conclusion:** this dependency order matches the project's fixed-statement setup and avoids the known semi-static key-as-auxiliary counterexample.

### Zhandry witness PRF

- source paper theorem/definitions: PPT/classical;
- construction: multilinear-map assumptions, not a standard PQ endpoint;
- QPT static extractability: **not supplied by the cited theorem**.

### Jin 2026/2063

- current retrievable claim: extractable WE for polylog-size circuits in generic group; generic NP WE from SNARGs;
- honest algorithms: classical according to the ordinary cryptographic syntax, but exact theorem text was not fully retrieved this run;
- QPT adversary/extractor: **UNVERIFIED**;
- generic-group security: not concrete PQ security;
- ORIGINAL-source extraction after the SNARG lift: **UNPROVED from soundness alone**.

### Hair–Sahai / current rank-mask line

- supplied low-rank -> source witness remains an algebraic/source-extraction component;
- arbitrary QPT key recovery -> supplied low-rank object remains missing;
- Run 130/131 statistical-hiding routes do not solve true-instance extraction.

---

## 9. Deterministic validation

`static_early_key_extraction_run133_check.py` is standard-library-only and deterministic.

The finalized checker was syntax-validated and executed twice with byte-identical output. It records **619 assertions** and checks:

1. for deterministic and randomized finite joint distributions, an exact comparison challenger has
   `Adv = Pr[exact recovery] - 1/|Y|`;
2. the random-challenge equality probability is exactly `1/|Y|` regardless of the recoverer's output distribution;
3. the comparison loss for 32/64/128/192/256-bit output ranges;
4. a finite all-witness/common-value fixture;
5. the dependency-order distinction between fixed pre-setup auxiliary data and auxiliary data set equal to the fresh key;
6. a logical interface fixture showing that perfect false-statement proof soundness does not itself provide an inverse from an accepting true-statement proof to the ORIGINAL source witness.

These are probability and interface checks only. They do not instantiate a witness PRF, prove LWE/SIS, validate a generic-group model, or establish QPT extraction.

---

## 10. Updated exact target and next handoff

The base target can now be stated without the auxiliary-input ambiguity:

> Build, from independently justified QPT-hard assumptions and classical public/offline algorithms, a **fixed-statement source-extractable common-value evaluator** whose complete setup-generated public view is QPT hiding on false statements, whose every valid ORIGINAL witness evaluates to the same `lambda`-bit value, and for which any QPT exact recovery of that value on a true statement—given arbitrary allowed pre-setup quantum side information but not the value itself as post-setup witness-derived auxiliary input—yields an ORIGINAL source witness or a standard QPT-hardness break.

The next mathematical work should return to the Run-131 handoff with this corrected extraction game in mind:

1. complete the **unconditional two-sided bilinear distribution** analysis for the actual Hair–Sahai source, rather than another one-sided conditioning proof;
2. if a hidden/ext mode is proposed, prove its true-instance reduction in the static game above and audit whether the extraction view can resample the canonical value (Run 126);
3. separately audit whether Jin's current full paper provides a knowledge-extractable SNARG path or only ordinary soundness once the PDF/proof text is retrievable; do not infer the former from “extractable small-circuit WE.”

The practical generic-NP public/offline PQ witness-KEM stopping condition remains **unmet**.
