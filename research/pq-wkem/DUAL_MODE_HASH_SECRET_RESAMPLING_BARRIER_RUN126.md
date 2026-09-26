# Run 126 — dual-mode hash-secret resampling barrier: public-key duality is not enough; the mode secrets must be conditionally incompatible

## Status

This run starts from the verified current state of `syscoin/PVUGC#1`:

- branch: `research/pq-wkem-validation-20260918`
- starting head: `4198b1815d3edc7be41ec1cb25c0c46fab24610e`
- PR: open, draft, unmerged
- latest substantive ordinary PR comment read: `5847380543`, which records the verified publication of Runs 112–121.

Relevant exact-version files read from that head include Run 112 (setup-known invariant barrier), Run 120 (public affine pseudowitness attack), Run 121 (VTDH fixed-digest canonicalization), Run 79 (anchor-shift MinRank spectrum), Runs 82–83 (actual Hair–Sahai low-rank tail and scalar-weight recombination), Run 100 (self-tensor source amplification), the rank-condenser/splicing note, and the literature assessment.

Runs 122–125 remain newer conversation checkpoints and are not silently treated as published. The present result builds specifically on their sharpened dual-mode target:

1. Run 122: the current formal VTDH hiding proof has a straight-line route to a QPT lift **conditional on QPT hardness of the exact ordinary-LWE family**; the earlier extra-binary-LWE reading was too pessimistic.
2. Run 123: arbitrary QPT final-key recovery transfers cleanly to ORIGINAL-source extraction if a statistically close extraction mode sees the **same canonical hidden target** and can extract from that target.
3. Run 124: Wee's EHPS is only precedent for the dual-mode shape; its public evaluator uses sampler coins for an efficiently samplable relation, not an arbitrary NP relation witness.
4. Run 125: an ordinary lattice short-preimage trapdoor does not enforce the low-rank Hair–Sahai source geometry.

The new result identifies another necessary condition that had not been stated sharply enough:

> **The hash-mode secret and extraction-mode trapdoor cannot be efficiently jointly resampled, even conditionally on the same public index.**
>
> Statistical closeness of the two *public* modes is insufficient. If, after generating the extraction-mode trapdoor, one can locally sample a hash-mode secret (or directly sample a correct canonical target) with non-negligible probability, then the setup/reduction itself becomes an efficient ORIGINAL-witness finder on every true source-hard instance for which extraction is supposed to work.

This rules out the most obvious `lattice trapdoor + independent LWE/hash secret` realization of the Run-123 interface. It does **not** rule out dual-mode source hashes in general: an evasive/mutually-exclusive secret correlation remains logically possible, but that correlation is now an explicit cryptographic obligation and cannot be replaced by ordinary public-key mode indistinguishability.

No production path is changed.

---

## 1. Abstract source relation and dual-mode target

Let `R(x,w)` be an NP relation. Setup receives only `x`; it is not given a source witness.

The desired dual-mode release shape has two setup algorithms:

\[
(P,hk)\leftarrow \mathsf{HashSetup}(x),
\qquad
(P,xk)\leftarrow \mathsf{ExtSetup}(x),
\]

whose **public** `P` distributions are identical or statistically close.

Hash mode computes a hidden canonical target

\[
H = \mathsf{HashVal}(P,hk,x).
\tag{1}
\]

Every valid source witness should obtain the same target, or an error-correcting representative of the same canonical class:

\[
\mathsf{WitnessEval}(P,x,w)=H
\qquad
\text{for every }R(x,w)=1.
\tag{2}
\]

Extraction mode should turn the correct target into an ORIGINAL witness:

\[
w'\leftarrow \mathsf{Ext}(P,xk,x,H),
\qquad R(x,w')=1.
\tag{3}
\]

Run 123 uses this shape only inside a reduction. The real setup has `hk` but not `xk`; the extraction hybrid has `xk` but is not supposed to have `hk`.

That separation is not cosmetic. It is necessary.

---

## 2. Theorem 1 — direct target-resampling collapse

Consider any classical PPT algorithm

\[
\mathsf{TargetSamp}(P,x,xk;\rho)\to \widehat H.
\]

Define its extraction success in the Ext experiment as

\[
\epsilon_x
=
\Pr\left[
R\!\left(x,
\mathsf{Ext}(P,xk,x,\widehat H)
\right)=1
\right],
\tag{4}
\]

where `(P,xk) <- ExtSetup(x)` and `\widehat H <- TargetSamp(P,x,xk)`.

### Theorem 1

If `epsilon_x` is non-negligible, then there is a classical PPT ORIGINAL-witness finder for `x` with success exactly `epsilon_x`.

### Proof

The witness finder simply executes the experiment in (4):

1. `(P,xk) <- ExtSetup(x)`;
2. `Hhat <- TargetSamp(P,x,xk)`;
3. `what <- Ext(P,xk,x,Hhat)`;
4. output `what` if `R(x,what)=1`.

Its success event is exactly the event defining `epsilon_x`. There is no reduction loss. ∎

This theorem is elementary, but it closes an important implementation loophole: **an extraction trapdoor is useful only if the correct extraction target remains evasive from the extraction-mode secret view.**

For a family of true instances on which source-witness search is intended to be hard, `epsilon_x` therefore must be negligible for every efficient Ext-view target sampler unless the construction is explicitly willing to let witness-free setup solve the source relation.

---

## 3. Theorem 2 — conditionally resamplable hash secret collapses the dual-mode construction

Suppose there is a classical PPT conditional sampler

\[
\mathsf{ResampHash}(P,x,xk)\to \widehat{hk}.
\tag{5}
\]

Define

\[
\widehat H
=
\mathsf{HashVal}(P,\widehat{hk},x).
\tag{6}
\]

### Theorem 2

If

\[
\Pr\left[
R\!\left(x,
\mathsf{Ext}(P,xk,x,
\mathsf{HashVal}(P,\widehat{hk},x))
\right)=1
\right]
\ge \epsilon_x,
\tag{7}
\]

then source-witness search is solvable by a classical PPT algorithm with success at least `epsilon_x`.

This is Theorem 1 with `TargetSamp = HashVal o ResampHash`.

### Important special case: separable secret

If the hash secret is sampled from a public efficiently samplable distribution **independently of the Ext trapdoor given `P`**, then `ResampHash` is immediate.

Therefore a candidate of the form

\[
(P,xk)\leftarrow \mathsf{TrapGen},
\qquad
hk\leftarrow D_{\rm public},
\qquad
H=F(P,hk,x),
\tag{8}
\]

cannot simultaneously claim that the extraction trapdoor turns `F(P,hk,x)` into an ORIGINAL witness for essentially every fresh `hk <- D_public` on a hard true source instance.

The Ext experiment can sample `hk` itself and extract the witness.

This is stronger than Run 112's setup-known-value observation. Run 112 ruled out giving the **real setup** a value `Z` from which a value-only extractor produces the witness. Theorem 2 says that moving the extractor to a statistically indistinguishable *alternate mode* does not repair the problem if that alternate mode can efficiently regenerate the hash-mode secret/target.

---

## 4. Statistical conditional-sampler corollary

The resampler need not reproduce the exact conditional distribution.

Let `D` be an ideal hash-secret/target distribution in the Ext experiment for which extraction succeeds with probability at least

\[
1-\eta.
\]

Let `J` be the actual efficient resampler distribution, and suppose their total-variation distance is at most `delta` in the **joint experiment containing all data used by the extraction-success event**.

Then for the event

\[
E=\{R(x,\mathsf{Ext}(P,xk,x,H))=1\},
\]

statistical distance gives

\[
\boxed{
\Pr_J[E]\ge 1-\eta-\delta.
}
\tag{9}
\]

The same statement holds for trace distance if the compared side information is quantum, because event probabilities differ by at most trace distance. No computational mode-switch theorem is needed for (9).

### Crucial qualification

Statistical closeness of the **public keys `P` alone** does *not* imply a sampler `J` for the missing hash secret. Conditional secret-key distributions can be mutually exclusive even when the public marginals are identical.

Therefore this run does **not** strengthen Run 123 into an impossibility theorem for all statistically dual-mode source hashes. It identifies exactly what a successful construction must prevent.

---

## 5. Evasive-target necessity

For an Ext key define the extraction-success set

\[
\mathcal E_{P,xk,x}
=
\left\{
H : R(x,\mathsf{Ext}(P,xk,x,H))=1
\right\}.
\tag{10}
\]

Theorem 1 can be restated as a necessary property:

> On source-hard true instances, `E_{P,xk,x}` must be **computationally evasive from the complete Ext-mode view**, even though Hash mode can compute one element of it and every valid source witness can compute the same canonical element/class.

This creates a three-way functionality:

1. `hk` computes the canonical target without a source witness;
2. `w` computes the canonical target without `hk`;
3. `xk` converts the canonical target into a source witness;
4. but `xk` alone cannot efficiently sample a target in its own extraction-success set, and cannot efficiently resample `hk`.

If both `hk` and `xk` are efficiently jointly obtainable, composition immediately solves witness search.

Thus the missing primitive is not merely a “dual-mode trapdoor.” It is a **mutually incompatible dual-mode source trapdoor**.

---

## 6. Consequence for the obvious lattice splice

Micciancio–Peikert's lattice trapdoor framework provides, among other things, efficient LWE inversion, SIS preimage sampling, and trapdoor delegation. Those are powerful *native lattice* inversion interfaces.

A tempting Run-123/125 splice is:

1. generate a lattice public matrix `A` together with an extraction trapdoor `T_A`;
2. sample an ordinary LWE/hash secret `s` independently;
3. compute a canonical target `H=F(A,s,x)`;
4. ask `T_A` to map the correct `H` into a source-bearing object and then an ORIGINAL witness.

If step 4 is guaranteed for essentially every fresh independent `s`, Theorem 2 kills the construction immediately: Ext mode already has `(A,T_A)` and can locally sample `s`, form `H`, and recover a source witness.

This is independent of whether the lattice trapdoor itself is post-quantum secure. It is a **functionality collapse**, not a hardness attack.

Therefore the surviving lattice route must make the correct target depend on a hash-mode secret that is *not* conditionally resamplable in the Ext mode. If one simply assumes that this target correlation is evasive, the core witness-encryption difficulty has been moved into a new correlated-trapdoor assumption rather than reduced to standard LWE/SIS.

Run 125's rank-versus-shortness mismatch remains separate: even if the resampling issue were solved, a generic short-preimage trapdoor still does not automatically output the Hair–Sahai low-rank source object.

---

## 7. Why Wee 2010 does not contradict the barrier

Hoeteck Wee's extractable hash proof system has exactly the useful public dual-mode shape:

- the relation `R` is efficiently samplable;
- public evaluation computes `H_PK(u)` from the sampling coins `r` used to sample `(u,s) in R`;
- Hash mode has a secret key that privately computes the hash;
- Ext mode has a secret key that extracts `s` from a correct hash value;
- the public-key distributions of the two setup modes are the same in the original construction/definition.

This is safe because the paper is built around an **efficiently samplable relation**. If Ext mode publicly samples a fresh relation pair, obtaining a witness for that freshly sampled `u` is not solving a fixed externally supplied source-hard NP instance.

For this project the instance `x` is fixed first. Replacing Wee's sampled relation with a fixed generic NP relation would require public evaluation coins that generate the **same fixed `x`**. On a source-hard instance, an efficient procedure that generated those relation coins/witness data would already solve source search. That is the sampler-coin mismatch isolated in Run 124.

So Wee remains a good precedent for the *mode-separation proof architecture*, not an instantiation of the missing fixed-instance source interface.

Primary source checked this run: Hoeteck Wee, *Efficient Chosen-Ciphertext Security via Extractable Hash Proofs*, CRYPTO 2010, IACR proceedings PDF.

---

## 8. Tsabary's architecture sits on the right side of the structural line, but under the wrong assumption/model

Rotem Tsabary's CRYPTO 2022 lattice WE candidate does **not** reduce its crucial correlated trapdoor step to ordinary LWE alone.

Its Assumption 31 samples `(A,A_TD) <- TrapGen` and allows the target matrix `T`, prefix matrices, auxiliary information, and other public matrices to be correlated with the trapdoor-generation experiment. The security corollary then assumes **Assumption 31 plus standard decisional LWE**, and is stated for `ppt` adversaries.

This is structurally relevant to Run 126: the construction recognizes that the target/trapdoor/prefix information cannot simply be treated as independent public randomness.

But it does not meet the present target:

- the correlated-trapdoor statement is an additional construction-specific assumption;
- the published adversary model is classical PPT;
- it does not give the required arbitrary-QPT final-key-recovery -> ORIGINAL-source-witness theorem.

Therefore Tsabary is a useful architecture lead, not a standard-LWE/QPT endpoint.

Primary source checked this run: Rotem Tsabary, *Candidate Witness Encryption from Lattice Techniques*, CRYPTO 2022, especially Assumption 31 and Corollary 1.

---

## 9. Distributed-setup consequence

The allowed setup ceremony does not erase this issue.

Suppose a distributed ceremony creates shares from which an authorized coalition can reconstruct both:

- the hash-side secret `hk` (or a correct target), and
- the extraction-side trapdoor `xk`.

Then that coalition can run

\[
H=\mathsf{HashVal}(P,hk,x),
\qquad
w=\mathsf{Ext}(P,xk,x,H),
\]

and recover an ORIGINAL source witness during setup.

Therefore a future ceremony for this route needs **access-structure incompatibility**, not just later erasure: no adversarially allowed coalition or transient reconstruction step may jointly obtain the two complete powers. An MPC that computes only the public transcript without reconstructing either full secret may still be possible, but it requires a separate malicious-security/abort proof.

This is not yet such a proof.

---

## 10. Exact checker

`dual_mode_hash_secret_resampling_run126_check.py` is deterministic and standard-library-only.

Two executions were byte-identical. The finalized output records **11,832 assertions** and checks:

1. 142 affine finite models in which an independently resampled hash secret generates an Ext-accepted target; Ext+resampling succeeds with probability exactly one;
2. 150 sparse/evasive-target controls where identical public mode data does **not** imply joint secret samplability, and independent resampling hits with probability exactly `1/q`;
3. 1,980 arbitrary finite total-variation event-transfer trials;
4. 1,440 bounded `[0,1]` extraction-success-function trials, checking expectation difference `<= TV`;
5. 1,440 conditional-sampler lower-bound trials checking `success_J >= 1-eta-delta` exactly;
6. identical-public-index negative controls for `q=17,31,61,127,257`;
7. 20 independent-hash-secret special cases with exact resampling success one.

The checker validates the finite probability identities and the scope distinction between public-mode equality and secret-key joint samplability. It is **not** evidence that LWE, SIS, MinRank, or any correlated trapdoor distribution is QPT-hard.

---

## 11. QPT/security ledger

| Component | Honest algorithm model | Adversary / reduction model | Assumption | Exact conclusion |
|---|---|---|---|---|
| target-resampling collapse | classical PPT | classical PPT witness finder (therefore also available to QPT) | none | non-negligible Ext-view target sampling immediately gives ORIGINAL witness |
| conditionally resamplable hash-secret collapse | classical PPT | classical PPT | none | if Ext mode can resample hash secret and its target extracts, source search collapses |
| statistical resampler transfer | classical sampling/extraction | unbounded event test; quantum side info only if trace-distance premise is supplied | exact TV/trace-distance premise | loss at most `delta` |
| ordinary lattice trapdoor capabilities | classical PPT | not a security theorem used here | native lattice trapdoor functionality | inversion/preimage sampling alone does not supply source-restricted target correlation |
| Wee EHPS precedent | classical PPT | classical model in source | factoring/CDH constructions in source | dual-mode shape for efficiently samplable hard-search relations; wrong fixed-instance source interface |
| Tsabary WE | classical PPT | PPT in source | Assumption 31 + standard decisional LWE | correlated-trapdoor WE candidate; not standard-LWE-only and not QPT/source-extractive here |
| required mutually-incompatible source trapdoor | classical public/offline | arbitrary QPT | **missing standard-QPT reduction** | must provide hash/witness evaluation + extraction while preventing Ext-view resampling |

No statement in this run promotes a PPT-only theorem to QPT security.

---

## 12. What is now closed and what survives

### Closed by this run

Do not instantiate Run 123 by taking:

- a standard lattice trapdoor public key in Ext mode;
- an independently samplable LWE/hash secret in Hash mode;
- a target function of both;
- and an Ext guarantee that works for essentially every fresh hash secret.

That is a witness-search algorithm, not a witness KEM construction.

Likewise, statistical equality of public keys plus *efficient conditional resampling of the other mode's secret* is fatal. Public-key duality alone is not the needed security property.

### Still logically open

A construction may survive if the same public index supports two **mutually incompatible** secret modes:

1. Hash secret computes the canonical target without a source witness.
2. ORIGINAL source witness publicly computes the same target.
3. Ext secret extracts an ORIGINAL witness from that target.
4. Given the complete Ext secret and public transcript, sampling either a valid target or a compatible Hash secret remains negligible for classical PPT and arbitrary QPT algorithms, unless one breaks an independently justified QPT-hard assumption.
5. The public modes remain statistically close enough for Run 123's straight-line QPT transfer.

This is much stronger than ordinary trapdoor inversion and much closer to the nonseparable correlated-target issue that Tsabary isolates with Assumption 31.

---

## 13. Precise next handoff

The next constructive test should target **standard-LWE realization of mutually exclusive secret modes**, not another ambient short-preimage sampler.

A candidate must expose exact algorithms for

\[
\mathsf{HashSetup},\ 
\mathsf{ExtSetup},\ 
\mathsf{HashVal},\ 
\mathsf{WitnessEval},\ 
\mathsf{Ext}
\]

and then answer two questions before any wider composition:

1. **Joint-secret test:** given `(P,xk)` from Ext mode, can a polynomial-time algorithm sample a compatible `hk` or an Ext-accepted target? If yes with non-negligible probability, reject immediately by Theorem 1/2.
2. **Standard-QPT reduction:** if not, is that incompatibility reduced straight-line to a recognized QPT-hard LWE/SIS distribution, rather than postulated as a new evasive/correlated-trapdoor assumption?

Only after both pass is it worth reconnecting the target to Hair–Sahai's supplied-low-rank ORIGINAL-source extractor or the VTDH fixed-digest same-key wrapper.

The complete practical generic-NP public/offline PQ witness-KEM stopping condition remains **unmet**.