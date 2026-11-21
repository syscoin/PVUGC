# Run 128 — UP/hash-isolation cannot supply generic all-witness same-key by a polynomial fixed target list

## Status and starting point

This run started by reading `syscoin/PVUGC#1` through the connected GitHub source at the actual current head:

- branch: `research/pq-wkem-validation-20260918`
- starting SHA: `4198b1815d3edc7be41ec1cb25c0c46fab24610e`
- PR state: open, draft, unmerged
- latest substantive ordinary PR comment: `5847380543`, which records the verified interactive publication of Runs 112–121.

Relevant exact-head files were then read at that SHA:

- `research/pq-wkem/WPRF_PUBLIC_OPENING_SOURCE_BARRIER_RUN113.md`, blob `b6ea1b9a2f56bb4fb3a7f46c19386c6047036862`;
- `research/pq-wkem/VTDH_FIXED_DIGEST_MAJORITY_CANONICALIZATION_RUN121.md`, blob `415623e48e8b5fe246663e560d3486545b408acd`;
- `research/pq-wkem/literature-20260924/ASSESSMENT.md`, blob `8a1bc1db08156c9ff6410f59963c1af3a0d5a924`.

The immediate handoff from local Run 127 was also retained: a source-preserving compiler from generic NP into a special WPRF language would already cross the general-purpose-WPRF boundary; witness-dependent target inputs do not automatically share the same WPRF value; the plausible escape is a *single statement-specific fixed target* whose canonical value is evaluable by every original witness.

This pass asks whether the strongest currently visible lattice-flavored **UP WPRF** route can avoid that fixed-target requirement by first isolating a unique witness (Valiant--Vazirani style), and then using the UP WPRF.

The answer is negative for the natural source-preserving/fixed-target-list composition, for an unconditional correctness reason that is independent of its cryptographic assumptions.

No production path is changed.

---

## 1. Exact literature facts used

### 1.1 Mathialagan--Peters--Vaikuntanathan WPRF for UP

Primary source inspected: Surya Mathialagan, Spencer Peters, Vinod Vaikuntanathan, *Adaptively Sound Zero-Knowledge SNARKs for UP*, Cryptology ePrint 2024/227, PDF currently served at

`https://eprint.iacr.org/2024/227.pdf`

The PDF header is dated **April 1, 2024**.

The relevant full-paper facts are:

1. Definition 5.1 defines a WPRF as a triple of **PPT** algorithms `(Gen,F,Eval)` and requires witness correctness.
2. The adaptive security definition explicitly quantifies over **PPT adversaries**.
3. Definition 5.2 defines a UP relation by the condition that a true instance has a **unique witness** and a false instance has none.
4. Theorem 5.5 constructs an adaptively secure WPRF for a UP language from ordinary LWE plus the paper's sampler-specific **evasive-LWE** assumptions.
5. The formal evasive-LWE definition in Section 4.5 itself quantifies `for every PPT A1 there exists another PPT A0`.
6. The paper explicitly discusses heuristic counterexamples to evasive LWE for general auxiliary input and treats its actual auxiliary-input family as a restricted, candidate-safe case rather than reducing it to ordinary LWE.

Therefore this result is a serious structural lead, but its security theorem is **classical/PPT as written**, and it relies on a nonstandard correlated/evasive lattice assumption. It is not a standard-LWE QPT WPRF theorem.

A screenshot of the relevant PDF pages was requested through the available PDF screenshot path, but that path returned a restricted-URL fetch error; the source statements above were taken from the PDF's extracted primary text, not from OCR or a secondary summary.

### 1.2 Valiant--Vazirani isolation

Primary bibliographic source: Leslie G. Valiant and Vijay V. Vazirani, *NP is as easy as detecting unique solutions*, Theoretical Computer Science 47 (1986), 85--93, DOI `10.1016/0304-3975(86)90135-0`.

The original result is a **randomized reduction** showing that unique-solution instances retain NP hardness in the appropriate randomized-reduction sense. The standard isolation step intersects a solution set with random hash/affine constraints so that *some* surviving solution is isolated with noticeable probability.

This run does not dispute or re-prove Valiant--Vazirani. It tests a different requirement: our WKEM demands that **every valid source witness** recover one common fixed key from one public offline capsule.

---

## 2. Source-fiber cover theorem

Let `R_src(x,w)` be the ORIGINAL source relation and let

`W_x = { w : R_src(x,w)=1 }`.

Suppose setup publishes `t` fixed target instances

`u_1,...,u_t`

for some auxiliary relation `Q`. Assume each fixed target instance has at most `L` accepted target witnesses:

`|Omega_i| <= L`, where `Omega_i={omega:Q(u_i,omega)=1}`.

Let a witness compiler map an original witness `w` to one or more target witnesses. For every accepted target witness `omega`, define its **source fiber**

`Fib(omega) = { w in W_x : CompWit(x,w) can use omega }`.

Assume a bound

`|Fib(omega)| <= c`.

Then the union of source witnesses served by all fixed targets has size at most

`|Covered| <= sum_i sum_{omega in Omega_i} |Fib(omega)| <= t L c`.

### Theorem 1 — fixed-target source-fiber cover bound

Universal all-witness correctness requires

`W_x subseteq Covered`.

Therefore necessarily

`boxed( t L c >= |W_x| )`.

This is pure counting. It assumes no hardness and no adversary model.

### UP, source-preserving special case

For a UP target relation,

`L=1`.

For the natural Valiant--Vazirani/source-preserving compiler, the isolated target witness is literally the original source assignment, so distinct source witnesses remain distinct target witnesses. Hence

`c=1`.

Then

`boxed( t >= |W_x| )`.

For generic NP relations, `|W_x|` can be exponential in the witness length. Therefore a polynomial explicit list of fixed source-preserving UP targets cannot cover all original witnesses.

This is not a hardness statement. A tautological verifier with all `2^n` strings accepted is enough to witness the *correctness/size* obstruction. The source search problem for that example is trivial, but a generic compiler is still required to be correct for it.

---

## 3. Why Valiant--Vazirani's guarantee is the wrong quantifier

Valiant--Vazirani needs a randomized reduction under which, for a satisfiable source instance, **some** witness survives uniquely with noticeable probability.

Our WKEM correctness requirement is different:

`for every w in W_x, Decaps(P_x,C_x,w)=K`.

Those quantifiers do not commute.

Consider a fixed affine hash target bucket

`h(w)=0^k`.

For a uniform affine family `h(w)=A w + b` over `F_2`, a fixed source witness belongs to that fixed bucket with exact probability

`2^{-k}`.

With `t` independently generated fixed-bucket target instances, the exact coverage probability for a fixed witness is

`1-(1-2^{-k})^t <= t/2^k`.

When `k` is chosen around `log_2 |W_x|` to make isolation plausible, a polynomial `t` can give a useful probability that **some** witness is isolated while still giving negligible coverage probability for a particular witness when `|W_x|` is exponential.

The checker independently validates the fixed-witness `2^{-k}` law for the complete small affine family and the exact `t`-target coverage formula.

Thus the isolation theorem cannot simply be substituted for all-witness WKEM correctness.

---

## 4. Stronger affine-bucket fact

For an affine map

`h : F_2^n -> F_2^k`,

all nonempty fibers have size

`2^{n-rank(A)}`.

Consequently, when `k<n`, every nonempty bucket contains at least two source strings. A fixed affine bucket cannot be a UP target at all unless the matrix rank reaches `n`, which requires `k>=n`.

When `k=n` and `A` is invertible, every bucket is a singleton. But there are exactly `2^n` buckets, so a source-preserving fixed-bucket cover of every source witness again needs all `2^n` buckets.

The checker exhaustively validates both facts for all small affine maps through `n=4`.

This is only a finite implementation check of the elementary linear-algebra identity; the mathematical statement follows directly from rank-nullity.

---

## 5. The theorem deliberately leaves a many-to-one escape

The counting theorem is **not** an impossibility theorem for every compiler into UP.

If exponentially many source witnesses map to the same accepted target witness, then `c` can be exponential. In the extreme,

`t=1, L=1, c=|W_x|`

satisfies the cover bound.

That escape is important and is retained in the checker as a negative control.

But it tells us exactly what such a compiler has accomplished: it has constructed a polynomial-time **many-to-one canonical witness representation** for the source relation. If every original witness can compute the same target witness `omega_x`, then

`w -> omega_x`

has already solved the all-witness canonicalization problem before the UP WPRF is invoked.

If, in addition, `omega_x` maps back to an ORIGINAL source witness for unauthorized extraction, then the compiler has also solved the source-bearing side of our missing primitive.

So UP does not make the hard step disappear. Either:

1. the compiler is source-preserving / bounded-fiber, and a polynomial fixed list cannot cover exponentially many valid source witnesses; or
2. the compiler has large source fibers, and the many-to-one canonicalization itself is the substantive missing construction.

This is the more precise correction to a possible over-reading of Run 127. The barrier is not “UP can never help”; it is “a polynomial **source-preserving fixed-target decomposition** into UP/FewP components cannot supply generic all-witness correctness.”

---

## 6. Bounded ambiguity / FewP generalization

Nothing in Theorem 1 is specific to uniqueness.

If every target instance has at most `L=poly(lambda)` accepted target witnesses and every accepted target witness represents at most `c=poly(lambda)` source witnesses, then a polynomial number `t` of targets covers only polynomially many source witnesses.

For a source statement with exponentially many valid witnesses, generic all-witness correctness therefore still fails.

Hence replacing UP by a bounded-ambiguity/FewP target does not fix the quantifier mismatch unless one also introduces a large many-to-one source fiber. Again, that source-fiber compression is exactly the interesting primitive and must itself survive the Runs 112/126 setup/resampling barriers.

---

## 7. Witness-dependent bucket repair falls back into Run 127

A natural repair is to let a source witness choose its own target bucket

`y=h(w)`.

Then every witness certainly belongs to *some* bucket, and if `h` is injective the target instance `(h,y)` can even be unique-witness.

But different source witnesses now evaluate the WPRF on different target inputs:

`u_w=(x,h,h(w))`.

Ordinary WPRF correctness only says all witnesses of the **same input** obtain the same `F(fk,u_w)`. It gives no theorem that

`F(fk,u_w)=F(fk,u_w')`

for distinct target inputs.

That is precisely the fixed-input pressure already isolated in Run 127. Adding a cross-input equality/canonicalization layer strong enough to make all these values equal is an additional primitive, not a consequence of UP or Valiant--Vazirani.

Thus the two obvious isolation routes land on the two sides of the same boundary:

- fixed bucket(s): cannot cover every source witness efficiently under bounded fibers;
- witness-chosen bucket: covers witnesses, but loses the common fixed WPRF input/key.

---

## 8. QPT security ledger

### This run's new theorem

- honest algorithm model: finite/classical combinatorial statement;
- adversary model: none required;
- hardness assumption: none;
- reduction model: direct counting and elementary affine linear algebra;
- conclusion: correctness/representation-size barrier for bounded-fiber fixed-target UP/FewP decompositions.

It therefore applies regardless of whether a future UP WPRF is classically or quantum secure.

### Mathialagan--Peters--Vaikuntanathan 2024

- honest algorithm model: PPT/classical algorithms in Definition 5.1;
- adversary model: **PPT** in the WPRF security definition;
- hardness: ordinary LWE plus theorem-specific sampler/correlated **evasive-LWE** assumptions;
- evasive-LWE reduction model: its formal definition itself quantifies PPT `A1 -> A0`;
- exact conclusion: adaptive WPRF security for UP in that classical framework;
- QPT classification: **UNPROVED from the cited theorem**.

Even replacing every PPT quantifier by a separately proved QPT analogue would not repair the all-witness fixed-target coverage barrier proved here.

### Standard LWE status

The current paper itself distinguishes ordinary LWE from evasive LWE and presents evasive LWE as an additional bridge assumption. Therefore its WPRF is not recorded here as a WPRF from ordinary standard LWE alone, and ordinary QPT-LWE hardness does not automatically instantiate the evasive-LWE step.

---

## 9. Consequence for the current architecture

This result narrows the surviving route further.

Do **not** try to turn generic NP into a polynomial explicit collection of source-preserving UP instances and then attach a UP WPRF. That can at best ensure that *some* original witness obtains a target; it cannot meet the required universal all-witness same-key semantics on dense source relations.

The structurally compatible object is still Run 127's one-shot target:

1. one fixed statement-specific public object `P_x`;
2. one hidden canonical value `Z_x`;
3. every original witness evaluates to that same `Z_x`;
4. false `x` hides `Z_x` against arbitrary QPT attackers;
5. unauthorized QPT recovery on a true source-hard statement implies an ORIGINAL witness or an independently justified QPT-hardness break;
6. the Ext view cannot itself resample a compatible Hash secret/accepted target (Run 126).

Hair--Sahai's statement-derived MinRank space remains more structurally compatible with this goal than UP isolation because many source witnesses can live inside one fixed algebraic statement space. Hair--Sahai still supplies only a *supplied-low-rank-object -> ORIGINAL witness* semantic extractor; it does not supply the canonical public/offline front end or arbitrary-key-recovery extraction.

A concrete next experiment is therefore:

> For the actual Hair--Sahai statement-derived space, test whether the witness-derived rank-one/Boolean-factor family admits a compact canonical quotient/value computable from every source witness **without** making that value computable by witness-free setup or creating an ambient pseudorepresentation. Immediately run the quotient through the Run-112 and Run-126 setup/resampling tests.

If that fails, return to the other Run-79 handoff: compute the complete rank-weight spectral mass of the actual statement-derived space under a precisely defined correlated Ext distribution, rather than ambient heuristics.

---

## 10. Reproducible checker

`up_hash_isolation_all_witness_run128_check.py` is deterministic and standard-library-only.

The finalized checker was executed twice and the JSON outputs were byte-identical. It records **415,313 assertions** and checks:

1. the source-fiber cover bound over 66,187 finite target/fiber assignments;
2. constructive tightness controls for the `t L c` bound;
3. exact source-preserving UP singleton-cover behavior;
4. exact fixed-witness membership probability `2^-k` over complete small affine-hash families;
5. every small affine map with `k<n`, confirming no nonempty bucket is singleton;
6. every small invertible affine map with `k=n`, confirming all buckets are singletons but there are `2^n` of them;
7. exact independent fixed-bucket coverage probability and its union bound;
8. the dense-source arithmetic obstruction;
9. bounded-ambiguity/FewP examples;
10. an explicit many-to-one `c=|W_x|` escape control, preventing the theorem from being overstated as a generic impossibility result.

The checks are finite combinatorial/algebraic validation only. They establish no WPRF, LWE, evasive-LWE, MinRank, or QPT hardness claim.

---

## 11. Result

The new checkpoint is a **focused falsification**, not a completed construction:

> **UP/hash isolation does not give a polynomial source-preserving route from generic NP to this project's all-witness same-key WKEM.** A polynomial list of fixed UP (or bounded-ambiguity) targets can cover all original witnesses only if each accepted target witness represents a correspondingly large source fiber. Building that large common fiber is itself the missing all-witness canonicalization primitive. Letting the witness instead choose a target bucket restores coverage but creates witness-dependent WPRF inputs and falls back into Run 127's cross-input same-key gap.

This conclusion is unconditional at the correctness/interface level. Separately, the audited 2024 UP WPRF theorem remains classical/PPT and depends on evasive LWE, so it does not satisfy the project's QPT/standard-assumption target even before this compiler barrier is considered.

The practical generic-NP public/offline PQ witness-KEM stopping condition remains **unmet**.