# Run 127 — special-WPRF compiler theorem and fixed-input source gate

## Verified starting point

Before research, PR `syscoin/PVUGC#1` was read at head `4198b1815d3edc7be41ec1cb25c0c46fab24610e`, branch `research/pq-wkem-validation-20260918`; it was open, draft, and unmerged. Latest ordinary publication comment `5847380543` records verified publication of Runs 112–121. Exact current-head Run 80, Run 113, Run 121, and `literature-20260924/ASSESSMENT.md` were reread. Runs 122–126 are later conversation checkpoints but are not on this GitHub head; they are used only as current research context, not backfilled here.

Run 113 already identified WPRF as the right same-value public-witness-evaluation abstraction. This run does **not** rename that result. It proves what a compiler into the 2026 special vector-commitment WPRF would have to accomplish, and why witness-dependent target commitments do not avoid the fixed-input problem.

## 1. Source-preserving special-WPRF compiler theorem

Let `R(x,w)` be the ORIGINAL source NP relation and `R0(u,omega)` a target relation with a WPRF. Suppose classical polynomial-time algorithms

`u = CompStmt(x)`, `omega = CompWit(x,w)`, and `w = SrcExt(x,omega)`

satisfy:

1. **witness preservation:** `R(x,w)=1 => R0(CompStmt(x),CompWit(x,w))=1`;
2. **false preservation:** `x notin L_R => CompStmt(x) notin L_R0`;
3. **source preservation:** `R0(CompStmt(x),omega)=1 => R(x,SrcExt(x,omega))=1`.

For target WPRF `(Gen0,F0,Eval0)`, define

`F(fk,x) = F0(fk,CompStmt(x))`

and

`Eval(ek,x,w) = Eval0(ek,CompStmt(x),CompWit(x,w))`.

Then every valid ORIGINAL witness evaluates to the same value by target correctness. False-instance pseudorandomness transfers by deterministic preprocessing. If the target theorem is QPT, this transfer is QPT-clean: compute `CompStmt(x)` classically, invoke the QPT adversary once, and return its bit; there is no rewinding, cloning, QROM programming, or classical extraction substitution. If target extraction yields an accepted `omega`, property 3 converts it directly to an ORIGINAL source witness.

Therefore a **uniform reusable source-preserving compiler** from arbitrary NP into a special-language WPRF is already a construction of a general-purpose source WPRF. This is not an impossibility theorem, but it locates the breakthrough: Bhadauria–Branco–Döttling–Garg–Policharla ePrint 2026/1079 says general-purpose WPRFs are currently only known from assumptions implying iO, while their special Libert–Yung local-opening WPRF uses standard pairing-group assumptions. A standard-LWE/SIS compiler satisfying the three properties above would not be a routine commitment adapter; it would cross the general-WPRF boundary.

The concrete 2026 pairing construction is also not a PQ endpoint.

## 2. Stronger than the public-opening sampler barrier

Run 113 already proved

`publicly samplable accepted target opening + universal target-opening -> source-witness extractor`

implies a public source-witness search algorithm.

A target language can avoid that simple collapse by defining a source-restricted subclass of openings. The new theorem shows the other side: if that subclass is efficiently and uniformly reachable from every source witness, false-preserving, and every accepted target witness maps back to the source, then it is precisely the missing general compiler. The source-restricted predicate is the cryptographic problem, not free metadata attached to a vector commitment.

## 3. Fixed-input pressure

A tempting escape is to let each source witness construct its own target commitment/input. Suppose setup masks its key with `Z0 = F0(fk,u0)`. A future witness `w` constructs `u_w` and gets `Z_w = F0(fk,u_w)`. Correctness requires `Z_w=Z0` for **every** valid witness.

Ordinary PRF/WPRF semantics do not promise equality on distinct inputs. For a random function with range size `q`, if `m` distinct witness-derived inputs are used,

`Pr[F(u1)=...=F(um)] = q^{-(m-1)}`.

Thus witness-dependent commitments merely move all-witness canonicalization into an unproved cross-input collision property. A direct special-WPRF compiler instead needs one fixed target input `u_x=CompStmt(x)` that all valid source witnesses can open/evaluate. This independently matches Run 121's fixed-digest pressure.

A specially correlated function family could deliberately canonicalize distinct inputs, so this is not a universal impossibility theorem. But that correlation would itself require a security theorem and cannot be inherited from normal PRF semantics.

## 4. Three branches for a local-opening route

**A. Setup samples the fixed source-bearing opening.** If setup can sample an accepted `omega` for `u_x` and every such `omega` source-extracts, setup followed by `SrcExt` solves source search. This is the Run 113/124 collapse.

**B. Each witness creates a fresh target input.** Then setup is tied to `u0` while witness evaluation occurs at `u_w`; without an extra canonicalization theorem, same-key correctness fails, with random-function coincidence only `q^{-(m-1)}`.

**C. All witnesses open one fixed `u_x`, but setup cannot manufacture a source-bearing opening.** This is structurally viable. It needs statement-only generation of `u_x`, witness-derived openings for that same `u_x`, no ambient/public source-bearing openings, false-input hiding, and source extraction. If this works uniformly under a reusable target WPRF, the theorem above promotes it to a general-purpose WPRF.

The project has one important weakening: its setup may be **statement-specific and one-shot**. A one-shot canonical witness function need not imply a reusable relation-wide WPRF. This is the best remaining escape from the general-WPRF barrier.

## 5. Hair–Sahai fits only as the last semantic arrow

Hair–Sahai supplies a useful arrow from a supplied source-valid low-rank object to an ORIGINAL source witness. Runs 79 and 125 explain why ambient low-rank geometry and ordinary lattice short-preimage geometry do not automatically provide that object.

In a special-WPRF composition, a target opening could contain or decode to the Hair–Sahai low-rank object, making `SrcExt` the Hair–Sahai extractor. The unsolved front half is still: create one fixed target statement without that object; let every ORIGINAL witness derive an accepted opening for it; exclude public/ambient openings; and prove complete-output QPT hiding/extraction from independently justified PQ assumptions. Hair–Sahai can supply the last semantic arrow, not the fixed-input source compiler.

## 6. Run-126 compatibility

Run 126's current handoff says a dual-mode Ext view must not be able to resample a compatible Hash secret or accepted canonical target. The theorem here is consistent with that: a fixed-statement canonical value must be witness-computable, but the extraction mode cannot manufacture the source-bearing target merely by resampling setup secrets.

For a lattice candidate, require all of the following simultaneously: Hash setup computes the canonical value without a source witness; every source witness evaluates the same value at one fixed public target; Ext converts a *correct recovered* target into a source-bearing representation; Ext alone cannot efficiently sample such a target; Hash/Ext public views are statistically/trace-distance close (or a weaker switch has a publicly recognizable success event); and false-statement hiding reduces straight-line to an exact QPT-hard LWE/SIS distribution. A generic GPV trapdoor plus an independent hash secret still fails Run 126's resampling test.

## 7. Quantum-security ledger

- Source-to-target correctness and target-witness-to-source extraction are classical direct reductions.
- Target **QPT** pseudorandomness transfers to source QPT pseudorandomness by straight-line classical preprocessing.
- No QPT theorem is inferred from the pairing-based 2026 WPRF.
- Hair–Sahai extraction is a supplied-representation semantic arrow, not arbitrary-QPT source extraction.
- The fixed-statement lattice source gate from standard QPT LWE/SIS remains **missing**.

No theorem here silently substitutes QPT for a published PPT adversary model.

## 8. Reproducible checker

`special_wprf_compiler_run127_check.py` is deterministic and standard-library-only. It was executed twice with byte-identical stdout; the finalized output records **16,489 assertions**. It checks finite witness/false/source preservation, same-value compilation over 125 deterministic function tables, exact target-witness-to-ORIGINAL-source extraction, challenge-distribution identity under deterministic compilation, explicit witness-dependent-input failures, exact exhaustive random-function collision probabilities `q^{-(m-1)}` for 12 `(q,m)` cases, setup-samplable-source collapse, and a public dummy-opening negative control.

These checks do not test any WPRF, pairing, LWE, SIS, MinRank, or QPT hardness assumption.

## 9. Literature boundary and next handoff

Fresh lookup verified ePrint 2026/1079 under the same authors/title; author and DBLP pages list it as ASIACRYPT 2026, and an abstract mirror repeats the special Libert–Yung local-opening / pairing-assumption / general-WPRF-via-iO boundary. The primary ePrint PDF was not successfully retrieved through the available web path this run, so no new full-proof audit is claimed. Run 113's primary-abstract-level audit remains the evidence boundary. Zhandry ePrint 2014/301 remains the primary WPRF reference and describes WPRFs as related to but apparently stronger than witness encryption.

The next constructive target is a **statement-specific one-shot canonical witness function**, weaker than reusable WPRF: `Setup(x)` creates fixed public `P_x` and hidden `Z_x`; every valid ORIGINAL witness computes the same `Z_x`; false `x` hides `Z_x` against QPT; arbitrary QPT recovery on true hard `x` yields an ORIGINAL witness or an independently justified QPT-hardness break; and an extraction trapdoor cannot resample `Z_x` or a source-bearing target itself. The next pass should try to instantiate this exact weaker object from a dual-mode lattice primitive and immediately test its complete Ext view against Run 126.

The stopping condition is **not met**.