# Run 123 — statistical dual-mode source hash: a quantum-clean extraction interface

## Checkpoint

At the start of this run `syscoin/PVUGC#1` was open, draft, and unmerged on
`research/pq-wkem-validation-20260918` at
`4198b1815d3edc7be41ec1cb25c0c46fab24610e`. The latest ordinary PR comment was
`5847380543`, recording verified publication through Run 121. Run 122 remains a
separate local-only checkpoint after its first scheduled write was safety-blocked;
this run does not retry or repackage that denied payload.

The live ePrint record for Branco–Choudhuri–Döttling–Jain–Malavolta–Srinivasan,
ePrint 2024/1514, confirms that 30 March 2026 is the last of three revisions. Its
current formal Section 5 proves key pseudorandomness in Lemma 8 directly from
ordinary LWE using `W=G^{-1}(A)` and `v=z+u'W`; Lemma 9 is statistical. Therefore
Run 122's conditional QPT lift for the *VTDH pad layer* remains valid if the exact
Section-5 LWE family is QPT-hard. This run addresses the still-missing reverse arrow:
arbitrary true-instance FINAL-key recovery -> ORIGINAL source witness.

No production path is changed.

## 1. The exact interface needed

Fix an NP relation `R(x,w)`. Define a **statistically dual-mode source hash** (SDMSH)
as an analysis target with classical PPT algorithms:

- `HashSetup(1^lambda,x) -> (P,hk)`;
- `ExtSetup(1^lambda,x) -> (P,xk)`;
- a mathematical canonical value `H_P(x) in {0,1}^kappa` indexed only by public
  `(P,x)`, not by mode or secret key;
- `Priv(hk,x)=H_P(x)`;
- `Eval(P,x,w)=H_P(x)` for every `w` with `R(x,w)=1`;
- for true `x`, `Extract(xk,x,H_P(x))` outputs an ORIGINAL witness except probability
  `eta_ext`;
- for true `x`, the **complete public views** output by HashSetup and ExtSetup are at
  statistical distance at most `delta_mode` (including every transcript field,
  checking datum, ceremony commitment and auxiliary encoding shown to the adversary);
- for false `x` in hash mode, `(P,H_P(x))` is QPT-indistinguishable from `(P,U_kappa)`
  with advantage at most `epsilon_smooth`, under an independently justified exact
  QPT-hard assumption.

This is deliberately a target interface, not a claimed construction. It is inspired
by Hoeteck Wee's CRYPTO 2010 **extractable hash proof system (EHPS)** syntax: Wee has
hashing and extraction setups, a public-key-indexed mathematical hash, exact
extraction from the correct hash in extraction mode, and statistically
indistinguishable public keys between modes. Wee's concrete relations are
unique/samplable and its instantiations are factoring/CDH-era, so they are not a PQ
generic-NP solution. The transferable ingredient is the dual-mode extraction shape.

## 2. WKEM transform

Real witness-free setup runs HashSetup, computes `H=Priv(hk,x)`, samples uniform
`K <- {0,1}^kappa`, publishes

`C = K xor H`

with the complete public view `P`, and erases `hk`. Any valid witness computes
`Eval(P,x,w)=H` and recovers `K=C xor H`. Thus every valid witness gets the same key.

For false `x`, replace `H` by uniform in the SDMSH QPT-smoothness game. Then `C` is a
one-time pad independent of `K`. Any arbitrary QPT exact-key recovery algorithm has

`Pr[Khat=K] <= 2^{-kappa} + epsilon_smooth`.

The reduction is straight-line: one adversary invocation and a classical equality
test. It uses no rewinding, QROM programming, superposition oracle, or extraction.

## 3. True-instance extraction theorem

Let `x` be true. Let an arbitrary QPT algorithm `A` recover the real WKEM key with
probability `rho` from the complete real public view and capsule. Construct `E^A`:

1. `(P,xk) <- ExtSetup(1^lambda,x)`;
2. sample `C <- {0,1}^kappa` uniformly;
3. run `Khat <- A(P,C)` once;
4. set `z := C xor Khat`;
5. output `Extract(xk,x,z)`.

In real hash mode, because `K` is uniform, `C=K xor H_P(x)` is itself exactly uniform.
So the real recovery event is equivalently

`Khat = C xor H_P(x)`.

Crucially, `H_P(x)` is the *same mathematical function of the public index* in both
modes. Applying the arbitrary QPT channel `A` and then testing the above event cannot
increase statistical/trace distance. Hence the event occurs in extraction mode with
probability at least `rho-delta_mode`. Whenever it occurs,
`z=C xor Khat=H_P(x)`, so extraction succeeds except `eta_ext`.

Therefore

`Pr[R(x,E^A(...))=1] >= rho - delta_mode - eta_ext`.

This is the desired arbitrary-QPT FINAL-key-recovery -> ORIGINAL-witness arrow. The
mode switch is information-theoretic and the adversary is invoked once. Quantum
auxiliary information is permitted provided it is fixed/identically distributed in
both experiments; there is no rewind, clone, QROM step, or measurement-transcript
extractor.

## 4. Two necessary conditions

### Canonical target must be mode-independent

Identical public views alone are insufficient if the hidden target may change with
mode. Toy counterexample: `P` is identical, `H_hash=0`, `H_ext=1`, and `A(P,C)=C`.
Then exact recovery succeeds with probability 1 in hash mode and 0 in extraction
mode although public-view statistical distance is 0. So `H_P(x)` must be a single
public-indexed mathematical value.

### Computational mode indistinguishability alone is not enough

The recovery event contains the generally hidden predicate `z=H_P(x)`. A conventional
computational mode-switch proof cannot transfer an event that its reduction cannot
efficiently test. A one-way-permutation/hardcore-bit thought experiment makes this
sharp: public indices conditioned on a hidden hardcore bit can be computationally
indistinguishable while a hidden-target recovery event differs maximally.

Thus the present theorem needs either:

1. statistical/trace-distance mode closeness; or
2. a separate efficient, mode-independent public predicate `Check(P,x,z)` that tests
   `z=H_P(x)`, plus a QPT computational mode-switch proof for that efficiently
   recognizable event.

No silent computational->statistical substitution is allowed.

## 5. Why this does not contradict Run 112

Run 112 ruled out a **real-setup value-only extractor**: if one algorithm receives
both the real hash secret (which computes `H`) and an extraction trapdoor for the same
public index, setup itself solves witness search.

SDMSH separates the trapdoors by mode. HashSetup has `hk` but no `xk`; ExtSetup has
`xk` but need not know `H`. A joint PPT setup that outputs both for the same index is
forbidden for a hard source relation. This is not a technicality; it is a required
ceremony invariant.

## 6. N-of-N root composition

The interface composes naturally with the allowed N-of-N ceremony model. Let operator
`j` contribute canonical share `H_j(P_j,x)` and let

`H = H_1 xor ... xor H_N`, `C=K xor H`.

For false statements, if one honest share is QPT-pseudorandom even conditioned on the
entire malicious auxiliary public view, xor with arbitrary other shares preserves
pseudorandomness.

For true-instance extraction, switch one honest operator `j*` to Ext mode and simulate
other shares in Hash mode. After `A` returns `Khat`, compute

`z_{j*}=C xor Khat xor (xor_{i != j*} H_i)`.

On successful recovery this equals `H_{j*}`, so `Extract_{j*}` gives the ORIGINAL
witness. Statistical mode closeness again transfers an arbitrary QPT recovery event.
If the reduction must guess which one of polynomially many operators is honest, it
loses a factor `N`; non-negligibility is preserved.

This does **not** yet prove a malicious-secure setup protocol. Commit/order rules,
t-of-X redundancy inside operators, adaptive-abort handling, auxiliary-input
smoothness, and erasure are still obligations.

## 7. Relation to VTDH and Hair–Sahai

The current VTDH `Setup/Setup*` modes are **not** SDMSH modes. Its trapdoor `Decode`
recovers hidden bits of a digest; it does not turn the correct recovered canonical pad
into an ORIGINAL NP witness. Run 121's fixed-digest same-key canonicalization and Run
122's conditional QPT hiding lift therefore remain useful components, but they do not
instantiate the new extraction arrow.

Hair–Sahai's supplied-low-rank theorem remains a plausible final extraction stage:

`correct canonical value in Ext mode -> low-rank element of the actual statement-derived space -> ORIGINAL witness`.

The first arrow is still missing. A plain linear projective hash cannot supply it,
because Run 114's ambient pseudorepresentation attack applies. Any rank-based repair
must bind the *correct canonical value itself* to a low-rank statement-space element,
not merely verify low rank after an adversary voluntarily supplies a representation.

## 8. Exact security ledger

| Component | Honest model | Adversary model | Assumption/model | Conclusion |
|---|---|---|---|---|
| Run-122 VTDH pad | classical PPT | QPT | exact Section-5 decisional LWE assumed QPT-hard; straight-line hybrids + statistical Lemma 9 | conditional QPT pad hiding |
| Wee 2010 EHPS pattern | classical PPT | statistical public-key mode switch in definition; concrete old assumptions | unique/samplable relation, factoring/CDH-era examples | useful dual-mode extraction syntax only |
| SDMSH true-key theorem | classical PPT setups/eval | arbitrary QPT | statistical complete-public-view mode closeness + mode-independent canonical target + correct Ext | recovery -> ORIGINAL witness with `rho-delta-eta` |
| SDMSH false hiding | classical PPT | arbitrary QPT | exact source-hash pseudorandomness assumption must independently be QPT-hard | key recovery <= `2^-kappa + epsilon` |
| generic-NP practical PQ WKEM | classical public/offline | arbitrary QPT | must instantiate both rows above from standard/exact PQ assumptions | **UNPROVED** |

## 9. Reproducible checker

`stat_dual_mode_source_hash_run123_check.py` is deterministic and standard-library
only. Two finalized executions were byte-identical. It records 3,107 assertions and
checks finite versions of: statistical event transfer under arbitrary classical
postprocessing, false-statement exact-recovery bounds, the mode-dependent-target
negative control, N-of-N xor composition/extraction identities, the forbidden joint
hash+extraction trapdoor composition, and multi-bit xor algebra.

These are algebra/distribution checks. They do **not** prove a QPT hardness assumption
or the existence of a generic-NP SDMSH.

## 10. Next handoff

The next pass should not invent another WPRF/HPS name. It should try to instantiate one
of the two missing arrows:

1. **rank path:** correct canonical value in Ext mode -> low-rank element of the actual
   Hair–Sahai statement-derived space, immediately testing ambient/public
   pseudorepresentations; or
2. **VTDH path:** augment the fixed-digest public view with a statistically close
   extraction mode whose correct canonical bit vector deterministically yields a
   source-bearing object, without giving HashSetup the extraction trapdoor.

For either path, the false-word hash distribution must have a direct QPT reduction to
an independently justified exact PQ assumption under the **full** public auxiliary
view. The stopping condition is not met.