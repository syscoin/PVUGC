# Run 124 — EHPS sampler-coin / fixed-instance barrier; PEPRF fixes the syntax but not the generic-NP/QPT source gate

## Checkpoint

Before new work, the live `syscoin/PVUGC#1` draft PR was read through the connected
GitHub tools. It is open, draft, and unmerged on branch
`research/pq-wkem-validation-20260918` at
`4198b1815d3edc7be41ec1cb25c0c46fab24610e`. The latest substantive ordinary PR
comment is `5847380543`, which records verified publication of Runs 112–121 at that
head. Exact Run-112, Run-114, Run-120, Run-121, and the 24 September literature
assessment were read at that commit before this derivation.

Runs 122 and 123 are later conversation checkpoints whose first scheduled GitHub
writes were reported safety-blocked. This run does **not** retry, rename, split, encode,
or republish either denied payload. It uses their scientific conclusions only where
needed. In particular, Run 123's abstract straight-line extraction theorem is retained,
but one literature analogy in that run needs a concrete correction.

No production path is changed.

## 1. Correction: Wee's EHPS is dual-mode, but its public evaluator takes sampler coins, not the relation witness

Run 123 described Hoeteck Wee's CRYPTO 2010 extractable hash proof system (EHPS) as a
useful antecedent for a statistically dual-mode source hash. The dual-mode/extraction
part is real, but that description understated a decisive interface mismatch.

Wee fixes an efficiently samplable one-way binary relation `R_PP`. The paper requires
an efficient sampler

`SampR(PP; r) -> (u,s)`

and, with overwhelming probability over public parameters, at most one relation
witness `s` for each `u`. The hardness statement is an *average-case sampled-instance*
one: given a random `u` arising from `SampR`, recover its `s` (or hard-core information
about it).

The EHPS algorithms are

`(SetupExt, SetupHash, Pub, Ext, Priv)`.

The exact public-evaluation clause is

`Pub(PK, r) = H_PK(u)` for `(u,s)=SampR(r)`.

It is **not**

`Pub(PK, u, s) = H_PK(u)`.

The extraction mode has the attractive property

`tau = H_PK(u)  <=>  (u, Ext(SK,u,tau)) in R`,

and the hashing mode computes the same mathematical `H_PK(u)` privately. The two
public-key distributions are statistically indistinguishable. Those are exactly the
parts that motivated Run 123. But future public evaluation is explicitly keyed by the
*sampling randomness* `r` that generated the relation pair.

Primary source: Hoeteck Wee, *Efficient Chosen-Ciphertext Security via Extractable Hash
Proofs*, CRYPTO 2010, author PDF
`https://www2.seas.gwu.edu/~hoeteck/pubs/exthps-crypto10.pdf`, especially pp. 2, 5–7
and §5.1. The paper states the sampler-coin public evaluation in the overview and again
in the formal definition.

This distinction matters directly for our target: a future party has an ORIGINAL NP
witness `w` for a fixed externally supplied statement `x`; it does not generally have
the random coins with which some unrelated relation instance was sampled.

## 2. The mismatch is concrete, not terminological

### Diffie–Hellman instantiation

Wee's DH relation is

`R_PP^dh = {(u,s): s=u^alpha}`

with `PP=(g,g^alpha)`. Its sampler chooses `r` and outputs

`u=g^r`, `s=g^(alpha r)`.

The EHPS public hash is evaluated as

`Pub(PK,TAG,r) = (g^(alpha TAG) * PK)^r`.

Thus the public evaluator needs `r`. The relation witness is instead

`s = g^(alpha r) = (g^alpha)^r`.

Consequently, converting the relation witness into the input expected by `Pub` is
exactly the representation problem

`r = log_{g^alpha}(s)`

on the sampled support. This is an algebraic identity, not a new hardness theorem: the
paper simply does not provide an efficient `s -> r` algorithm. Its security is built
around DH-era assumptions, not around making this logarithm available.

### Iterated-squaring/factoring instantiation

For the factoring relation, the sampler chooses `r` and outputs, schematically,

`u = g^(2^k r)`, `s=g^r`.

Again `Pub` uses the integer `r`. Turning the relation witness `s=g^r` back into that
sampler coin is a discrete-log representation problem in the signed quadratic-residue
group. Nothing in the factoring EHPS interface supplies it.

So even possession of the *EHPS relation witness* is not, in the concrete examples, the
same capability as possession of the public-evaluation randomness.

## 3. Fixed-instance source-bearing sampler theorem

The sampler mismatch becomes a generic barrier when one tries to graft EHPS directly
onto a generic NP source relation.

Let `R_src(x,w)` be the ORIGINAL NP relation. Suppose a compiler tries to produce for
an externally fixed statement `x` an EHPS relation instance `u_x` with these two
properties:

1. a witness-free setup can run the EHPS sampler (or an equivalent public sampler) to
   obtain a valid relation witness `s_x` for that same fixed instance `u_x`; and
2. there is an efficient source extractor
   `SrcExt(x,s_x) -> w` such that `R_src(x,w)=1` for every usable relation witness
   `s_x`.

Then witness-free setup itself solves the source search problem:

`sample s_x -> SrcExt(x,s_x) -> w`.

This is exactly the Run-112 setup-known-value obstruction in relation-witness form.
If source witness search is assumed QPT-hard, it is already impossible for a classical
PPT setup to have both capabilities.

### Corollary for Hair–Sahai low-rank extraction

A particularly tempting composition is:

`EHPS Ext(correct hash) -> low-rank element S_x -> Hair–Sahai source extractor -> ORIGINAL w`.

If the EHPS relation sampler used by the real/hash setup can itself sample that same
source-bearing low-rank element `S_x` for the fixed statement, the composition
collapses immediately: setup samples `S_x` and applies the Hair–Sahai extractor.

Therefore a viable dual-mode construction must be asymmetric in a stronger sense:

- **Hash mode** may compute the canonical hash value without sampling any source-bearing
  low-rank witness;
- **Ext mode** may recover a source-bearing low-rank object *from the correct canonical
  hash value*;
- the complete public views of those modes must remain suitably close;
- a future ORIGINAL source witness must directly evaluate the same canonical value.

That is much closer to Run 123's abstract interface than to a stock EHPS sampler.

## 4. If setup does not sample the source-bearing witness, future evaluation needs a new `w -> r` compiler

Avoiding the setup collapse means the real setup cannot simply create the
source-bearing `s`. But stock EHPS public evaluation still asks for `r`.

For a fixed external statement, one therefore needs an additional algorithm of the
form

`Coins(P,x,w) -> r`

such that

`SampR(r) = (u_x, s_x)`

for the fixed compiled instance and `Pub(PK,r)` equals the canonical value.

This is not supplied by Wee's definition. In the concrete DH example, even starting
from the EHPS relation witness `s`, recovering the necessary `r` is the discrete-log
representation above. In a generic NP compiler, constructing `Coins` from the
ORIGINAL witness while preventing false/pseudowitness evaluation is precisely the
missing witness-restricted public-evaluation problem, not a free consequence of EHPS.

Hence a naive statement of the form

`EHPS + source-to-relation-witness map => public offline witness release`

is false. One also needs a *source-witness-to-public-evaluation representation* map,
or a different public evaluator that consumes the source witness directly.

## 5. PEPRF has the right evaluator syntax, but the published security target is different

A directly relevant predecessor is Yu Chen and Zongyang Zhang,
*Publicly Evaluable Pseudorandom Functions and Their Applications*, ePrint 2014/306,
last revised 27 February 2016:
`https://eprint.iacr.org/2014/306`.

Its defining functionality is syntactically much closer to what we need. For a domain
`X` containing a language `L` with a hard relation, `F_sk(x)` can be evaluated either
with the secret key or publicly from

`(pk, x, w)` for a witness `w` that `x in L`.

So PEPRF repairs the precise `r`-versus-`w` mismatch above.

But the accessible primary record states a different security target:

- the basic notion is **weak pseudorandomness on uniformly random chosen inputs**;
- the stronger notion is adaptive weak pseudorandomness with evaluation-oracle access;
- the constructions are from injective trapdoor functions, HPS, EHPS, or puncturable
  PRFs plus obfuscation.

That does not by itself give the generic-NP WKEM property required here:

- setup receives an *arbitrary externally fixed* NP statement, not a random instance
  sampled from a hard relation;
- false-statement hiding is required for every false source statement in the target
  security game, not merely a random input distribution;
- every valid source witness must recover one canonical key;
- arbitrary QPT early FINAL-key recovery on a true statement must imply an ORIGINAL
  source witness or an independently justified QPT-hardness break;
- the complete public auxiliary view and malicious setup ceremony must compose.

The 2014/2016 PEPRF paper is classical-era work; nothing in its stated result supplies
our required QPT theorem. Generic constructions *from* EHPS also inherit the need to
instantiate the underlying hard relation and do not automatically turn an arbitrary
fixed NP statement into a source-preserving hard instance.

Therefore:

**PEPRF is evidence that the desired witness-public-evaluation syntax is coherent, but
it is not a generic-NP/PQ base construction for this project.**

This also explains why simply renaming the missing primitive “PEPRF” or “witness PRF”
would be circular.

## 6. Correction to Run 123's literature classification

Run 123's *theorem* remains intact:

if a construction has statistically close complete public views, a mode-independent
canonical target, direct evaluation from every ORIGINAL source witness, and extraction
of an ORIGINAL source witness from the correct target in Ext mode, then arbitrary QPT
FINAL-key recovery transfers straight-line to source extraction with the stated
statistical loss.

What changes is the precedent claim:

- Wee 2010 supplies a genuine **dual-mode statistical/extraction pattern**;
- it does **not** supply Run 123's direct `Eval(P,x,w)` interface for an externally fixed
  generic NP statement;
- its `Pub` input is sampler randomness `r`, and its one-way relation is an efficiently
  samplable average-case relation.

So Wee should be cited only for the dual-mode/extraction architecture, not as a near
instantiation of the full source-hash interface.

## 7. QPT/security ledger

| Component | Honest algorithms | Adversary / hardness actually stated | Reduction/model issue | Exact conclusion here |
|---|---|---|---|---|
| Wee EHPS definition | classical PPT | classical probabilistic-time adversaries; factoring/DH-era concrete assumptions | public eval uses sampler coins; relation is sampled/average-case | dual-mode extraction syntax only; **not PQ and not fixed-instance source evaluation** |
| EHPS sampler-coin barrier | classical PPT | unconditional interface argument | no rewinding, oracle programming, or hardness needed | stock EHPS does not turn a relation witness into its public-evaluation coins |
| Fixed-instance source-bearing sampler theorem | classical PPT setup | applies even before choosing classical/QPT attacker model | straight-line composition of sampler and source extractor | if setup can sample a source-bearing relation witness, setup itself solves source search |
| Chen–Zhang PEPRF syntax | classical PPT | weak/adaptive-weak PRF security on its stated hard-relation input model | no QPT theorem imported | direct `(pk,x,w)` evaluation is the right syntax, but generic fixed-NP/QPT security remains absent |
| Run-123 SDMSH theorem | classical PPT honest algorithms | arbitrary QPT adversary, conditional on statistical complete-view mode closeness and exact QPT false-hiding assumption | one adversary invocation; no rewinding/QROM | abstract recovery-to-ORIGINAL-witness theorem survives this correction |

No classical theorem is silently relabeled QPT. Neither discrete-log resistance nor
absence of an attack is used as evidence of PQ security.

## 8. Exact reproducible validation

`ehps_fixed_instance_sampler_coin_run124_check.py` is deterministic and
standard-library-only. Two finalized executions were byte-identical and record
**2,771 assertions**.

The finite checker validates on the prime-order subgroup of `Z_23^*` with `q=11`:

1. the DH relation `SampR(r)=(g^r,g^(alpha r))`;
2. the exact extraction-mode EHPS identity over every toy secret key, nonzero tag, and
   sampler coin;
3. the all-but-one target hashing identity and non-target extraction identity;
4. exact equality of the two public-key distributions in the toy modes;
5. that converting the DH relation witness `s=(g^alpha)^r` into the sampler coin is
   exactly a discrete-log table `r=log_{g^alpha}(s)` on the sampled support;
6. a finite reduction-shape control showing that any extractor which maps a setup-
   sampled relation witness to an ORIGINAL witness immediately lets witness-free setup
   solve the source relation.

The checker does **not** test DL/CDH/factoring/LWE/SIS hardness, QPT security, or the
existence of the missing generic-NP construction.

## 9. Updated construction target

The next useful object is now sharper than “EHPS for NP.” It must simultaneously have:

1. **fixed external statement:** setup is parameterized by the user's arbitrary `x`,
   not by a fresh `SampR` instance;
2. **direct witness evaluation:** every ORIGINAL `w` computes the same canonical
   `H(P,x)` without recovering hidden sampler coins or receiving an authority key;
3. **hash mode without source witness:** witness-free setup can compute `H(P,x)` but
   never obtains a source-bearing extractable representation;
4. **extraction mode without hash secret:** from the *correct same* `H(P,x)`, a
   trapdoor recovers a source-bearing low-rank/structured object and then an ORIGINAL
   witness;
5. **statistical/trace-distance public-mode closeness** (or a separately justified
   efficiently recognizable event strong enough for the Run-123 transfer);
6. **false-statement full-view QPT hiding** reduced straight-line to an independently
   justified exact QPT-hard assumption such as an appropriate standard LWE/SIS
   distribution, not a newly named witness-release assumption.

The most concrete next test is therefore not another EHPS wrapper. It is to ask whether
a **dual-mode lattice trapdoor** can be indexed by the actual Hair–Sahai statement
space so that Ext mode inverts the canonical target into a low-rank member while Hash
mode computes that target without ever sampling one. Any design that lets Hash mode
sample the low-rank member is rejected immediately by the theorem above; any design
whose witness evaluation uses an ambient affine representation is rejected by Runs
114/120.

The practical generic-NP public/offline PQ witness-KEM stopping condition remains
**unmet**.