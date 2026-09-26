# Run 109 — hidden-input EPHF boundary: fixed-input WEFC exists, but natural universal projection leaks the hash through the SIS gadget

## Status

Verified starting PR head:
`5a612472b4f5e16120a6a07097ef25788415cb94`
on branch `research/pq-wkem-validation-20260918`.
PR #1 was open, draft, and unmerged.

The latest substantive PR comment is `5839832728`, recording verified publication of
Runs 100–103. Runs 104–108 remain local-only after separate safety-blocked
publication attempts. This run does not retry, rename, split, encode, or reroute any
previously denied payload.

This run builds directly on the latest local Run-108 checkpoint:

* de Castro–Peikert gives a polynomial-size transparent SIS functional commitment
  where setup commits to the verifier function and a future input `w` computes a short
  opening `S_w`;
* for a valid Boolean witness, the opening satisfies a same-output
  witness-dependent equation of the form

  \[
  (C-\operatorname{Rep}(w)\otimes g^T)S_w=t_1;
  \]

* Run 108 showed that the obvious fixed-matrix common-target linearization loses
  witness consistency and admits public gadget-only short preimages.

The new literature result examined here is
Campanelli–Fiore–Khoshakhlagh,
*Witness Encryption for Succinct Functional Commitments and Applications*,
IACR ePrint 2022/1510 / PKC 2024.

That paper contains an exact conceptual near-match: it combines a functional
commitment whose verification is **linear in the opening proof** with an
**extractable projective hash function (EPHF)**.  Encryption publishes a projection
key for the verification matrix and masks the bit with the true hash; a valid opening
proof computes the same hash projectively.

The new conclusion is:

> fixed-public-input EPHF is the right downstream release technology, but moving the
> unknown future witness input from the public statement into the witness changes the
> de Castro verification equation from affine to bilinear.  The natural universal
> projection key that defers the input leaks the true hash information-theoretically
> through the powers-of-two gadget.

This is not merely the old fixed-matrix preimage attack.  It shows why the existing
WEFC/EPHF compiler itself cannot be naively made witness-input-independent.

No production path is changed.

---

## 1. What Campanelli–Fiore–Khoshakhlagh actually prove

Their language has a **public statement**

\[
x=(cm,\beta,y)
\]

and witness `op` satisfying

\[
\operatorname{Verify}(ck,cm,op,\beta,y)=1.
\]

The construction assumes the verification equation is affine/linear in the opening
proof.  Therefore it can be written as

\[
\Theta(x)=M(x)\,op_f.
\tag{1}
\]

With hash key `hk`, encryption publishes

\[
hp=[hk\,M(x)]
\tag{2}
\]

and defines the true hash

\[
H=[hk\,\Theta(x)].
\tag{3}
\]

A valid opening computes

\[
pH=[hp\,op_f]=H.
\tag{4}
\]

The encrypted bit is protected by a Goldreich–Levin mask of an encoding of `H`.

This is exactly the projective-hash pattern we would like.

However, their public statement includes the functional-commitment input `β`.  The
paper explicitly observes that its WEFC notion loses the pure nondeterministic flavor
of witness encryption because there must already be a commitment to the decryption
witness/input.

That distinction is central for us: setup knows the NP statement but **does not know
the future witness input**.

---

## 2. Their EPHF extraction theorem is not our QPT source-extraction theorem

The paper's knowledge-smooth EPHF is defined against **PPT** adversaries.

Its extractor is required to recover the representation

\[
w'=\Lambda(x,w)
\]

that satisfies the affine PHF relation; it is explicitly not required to recover the
underlying semantic witness `w`.

For the paper's WEFC application, evaluation binding of the functional commitment is
then used to derive the semantic contradiction needed for false-statement security.

This differs from our true-instance target:

\[
\boxed{
\text{arbitrary QPT FINAL-key recovery}
\Longrightarrow
\text{ORIGINAL NP witness}
\text{ or independently justified QPT-hardness break}.
}
\]

The paper's concrete EPHF uses bilinear groups and discrete logarithm, with
extractability in the algebraic/generic-group model.  The authors explicitly explain
that even their AGM extraction cannot simply be lifted through the WE reduction
because the WE adversary outputs only a bit; their semantic-security theorem is
therefore stated in the GGM.

So this literature supplies an important **compiler shape**, not a PQ endpoint.

---

## 3. The de Castro witness-local opening relation

For the SIS functional commitment, the exact verification relation is

\[
\boxed{
(C-\operatorname{Rep}(w)\otimes g^T)S_w
=
C_f-\operatorname{Rep}(f(w))\otimes g^T.
}
\tag{5}
\]

For the statement verifier

\[
f_x(w)=R(x,w)
\]

and desired output `1`, define the common right-hand target

\[
t_1
=
C_f-\operatorname{Rep}(1)\otimes g^T.
\tag{6}
\]

Every valid witness has an efficiently computable short opening satisfying

\[
\boxed{
M(w)S_w=t_1,
\qquad
M(w)=C-\operatorname{Rep}(w)\otimes g^T.
}
\tag{7}
\]

For **fixed public `w`**, (7) is linear in `S_w`.

This is exactly the kind of relation the fixed-input EPHF methodology can consume.

The difficulty is that our encryption must be produced **before `w` is known**.

---

## 4. Why simply moving `w` into the witness makes the relation bilinear

For Boolean input coordinates, suppressing representation bookkeeping,

\[
M(w)=C-\sum_i w_i G_i,
\tag{8}
\]

where each `G_i` contains the public powers-of-two gadget in the block corresponding
to input bit `i`.

Equation (7) becomes

\[
CS-\sum_i w_i G_iS=t_1.
\tag{9}
\]

The unknowns now include both `w` and `S`.

The product terms

\[
w_iS
\]

make (9) degree two.

A standard affine linearization introduces independent variables

\[
Z_i=w_iS
\]

and writes

\[
\boxed{
CS-\sum_i G_iZ_i=t_1.
}
\tag{10}
\]

But the omitted consistency conditions

\[
Z_i=w_iS,\qquad w_i\in\{0,1\}
\tag{11}
\]

are nonlinear.

The set

\[
\{(w,S,Z):w\in\{0,1\},\,Z=wS\}
\]

contains zero but is not closed under addition, so it is not a linear subspace and
cannot be captured exactly by a homogeneous linear system.

This is why the existing affine EPHF compiler does not directly apply when the
functional-commitment input is moved from the public statement into the witness.

---

## 5. Natural universal projective key

There is a tempting way to defer `w` without linearizing the witness relation.

Let a hash key be `h`.  Instead of publishing the fixed-input projection

\[
hp_w=hM(w),
\]

publish the affine basis projections

\[
\boxed{
hp_C=hC,\qquad hp_i=hG_i.
}
\tag{12}
\]

A later witness can combine them:

\[
hp_w=hp_C-\sum_i w_i hp_i,
\tag{13}
\]

then compute

\[
hp_wS_w
=
hM(w)S_w
=
ht_1.
\tag{14}
\]

At first sight this appears to solve the unknown-input problem perfectly: encryption
is witness-independent and every future valid witness derives the same hash.

It is insecure.

---

## 6. Universal-projection gadget-hash theorem

The de Castro gadget is

\[
g^T=(1,2,4,\ldots,2^{\ell-1}),
\qquad
\ell=\lceil\log_2 q\rceil,
\]

with public decomposition

\[
g^{-1}(u)\in\{0,1\}^{\ell}
\]

satisfying

\[
g^Tg^{-1}(u)=u
\qquad\forall u\in\mathbb Z_q.
\tag{15}
\]

The matrix form has the analogous property

\[
(X\otimes g^T)\,g^{-1}(Y)=XY.
\tag{16}
\]

Each input block `G_i` therefore has efficient public short preimages for the relevant
target components.

The following general statement is immediate.

### Theorem 1 — public basis-preimage leak

Let a target be `t` and let a public basis matrix `B` admit a publicly computable
vector `d_t` such that

\[
Bd_t=t.
\]

If a universal projective key publishes

\[
hp_B=hB,
\]

then anyone computes the true projected target hash

\[
\boxed{
H=ht=hp_Bd_t.
}
\tag{17}
\]

No witness is required.

### Application to the functional commitment

For a gadget block \(G_i\), public gadget decomposition supplies the necessary short
`d_{t_1}` blockwise.

Thus publishing the basis projection

\[
hp_i=hG_i
\]

needed to let a future `w_i` select that block also gives an unauthorized computation
of the message-masking hash.

Therefore

\[
\boxed{
\text{natural affine universalization of the EPHF projection key}
\Longrightarrow
\text{public hash recovery}.
}
\tag{18}
\]

This is information-theoretic and classical.

It defeats arbitrary QPT security a fortiori.

---

## 7. The same failure reappears in affine witness linearization

Equation (10) has an even more explicit pseudowitness.

Set

\[
S=0.
\]

Choose one gadget block \(G_j\).  Let

\[
Z_j=-d_{t_1}
\]

for a public gadget preimage, with all other `Z_i=0`.

Then

\[
CS-\sum_iG_iZ_i
=
G_jd_{t_1}
=
t_1.
\tag{19}
\]

So the affine relaxation admits a short witness constructed entirely from public
data.

It cannot correspond to a valid product assignment because with \(S=0\),

\[
w_iS=0
\]

for every Boolean `w_i`, while \(Z_j\ne0\).

This is the projective-hash analogue of Run 108's fixed-matrix common-target attack.

The important addition in this run is that **both obvious EPHF adaptations fail**:

1. linearize the hidden products -> public gadget-only affine witness;
2. publish affine projection-key basis elements -> public true-hash recovery.

---

## 8. Why fixed-input WEFC avoids the attack

In the Campanelli construction the input `β` is already public at encryption time.

Therefore encryption publishes only

\[
hp=hM(\beta),
\]

not independent projections of the internal affine basis matrices from which
\(M(\beta)\) was assembled.

The evaluator cannot arbitrarily switch `β` after seeing the ciphertext.

That is precisely what changes when we require permissionless evaluation by an
unknown future witness.

So the gap is not "EPHF cannot handle functional commitments." It can.

The gap is:

\[
\boxed{
\text{EPHF for a fixed public FC input}
\quad\neq\quad
\text{EPHF for a hidden future FC input contained in the witness}.
}
\tag{20}
\]

---

## 9. Nearby lattice SPHF literature does not close this gap

Benhamouda–Blazy–Ducas–Quach,
*Hash Proof Systems over Lattices Revisited*
(ePrint 2017/997 / PKC 2018), constructs SPHFs for standard LWE-ciphertext languages
and even a word-independent lattice SPHF.

Their Appendix C gives a relaxed witness-encryption construction

\[
ct=(hp,H\oplus M)
\]

with witness decryption through `ProjHash`.

This is a useful precedent that projective hashing can produce a PQ-flavored release
layer for **restricted lattice ciphertext languages**.

But the paper itself stresses that its witness-encryption language is restricted, not
NP-complete, and has a correctness/soundness language gap.

More importantly for our present interface, these SPHFs do not provide a
knowledge-smooth **extractable** PHF for relation (9), where the unknown FC input is
part of the witness and multiplies another witness component.

Targeted literature search in this run found lattice SPHF/HPS constructions for
standard LWE ciphertext, PAKE, OT, and related linear languages.  It did not supply a
source-extractable hidden-input PHF for the bilinear FC opening relation.

Absence from this search is not an impossibility theorem; the missing primitive
remains an explicit research target.

---

## 10. Candidate primitive after this audit

The source side is now surprisingly concrete.

We have:

1. a statement-only transparent SIS commitment \(C_f\);
2. for every valid future witness, a short locally computed opening \(S_w\);
3. exact public verification

   \[
   M(w)S_w=t_1;
   \]

4. an ORIGINAL source verifier \(R(x,w)=1\).

What is missing can be stated as a **hidden-input source EPHF**.

A candidate must publish, before `w` is known, a compact projection object `hp*` such
that:

### Projective correctness

For every valid `(w,S_w)`,

\[
\mathsf{ProjHash}(hp^*,w,S_w)=H
\]

for the same hidden `H`.

### False-instance QPT hiding

When no valid source witness exists, `H` is hidden from arbitrary QPT adversaries
given the entire public output.

### True-instance source extraction

Any arbitrary QPT algorithm recovering `H` or the FINAL key early yields:

* an ORIGINAL witness `w`; or
* a break of an independently justified QPT-hard assumption.

### No universal basis-preimage leak

The public projection object must not expose separately projectable basis components
whose public short preimages span the target.

### Classical honest use

Setup, encapsulation, and honest witness evaluation remain classical PPT.

This is substantially narrower than assuming generic WE/iO/FE.

But it is still an unresolved cryptographic primitive, so it cannot be named into
existence as an assumption.

---

## 11. QPT/security ledger

### New algebraic attacks

The universal-projection attack and affine-linearization pseudowitness are classical,
deterministic, and information-theoretic.

They therefore refute QPT security of those natural adaptations immediately.

### Campanelli EPHF/WEFC

The published adversary model is PPT.

The concrete EPHF is discrete-log / bilinear-group based and its strongest composed
WEFC theorem is in the generic-group model.

Its knowledge extractor extracts a relation representation
\(\Lambda(x,w)\), not automatically the underlying semantic witness.

The semantic-security proof invokes classical Goldreich–Levin oracle decoding before
EPHF extraction.

No QPT theorem from that work is imported.

### de Castro–Peikert functional commitment

The public setup/opening algebra is unconditional.

Its published evaluation-binding theorem is classical/PPT and selective-input by
default; the generic adaptive upgrade loses the input-space factor.

A selective QPT reduction under exact QPT-hard normal-form SIS remains plausible but
unverified.

### Lattice SPHF

The 2018 lattice SPHF results cover restricted LWE ciphertext languages and do not
supply the hidden-input extractable relation required here.

---

## 12. Exact validation

`hidden_input_ephf_run109_check.py` is deterministic and standard-library-only.

Finalized executions are byte-identical.

It verifies:

1. public powers-of-two gadget decomposition for every target in
   \(\mathbb F_{257}\);
2. **4,096** fixed-input/projective-hash fixtures in which a valid witness obtains
   `H=h*t` while the natural universal basis projection lets a witness-free attacker
   obtain the identical hash through gadget decomposition;
3. **72** multi-bit hidden-input relations, each with both:
   * a consistent honest linearized witness, and
   * an inconsistent gadget-only affine pseudowitness;
4. explicit non-closure of the Boolean product-consistency relation
   \(Z=wS\) over several prime fields;
5. a general basis-preimage/projected-target identity over padded gadget bases;
6. the small norm of the public gadget pseudowitnesses.

The checker establishes finite algebra only. It does not prove SIS/LWE hardness or a
general impossibility theorem for nonlinear hidden-input EPHFs.

---

## 13. Research consequence and next handoff

This run rules out the most direct way to combine the two strongest recent positive
pieces:

\[
\text{de Castro SIS witness-local openings}
+
\text{Campanelli fixed-input EPHF}.
\]

The obstacle is now sharply local:

\[
\boxed{
\text{project on }M(w)\text{ without knowing }w,
\text{ but without publishing projectable gadget basis pieces}.
}
\]

A next candidate should focus on a **nonlinear witness-gated projection mechanism**,
not on another source compiler.

Useful directions:

1. Can a lattice hash-proof system project a *committed* matrix \(M(w)\) using a
   short FC opening without separately exposing the affine gadget basis?
2. Can the projection object itself be statistically/computationally bound to the
   de Castro commitment so that changing `w` without a valid opening is equivalent to
   a QPT-SIS break?
3. Can Run 102's one-copy QPT operator-Fourier extractor be applied directly to a
   noisy hidden-input projection channel, avoiding an affine EPHF linearization?
4. Can a succinct proof/argument of the nonlinear product constraints
   \(Z_i=w_iS\) be used **without** becoming an online verifier or assuming a
   base WE/iO-like release compiler?

Any candidate that publishes `hG_i`, publishes independent `Z_i` without nonlinear
consistency, or treats a fixed-public-input EPHF theorem as though the input were part
of the witness should be rejected immediately.

The practical generic-NP PQ WKEM remains open.
