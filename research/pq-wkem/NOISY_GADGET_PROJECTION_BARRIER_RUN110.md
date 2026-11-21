# Run 110 — noisy gadget projection barrier: correctness-compatible powers-of-two projections reveal the hidden hash key

## Status

Verified starting PR head: `568446e21cedb83c07c20227cd9c443f51fabb82` on branch
`research/pq-wkem-validation-20260918`. PR #1 was open, draft, and unmerged.
The latest substantive PR comment is `5842442762`, recording verified publication of
Run 109.

This run continues the exact surviving interface from Runs 108–109. Those runs showed
that:

* de Castro–Peikert gives a polynomial-size witness-local SIS opening relation;
* a noiseless universal projective key exposing the powers-of-two gadget basis leaks
  the target hash immediately through public gadget preimages;
* a fixed-matrix affine linearization also admits public gadget-only pseudowitnesses.

Run 108 included only a finite warning that even a **noisy** dual-Regev-style gadget
projection can expose the secret coordinate. Run 110 upgrades that warning to a
parameter-independent theorem for the full powers-of-two gadget.

> The powers-of-two gadget is an error-correcting encoding of each hidden hash-key
> coordinate with centered `l_infinity` distance at least `q/3`. Therefore any public
> projection `h G + e` with coordinate error below `q/6` uniquely determines `h`.

For a natural noisy hidden-input EPHF, the conservative error bound required for
worst-case correct witness evaluation is already at most `q/8` as soon as at least
one witness-selected gadget block is present. Thus adding ordinary small LWE-style
noise does not repair the universal-projection leak; it gives a classical secret-key
recovery attack.

No production path is changed.

---

## 1. Exact source gadget

de Castro–Peikert use

\[
g=(1,2,4,\ldots,2^{\ell-1})^T,
\qquad
\ell=\lceil\log_2 q\rceil,
\tag{1}
\]

and the matrix gadget

\[
G=I_n\otimes g^T.
\tag{2}
\]

Their public decomposition `g^{-1}` returns the binary representation of a target and
satisfies

\[
g^T g^{-1}(u)=u\pmod q.
\tag{3}
\]

This is the same robust gadget that appears in the functional-commitment verification
relation used in Runs 108–109.

The paper also notes that the **decomposition algorithm** can be randomized for
function hiding. That does not change the public matrix `G` in (2), and therefore
will not affect the dual noisy-projection theorem below.

---

## 2. Powers-of-two gadget distance theorem

For `a in Z_q`, write its centered residue norm as

\[
|a|_q=\min_{z\in\mathbb Z}|a-zq|.
\tag{4}
\]

For nonzero `delta in Z_q`, define the gadget-code distance

\[
D_g(\delta)
=
\max_{0\le j<\ell}|2^j\delta|_q.
\tag{5}
\]

### Theorem 1

For every `q>=2` and every nonzero `delta in Z_q`,

\[
\boxed{D_g(\delta)\ge q/3.}
\tag{6}
\]

### Proof

Let

\[
a=|\delta|_q\in[1,q/2].
\]

Choose the smallest `j>=0` such that

\[
2^j a\ge q/3.
\]

Such a `j` exists with `j<=ell-1`, because

\[
2^{\ell-1}\ge q/2
\]

and `a>=1`.

If `j=0`, then

\[
q/3\le a\le q/2.
\]

If `j>0`, minimality gives

\[
2^{j-1}a<q/3,
\]

hence

\[
q/3\le 2^j a<2q/3.
\]

In either case, the centered representative of `2^j delta mod q` has magnitude at
least `q/3`. This proves (6).

So the map

\[
h\longmapsto(h,2h,4h,\ldots,2^{\ell-1}h)\pmod q
\tag{7}
\]

has centered `l_infinity` minimum distance at least `q/3`.

---

## 3. Deterministic noisy secret recovery

Suppose a public projection exposes one gadget block

\[
y_j=2^j h+e_j\pmod q,
\qquad 0\le j<\ell,
\tag{8}
\]

with

\[
|e_j|\le B.
\tag{9}
\]

### Theorem 2

If

\[
\boxed{B<q/6,}
\tag{10}
\]

then `h` is the unique field element consistent with all observations and the error
bound.

### Proof

Assume two candidates `h,h'` are both consistent. Put

\[
\delta=h-h'.
\]

For every `j`, the difference between their two allowed errors gives

\[
|2^j\delta|_q\le 2B<q/3.
\tag{11}
\]

Theorem 1 says this is impossible for nonzero `delta`. Hence `h=h'`.

### Recovery algorithm

When `q=poly(lambda)`, enumerate the `q` possible values of `h` and retain the unique
candidate satisfying (9) in every coordinate. Runtime is

\[
O(q\log q),
\]

hence classical polynomial time in the standard polynomial-modulus lattice regime.

For

\[
G=I_n\otimes g^T,
\]

the attack applies independently to every hash-key coordinate. Therefore

\[
\boxed{
hG+e\text{ with }\|e\|_\infty<q/6
\Longrightarrow
\text{public recovery of the entire }h.
}
\tag{12}
\]

Once `h` is known, the attacker computes the hidden release hash

\[
H=ht_1
\tag{13}
\]

directly.

No SIS or LWE problem is solved.

---

## 4. Noisy hidden-input universal projection

The natural attempt left open by Run 109 is to hide the noiseless basis projections
with LWE-style errors.

Publish

\[
p_C=hC+e_C,
\tag{14}
\]

and for every witness-input gadget basis block,

\[
p_i=hG_i+e_i.
\tag{15}
\]

A future witness `w` forms

\[
p_w=p_C-\sum_i w_i p_i
=
hM(w)+e_w,
\tag{16}
\]

where

\[
e_w=e_C-\sum_i w_i e_i.
\tag{17}
\]

Using its short FC opening `S_w`, it computes

\[
p_w S_w
=
ht_1+e_wS_w.
\tag{18}
\]

This has exactly the projective correctness shape we wanted, now only approximately.

But every published `p_i` contains a complete noisy powers-of-two gadget encoding of
the same hidden hash key `h`.

If those errors are narrow enough for Theorem 2, `h` is recovered before the
functional-commitment witness is used.

---

## 5. Correctness-compatible bounded noise lies inside the attack radius

Assume a worst-case per-coordinate error bound

\[
\|e_C\|_\infty,\ \|e_i\|_\infty\le B.
\tag{19}
\]

Let a valid witness select `r>=1` gadget basis blocks, and suppose its opening obeys

\[
\|S_w\|_1\le\kappa,
\qquad\kappa\ge1.
\tag{20}
\]

Then

\[
\|e_w\|_\infty\le(r+1)B,
\]

so

\[
\|e_wS_w\|_\infty
\le
(r+1)\kappa B.
\tag{21}
\]

For a standard nearest-half / bit-decoding radius at most `q/4`, a sufficient
worst-case correctness condition is

\[
(r+1)\kappa B<q/4.
\tag{22}
\]

Because `r>=1` and `kappa>=1`,

\[
(r+1)\kappa\ge2.
\]

Therefore (22) implies

\[
\boxed{B<q/8<q/6.}
\tag{23}
\]

Combining with Theorem 2:

\[
\boxed{
\text{ordinary bounded noise sufficient for guaranteed witness correctness}
\Longrightarrow
\text{classical recovery of }h.
}
\tag{24}
\]

This is a direct correctness/security incompatibility for the natural noisy universal
projection.

---

## 6. Probabilistic noise version

For an unbounded distribution such as a discrete Gaussian, Theorem 2 applies on the
event

\[
\|e_i\|_\infty<B<q/6.
\]

If the public projection errors satisfy this event with probability at least

\[
1-\varepsilon,
\]

then the classical recovery algorithm succeeds with probability at least

\[
1-\varepsilon.
\tag{25}
\]

Thus choosing the usual narrow-noise regime where all gadget-projection coordinates
are small with overwhelming probability gives overwhelming-probability key recovery.

This does **not** prove that every correlated or deliberately wide-noise construction
fails. A candidate using large or specially correlated projection noise must prove
both:

1. why the gadget secret is no longer recoverable; and
2. why every valid short opening still cancels/decodes that noise.

That is a materially different construction, not ordinary independent LWE error.

---

## 7. Public short-link randomization also inherits the noisy attack

A natural repair is to replace `G` by a public randomized basis `B` and publish a
short transformation `R` with

\[
BR=G.
\tag{26}
\]

Run 108 already showed the noiseless target-preimage attack:

\[
B(Rg^{-1}(t))=t.
\]

With noisy projection

\[
p_B=hB+e,
\tag{27}
\]

an attacker computes

\[
p_BR=hG+eR.
\tag{28}
\]

If `R` is a signed permutation, or more generally keeps `eR` within the `q/6`
gadget-decoding radius, Theorem 2 recovers `h` exactly.

So merely hiding the visible powers-of-two ordering behind a public short,
well-conditioned change of basis does not help.

The checker validates this exactly for public permutation links.

A large-condition-number `R` can destroy the attack by amplifying noise, but it also
amplifies the corresponding honest opening/noise path. Whether some asymmetric
construction can exploit that is open; it is not supplied by the existing FC
interface.

---

## 8. Relation to the de Castro functional commitment

This barrier does **not** attack the de Castro–Peikert commitment itself.

Their scheme publishes the gadget as part of a transparent SIS verification relation;
it does not publish a noisy hidden hash-key projection `hG+e` intended to conceal
`h`.

The attack applies only when we try to turn those public gadget basis matrices into a
witness-independent noisy projective-hash / dual-Regev release layer.

The distinction is important:

\[
\boxed{
\text{transparent FC opening remains useful}
\quad\text{but}\quad
\text{ordinary noisy projection of its gadget basis is not a secure release layer}.
}
\tag{29}
\]

---

## 9. QPT/security classification

### Honest algorithm model

The candidate noisy projection and honest FC opening evaluation are classical.

### Attack adversary model

The attack is classical deterministic bounded-distance decoding, plus enumeration of
`q` candidates per coordinate.

For `q=poly(lambda)`, it is PPT and therefore also available to QPT adversaries.

### Hardness distribution

No hardness assumption is used by the attack.

It does not challenge SIS or LWE on random matrices; it exploits the deterministic
powers-of-two gadget structure.

### Reduction model

No rewinding, QROM, extraction oracle, superposition query, or quantum auxiliary
state occurs.

### Exact conclusion

The natural hidden-input release

\[
(hC+e_C,\{hG_i+e_i\}_i)
\]

is insecure whenever the gadget errors lie inside the `q/6` decoding radius with
nonnegligible probability; under the ordinary worst-case correctness bound of
Section 5, they necessarily lie in that radius.

### Not proved

This is not an impossibility theorem for:

* alternative gadgets with different dual distance;
* specially correlated noise canceled only by a valid FC opening;
* nonlinear witness-gated projections that never expose a full noisy gadget basis;
* computationally hidden basis transforms without a public short inverse link.

Those remain possible research directions.

---

## 10. Exact validation

`noisy_gadget_projection_run110_check.py` is deterministic and standard-library-only.

It verifies:

1. for every modulus `q=2,...,257`, the exact full-gadget centered
   `l_infinity` distance is at least `q/3`;
2. exhaustive unique decoding at `q=17`, `B=2` over **all 53,125** secret/error
   observations;
3. near-threshold decoding at `q=257`, `B=42<q/6` across every secret and a family of
   extremal signed error patterns;
4. the worst-case correctness/attack inequality for multiple realistic moduli,
   witness Hamming weights, and opening norms;
5. public permutation/randomization links `BR=G`, confirming that a short
   well-conditioned link preserves the decoding attack;
6. the direct success-probability transfer from a bounded-noise tail event.

These tests validate finite instances of the proved theorem. They are not evidence
for or against generic SIS/LWE hardness.

---

## 11. Updated research boundary

Runs 108–110 now rule out three increasingly permissive versions of the same direct
release idea:

1. **exact fixed-matrix linearization** — public gadget preimage;
2. **exact universal projective basis** — public target-hash computation;
3. **ordinary small-noise universal projective basis** — public recovery of the
   hidden hash key itself.

The surviving primitive must avoid publishing even a noisy complete gadget encoding
of the release/hash secret.

That points toward a stricter form of witness-gated projection:

* projection components should remain computationally hidden or secret-shared until
  a valid FC opening is supplied;
* the opening must cancel/reconstruct the release value without exposing a universal
  chosen-input completion oracle;
* unauthorized final-key recovery must still feed an ORIGINAL-witness extractor or a
  QPT-hardness reduction.

A particularly concrete next question is whether a **correlated-noise projection**
can be arranged so that `S_w` cancels the noise exactly only when

\[
(C-\operatorname{Rep}(w)\otimes g^T)S_w=t_1,
\]

while the public marginal of each gadget block is statistically or QPT-computationally
independent of `h`. Any such proposal must also be checked against Run 104's public
searchable-support barrier and Run 106/107's public-completion barrier.

The practical generic-NP PQ WKEM remains open.
