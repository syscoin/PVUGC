# Run 115 — noisy short-preimage HPS boundary: noise converts the ambient-solution leak into a quantitative short-pseudowitness condition

## Status

Verified starting PR head:
`a0803edfa691f184e33ca92620471a81c17c611c`
on branch `research/pq-wkem-validation-20260918`.
PR #1 was open, draft, and unmerged. The latest ordinary PR comment was
`5843580758`, recording verified publication of Runs 104–108 and 110–111.

This run builds directly on the current local handoff from Runs 112–114. It does **not**
retry or republish those previously blocked local artifacts.

Run 114 proved a complete obstruction for the exact public linear projective hash

\[
  p=A^T a,\qquad H=a^T t,
\]

because *any* ambient solution `u` of `Au=t` publicly computes `H=p^T u`, even when
`u` is invalid for the intended structured source relation.

The present run asks the narrow constructive question:

> Can an LWE-style error term make dense ambient pseudowitnesses useless while short
> source-derived witnesses still recover one common key?

The answer is **yes at the algebra/functionality level**, with a sharp limitation:
noise replaces Run 114's fatal "any ambient pseudowitness" condition by a
**short/low-projected-error pseudowitness** condition. This is genuine progress, but
it is not yet a complete construction because the generic-NP short-preimage compiler
and the required QPT target-value hiding theorem remain unproved.

No production path is changed.

---

## 1. Noisy projective-hash candidate

Work over \(\mathbb Z_q\), with odd modulus `q`. Let

\[
A\in\mathbb Z_q^{n\times m},\qquad
s\in\mathbb Z_q^n,
\]

and sample a small error vector

\[
e\in\mathbb Z^m.
\]

Publish the noisy projection key

\[
\boxed{
  hp=A^Ts+e\pmod q.
}
\tag{1}
\]

For a public target

\[
t\in\mathbb Z_q^n,
\]

define the hidden target value

\[
\boxed{
  z=s^Tt\pmod q.
}
\tag{2}
\]

A witness candidate is an integer vector `u` satisfying

\[
Au=t\pmod q.
\tag{3}
\]

Then, identically,

\[
\boxed{
  hp^Tu=z+e^Tu\pmod q.
}
\tag{4}
\]

So a sufficiently short `u` gives a noisy approximation to one witness-independent
hidden value `z`.

Equation (4) is the key difference from Run 114. In the exact construction every
ambient solution gives `z` exactly; here an unrestricted ambient solution also carries
its projected error \(e^Tu\).

---

## 2. Exact one-bit KEM wrapper

The noisy hash can be converted into an exact common bit without publishing a helper
that itself needs a separate semantic interpretation.

Let

\[
c_0=0,\qquad c_1=\lfloor q/2\rfloor.
\]

Setup chooses a bit

\[
K\leftarrow\{0,1\}
\]

and publishes the offset

\[
\boxed{
  d=c_K-z\pmod q.
}
\tag{5}
\]

A witness `u` computes

\[
  y_u=hp^Tu+d
      =c_K+e^Tu\pmod q
\tag{6}
\]

and decodes to the nearest of `c_0,c_1`.

If

\[
  |e^Tu|_q<q/4-O(1),
\tag{7}
\]

then decoding returns exactly `K`.

This gives an all-witness correctness condition: every valid source witness may be a
different short preimage, yet every one decodes the same setup-selected key bit.

For a \(\kappa\)-bit raw key, run \(\kappa\) independent rows in parallel. This is
not claimed to be bandwidth-optimal; it establishes the primitive interface without a
circular KDF assumption.

---

## 3. Final-key recovery reveals the hidden target value exactly

The wrapper has a useful extraction property absent from an ordinary lossy KDF.

From a recovered bit `K` and public `d`, anyone computes

\[
\boxed{
  z=c_K-d\pmod q.
}
\tag{8}
\]

**exactly**.

Therefore

\[
\boxed{
  \text{exact FINAL-key recovery}
  \Longrightarrow
  \text{exact recovery of the hidden target value }z.
}
\tag{9}
\]

This is deterministic and straight-line. It does not rewind a QPT adversary, clone
quantum advice, program a random oracle, or require an extractor to invert a KDF.

For \(\kappa\) parallel rows, recovering the whole raw key reveals every corresponding
hidden target value \(z_j\).

This does **not** yet yield an ORIGINAL NP witness. The remaining security theorem
must say that recovering the targeted hidden value either yields an ORIGINAL source
witness or breaks an independently justified assumption secure against QPT attackers.

---

## 4. Exact masking hybrid

If `z` were uniform in \(\mathbb Z_q\), then for either bit `K`

\[
  d=c_K-z
\]

is itself exactly uniform in \(\mathbb Z_q\). Hence `d` is statistically independent
of `K`.

Consequently, a computational theorem of the form

\[
(A,t,A^Ts+e,s^Tt)
\approx_c
(A,t,A^Ts+e,U_q)
\tag{10}
\]

against arbitrary QPT distinguishers would immediately imply QPT hiding of the bit
wrapper through a straight-line hybrid.

**Run 115 does not assume that ordinary LWE already proves (10).** The target
\(t\) is statement-derived, and (10) exposes a noiseless linear function of the LWE
secret. Standard QPT-LWE hardness is not silently upgraded to this targeted leakage
statement.

This is now one of the two exact missing theorems.

---

## 5. Short-pseudowitness theorem

Noise does not magically enforce the source relation.

Let the decoder tolerate centered error through radius `rho`, meaning

\[
  |\delta|_q\le\rho
  \Longrightarrow
  \operatorname{Decode}(c_K+\delta)=K.
\tag{11}
\]

Then **every** ambient vector `u`, source-valid or not, satisfying

\[
  Au=t\pmod q,
  \qquad
  |e^Tu|_q\le\rho
\tag{12}
\]

recovers the final bit.

If the setup guarantees

\[
  \|e\|_\infty\le B_e,
\]

then

\[
  |e^Tu|
  \le
  \|e\|_\infty\|u\|_1
  \le
  B_e\|u\|_1.
\tag{13}
\]

Therefore any source-invalid ambient preimage with

\[
\boxed{
  \|u\|_1\le \rho/B_e
}
\tag{14}
\]

is a deterministic correctness-radius break.

### Theorem — noisy short-preimage boundary

For the construction (1)–(6), false-source security requires that finding **any**
source-invalid ambient solution with projected error inside the honest decoding radius
be hard. A public short pseudowitness inside that radius defeats the construction
classically and therefore defeats QPT security a fortiori.

This is the noisy analogue of Run 114's exact linear-HPS dichotomy.

The difference is important:

* Run 114: every ambient preimage is fatal;
* Run 115: only ambient preimages whose projected noise lands in the decoding region
  are immediately fatal.

Thus noise can potentially separate short source-derived witnesses from dense public
linear-algebra solutions.

---

## 6. Dense ambient preimages can become statistically useless — but this is not a security proof

The checker contains an explicit finite example with

\[
q=101,\qquad
A=(1,0,0,0).
\]

Both

\[
  u_{short}=(1,0,0,0)
\]

and arbitrarily dense vectors beginning in `1` solve the same ambient equation.

For independent error coordinates uniform in

\[
\{-2,-1,0,1,2\},
\]

the short vector has projected error in the tested decoding window with probability
`1`. In contrast,

\[
  u=(1,7,19,31)
\]

has full support over all 101 residues; the tested decode-window probability is
`0.1232`, and its exact total-variation distance from uniform is about `0.0841`.
For

\[
  u=(1,5,25,24),
\]

the TV distance drops to about `0.02468`.

These examples demonstrate the *mechanism* that exact HPS lacks: dense ambient
solutions can amplify/mix the error enough to cease being useful projective witnesses.

They do **not** prove that every long ambient solution is harmless. A long vector can
still have small \(e^Tu\) through arithmetic structure or cancellation. Full security
requires an anti-concentration or computational theorem over the complete ambient
solution distribution.

---

## 7. Why Run 110 does not kill this direction automatically

Run 110 proved that the specific powers-of-two gadget projection

\[
(1,2,4,\ldots)
\]

is publicly decodable throughout the ordinary small-noise regime needed for honest
correctness. That proof used the complete gadget's deterministic separation property.

The present construction deliberately removes that structure. It does **not** publish
an entire powers-of-two encoding of the hidden target secret. It publishes ordinary
LWE-style samples

\[
A^Ts+e.
\]

Accordingly, the Run-110 decoder does not directly apply.

But the old functional-commitment compiler from Runs 108–109 still cannot simply be
plugged in: its affine relaxation admits a **short gadget pseudowitness**. Such a
pseudowitness lies precisely in the dangerous regime of (12)–(14), so adding small
noise to that existing relaxation does not repair it.

The source compiler must genuinely ensure a quantitative short-preimage gap.

---

## 8. What generic NP would now need

A complete compiler would map an NP statement `x` to

\[
(A_x,t_x)
\]

and every source witness `w` to a short vector

\[
  u_w\leftarrow\operatorname{Encode}(x,w)
\]

such that

\[
  A_xu_w=t_x\pmod q,
  \qquad
  \|u_w\|_1\le B_{hon}.
\tag{15}
\]

It then needs **short-preimage source soundness**:

\[
\boxed{
  A_xu=t_x,\quad \|u\|_1\le B_{bad}
  \Longrightarrow
  \text{ORIGINAL source witness}
  \text{ or QPT-hardness break},
}
\tag{16}
\]

for a threshold satisfying

\[
  B_{hon}<B_{bad}
  \lesssim
  \rho/B_e.
\tag{17}
\]

This is more concrete than the previous generic phrase "nonlinear source-validity
predicate." The release layer needs a **quantitative norm gap** between all honest
source encodings and every source-invalid ambient solution.

### Relation to Hair–Sahai

Hair–Sahai's supplied low-rank representation extractor is structurally relevant, but
rank is not an \(\ell_1\)-norm gap. A low-rank matrix may have large entries, and a
high-rank matrix may have very small entries. Their rank-gap source compiler therefore
does not directly instantiate (16).

Their later source-preserving \(\ell_p\)-SVP hardness work for \(p>2\) is closer in
spirit because it supplies a geometric gap, but a shortest nonzero lattice vector is a
homogeneous relation. Run 115 needs an **affine common target** with all source
witnesses mapping to short preimages of the same `t_x`. Turning the SVP gap into that
affine all-witness interface remains unproved.

---

## 9. Relation to linearly verifiable SNARKs and lattice SNARKs

Garg–Hajiabadi–Kolonelos–Kothapalli–Policharla's CRYPTO 2025 framework organizes
special-purpose witness encryption around gadgets induced by **linearly verifiable
arguments**, and composes those gadgets into larger relations.

That is conceptually aligned with (15): first compile an NP witness into a compact
proof representation, then projectively hash that representation.

But a *plain public field-linear* verification equation cannot suffice here: Run 114
shows that public linear algebra constructs unrestricted ambient solutions. The missing
PQ object must make validity depend on a short/noisy representation whose unrestricted
solutions do not fall inside the honest decoding radius.

There are lattice designated-verifier zkSNARKs following the linear-PCP + linear-only
vector-encryption blueprint (Ishai–Su–Wu, CCS 2021). This is evidence that compact
post-quantum proof representations and lattice linear-only encodings can coexist. It
is **not** an instantiation of (16), and this run does not import its proof system as a
public/offline WPRF or claim a QPT source extractor from it.

---

## 10. Why recent leakage-robust LWE results are relevant but insufficient

Lai–Swarnakar–Woo's 2025 Leaky-LWE result proves hardness of LWE even with certain
semi-adaptively chosen **noisy low-norm linear leakages** of the secret and error,
with polynomial parameter losses.

That is directionally encouraging because the Run-115 public/evaluator view also
contains low-norm linear combinations of an LWE secret/error pair.

However, our desired theorem (10) exposes a **noiseless statement-derived target
value** \(s^Tt\) in the security game, and the target must also admit source-witness
projective evaluation. The Leaky-LWE theorem is therefore not silently identified
with (10).

Likewise, older LWE robustness results show security with substantial secret leakage
or auxiliary input under entropy conditions, but they do not by citation alone give
the exact targeted-value pseudorandomness and source-extraction statement required
here.

Quantum classification remains explicit:

* honest algorithms in Run 115 are classical polynomial-time;
* equations (4), (8), and the short-pseudowitness attack are unconditional and
  classical;
* classical attacks therefore refute QPT security whenever the short-pseudowitness
  condition occurs;
* QPT hiding of `z` under the complete statement-derived public distribution is
  **UNPROVED**;
* QPT source extraction from arbitrary short-preimage recovery is **UNPROVED**.

---

## 11. Exact validation

`noisy_short_preimage_hps_run115_check.py` is deterministic and standard-library
only. Three finalized executions are byte-identical.

It validates:

1. the exact identity
   \(hp^Tu=s^Tt+e^Tu\) on exhaustive finite systems;
2. the one-bit offset wrapper and all-witness nearest-center correctness;
3. exact inversion `K,d -> z` for the final-key-to-hidden-value arrow;
4. exhaustive short-pseudowitness decoding whenever projected error is inside the
   correctness radius;
5. the sufficient \(\|e\|_\infty\|u\|_1\) attack bound;
6. exact masking independence when `z` is uniform;
7. parallel multi-bit wrapper consistency;
8. finite dense-solution anti-concentration examples, including exact support and TV
   distance from uniform.

The finalized checker records **1,312,354 assertions**.

These are algebra/functionality checks. Passing them does not establish LWE hardness,
anti-concentration for all ambient solutions, a generic-NP compiler, or QPT security.

---

## 12. Exact dependency/QPT ledger after Run 115

### Established unconditionally

* Noisy projective identity (4).
* Exact all-witness bit wrapper under the projected-error radius.
* Exact final-key recovery -> exact hidden target-value recovery.
* Any source-invalid ambient preimage inside the same radius breaks the wrapper.
* Uniform hidden target value gives perfect one-time-pad masking of `K` through `d`.

### Useful external components, not endpoints

* Lattice SPHF/HPS: demonstrates PQ-flavored projective hashing for restricted LWE
  languages, not generic NP.
* Linearly verifiable-SNARK WE framework: useful source/gadget architecture, but its
  concrete assumptions and public linear representations do not automatically become
  a lattice short-preimage compiler.
* Lattice designated-verifier zkSNARKs: show compact lattice proof representations,
  not our public/offline source-extractable WPRF.
* Leaky/robust LWE: relevant to noisy linear leakage, but not yet theorem (10).

### Still missing

1. a generic-NP compiler satisfying the affine short-preimage source-soundness gap
   (15)–(17);
2. an explicit quantum-valid reduction establishing targeted hidden-value
   pseudorandomness (10) from independently justified QPT-hard assumptions;
3. arbitrary-QPT recovery-to-ORIGINAL-witness extraction or a clean reduction to such
   a QPT-hard assumption for **true** statements;
4. malicious-secure ceremony/abort and full auxiliary-output composition;
5. concrete parameters proving honest error radius, false/source-invalid gap, and
   practical resource bounds simultaneously.

The stopping condition is not met.

---

## 13. Next handoff

The next pass should not return to exact public-linear HPS or the de Castro affine
gadget relaxation; those are already ruled out.

The highest-value target is now:

\[
\boxed{
\text{generic-NP affine short-preimage compiler with a quantitative norm gap}
}
\]

paired with the noisy projective wrapper above.

Two concrete routes deserve priority:

1. audit whether a **lattice linear-PCP / designated-verifier SNARK** can expose a
   statement-only affine target whose honest proof encoding is short while every
   source-invalid affine preimage below a public norm threshold yields knowledge or an
   SIS/LWE break; and
2. test whether the Hair–Sahai source-preserving geometric gaps can be affinely
   anchored without destroying all-witness common-target correctness.

For either route, immediately test the full public matrix, proving/verification keys,
auxiliary encodings, and any decoder for a short public pseudowitness. A construction
that merely says "the honest proof is short" without proving *all invalid ambient
preimages are long or hard to find* does not solve the Run-115 requirement.
