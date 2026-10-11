# Run 106 — standard-LWE compact merge exists, but the OTE/adaptive-lattice machinery is input-specific and not a public offline witness release

## Status

Verified starting PR head:
`5a612472b4f5e16120a6a07097ef25788415cb94`
on branch `research/pq-wkem-validation-20260918`.
PR #1 was open, draft, and unmerged.

The latest substantive PR comment is `5839832728`, recording verified interactive
publication of Runs 100–103. Runs 104 and 105 remain local-only after their own
safety-blocked publication attempts; this run does not retry, rename, split, encode,
or reroute either denied payload.

This run audits Abram–Malavolta–Roy,
*Succinct Oblivious Tensor Evaluation and Applications: Adaptively-Secure Laconic
Function Evaluation and Trapdoor Hashing for All Circuits*,
arXiv:2508.09673v2 (19 April 2026).

The first result is a correction:

> Run 105 was too broad in saying that a compact branch/merge gadget from standard
> LWE was still unproved.

For bounded-depth RMS programs, adaptive lattice encodings already provide compact
correlated-key addition/multiplication and compressed encodings from standard LWE plus
NI-OTE. The missing property for this project is different:

> the published machinery is input-specific and two-party. It does not give a
> statement-only public object from which an arbitrary future witness can
> permissionlessly recover the same secret key offline.

Two exact barriers are established below:

1. direct affine universalization of adaptive lattice encodings exposes their
   authentication key `r`;
2. turning OTE's missing encoder share into a public evaluator for arbitrary future
   inputs defeats encoder-input hiding: anyone can choose a basis input and recover
   the encoder's vector.

Thus the bounded-depth merge technology is useful downstream machinery, not the
missing base witness-release compiler.

No production path is changed.

## 1. What the OTE paper actually gives

NI-OTE has algorithms

\[
(\mathsf{Setup},\mathsf{Hash},\mathsf{Enc},
 \mathsf{HashEval},\mathsf{EncEval}).
\]

For inputs \(x,y\),

\[
(d,\psi)\leftarrow\mathsf{Hash}(\mathsf{pk},x),
\]

\[
(E,\phi)\leftarrow\mathsf{Enc}(\mathsf{pk},y),
\]

and the parties compute shares

\[
v=\mathsf{HashEval}(\mathsf{pk},E,\psi),
\]

\[
w=\mathsf{EncEval}(\mathsf{pk},d,\phi),
\]

with

\[
v+w\approx x\otimes y.
\tag{1}
\]

The crucial syntax point is that `phi` is encoder private information. For bilinear
encoder evaluation,

\[
w=P(d\otimes\phi\otimes g_q).
\tag{2}
\]

In the half-succinct construction, \(\phi=s\) is literally the sampled LWE secret.

The fully succinct recursion compresses the public encoder message, but still outputs
a final private state \(\phi_r\). Succinctness does not turn `EncEval` into a public
evaluation algorithm.

The paper's LWE and privacy definitions quantify over PPT adversaries, not QPT
adversaries. The visible encoder-privacy and compressed-encoding hybrids are
straight-line reductions, which is promising for a separate QPT re-proof under exact
QPT-LWE assumptions, but such a re-proof is not silently imported here.

## 2. Correction to Run 105: bounded-depth compact merge is already present

Adaptive lattice encodings use

\[
G=I_k\otimes g_q^T
\]

and encode

\[
\mathsf{LEnc}_A(x;s,r,e)
=
s^TA+x\,r^TG+e^T.
\tag{3}
\]

The paper gives exact homomorphic identities for addition, scalar multiplication, and
multiplication of correlated-key encodings, cancelling the shared middle key.

For vector input \(\hat x\), level encodings are

\[
c_i^T=\mathsf{LEnc}_A(\hat x;s_i,s_{i+1},e_i).
\tag{4}
\]

Lemma 4.2 evaluates a \(T\)-bounded depth-\(d\) RMS program into a level-\((0,d)\)
encoding, with noise bounded by

\[
\beta O(T(k\log q)^d).
\tag{5}
\]

Therefore the statement "standard LWE has no compact bounded-depth merge gadget" is
too broad. The correct missing boundary is public offline input independence.

## 3. Input-specific compressed encodings

The compression algorithm is explicitly

\[
\mathsf{Compress}(\mathsf{ck},A,x,s_0,s_1,r).
\tag{6}
\]

It first hashes the actual input \(x\). Expansion later receives that same \(x\) and
recomputes its hash:

\[
\mathsf{Expand}(\mathsf{ck},A,h,E,x).
\tag{7}
\]

The paper also explicitly notes in its input-succinct reverse-TDH construction that
successful encoding requires knowing \(x\).

Our setup knows the NP statement but not which valid witness will later be supplied.
Every valid witness must recover the same key. Therefore an input-specific compressed
encoding cannot simply be created during setup for the unknown future witness.

## 4. Direct affine universalization leaks the authentication key

For vector input,

\[
\mathsf{LEnc}_A(x;s,r,e)
=
s^TA+r^T(x^T\otimes G)+e^T.
\tag{8}
\]

The exact coefficient multiplying each input coordinate \(x_j\) is

\[
\boxed{B=r^TG.}
\tag{9}
\]

The gadget vector starts with 1:

\[
g_q^T=(1,2,4,\ldots).
\]

Since

\[
G=I_k\otimes g_q^T,
\]

the first coordinate of gadget block \(i\) in \(r^TG\) is exactly \(r_i\). Hence

\[
\boxed{r^TG\mapsto r}
\tag{10}
\]

by a trivial public projection.

Thus publishing the exact affine coefficient table that would let a later witness
instantiate (8) at arbitrary \(x\) exposes `r` information-theoretically.

In the RMS chain those authentication keys are the correlated level keys
\(s_{i+1}\). The direct "publish all input coefficients now" transformation therefore
publishes chain keys that the privacy proof treats as hidden.

This is an exact failure of this natural universalization; it is not an impossibility
theorem for every conceivable witness-independent compiler.

## 5. Publishing OTE's missing share state reveals the encoder input

Could OTE hide those coefficients?

The public encoding `E` alone is protected by encoder privacy. The missing additive
share still requires private `phi`:

\[
w=\mathsf{EncEval}(\mathsf{pk},d,\phi).
\]

If `phi` is made public, anyone can choose an arbitrary input \(x\), run public
`Hash` to obtain `(d,psi)`, compute both

\[
v=\mathsf{HashEval}(\mathsf{pk},E,\psi)
\]

and

\[
w=\mathsf{EncEval}(\mathsf{pk},d,\phi),
\]

and reconstruct

\[
x\otimes y.
\tag{11}
\]

Choosing a basis vector \(x=e_j\) reveals \(y\) in the corresponding block. Hence

\[
\boxed{(E,\phi)\text{ public}\Longrightarrow\text{public recovery of }y.}
\tag{12}
\]

This is functionality-level and does not break LWE.

The half-succinct construction is especially concrete: \(\phi=s\), the encoder's LWE
secret. The checker validates the exact zero-noise construction on a small field.

## 6. Stronger public-completion barrier

The problem is not specific to publishing raw `phi`.

Suppose a public algorithm \(W(d)\) produced the missing encoder share for every
digest generated by a future chosen \(x\):

\[
W(d)=\mathsf{EncEval}(\mathsf{pk},d,\phi).
\]

Then anyone can choose \(x\), compute `(d,psi)`, compute the public hasher share,
compute \(W(d)\), and recover \(x\otimes y\). A basis query again reveals \(y\).

Therefore

\[
\boxed{
\text{public completion of OTE's missing share for arbitrary future }x
\Longrightarrow
\text{public recovery of }y.
}
\tag{13}
\]

This is exactly incompatible with using OTE directly as a public offline release when
`y` carries the secret/key-bearing state.

Precomputing the missing share for every possible generic-NP witness is exponential
unless another compiler compresses this function. Assuming such a compiler merely
relocates the base witness-release problem.

## 7. Fully succinct OTE does not remove the private state

The recursive construction computes

\[
(E_i,\phi_{i+1})
\]

at each layer and returns

\[
E=\{E_i\},\qquad\phi=\phi_r.
\tag{14}
\]

Thus "fully succinct" does not mean "fully publicly evaluable."

## 8. Reverse TDH also remains input/key-holder interactive

Reverse trapdoor hashing has

\[
(d,\rho)\leftarrow\mathsf{Hash}(\mathsf{hk},f),
\]

\[
(\mathsf{ek},\mathsf{td})\leftarrow\mathsf{Gen}(\mathsf{hk},x),
\]

\[
e\leftarrow\mathsf{Enc}(\mathsf{hk},\mathsf{ek},f,\rho),
\]

\[
e'\leftarrow\mathsf{Dec}(\mathsf{hk},\mathsf{td},d),
\]

with \(e\oplus e'=f(x)\).

A future witness holder can run `Gen(hk,x)`, but the setup-side `Enc` requires the
resulting `ek` and the hasher-private state `rho`. With nobody online after setup,
setup cannot later receive the witness-generated `ek`.

Publishing `rho` or a universal replacement for `Enc` is outside the paper's theorem
and again attempts to publicly complete a two-party functionality.

Reverse TDH is therefore downstream machinery, not a direct permissionless base
witness release.

## 9. QPT classification

The paper explicitly defines LWE against PPT adversaries.

Its half-succinct encoder-privacy proof has direct hybrids to LWE. Its
compressed-encoding simulatability theorem similarly uses a direct LWE hybrid and an
OTE encoder-privacy hybrid. No classical rewinding is visible in those local proofs.

Accordingly:

* a QPT re-proof is **plausible** if the exact underlying LWE/NLWE distributions are
  QPT-hard and all prerequisite reductions are quantum-valid;
* the published theorem itself is **not QPT security**;
* the NLWE-from-LWE step for binary public matrices also needs an explicit quantum
  reduction audit before final composition.

## 10. Tree Encodings IV does not close the base release

Abram--Malavolta--Roy,
*Tree Encodings IV: Depth-Unbounded Attribute-Based Encryption and Delay Encryption*,
ePrint 2026/2094, was listed as updated 22 September 2026.

Its current public abstract advertises ciphertext-policy ABE for depth-unbounded,
bounded-space predicates from **Decomposed LWE**, contrasting this with earlier
evasive-LWE or discrete-log routes.

A separate 2026 preprint,
*Decomposed LWE is Equivalent to Succinct LWE*,
states equivalence under appropriate parameter settings.

This still does not give the present primitive:

1. Decomposed/Succinct LWE is not thereby reduced to ordinary LWE.
2. CP-ABE is authority-keyed. An arbitrary NP witness is not by itself an ABE secret
   key. Turning every arbitrary valid witness into a permissionless decapsulation key
   remains the missing release problem.

The full Tree Encodings IV primary PDF was not retrievable through the available
primary fetch path in this run, so no theorem-level use beyond the current abstract
is made.

## 11. Exact validation

`adaptive_lattice_offline_barrier_run106_check.py` is deterministic and
standard-library-only. Finalized executions have byte-identical JSON output.

It validates:

1. \(r^TG\) recovers `r` exactly over several prime fields and gadget dimensions;
2. exact affine coefficient tables reconstruct all later inputs and expose the
   authentication key;
3. the actual half-succinct OTE zero-noise algebra over `F_5` for all small `A,S,y`;
4. the functionality-level public-completion implication;
5. the adaptive lattice multiplication identity, including noisy terms, on a finite
   toy;
6. persistence of the final private state through the succinct recursion.

The checker validates algebra and syntax only, not LWE.

## 12. Updated dependency/QPT ledger

### Established unconditionally

* bounded-depth adaptive-lattice merge identities;
* direct affine-universalization authentication-key leakage;
* OTE public-completion implies encoder-input recovery;
* compressed LEnc and reverse TDH are input-specific/two-party.

### Conditional computational component

The OTE/compressed-encoding privacy proofs have a plausible straight-line QPT route
conditional on exact QPT-hard LWE/NLWE distributions and quantum-valid prerequisite
reductions. This remains `UNVERIFIED`.

### Still absent

* statement-only setup for unknown future witnesses;
* public offline permissionless evaluation with no retained private share;
* every-valid-witness same-key recovery in a complete scheme;
* arbitrary-QPT FINAL-key recovery -> ORIGINAL witness;
* malicious-secure erased ceremony for any additional setup secret.

## 13. Next handoff

Do not spend the next pass re-inventing bounded-depth merge: it already exists.

The missing primitive is now

\[
\boxed{
\text{witness-independent setup}
+
\text{later public witness binding}
+
\text{no online private evaluator}
+
\text{no public-completion leak}.
}
\]

A useful next candidate must let a witness locally create or unlock only the
source-valid missing share, while making a universal public evaluator impossible.

Immediate audit questions:

1. Can a statement-derived public digest plus a witness generate the missing OTE
   share **only when the ORIGINAL source relation verifies**, without exposing a
   chosen-input public completion oracle?
2. Can the Run-102 one-copy QPT extractor turn any unauthorized completion ability
   into an ORIGINAL witness?
3. Is there a standard-LWE/SIS primitive with this witness-gated public-evaluation
   syntax, rather than authority-issued ABE keys or two-party shares?

Any candidate that merely publishes `phi`, publishes affine LEnc coefficients, or
precomputes a universal encoder-share evaluator should be rejected immediately.

The practical generic-NP PQ WKEM remains open.
