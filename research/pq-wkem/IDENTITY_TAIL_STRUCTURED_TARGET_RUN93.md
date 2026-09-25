# Run 93 — identity-tail source transfer and the exact structured-target LWE bottleneck

## Status

Starting verified PR head: `f127e33fb43ed2898bcc0a67ddbc944c5f514ca9` on branch
`research/pq-wkem-validation-20260918`. The PR was read as open, draft, and unmerged.

This run continues the Run-92 short-kernel handoff and the Run-91 correlated-trapdoor audit.
It does **not** complete the requested post-quantum witness KEM.

The new positive result is a simple trapdoor-preimage layout that makes the map from a
supplied decoder/zeroizer back to the source relation *lossless and norm-monotone*.
The equally important negative result is an exact public projection showing that this
layout does not solve false-statement hiding: the public capsule collapses to an LWE-like
sample over the statement-derived target matrix itself.

A second literature result narrows the gap. Waters–Wee–Wu (TCC 2022 / ePrint 2022/1194)
prove a generalized related-trapdoor LWE theorem from plain LWE for a carefully
transverse family of preimage queries. Their theorem is genuinely relevant, but its
full-rank/transversality gate excludes the same-direction preimage access needed by the
simple source decoder below. Therefore it cannot be cited as a plain-LWE proof of this
candidate.

Production code is unchanged.

---

## 1. Source interface inherited from Runs 42 and 92

Let the source compiler output a public target matrix

\[
T_x\in\mathbb Z_q^{n\times \ell}
\]

and a public normalization coordinate \(h\in[\ell]\).

Assume a valid source witness \(w\) deterministically gives a centered vector
\(a_w\in\mathbb Z^\ell\) with

\[
T_x a_w=0\pmod q,\qquad (a_w)_h=1,\qquad
\|a_w\|_2\le \beta_{\rm yes}. \tag{1}
\]

The useful source-binding property is:

> from any supplied nonzero normalized relation \(a\) satisfying
> \(T_xa=0\), \(a_h=1\), and \(\|a\|_2\le\beta_{\rm ext}\),
> recover an ORIGINAL source witness, or produce an independently justified
> short SIS solution.

Run 42 established this kind of interface for its randomized SIS lift, but only for a
**supplied** short representation. Run 92 showed that a source-preserving GapMDP code
would also give it directly if the real reduction has bounded honest amplitude \(B\)
and extraction through support \(B^2d\). Those Jin-specific conditions remain unverified.

The missing local question after Run 91 was:

> if a decoder is represented by a trapdoor preimage \(z=Ka\), can shortness of
> \(z\) force shortness of the underlying source relation \(a\), rather than allow
> cancellation in \(K\)?

The construction below answers that local question exactly.

---

## 2. Identity-tail preimage conditioning

Generate a trapdoored matrix

\[
A_0\in\mathbb Z_q^{n\times m}.
\]

Independently sample

\[
B\leftarrow \mathbb Z_q^{n\times\ell}.
\]

Using the trapdoor of \(A_0\), sample a short matrix \(K_0\in\mathbb Z^{m\times\ell}\)
columnwise such that

\[
A_0K_0=T_x-B\pmod q. \tag{2}
\]

Define

\[
\boxed{
A=[A_0\mid B],\qquad
K=\begin{bmatrix}K_0\\ I_\ell\end{bmatrix}.
}
\tag{3}
\]

Then

\[
\boxed{AK=T_x\pmod q.} \tag{4}
\]

This is a custom conditioned preimage layout. It is **not** the distribution of
Tsabary's ordinary `K <- A^TD(T)` sampler, and no security theorem is attributed to it.

### 2.1 Exact source recovery from an image decoder

For any source relation \(a\), define

\[
z=Ka=
\begin{bmatrix}
K_0a\\
a
\end{bmatrix}. \tag{5}
\]

The final \(\ell\) coordinates are literally \(a\). Hence the public projection

\[
\pi_{\rm tail}(z)=a \tag{6}
\]

is an exact left inverse on \({\rm Im}(K)\).

In particular, for centered representatives,

\[
\boxed{
\|a\|_2\le \|z\|_2.
}
\tag{7}
\]

So a short image decoder can no longer hide a long source relation by cancellation.

Conversely, with centered \(K_0\), a safe deterministic upper bound is

\[
\|z\|_2
\le
\sqrt{\|K_0\|_{2\to2}^2+1}\,\|a\|_2
\le
\sqrt{\|K_0\|_F^2+1}\,\|a\|_2. \tag{8}
\]

Thus a genuinely short trapdoor sampler gives two-sided source/decoder norm control.

### 2.2 Prefix preservation

If \(T_xa=0\), then

\[
Az=AKa=T_xa=0. \tag{9}
\]

For every public left prefix \(S\),

\[
(SA)z=0. \tag{10}
\]

This preserves the positive Run-91 observation: a valid target relation yields a
zeroizer through every left prefix. The difference is that now a supplied image
zeroizer \(z=Ka\) exposes the original relation \(a\) exactly.

### 2.3 Conditional supplied-decoder extraction theorem

Suppose the source compiler has the extraction threshold \(\beta_{\rm ext}\).
Then any algorithm that supplies

\[
z\in{\rm Im}(K),\qquad
Az=0,\qquad
(\pi_{\rm tail}(z))_h=1,\qquad
\|z\|_2\le\beta_{\rm ext}
\tag{11}
\]

immediately supplies

\[
a=\pi_{\rm tail}(z),\qquad
T_xa=0,\qquad
a_h=1,\qquad
\|a\|_2\le\beta_{\rm ext}. \tag{12}
\]

Therefore the existing source extractor applies.

This is a **supplied-representation** theorem only. An arbitrary key-recovery
algorithm is not forced to output \(z\).

---

## 3. A complete one-bit correctness interface

The local algebra does support a very simple common-key release experiment.

Let

\[
u_h=(0_m,e_h)\in\mathbb Z_q^{m+\ell},
\]

choose \(s\leftarrow\mathbb Z_q^n\), small error \(e\), message bit
\(\mu\in\{0,1\}\), and spacing \(\Delta\). Publish

\[
c=A^Ts+e+\mu\Delta u_h. \tag{13}
\]

A witness computes its normalized relation \(a_w\), then \(z_w=Ka_w\), and obtains

\[
\begin{aligned}
z_w^Tc
&=a_w^TK^TA^Ts+z_w^Te+\mu\Delta z_w^Tu_h\\
&=a_w^TT_x^Ts+z_w^Te+\mu\Delta(a_w)_h\\
&=\boxed{z_w^Te+\mu\Delta}\pmod q.
\end{aligned}
\tag{14}
\]

Every valid normalized witness therefore sees the **same** message displacement.

For bounded coordinate error \(|e_i|\le B_e\),

\[
|z_w^Te|
\le B_e\|z_w\|_1
\le B_e\sqrt{m+\ell}\,
\sqrt{\|K_0\|_F^2+1}\,\beta_{\rm yes}. \tag{15}
\]

A standard nearest-center decoder is correct whenever this is sufficiently below the
chosen spacing (for a binary \(0\) versus \(q/2\) encoding, below \(q/4\)).

This establishes correctness *conditional on an actually short trapdoor preimage
table*. The checker in this run deliberately uses ordinary finite-field solving, not a
Gaussian trapdoor sampler, and therefore does **not** claim practical noise parameters.

A \(\lambda\)-bit key could be obtained by parallel repetition, but that is not a
practical final KEM estimate and is not promoted here.

---

## 4. Exact collapse to statement-target LWE

The crucial complete-public-output check is immediate.

Multiply the public capsule by \(K^T\):

\[
\boxed{
K^Tc
=
T_x^Ts+K^Te+\mu\Delta e_h.
}
\tag{16}
\]

So the trapdoor-preimage layer has not hidden the release problem. It has merely
transported it to an LWE-like sample over the **statement-derived target matrix**
\(T_x\), with induced error \(K^Te\).

In fact, once setup has computed the induced error, an equivalent public release form is

\[
d=T_x^Ts+\eta+\mu\Delta e_h,\qquad \eta=K^Te, \tag{17}
\]

and a witness can decode directly from

\[
a_w^Td=a_w^T\eta+\mu\Delta. \tag{18}
\]

Thus the public \(K\) is not even logically necessary for witness correctness if setup
can generate the desired \(\eta\) before erasing its trapdoor.

This gives a useful normal form:

\[
\boxed{
\text{short-kernel witness release}
\quad\Longrightarrow\quad
\text{security of noisy linear samples over the statement-derived }T_x.
}
\tag{19}
\]

The remaining problem is therefore not trapdoor preimage algebra. It is to make
the false-statement distribution associated with \(T_x\) QPT-hard while retaining
witness-computable short normalized right-kernel relations on true statements.

High minimum distance or supplied-short extraction does **not** by itself imply this
pseudorandomness. A structured high-distance code may still have an efficiently
decodable or otherwise distinguishable syndrome/codeword distribution.

---

## 5. Why ordinary LWE does not automatically prove (19)

If \(T_x\) were a uniformly random LWE matrix, ordinary decisional LWE could hide the
message shift. But setup must also guarantee that every valid witness produces a short
normalized vector in \(\ker T_x\), without setup knowing any witness.

The Run-42 lift

\[
T_x=[CH_x\mid A]
\]

illustrates why merely adding random matrices is insufficient: every semantic kernel
vector of \(H_x\), including false pseudomodes, survives in the right kernel of \(T_x\).
The source structure is visible through exact linear algebra.

Likewise, row scrambling cannot hide the kernel, while secret column scrambling prevents
a witness from computing the transformed relation unless an additional witness-restricted
mechanism is supplied.

So the core open primitive can now be stated more tightly:

> **False-mode pseudorandom target compiler.**
> Given only \(x\), classically and in polynomial time, output \(T_x\) such that
> every valid witness computes a common short normalized right-kernel relation,
> but on false statements the entire public noisy-sample distribution is QPT-hard
> under an independently justified assumption.

This is not supplied by standard SIS hardness, ordinary GapMDP distance, or the local
identity-tail trick.

---

## 6. Important literature refinement: some related-trapdoor LWE *does* reduce to plain LWE

The previous runs correctly warned that Tsabary's Assumption 31 is an extra correlated
trapdoor assumption, not ordinary LWE. This run found a narrower positive result that
should be retained rather than overgeneralizing the warning.

Waters, Wee, and Wu, *Multi-Authority ABE from Lattices without Random Oracles*,
ePrint 2022/1194 (TCC 2022), Section 4, define a **generalized related-trapdoor LWE**
game and prove Theorem 4.2 reducing that game to standard LWE for their parameter
regime.

Primary source:
`https://eprint.iacr.org/2022/1194.pdf`

Their game fixes a nonzero vector \(u\in\{0,1\}^L\), gives the adversary an LWE
challenge in the direction

\[
(u^T\otimes I_n)B,
\]

and permits preimage queries for matrices

\[
(M\otimes I_n)B
\]

only when

\[
\boxed{
\begin{bmatrix}M\\u^T\end{bmatrix}
\text{ has full rank.}
}
\tag{20}
\]

Their proof programs

\[
B=[\widehat A\mid \widehat A R+U^\perp\otimes G]
\]

and derives the query trapdoor

\[
\begin{bmatrix}-R\\I\end{bmatrix}
\]

because the rows of \(M\) are transverse to the challenge direction \(u\).
The sole computational hybrid in the core Section-4 proof is a direct standard-LWE
reduction; the surrounding hybrids are statistical.

This is a genuine example where **structured related trapdoors are not automatically
an extra evasive-LWE assumption**.

### 6.1 But the theorem excludes our same-direction decoder

Set \(M=u^T\). Then

\[
\begin{bmatrix}M\\u^T\end{bmatrix}
=
\begin{bmatrix}u^T\\u^T\end{bmatrix}
\]

is rank deficient, so the oracle rejects the query.

The paper's overview explicitly notes that a restriction on \(M\) is necessary; if the
query direction coincides with the challenge direction, the challenge is easy to
distinguish.

Our identity-tail decoder is precisely aligned with the statement-target direction:
it publishes/uses a short preimage whose purpose is to annihilate the same target
sample that carries the message. Therefore Theorem 4.2 does **not** prove security of
this candidate.

This is the sharp literature conclusion:

\[
\boxed{
\text{plain-LWE related-trapdoor security is available for transverse access,}
\quad
\text{not for the same-direction source decoder used here.}
}
\tag{21}
\]

That distinction is a more useful boundary than saying all correlated trapdoor views
necessarily require evasive LWE.

---

## 7. Relation to Tsabary's Assumption 31

Rotem Tsabary, *Candidate Witness Encryption from Lattice Techniques*, CRYPTO 2022,
Section 3.2, explicitly samples a trapdoored \(A\), arbitrary correlated target \(T\),
prefix matrices \(S\), and

\[
K\leftarrow A^{TD}(T),
\]

then compares LWE over \(\{SA\}\) with auxiliary \(K\) against LWE over
\(\{SA,ST\}\) without \(K\).

Primary source:
`https://crypto.iacr.org/2022/papers/530630_1_En_19_Chapter_OnlinePDF.pdf`

The paper defines its hardness relation against PPT distinguishers and its final
security corollary for PPT adversaries. Standard LWE has separate quantum worst-case
lattice foundations in suitable parameter regimes, but that does not automatically
upgrade Assumption 31 itself.

The current construction does **not** instantiate Assumption 31's exact sample
distribution anyway: the identity-tail \(K=[K_0;I]\) is deliberately structured.

---

## 8. Quantum-security classification

### Honest algorithms

All algebra in this run is classical polynomial time. A real implementation of (2)
would use a classical lattice trapdoor sampler and erase the trapdoor after setup.

### Adversary model

The checker and the new source-transfer theorem make no hardness claim. The
identity/projection attacks are classical PPT and therefore are also available to QPT
adversaries.

### Base assumptions

- Ordinary LWE can be instantiated at parameters with known reductions from quantum
  worst-case lattice problems.
- Tsabary Assumption 31 is an additional correlated-trapdoor assumption stated/proved
  only in the paper's classical adversary framework.
- Waters–Wee–Wu Theorem 4.2 reduces their **specific transverse related-trapdoor game**
  to ordinary LWE. Their paper does not state the theorem as a QPT theorem.
- Inspection of their Section-4 proof shows straight-line computational use of the
  LWE adversary plus statistical hybrids, with no rewinding or random oracle. This is
  encouraging for a quantum lift under QPT-LWE when all oracle interfaces are classical,
  but the paper does not analyze quantum auxiliary states or superposition preimage
  queries. Therefore a full arbitrary-QPT extension remains **UNPROVED here**.

### Exact conclusion

This run proves:

1. exact supplied-decoder source recovery for the identity-tail layout;
2. exact witness correctness algebra;
3. exact public collapse to structured-target LWE;
4. exact inapplicability of the Waters–Wee–Wu transversality theorem to the
   same-direction preimage query.

It does **not** prove:

- false-statement QPT hiding;
- arbitrary-QPT final-key recovery -> supplied decoder;
- arbitrary-QPT final-key recovery -> ORIGINAL source witness;
- a standard-LWE reduction for statement-derived \(T_x\);
- malicious-ceremony composition or practical final parameters.

---

## 9. Fresh deterministic checker

`identity_tail_source_transfer_run93_check.py` is standard-library-only and deterministic.
It ran twice with byte-identical JSON.

It validates:

- 320 exact identities including \(AK=T\), \(Az=0\), and exact tail recovery
  \(\pi_{\rm tail}(Ka)=a\);
- 240 prefix-zeroization checks;
- 240 centered norm lower/upper-bound controls;
- 320 one-bit capsule congruence checks;
- 120 complete public-projection checks of Eq. (16);
- an exhaustive tiny-field independent-\(K\) control showing that the exact correlation
  \(AK=T\) is information-theoretically visible (for the tiny instance, an independent
  random \(K\) satisfies it with exactly \(q^{-n\ell}=1/25\));
- a finite-field transversality control showing `M=u^T` fails the Waters–Wee–Wu full-rank
  gate while an independent row direction passes it.

The toy solver used by the checker is ordinary modular Gaussian elimination, **not**
a lattice trapdoor Gaussian sampler. Its large observed noise inner products are
therefore a negative practical control, not trapdoor-sampler parameter evidence.

Checker SHA-256:
`fceedc88a3daef2b32724e420b5baa0a97e10206f8705ec486b51fbff54de155`

Captured JSON SHA-256:
`263aabe62e6f9ff92d1726312c669b8545ad48d299fad61bfc0f879eaa652bc0`

---

## 10. Exact next handoff

The next constructive target is no longer "make the trapdoor preimage preserve source
norms"; Run 93 solves that locally.

The high-value target is one of the following, in priority order:

1. **Exploit a plain-LWE-related-trapdoor theorem without same-direction access.**
   Look for a verifier/source layout where all public preimage material is transverse
   in the precise Waters–Wee–Wu sense, but a valid witness can nevertheless compose
   it into a common-key decoder while an arbitrary party holding *all* public material
   cannot do so. This must be tested against the prior public-closure/BFS failures.
2. **Construct a false-mode pseudorandom target compiler.**
   Randomize the Run-92/GapMDP source code into a target whose false-instance noisy
   linear samples reduce straight-line to QPT-hard LWE/SIS, while a true witness still
   computes a short normalized right-kernel relation. Row-only scrambling and public
   linear column transforms are already insufficient.
3. **Audit Jin 2026/2063's full source reduction when the manuscript becomes available**
   for the exact bounded-alphabet/extraction threshold. That only addresses source
   binding, not the structured-target pseudorandomness problem.

The stopping condition is not met.
