# Run 94 — transverse related-trapdoor LWE has a QPT-classical-query lift, but clear public ABE key prepublication collapses the source gate

## Status

Starting verified PR head: `f127e33fb43ed2898bcc0a67ddbc944c5f514ca9` on branch `research/pq-wkem-validation-20260918`.

This run does **not** complete the requested generic-NP post-quantum witness KEM. It follows the Run-93 handoff and audits the related-trapdoor LWE construction of Waters–Wee–Wu (TCC 2022 / ePrint 2022/1194) at the exact interface we would need.

There are two results:

1. **Positive, derived quantum lift.** The generalized related-trapdoor LWE proof can be lifted to QPT adversaries that make only **classical** preimage queries, provided the exact LWE distribution used in their computational hybrid is QPT-hard. This is a derived theorem here, not a theorem stated by Waters–Wee–Wu. It does not cover coherent superposition access to the preimage oracle.
2. **Negative source-gate result.** In their subset-policy instantiation, the full-rank/transversality condition is exactly the unauthorized-set condition. The secret-key components for an authorized set share one binding Gaussian vector `r`. A clear public offline pool of same-binding components sufficient for every valid witness necessarily exposes an authorized decryption key on a true statement. Using independent bindings destroys the core cancellation identity; deriving a witness-dependent common binding and its preimages from public data is itself the missing witness-restricted primitive.

So this literature route is useful as a **transverse auxiliary shell once a source capability already exists**, but it does not supply the missing generic-NP source capability.

Production code is unchanged. All artifacts for this run are research-only.

---

## 1. Exact primary-source interface

Primary source:

- Brent Waters, Hoeteck Wee, David J. Wu, *Multi-Authority ABE from Lattices without Random Oracles*, TCC 2022 / ePrint 2022/1194.
- ePrint: <https://eprint.iacr.org/2022/1194>
- author/NTT PDF inspected: <https://ntt-research.com/wp-content/uploads/2023/01/Multi-authority-ABE-from-lattices-without-random-oracles.pdf>

The paper defines a generalized related-trapdoor LWE game. The challenge direction is a nonzero

\[
u\in\{0,1\}^L,
\]

and the challenge contains an LWE sample in direction

\[
(u^T\otimes I_n)B.
\]

The adversary may request a Gaussian preimage for

\[
(M\otimes I_n)B
\]

only when

\[
\boxed{
\bar M=\begin{bmatrix}M\\u^T\end{bmatrix}
\text{ is full row rank.}
}
\tag{1}
\]

Theorem 4.2 reduces this generalized related-trapdoor LWE game to ordinary LWE under the stated lattice/noise conditions. The paper also explicitly warns that some restriction on `M` is necessary: same-direction access such as `M=u^T` makes the challenge easy to distinguish.

The relevant source material is Assumption 4.1, Theorem 4.2, and Lemmas 4.3–4.7.

---

## 2. Exact subset-policy meaning of the transversality gate

For the core subset-policy ABE, a ciphertext is associated with a set

\[
X\subseteq[L]
\]

and a secret key with a set

\[
Y\subseteq[L].
\]

Decryption is authorized when

\[
X\subseteq Y.
\tag{2}
\]

In the reduction, `u_X` is the indicator vector of `X`, and `M_Y` is obtained by selecting from the identity matrix `I_L` the rows indexed by `Y`.

This gives an exact elementary identity:

\[
\boxed{
u_X\in\operatorname{rowspan}(M_Y)
\iff X\subseteq Y.
}
\tag{3}
\]

Therefore

\[
\boxed{
\operatorname{rank}
\begin{bmatrix}M_Y\\u_X^T\end{bmatrix}
=
\operatorname{rank}(M_Y)+1
\iff X\not\subseteq Y.
}
\tag{4}
\]

This is not merely analogous to the ABE security condition. It **is** the security condition: the related-trapdoor oracle is available exactly for unauthorized key sets.

The finalized checker exhaustively verifies (3)–(4) for every pair `(X,Y)` for `2 <= L <= 8`, totaling 87,376 pairs.

---

## 3. The core common-binding key algebra

The paper's technical overview gives the following core subset-policy structure. For each attribute `i`, public matrices/vectors include `A_i,B_i,p_i`. A ciphertext for `X` contains, suppressing small LWE noises in this algebraic identity,

\[
\{s^TA_i\}_{i\in X},
\qquad
s^T\sum_{i\in X} B_i,
\qquad
s^T\sum_{i\in X}p_i+\mu\Delta.
\tag{5}
\]

A secret key for `Y` uses a **single common Gaussian binding vector** `r` and components

\[
\boxed{
k_i(r)=A_i^{-1}(p_i+B_i r),\quad i\in Y,}
\tag{6}
\]

together with `r` itself.

For `X subseteq Y`, the decryption cancellation is

\[
-\left(s^T\sum_{i\in X}B_i\right)r
+
\sum_{i\in X}s^TA_i\,k_i(r)
=
 s^T\sum_{i\in X}p_i,
\tag{7}
\]

up to the controlled lattice noise terms. The common `r` is therefore a functional part of the key, not cosmetic metadata.

The checker independently instantiates a finite-field noiseless analogue of (5)–(7) for 500 fresh systems and verifies exact decryption in all 500 cases. This checks the algebra only, not lattice correctness or security.

---

## 4. Public-prepublication collapse theorem

### Theorem 4.1 — clear same-binding prepublication cannot be the source gate

Fix a challenge set `X`. Suppose a public offline setup publishes clear key material containing, for one common binding `r`, the components

\[
\{k_i(r):i\in U\}
\quad\text{and }r,
\tag{8}
\]

where `U` contains the union of attribute sets intended to support valid witnesses.

If there exists even one valid witness whose associated authorized set `Y_w` satisfies

\[
X\subseteq Y_w\subseteq U,
\tag{9}
\]

then the public transcript contains all components

\[
\{k_i(r):i\in X\}
\]

and `r`. By (7), **any party** can decrypt. No source witness is needed.

So a polynomial clear pool of same-binding components cannot simultaneously be:

1. public;
2. sufficient for a valid witness to assemble an authorized key; and
3. unavailable for witness-free decryption.

This is unconditional and does not depend on LWE hardness.

The checker validates the same-binding collapse in 500 independently generated finite-field systems: after forming one or more authorized witness supersets whose union contains `X`, the public same-binding pool decrypts in all 500 cases.

### Scope

This is **not** an impossibility theorem for all ABE, WE, FE, or witness-restricted public encodings. It rules out the direct idea of using clear, prepublished Waters–Wee–Wu-style secret-key components as our generic-NP source gate.

---

## 5. Why independent bindings do not repair the direct construction

A tempting repair is to publish attribute components under independently sampled bindings

\[
r_i.
\]

Then the component for attribute `i` is

\[
A_i^{-1}(p_i+B_i r_i).
\tag{10}
\]

But the cancellation in (7) requires one common `r`. With unrelated `r_i`, the decryption expression leaves the residual

\[
\sum_{i\in X}s^TB_i(r_i-r),
\tag{11}
\]

for any attempted single `r`, except in accidental/specially engineered cases.

The checker includes 300 negative-control systems with independently bound components; 299/300 fail the single-binding cancellation identity and one accidental equality occurs modulo the toy prime. This finite test is only a sanity check for (11), not a security theorem.

The deeper point is architectural. To use a witness-dependent binding `r_w`, public setup—which does not know the future witness—would need an efficient public process that, from a valid `w`, produces the mutually correlated preimages

\[
\{A_i^{-1}(p_i+B_i r_w)\}_{i\in Y_w}
\tag{12}
\]

while an invalid/non-witness user cannot obtain an authorized family. That process is already a **witness-restricted key derivation primitive**. Assuming it as a subroutine would reintroduce the missing base WE/WKEM problem rather than solve it.

Exponential clear prepublication does not help practicality and, if complete authorized key blocks are themselves public, immediately destroys confidentiality.

---

## 6. Derived QPT theorem for the transverse/classical-query RTLWE game

Waters–Wee–Wu formulate Theorem 4.2 for efficient adversaries and do not state the following quantum theorem. However, their proof structure supports a clean restricted lift.

### Derived Theorem 6.1

Assume the **exact decision-LWE distribution used in Lemma 4.5 / Theorem 4.2 is hard for QPT distinguishers** at the chosen parameters.

Consider a QPT adversary against generalized related-trapdoor LWE that:

1. may keep arbitrary polynomial-size quantum auxiliary/work state;
2. receives all challenge data as classical strings;
3. makes only polynomially many **classical** oracle queries `(M,t)` and receives classical sampled preimages; and
4. eventually outputs a classical bit.

Then the Waters–Wee–Wu hybrid proof extends to this adversary with negligible loss, under the same statistical parameter conditions and the QPT-LWE assumption above.

### Why the lift works

The proof has three kinds of steps.

#### A. Information-theoretic challenge hybrids

Lemmas 4.3 and 4.7 use classical statistical/leftover-hash closeness. For classical distributions `P,Q`, the corresponding diagonal quantum states have trace distance equal to total variation distance. Arbitrary QPT post-processing cannot increase trace distance. Hence these steps remain valid with quantum auxiliary computation.

#### B. Preimage-response hybrids

Lemmas 4.4 and 4.6 replace an ideal conditional Gaussian preimage sampler with `SamplePre`, using statistical closeness and a standard hybrid over oracle queries. With **classical** queries and classical responses, conditioned on each classical query the two response distributions are statistically close. Contractivity of trace distance plus a polynomial hybrid over the number of queries preserves negligibility even when the adversary carries an arbitrary quantum state between calls.

This argument does **not** establish security for coherent superposition access to the preimage oracle.

#### C. The computational LWE hybrid

Lemma 4.5 is straight-line. The reduction receives one ordinary LWE challenge, constructs the public matrices/challenge, runs the distinguisher, answers admissible classical preimage queries using the constructed trapdoor, and outputs the distinguisher's bit. It does not rewind the adversary, extract from a measurement transcript, or program a random oracle.

Therefore the same reduction can invoke a QPT distinguisher as a subroutine. If that distinguisher separated the two hybrids, it would distinguish the exact underlying LWE distribution in QPT.

### Exact conclusion

This yields a **derived QPT classical-query RTLWE theorem**, not a quantum-oracle theorem. A fixed public offline transcript containing only classical transverse auxiliary material is a still more restricted special case, so no superposition-query issue arises there.

This is useful for our target because honest setup/encapsulation/decapsulation can remain classical. It is also a correction to the overly cautious reading that every correlated trapdoor view necessarily needs a separate post-quantum assumption. Some carefully transverse views inherit security from QPT-LWE by a straight-line/statistical proof.

---

## 7. Why the positive QPT lift still does not solve our WKEM

The same transversality that makes the theorem reducible to LWE prevents it from supplying an **authorized** source decoder.

For subset policies, the reduction may answer secret-key/preimage requests only when

\[
X\not\subseteq Y.
\]

But a source witness needs exactly the opposite:

\[
X\subseteq Y_w.
\]

Equivalently, by (3), the authorized direction is precisely where `u_X` enters the row span and the full-rank gate fails.

So we cannot take the theorem that protects **transverse unauthorized auxiliary data** and silently apply it to the **aligned authorized source key**. The paper itself flags same/aligned directions as requiring exclusion because otherwise distinguishing becomes easy.

The construction is therefore naturally positioned **after** a source capability has already been obtained, matching Run 72's result:

- Run 72: standard LWE gives secure directional/AND capability transport once a parent capability exists.
- Run 94: generalized RTLWE can protect transverse classical auxiliary preimages under QPT-LWE (derived lift), but clear authorized key prepublication cannot create the missing parent/source capability.

---

## 8. QPT/security ledger

### Honest algorithm model

All source compilation, lattice setup, public transcript generation and witness decapsulation envisioned here are classical PPT. No quantum hardware is required for honest users.

### Adversary model

The new positive theorem covers QPT adversaries with arbitrary quantum internal state but only **classical** access to the related-preimage interface. A static public classical transcript is included as a special case. Coherent quantum oracle queries are **not** covered.

### Exact hardness distribution

The computational step requires QPT hardness of the same LWE distribution/parameters appearing in Waters–Wee–Wu Theorem 4.2 and Lemma 4.5. This run does not replace that with a vague “lattice hardness” claim and does not assert that Tsabary's correlated-trapdoor assumption follows from it.

### Reduction model

Straight-line invocation of the QPT distinguisher for the LWE hybrid, plus information-theoretic statistical hybrids. No classical rewinding, QROM, random-oracle programming, quantum extraction, or superposition-query simulation is used.

### Exact conclusions

**Proved/derived:**

- selector transversality `(4)`;
- clear same-binding public prepublication collapse `(8)–(9)`;
- common-binding decryption algebra `(7)`;
- derived QPT validity of the generalized RTLWE hybrid proof for classical-query/static views, conditional on exact QPT-LWE hardness.

**Still UNPROVED:**

- a generic-NP public source capability;
- false-statement full-public-output QPT hiding for the complete WKEM;
- arbitrary-QPT early final-key recovery -> ORIGINAL source witness or independently justified QPT-hardness break;
- malicious-secure distributed setup/abort and auxiliary-output composition;
- practical final parameters.

---

## 9. Fresh validation executed

`transverse_rtlwe_publication_run94_check.py` is deterministic and standard-library-only. The finalized checker was run twice and produced byte-identical JSON.

It verifies:

1. **87,376** exhaustive subset pairs for `2 <= L <= 8`, confirming
   `rank([M_Y;u_X]) = rank(M_Y)+1` iff `X not subset Y`;
2. **500** fresh finite-field core-ABE systems satisfying the exact common-binding cancellation identity;
3. **500** public same-binding pool controls where an authorized union contains `X` and therefore decrypts publicly;
4. **300** independent-binding negative controls, with 299 failures of the single-binding identity and one accidental equality modulo the toy prime.

These tests validate the finite algebra only. They do not test GPV sampling, lattice correctness parameters, LWE hardness, the paper's security theorem, or the derived QPT hybrid theorem.

---

## 10. Precise next handoff

Do **not** try to turn subset-ABE secret-key issuance itself into the base public witness selector.

The useful decomposition is now:

1. **Source gate:** continue the Run-92 route—a bounded-alphabet/source-preserving GapMDP (or another source compiler) plus the Run-42 SIS source binder—until a valid witness gives one short source capability and every comparably short supplied relation extracts the ORIGINAL witness or breaks standard QPT-hard SIS.
2. **Auxiliary/transport layer:** once that capability exists, use Run 72's standard-LWE directional transport and, where useful, Waters–Wee–Wu-style **transverse** related-preimage material. The derived QPT classical-query theorem gives a credible route to standard QPT-LWE for this auxiliary shell.
3. **Complete-output extraction:** prove, not assume, that arbitrary final-key recovery from the whole public transcript yields the source capability or a standard PQ-hardness break. This remains the central missing reduction.

A narrower constructive follow-up is to formulate a `witness-bound common-r` compiler and immediately test whether the binding can be generated from the Run-92/Run-42 source relation using only standard QPT-LWE/SIS. If the construction requires public arbitrary-witness key derivation, it has merely renamed the missing WE primitive and should be rejected early.

The full stopping condition remains unmet.
