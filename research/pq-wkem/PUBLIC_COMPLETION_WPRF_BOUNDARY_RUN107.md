# Run 107 — public-completion / WPRF boundary: simultaneous-message LWE is one online share short of offline witness release

## Status

Verified starting PR head:
`5a612472b4f5e16120a6a07097ef25788415cb94`
on branch `research/pq-wkem-validation-20260918`.
PR #1 was open, draft, and unmerged.

The latest substantive PR comment is `5839832728`, recording verified publication of
Runs 100–103. Runs 104–106 remain local-only after their separate safety-blocked
publication attempts. This run does not retry, rename, split, encode, or reroute any
previously denied payload.

Exact current repository inputs read before this run include Runs 42, 68, 72, 80, 95,
102 and 103 plus the scalar-descent literature record.

This run audits two bodies of work that look close to the missing primitive:

* simultaneous-message/succinct secure computation and laconic conditional disclosure;
* witness pseudorandom functions (WPRFs), including the new 2026 vector-commitment
  WPRF.

The main conclusion is structural:

> Standard-LWE simultaneous-message/laconic protocols already compress interaction,
> but they remain **one online input-dependent share short** of the public/offline
> witness release required here.

Making that missing share publicly computable for arbitrary future witnesses is not a
minor optimization. For the relation-specific function needed by this project, it is
already a witness-release primitive.

The WPRF literature gives the right name for this missing functionality. But the
currently visible 2026 standard-assumption construction is for a special
vector-commitment local-opening language and uses pairing groups, while
general-purpose WPRFs remain much stronger objects. Moreover, the project's
true-instance requirement needs source extraction from unauthorized key recovery, not
only false-instance pseudorandomness.

No production path is changed.

## 1. Exact SMS syntax

Boyle--Jain--Servan-Schreiber--Srinivasan define simultaneous-message and succinct
(SMS) secure computation after a CRS setup.

Alice holds a large input `X`; Bob holds a small input `y`.

They produce public encodings

\[
pe_A\leftarrow\mathsf{Encode}_A(X),
\qquad
pe_B\leftarrow\mathsf{Encode}_B(y).
\]

Then, **after seeing the other public encoding**, they locally compute additive output
shares

\[
z_A\leftarrow\mathsf{Decode}_A(X,pe_B),
\]

\[
z_B\leftarrow\mathsf{Decode}_B(y,pe_A),
\]

and reconstruction gives

\[
z_A+z_B=f(X,y).
\tag{1}
\]

The important point is the dependency graph:

\[
\boxed{
z_A\text{ still depends on Bob's future }pe_B.
}
\tag{2}
\]

Thus publishing Alice's first message during setup does not leave behind a complete
offline public evaluator.

## 2. One-sided public completion theorem

Abstract any SMS/additive-share scheme as above.

Suppose Alice wants to disappear permanently after setup. Then setup would need to
publish an additional token

\[
\tau_X
\]

such that a public algorithm computes Alice's missing share for every valid future
Bob encoding:

\[
\mathsf{Complete}(\tau_X,pe_B)
=
\mathsf{Decode}_A(X,pe_B).
\tag{3}
\]

Bob can already compute \(z_B\) from his local input/state and Alice's public first
message.

Therefore `(pe_A,tau_X)` plus Bob's ordinary algorithms is a one-sided noninteractive
public evaluator for

\[
f(X,y).
\tag{4}
\]

This is a functionality theorem; no computational assumption is involved.

Now instantiate

\[
X=(x,K)
\]

and define

\[
f((x,K),w)
=
\begin{cases}
K,&R(x,w)=1,\\
0,&R(x,w)=0.
\end{cases}
\tag{5}
\]

If every valid witness `w` obtains `K`, while on a false statement the public artifact
hides `K`, then `(pe_A,tau_X)` is already a witness-release/KEM artifact for the NP
relation.

Hence:

\[
\boxed{
\text{secure public completion of Alice's future share}
\Longrightarrow
\text{the missing witness-release primitive itself}.
}
\tag{6}
\]

SMS security does not prove security after publishing such a completion token,
because the protocol model keeps Alice's decode state/input on Alice's side and lets
her compute \(z_A\) only after Bob's message exists.

So "make the reusable/succinct SMS first message public and offline" is not a
construction of WKEM unless the new public-completion step is independently proved.
That step is the hard problem.

## 3. Public reconstruction does not remove the online share

Some SMS variants allow final additive shares to be publicly reconstructed once they
exist.

That changes the output party, not the order:

1. Bob forms \(pe_B\);
2. Alice computes \(z_A\) using \(pe_B\);
3. Bob computes \(z_B\);
4. the shares are reconstructed.

Making step 4 public does not precompute step 2.

This is the same boundary found for NI-OTE in Run 106: a succinct public message does
not imply a public evaluator for the missing share.

## 4. Laconic CDS remains interactive in the exact missing place

Döttling--Garg--Goyal--Malavolta's laconic CDS releases a message conditioned on an
NP witness with laconic verifier work/communication.

But it is a **two-round** protocol: the witness holder sends the first message and the
verifier responds.

Nobody may remain online after setup in this project. Setup does not know the future
witness-holder message.

Precomputing verifier responses for all possible future prover messages is again the
public-completion problem of Section 2.

Thus laconic CDS from LWE/CDH shows that witness-conditioned release is achievable
with one online response; it does not provide the required offline artifact.

## 5. Exponential public completion exists trivially

The missing functionality is not logically impossible. It is easy with an
exponential encoder.

Let the witness domain be

\[
W=\{0,1\}^n.
\]

Choose a random mask `r` and secret bit `K`. Publish `r` and

\[
T[w]
=
r\oplus\left(R(x,w)\cdot K\right)
\qquad\forall w\in W.
\tag{7}
\]

A valid witness computes

\[
T[w]\oplus r=K.
\tag{8}
\]

If `x` is false, every entry equals `r`, so the artifact is independent of `K`.

It therefore has perfect false-statement hiding and all-witness correctness.

Its size is

\[
\boxed{2^n+1}.
\tag{9}
\]

This is exactly the exponential-encoder escape hatch excluded by the project goal.

The checker exhaustively validates this construction on all small relations.

## 6. Transparent compression is not enough

The table is represented by the simple circuit

\[
C_{x,K,r}(w)
=
r\oplus\left(R(x,w)\cdot K\right).
\tag{10}
\]

Publishing an ordinary transparent circuit hard-codes `K` and `r`, exposing them in
the direct representation.

Hiding those constants while retaining public evaluation is precisely an
obfuscation/witness-release style task.

This conclusion is scoped:

\[
\boxed{\text{direct transparent compression fails}.}
\]

It is not an impossibility theorem for all cryptographic compilers. An obfuscator,
FE-like compiler, or WE-like primitive could hide the constants. But using such a
primitive as the unexplained completion layer would be circular for the base-WKEM
goal.

## 7. Witness PRFs name almost exactly the desired public gate

A witness PRF has a public evaluation mode: given a valid NP witness, the PRF output
can be evaluated publicly, while the output remains pseudorandom to parties lacking
the required witness under the scheme's security definition.

If a generic WPRF supplies

\[
z=\mathsf{PRF}_{sk}(x)
\]

and

\[
z=\mathsf{PubEval}(pk,x,w)
\quad\text{when }R(x,w)=1,
\tag{11}
\]

then encapsulation can derive

\[
K=\mathsf{KDF}(z).
\tag{12}
\]

Every valid witness recovers the same `z` and therefore the same `K`.

This makes WPRF the correct abstraction for the **public witness-gated evaluation**
syntax isolated by Runs 106–107.

## 8. Ordinary WPRF security is not automatically the full true-instance theorem

The project requires more than false-statement hiding.

On a true statement, arbitrary QPT early FINAL-key recovery must imply an ORIGINAL
source witness or an independently justified QPT-hardness break.

A WPRF theorem that only guarantees pseudorandomness in a no-witness/false-instance
game does not automatically supply this knowledge/source-extraction implication.

The needed object is closer to

\[
\boxed{\text{source-extractable / knowledge WPRF}.}
\tag{13}
\]

No generic PQ construction of that object is imported here.

## 9. The 2026 vector-commitment WPRF narrows the target

Bhadauria--Branco--Döttling--Garg--Policharla,
*Witness Pseudorandom Functions for Vector Commitments and Applications*,
IACR ePrint 2026/1079, is directly relevant.

The currently indexed abstract says:

* general-purpose WPRFs were previously known only from assumptions strong enough for
  indistinguishability obfuscation;
* the new construction targets a **specific vector-commitment language**;
* public evaluation uses a valid **local opening**;
* the construction relies on standard assumptions on pairing groups and is black-box.

This shows that WPRF-strength public witness-gated evaluation can become easier when
the witness language has special algebraic structure.

It still does not meet the target:

1. pairing-group assumptions are not post-quantum;
2. the language is a special local-opening language rather than generic NP;
3. the full primary ePrint PDF was not retrievable through the available primary
   fetch path in this run, so no theorem-level QPT or extraction property is assumed.

## 10. Generic NP -> local opening is itself a source compiler

The naive adapter commits to the truth vector

\[
V_x[w]=R(x,w)
\]

indexed by all \(n\)-bit witnesses.

A witness index can then ask for a local opening of a `1` entry.

But the vector has

\[
\boxed{2^n}
\]

coordinates. Conventional explicit vector-commitment setup/opening state inherits the
same exponential table problem as Section 5.

To use the 2026 special-language WPRF for generic NP, one needs a succinct
statement-to-commitment compiler such that:

* setup computes the digest from `x` without a witness;
* any valid witness independently derives a valid local opening;
* invalid witnesses cannot derive one;
* security is QPT;
* arbitrary unauthorized FINAL-key recovery source-extracts an ORIGINAL witness.

That adapter is itself extremely close to the missing witness/source compiler and
cannot be assumed for free.

## 11. Relation to Run 72

Run 72 already showed that once a cryptographic capability exists, ordinary LWE can
transport it directionally and can implement native AND transport.

The missing step was how a generic NP witness obtains exactly the correct initial
capability from a public transcript.

Runs 106–107 find the same boundary from secure computation:

\[
\boxed{
\text{native encryption/transport is not source-witness transfer}.
}
\]

OTE/SMS efficiently combine shares; WPRF supplies the correct witness-gated
abstraction; the unresolved object is the PQ source-witness -> public-capability gate.

## 12. QPT ledger

### Honest algorithms

The functionality theorems and finite checker are classical.

A practical solution must replace the exponential table with polynomial-time
classical setup/evaluation.

### SMS / CDS

The cited constructions are standard-assumption results in their published classical
models. They are not silently promoted to QPT security.

Even a QPT re-proof would not remove the online-share dependency.

### WPRF

The visible 2026 vector-commitment construction is pairing-based and not a PQ
endpoint.

The full current theorem was not independently audited here because the primary PDF
was unavailable.

### Reduction model

The public-completion theorem is functionality-level/information-theoretic.

No rewinding, QROM, superposition oracle, or extraction argument is used.

### Exact conclusion

Standard-LWE SMS/OTE/laconic machinery does not automatically compile into a public
offline witness release. Secure public completion of the missing future-input share
would itself instantiate essentially the primitive being sought.

### Still unproved

1. polynomial-size generic-NP public witness-gated evaluation from standard QPT-hard
   assumptions;
2. a PQ source-extractable WPRF or equivalent capability gate;
3. arbitrary-QPT FINAL-key recovery -> ORIGINAL witness for a complete practical
   scheme;
4. malicious-secure erased setup/abort for any future setup-secret construction;
5. final concrete resource estimates.

The stopping condition is not met.

## 13. Next handoff

The best next target is a **PQ source-specific WPRF / witness-gated capability
primitive**, not another generic two-party secure-computation compiler.

The most concrete questions are:

1. can a lattice/SIS vector or functional commitment support a succinct
   `x,w -> local opening` compiler without trusted per-witness keys;
2. can the Run-92 GapMDP/SNARG source be turned into such an opening language while
   preserving ORIGINAL-witness extraction;
3. can Run 102's one-copy QPT extractor upgrade a witness-gated capability into the
   required true-instance knowledge property.

Any candidate whose last step is "publish Alice's missing share", "make EncEval
public", "publish all witness responses", or "assume a generic WPRF" should be
rejected as insecure, exponential, or circular.

The practical generic-NP PQ WKEM remains open.
