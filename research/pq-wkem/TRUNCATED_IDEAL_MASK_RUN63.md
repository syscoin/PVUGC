# Run 63 — nonlinear truncated-ideal mask: exact coset dichotomy and public-dual break

## Status

This is a research checkpoint, **not** a completed witness KEM and not a PQ security claim.

Run 62 established that putting an entire *linear* consistency relation into one capsule prevents componentwise representation switching, but it also made clear that exact affine solvability is not the missing generic-NP condition: one-hot/source-witness validity is nonlinear, and false algebraic representations survive the public linear relaxation.

This run tests a genuinely nonlinear semantic encoding while keeping a **single global key-bearing object**. The attempt is a Boolean-quotient polynomial mask. It has attractive exact correctness and false-instance hiding whenever the statement has a bounded-degree algebraic refutation. The complete-public-output audit, however, finds a decisive source-transfer failure: on every satisfiable instance the public masking subspace necessarily has a public linear annihilator that recovers the key without a witness.

The positive algebraic statements below are proved. The tests validate the implementation of those statements. They are not evidence of cryptographic security.

---

## 1. Candidate

Let

\[
R_q = \mathbb F_q[x_1,\ldots,x_n]/(x_i^2-x_i)
\]

be the Boolean quotient. Its canonical basis is the set of squarefree monomials

\[
x_S=\prod_{i\in S}x_i.
\]

For a CNF clause \(C\), define its **falsity polynomial** \(g_C\):

- a positive literal \(x_i\) contributes \((1-x_i)\);
- a negative literal \(\neg x_i\) contributes \(x_i\);
- multiply the factors for all literals in the clause.

For every Boolean assignment \(w\),

\[
g_C(w)=0 \iff C(w)=1.
\]

Fix a public degree cutoff \(D\). Let

\[
P_{\le D}=\operatorname{span}\{x_S:|S|\le D\}
\]

and define the public bounded-product mask subspace

\[
V_D=\operatorname{span}\{x_M g_C:\deg(\operatorname{red}(x_Mg_C))\le D\}
\subseteq P_{\le D}.
\]

Here `red` is reduction by \(x_i^2=x_i\). This is the exact subspace implemented by the checker. It is intentionally defined by individually degree-bounded products; no high-degree term is silently truncated away, because truncation would destroy the vanishing identity used for correctness.

Setup samples a uniform

\[
v\leftarrow V_D
\]

and publishes one coefficient vector

\[
\boxed{F=K\cdot 1+v.}
\]

There are no per-clause key shares and no independently decodable challenge components.

---

## 2. Proved: all valid witnesses recover the same key

Let \(w\) be any satisfying Boolean witness. Every clause falsity polynomial vanishes at \(w\), so every generator multiple in \(V_D\) vanishes at \(w\). Therefore

\[
v(w)=0
\]

for every \(v\in V_D\), and

\[
\boxed{F(w)=K.}
\]

This is genuinely one-global-object correctness. Different valid witnesses all obtain the same key from the same published polynomial.

The finalized checker instantiated a two-variable clause with three valid assignments and checked 900 witness evaluations across 300 sampled capsules.

That correctness result is **not** source-witness security.

---

## 3. Proved complete-output break on every satisfiable instance

The same vanishing property implies a general no-go for the noiseless public-subspace-mask architecture.

Let \(e_w:P_{\le D}\to\mathbb F_q\) denote evaluation at a valid witness \(w\). Then

\[
e_w(V_D)=0,
\qquad
 e_w(1)=1.
\]

Hence

\[
1\notin V_D.
\]

Because \(V_D\) and the coefficient basis are public, ordinary Gaussian elimination can construct a public linear functional

\[
\lambda:P_{\le D}\to\mathbb F_q
\]

such that

\[
\boxed{\lambda(V_D)=0,\qquad \lambda(1)=1.}
\]

Applying it to the complete published coefficient vector gives

\[
\boxed{\lambda(F)=K.}
\]

No witness is used or extracted.

### General form of the lemma

This is not specific to CNF polynomials. Let \(W\) be a public finite-dimensional vector space, \(V\subseteq W\) a public masking subspace, and \(u\in W\) the public key carrier. If a legitimate decryption functional \(L_w\) obeys

\[
L_w(V)=0,
\qquad
L_w(u)=1,
\]

then \(u\notin V\), so public linear algebra produces *some* functional \(\lambda\) with the same two algebraic properties. A noiseless capsule

\[
F=Ku+v,
\qquad v\in V,
\]

is therefore publicly decryptable.

The legitimate functional may be hard to obtain from a source witness, but the complete public output does not force the adversary to use that functional.

This is exactly the distinction between **native witness evaluation** and **source-witness transfer** that earlier candidates failed to preserve.

In the finalized true-instance fixture, the intended witnesses recovered the key 900/900 times, while the independently synthesized public dual recovered the key 300/300 times without a witness. Its Hamming weight happened to be 2 in that fixture; the theorem itself does not depend on that weight.

---

## 4. Proved false-instance coset dichotomy

For a false statement, consider the complete distribution of

\[
F=K\cdot1+v,
\qquad v\leftarrow V_D.
\]

There are exactly two algebraic cases.

### Case A: \(1\in V_D\)

For any \(K,K'\in\mathbb F_q\),

\[
(K-K')1\in V_D,
\]

so

\[
K1+V_D=K'1+V_D=V_D.
\]

Uniform sampling of \(v\) therefore gives **identical complete coefficient-vector distributions for every key**. Hiding is information-theoretic.

### Case B: \(1\notin V_D\)

Public linear algebra gives a separator \(\lambda\) with

\[
\lambda(V_D)=0,
\qquad
\lambda(1)=1,
\]

and again

\[
\boxed{\lambda(F)=K.}
\]

So the noiseless candidate has no computational middle ground: for this complete-output distribution, the key is either perfectly hidden by coset equality or exactly recoverable by a public dual.

The checker verified both sides explicitly. A contradictory one-variable CNF at sufficient cutoff has identical exhaustive key-conditioned supports. A three-variable contradiction at insufficient cutoff has nonzero \(V_D\) but no constant certificate; a public dual recovered 500/500 sampled keys.

---

## 5. Proved full-degree refutation for every unsatisfiable CNF

For a Boolean assignment \(a\in\{0,1\}^n\), define the assignment indicator

\[
\delta_a(x)=
\prod_{i:a_i=1}x_i
\prod_{i:a_i=0}(1-x_i).
\]

In the Boolean quotient,

\[
\delta_a(b)=\mathbf 1[a=b],
\qquad
\sum_{a\in\{0,1\}^n}\delta_a=1.
\]

If a CNF is unsatisfiable, every assignment \(a\) falsifies at least one clause \(C(a)\). Its falsity polynomial \(g_{C(a)}\) is a factor of \(\delta_a\), because all clause literals have exactly their falsifying values in \(a\). Therefore

\[
\delta_a\in\langle g_C\rangle
\]

with degree at most \(n\). Summing all assignment indicators gives

\[
\boxed{1\in V_n.}
\]

So at full Boolean degree the construction does perfectly hide false statements.

The cost is the ambient dimension

\[
\dim P_{\le n}=2^n,
\]

which is an exponential encoder and therefore disallowed as a final generic-NP construction.

The checker verified full-degree membership for two concrete unsatisfiable families.

---

## 6. Exact all-exclusions threshold

Take \(k\) variables and one clause excluding each of the \(2^k\) assignments. The corresponding falsity generators are exactly the assignment indicators \(\delta_a\), all of degree \(k\).

For any squarefree monomial \(x_M\), the Boolean-reduced product \(x_M\delta_a\) is either

- zero, if \(M\) contains a variable forced to zero by \(\delta_a\); or
- \(\delta_a\) itself, if every variable of \(M\) is forced to one by \(\delta_a\).

Therefore every nonzero generator multiple still has degree exactly \(k\). Hence

\[
\boxed{V_D=\{0\}\quad\text{for }D<k.}
\]

At \(D=k\), all \(\delta_a\) occur. They are linearly independent as Boolean functions and satisfy

\[
\sum_a\delta_a=1.
\]

Thus

\[
\boxed{\dim V_k=2^k,\qquad 1\in V_k.}
\]

The checker verified this exact transition for every \(k=2,3,4,5,6\).

This family itself has \(2^k\) clauses, so it is **not** a proof that every polynomial-size CNF needs exponential cutoff. It is only an exact stress test of the candidate's degree/size behavior.

---

## 7. A compact diagnostic, without a general degree claim

The checker also used the false chain

\[
(x_1)\land
(\neg x_1\lor x_2)\land
(\neg x_2\lor x_3)\land
(\neg x_3).
\]

For the implemented bounded-product span over \(\mathbb F_2\):

- \(D=0\): ambient dimension 1, mask-span dimension 0, \(1\notin V_D\);
- \(D=1\): ambient 4, span 2, \(1\notin V_D\);
- \(D=2\): ambient 7, span 7, \(1\in V_D\);
- \(D=3\): ambient 8, span 8, \(1\in V_D\).

This is only a concrete diagnostic. No general asymptotic certificate-degree theorem is claimed from it.

---

## 8. Adding coefficient noise: exact identity, unresolved hardness

A natural repair is

\[
F=K\cdot1+v+e\pmod q.
\]

A valid witness now obtains

\[
F(w)=K+e(w).
\]

The public annihilator on any instance with \(1\notin V_D\) obtains

\[
\boxed{\lambda(F)=K+\lambda(e).}
\]

This identity is exact; the checker validated it in 1000 sampled trials.

Noise therefore changes the missing problem into a metric one:

> Can every valid witness evaluation remain decodable while every efficiently obtainable public annihilator that does not encode a source witness has sufficiently large/hiding noise?

Nothing in this run proves such a gap. In particular, simply naming the task “short annihilator hardness”, “LWE-like”, or “SIS-like” would be circular. A surviving version needs an actual reduction on the **complete published coefficient/noise distribution** to an independently justified PQ assumption, or an information-theoretic argument showing the unauthorized projection is hiding while legitimate evaluations remain correct.

The current noiseless candidate does not meet the goal, and the noisy variant is only a conditional research direction.

---

## 9. Resource size

The ambient coefficient count is

\[
M(n,D)=\sum_{i=0}^D\binom ni.
\]

The public mask span can be built from at most `(#constraints) * M(n,D)` monomial-generator products before row reduction, and the published polynomial itself has \(M(n,D)\) field coefficients.

Exact counts recorded by the checker include:

| n | D | coefficients | bytes at 16 bits/coefficient |
|---:|---:|---:|---:|
| 64 | 3 | 43,745 | 87,490 |
| 64 | 4 | 679,121 | 1,358,242 |
| 128 | 4 | 11,017,633 | 22,035,266 |
| 128 | 5 | 275,584,033 | 551,168,066 |
| 256 | 4 | 177,589,057 | 355,178,114 |

This already makes clear that even modest degree growth becomes expensive. Full degree is exponential.

---

## 10. Implemented validation

Final checker: `truncated_ideal_mask_run63_check.py`.

It was executed twice after finalization; the two JSON outputs were byte-identical.

The captured run checked:

- 300 true-instance capsules and 900 valid-witness evaluations;
- 300/300 public no-witness recoveries on that same satisfiable instance;
- exhaustive key-conditioned support equality for a false instance with \(1\in V_D\);
- 500/500 public-dual key recoveries on an insufficient-cutoff false instance;
- the compact-chain cutoff diagnostic above;
- exact all-exclusions thresholds for \(k=2\ldots6\);
- full-degree certificate membership on two explicit unsatisfiable families;
- 90 deterministic random small CNF/cutoff cases: 11 with \(1\in V_D\), 79 with public duals, and 632 sampled dual recoveries;
- 1000 exact noisy-dual identities;
- exact resource-count calculations.

SHA-256:

- checker: `b733cee7fe71c1684082a1dda2bb1611756dc93072ec9dceece157f9cca8b0e3`
- captured validation: `8bed792cad95687b900243099abb545dc1b055bc3e6bb4b08ea75b5a8bf22a60`

Passing these tests does **not** establish security.

---

## 11. Result and handoff

### Proved / implemented

1. A single nonlinear Boolean-quotient object gives exact same-key correctness for every valid witness.
2. For false instances, the noiseless complete output has an exact coset dichotomy: `1 in V_D` gives perfect hiding; otherwise a public dual exactly extracts the key.
3. More importantly, every satisfiable instance necessarily has `1 notin V_D`, so the same public-dual construction gives unauthorized no-witness recovery. This breaks source-witness transfer for the entire noiseless public-subspace-mask architecture.
4. Every unsatisfiable CNF has a full-degree certificate `1 in V_n`, but the ambient representation is exponential.
5. The all-exclusions family has the exact cutoff transition described above.
6. With additive coefficient noise, the public attack becomes the exact scalar projection `K + lambda(e)`; whether a useful metric separation can be justified remains unresolved.

### Not proved

- no generic polynomial-degree refutation bound;
- no practical generic-NP encoder;
- no LWE/SIS reduction for the noisy public-dual problem;
- no theorem that every noisy or nonlinear binder is impossible;
- no arbitrary-QPT early-key-recovery-to-source-witness reduction;
- no malicious-secure ceremony/auxiliary-input composition for a surviving inner primitive.

### Next constructive target

A useful successor must stop public linear algebra from synthesizing an unauthorized decryption functional while preserving one-global-representation correctness. The most concrete remaining direction is a noisy/cryptographic functional encoding where:

- legitimate source-witness evaluations are provably short/decodable;
- any non-source public annihilator is either information-theoretically hiding or computing a short one reduces to standard LWE/SIS;
- the reduction is over the **complete public output**, not a hidden internal interface;
- common-representation binding is native to the one key-bearing object rather than added as separable shares.

Until that is supplied, this run is a negative result for the noiseless construction and a sharper specification of the missing noisy primitive, not a WKEM breakthrough.
