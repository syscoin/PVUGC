# Run 278 — unique abstract orbit for the surviving field-span-three scattered W5 core

## Checkpoint

This bounded pass began by reading the actual live `syscoin/PVUGC#1` draft PR.

- branch: `research/pq-wkem-validation-20260918`
- starting SHA: `421a03f2882149051a086e23a56ee9149bf4d500`
- PR state: open, draft, unmerged
- latest substantive ordinary PR comment: `5945825660`

Exact current-head scientific inputs read:

- `research/pq-wkem/HAIR_SAHAI_CLOSURE_BARRIER_RUN220.md`, blob `bdf9b7d699864e616aedd69dfe77df40a7b955af`
- `research/pq-wkem/hair_sahai_closure_barrier_run220_check.py`, blob `7cfe00449e9e7730bb7dca301fc103b824f3c014`
- `research/pq-wkem/HAIR_SAHAI_ADJOINT_CLOSURE5_RUN221.md`, blob `8e30d1a6215d4842fa5ffb9b3383401d7bf2a49d`
- `research/pq-wkem/hair_sahai_adjoint_closure5_run221_check.py`, blob `f58a7ed0e686e85516a549ca07abe980ebd73d4b`
- `research/pq-wkem/HPS_SZK_LACONIC_WE_BARRIER_RUN262.md`, blob `5c9471b0498577a17d62d17f6553c08eeafcf75d`

The conversation-local handoff narrowed the scalar-minimal closure-six branch to a field-span-three scattered binary five-space `W <= GF(16)^3` with the surviving field-hyperplane profile

[
(0,7,106,160)
]

and dual `[5,2]` parity-check projective rank spectrum

[
7	imes3 + 10	imes4.
]

This run completely classifies that **abstract** core.

The result is stronger than another support census:

> There is exactly one `GL_3(GF(16))` equivalence class of surviving field-span-three `W_5` cores. Its field-linear automorphism group is trivial.

So there is no remaining abstract `[5,2]` code classification problem. The next work is purely tensor embedding: test one rigid normal form against the actual Hair–Sahai source map.

---

## 1. Parity-check reduction

Choose an `F_2` basis

[
w_1,dots,w_5
]

of a field-span-three binary subspace

[
Wle GF(16)^3.
]

Put those vectors into the columns of

[
Gin GF(16)^{3	imes5}.
]

Its row space is a `[5,3]` `GF(16)` rank-metric code.

Let

[
Hin GF(16)^{2	imes5}
]

be any full-row-rank parity-check matrix for that row space.

Changing the `F_2` basis of `W` acts on the five columns by

[
Bin GL_5(F_2).
]

Changing the ambient `GF(16)^3` basis acts by left multiplication on `G` and therefore does not change its field row space.

Changing the two parity-check rows acts by

[
Min GL_2(GF(16)).
]

Therefore the `GL_3(GF(16))` equivalence class of `W`, modulo its internal binary basis choice, is captured by the binary column span

[
P_H
=
operatorname{span}_{F_2}{H_1,dots,H_5}
le GF(16)^2
]

modulo `GL_2(GF(16))`.

For the surviving spectrum, `P_H` has binary dimension five.

---

## 2. Complete census of binary five-spaces in GF(16)^2

There are

[
{8rack5}_2
=
97,155
]

binary five-dimensional subspaces of the eight-dimensional binary space `GF(16)^2`.

The checker enumerates every one in canonical RREF form.

For each binary five-space `P`, consider its intersection dimensions with the seventeen `GF(16)` projective lines of `GF(16)^2`.

Exactly three profiles occur:

| line-intersection profile | number of binary 5-spaces |
|---|---:|
| `10 x dim1, 7 x dim2` | **61,200** |
| `12 x dim1, 4 x dim2, 1 x dim3` | 35,700 |
| `16 x dim1, 1 x dim4` | 255 |

The surviving parity-check rank spectrum is exactly the first class:

[
oxed{
10	imes dim1
+
7	imes dim2.
}
	ag{1}
]

The count is already suggestive because

[
|GL_2(16)|
=
(16^2-1)(16^2-16)
=
61,200.
	ag{2}
]

---

## 3. The 61,200 candidates form one regular GL2(16) orbit

Take the first canonical candidate `P_0`.

Act using three elementary field-linear generators:

1. coordinate swap;
2. shear
   [
   (x,y)mapsto(x+y,y);
   ]
3. primitive diagonal scaling
   [
   (x,y)mapsto(2x,y),
   ]
   where `2` has multiplicative order fifteen in
   `GF(16)=F_2[x]/(x^4+x+1)`.

Breadth-first closure from `P_0` reaches exactly

[
61,200
]

distinct five-spaces.

Every visited five-space has the target line profile, and the reached set equals the complete set of all 61,200 target-profile spaces.

Since a subgroup of `GL_2(16)` cannot have an orbit larger than its group order and

[
|GL_2(16)|=61,200,
]

the generated subgroup is all of `GL_2(16)` and the orbit is regular.

Therefore

[
oxed{
	ext{there is exactly one target }GL_2(16)	ext{ orbit}
}
	ag{3}
]

and

[
oxed{
operatorname{Stab}_{GL_2(16)}(P_0)=1.
}
	ag{4}
]

---

## 4. Canonical parity-check and source core

A deterministic canonical basis of the representative is

[
P_0=
operatorname{span}_{F_2}
{
(1,4),
(2,2),
(0,1),
(8,0),
(4,0)
}.
]

Thus one canonical parity-check matrix is

[
oxed{
H=
egin{pmatrix}
1&2&0&8&4\
4&2&1&0&0
end{pmatrix}.
}
	ag{5}
]

A canonical generator of its orthogonal `[5,3]` code is

[
oxed{
G=
egin{pmatrix}
11&12&1&0&0\
7&14&0&1&0\
10&7&0&0&1
end{pmatrix}.
}
	ag{6}
]

The five columns of `G` form an `F_2` basis of the canonical

[
W_0le GF(16)^3.
]

The checker independently verifies:

- binary dimension of `W_0`: `5`;
- field span dimension: `3`;
- every nontrivial scalar intersection
  [
  W_0caplambda W_0
  ]
  is zero;
- the `[5,2]` parity-check projective rank spectrum is
  [
  7	imes3+10	imes4;
  ]
- the full `[5,3]` dual rank distribution is
  [
  oxed{
  A_0=1,quad
  A_1=0,quad
  A_2=105,quad
  A_3=1590,quad
  A_4=2400;
  }
  	ag{7}
  ]
- the source field-hyperplane restriction profile is
  [
  oxed{
  7	imes2+106	imes3+160	imes4.
  }
  	ag{8}
  ]

So the canonical object rederives the conversation-local rank-spectrum handoff rather than assuming an arbitrary representative has the correct geometry.

---

## 5. Consequence: one GL3(GF16) orbit of W5 cores

Suppose `W` and `W'` are two surviving source cores.

Choose binary bases and corresponding generator matrices `G,G'`.

Their parity-check column spans `P_H,P_H'` both satisfy (1).

By the single-orbit theorem there is

[
Min GL_2(GF(16))
]

sending one parity-check column span to the other.

The induced binary change of the five parity-check columns is exactly a change of the `F_2` basis of `W`.

After that basis change, the two parity-check row spaces agree.

Hence the two `[5,3]` generator row spaces agree, and therefore the corresponding source cores differ only by an ambient

[
Ain GL_3(GF(16)).
]

Thus

[
oxed{
	ext{all surviving field-span-three }W_5
	ext{ are }GL_3(GF(16))	ext{-equivalent to }W_0.
}
	ag{9}
]

No second abstract code class survives.

---

## 6. Trivial field-linear automorphism group

Let

[
Ain GL_3(GF(16))
]

preserve `W_0`.

On an `F_2` basis of `W_0`, it induces

[
Bin GL_5(F_2).
]

On the parity-check side this means some

[
Min GL_2(GF(16))
]

stabilizes the binary column space `P_0`.

Equation (4) forces

[
M=I.
]

The five parity-check columns are binary independent, so the induced binary basis change must also be trivial:

[
B=I.
]

Since the columns of `G` field-span all of `GF(16)^3`,

[
A=I.
]

Therefore

[
oxed{
operatorname{Aut}_{GL_3(16)}(W_0)=1.
}
	ag{10}
]

This matters operationally: embeddings into an actual tensor hyperplane do not come with a hidden field-linear stabilizer quotient. The normal form is rigid.

---

## 7. Heavy-plane incidence geometry is also rigid

The seven rank-two field-hyperplane restrictions of `W_0` have dual projective normals

[
(1,0,1),
(1,1,9),
(1,1,12),
(1,4,0),
(1,7,1),
(1,8,8),
(0,1,2).
]

Among the

[
{7choose3}=35
]

triples, exactly two are collinear:

[
oxed{
{0,2,3}
quad	ext{and}quad
{1,5,6}.
}
	ag{11}
]

The two triples are disjoint.

In primal projective language, the seven heavy source field planes therefore consist of:

- one concurrent triple;
- a second disjoint concurrent triple;
- one residual heavy plane.

For each concurrent triple, the three binary heavy cores

[
Q_i=Wcap P_i
]

share the same binary one-space inside their common `GF(16)` line.

The two concurrent triples share **different** binary one-spaces of `W`.

The seventh heavy plane contains neither of those two lines.

So every surviving field-span-three core has the same rigid pattern:

[
oxed{
3+3+1
	ext{ heavy-plane geometry with two distinguished binary source lines.}
}
	ag{12}
]

This is a stronger tensor-search invariant than the rank spectrum alone.

---

## 8. Why this is useful for the actual Hair–Sahai tensor

Before this pass the remaining abstract search was:

> classify all field-span-three scattered `W_5` cores having the surviving seven-heavy-plane / dual `[5,2]` rank profile.

That classification is now complete.

There is only one abstract object.

Therefore the next tensor-specific search can fix the canonical normal form (5)–(6) and ask only:

> can an embedding
> [
> A W_0
> ]
> into one actual Hair–Sahai source field hyperplane have binary column support at most nine?

The two concurrent triples plus one residual heavy plane provide additional pruning data for that embedding problem.

Do **not** spend another pass classifying `[5,2]` rank spectra.

---

## 9. Falsification / scope control

The unique-orbit theorem is an **abstract finite classification**.

It does not imply that an embedding into the actual Hair–Sahai source tensor exists or does not exist.

In particular, the ambient `GL_3(GF(16))` action used for classification is not claimed to be an automorphism of the Hair–Sahai tensor.

So one cannot take the canonical representative, test one arbitrary source basis embedding, and conclude globally.

The remaining work is the tensor embedding problem.

---

## 10. Reproducibility

Artifacts:

- `HAIR_SAHAI_UNIQUE_W5_ORBIT_RUN278.md`;
- `hair_sahai_unique_w5_orbit_run278_check.py`;
- `hair-sahai-unique-w5-orbit-run278-validation.json`;
- `HAIR_SAHAI_UNIQUE_W5_ORBIT_RUN278_PROVENANCE.json`.

Final local validation:

- `/usr/bin/python3 -m py_compile` passed;
- two complete executions were byte-identical;
- **183,657 explicit assertions**;
- exact enumeration of all `97,155` binary five-spaces in `GF(16)^2`;
- complete three-profile line-intersection census;
- exact `61,200`-element regular `GL_2(16)` orbit traversal;
- canonical parity-check/generator reconstruction;
- full dual rank distribution check;
- all fourteen nontrivial scalar-intersection checks;
- complete seven-heavy-plane triple-incidence check.

The checker proves finite algebra only.

---

## 11. QPT/security ledger

| Component | Model | Assumption | Exact conclusion |
|---|---|---|---|
| binary `5`-space census in `GF(16)^2` | finite exhaustive algebra | none | exactly three line-intersection profiles |
| target orbit classification | finite group action | none | all 61,200 target spaces form one regular `GL_2(16)` orbit |
| source-core equivalence | finite linear algebra | parity-check reduction | one `GL_3(16)` orbit of surviving `W_5` cores |
| automorphism theorem | finite linear algebra | regular orbit | field-linear automorphism group of canonical `W_0` is trivial |
| heavy-plane geometry | finite projective incidence | canonical representative + orbit invariance | two concurrent triples plus one residual plane |
| actual tensor embedding exclusion | — | missing | **UNPROVED** |
| arbitrary-QPT false hiding | arbitrary QPT | missing | **UNPROVED** |
| capability recovery -> ORIGINAL witness | arbitrary QPT | missing | **UNPROVED** |

The practical PQ witness-KEM stopping condition remains **unmet**.

---

## 12. Core handoff

The next bounded pass should no longer classify abstract `[5,2]` or `[5,3]` codes.

Fix the canonical source core

[
G=
egin{pmatrix}
11&12&1&0&0\
7&14&0&1&0\
10&7&0&0&1
end{pmatrix}
]

and attack only its embeddings into the actual Hair–Sahai field hyperplanes.

Use as pruning invariants:

1. binary column support at most nine;
2. scattered scalar-orbit condition;
3. two concurrent heavy-plane triples sharing two distinguished binary lines;
4. one residual heavy plane;
5. trivial `GL_3(16)` automorphism group.

If those embeddings can be globally excluded, the scalar-minimal row-support-nine closure-six branch closes.

The practical generic-NP public/offline PQ witness-KEM stopping condition remains unmet.
