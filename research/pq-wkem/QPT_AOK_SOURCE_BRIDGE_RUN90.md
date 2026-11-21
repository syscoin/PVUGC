# Run 90 — QPT argument-of-knowledge source bridge: the SNARG-soundness gap can be repaired in QROM, but the base release remains open

**Status:** constructive composition lemma and parameter audit. This run identifies a real repair for one arrow in the current witness-KEM extraction chain: an accepting intermediate SNARG proof can be made to imply an **ORIGINAL NP witness against a QPT proof generator** by using a QROM succinct argument of knowledge rather than soundness alone. The repair is conditional on an appropriate preprocessing QROM SNARK interface and on the preceding release layer actually extracting an accepting proof. It does **not** provide false-statement QPT hiding, does **not** replace the missing concrete PQ release layer, and does **not** turn Jin's generic-group WE theorem into a concrete post-quantum theorem.

**Starting verified PR head:** `ff14c55c7d3449d692d0f1da0243239f2472bd21` on `research/pq-wkem-validation-20260918`.

Production code is unchanged.

## 1. Why this is the next bottleneck after Run 89

Run 89 rules out the proposed additive-share Fourier contraction for the literal Hair–Sahai source representation. Its handoff is to seek a source compressor whose effective online verifier/witness relation is much smaller than the original public source dimension, while preserving a route back to the original NP witness.

Jin, *Witness Encryption for NP from SNARGs and Groups* (ePrint 2026/2063), is directly relevant. The accessible primary-venue metadata says that the construction:

* assumes a SNARG for NP with **subexponential soundness** and **polylogarithmic online verification after input preprocessing**;
* gives a Karp–Levin reduction from `polylog(lambda)`-size circuit SAT to GapMDP over a large prime field with an `omega(log lambda)` approximation gap; and
* combines that reduction with the Barta–Ishai–Ostrovsky–Wu framework to obtain extractable WE for `polylog(lambda)`-size circuits in the generic-group model.

The full 2026/2063 manuscript was not retrievable through the accessible source in this run. Accordingly, this note treats those abstract-level claims as such and does not invent theorem numbers, exact adversary quantifiers, or a proof chain that was not inspected.

The crucial logical issue for **our stronger target** is independent of those missing details:

> SNARG **soundness** can prevent accepting proofs on false statements, but soundness by itself does not say that an algorithm producing an accepting proof for a true statement knows, contains, or permits extraction of the original NP witness.

Thus the chain

```
early FINAL-key recovery
 -> witness for the small verifier circuit
 -> accepting SNARG proof pi
 -> ORIGINAL NP witness
```

has an unjustified final arrow if the intermediate SNARG is assumed only sound.

This is not a criticism of ordinary witness encryption: standard WE false-statement security only needs soundness. It is a gap relative to this project's stronger unauthorized-early-key-recovery extraction requirement.

## 2. Primary-source QROM repair: succinct non-interactive arguments of knowledge

Chiesa–Manohar–Spooner, *Succinct Arguments in the Quantum Random Oracle Model* (TCC 2019; ePrint 2019/834), proves the required kind of **QPT knowledge extraction** in the QROM.

Their model is explicit:

* honest prover and verifier algorithms are classical polynomial-time;
* the malicious prover is a `t`-query **quantum** oracle algorithm and can query the random oracle in superposition;
* an argument of knowledge has a polynomial-time **quantum extractor** with black-box access to that quantum prover in the Unruh sense;
* the proof-of-knowledge construction does not arise by silently reusing a classical rewinding proof.

For the Micali construction, if the underlying PCP has knowledge error `k`, the paper's proof sketch bounds the event that the quantum prover wins while extraction fails by

```
O(t^2 k + t^3 / 2^kappa),                              (1)
```

where `kappa` is the random-oracle output length. If the prover makes the argument verifier accept with probability `mu`, witness extraction succeeds with probability at least

```
Omega(mu - t^2 k - t^3 / 2^kappa).                    (2)
```

The extracted object is a valid witness for the NP relation of the argument, not merely a transcript that passes verification.

The same paper proves the BCS route secure in QROM for suitable round-by-round-sound IOPs, and that proof-of-knowledge is inherited when the IOP has the corresponding round-by-round knowledge property.

This is exactly the missing semantic type of the last arrow: **accepting-proof generation by a QPT algorithm -> original relation witness**.

## 3. A preprocessing version exists on the SNARK side

A second primary source, Chiesa–Ojha–Spooner, *Fractal: Post-Quantum and Transparent Recursive Proofs from Holography* (EUROCRYPT 2020; ePrint 2019/1076), is relevant because Jin explicitly asks for small **online** verification after preprocessing.

Fractal's Theorem 10.1 gives a polynomial-time transformation from a public-coin holographic IOP to a **preprocessing non-interactive argument**. If the holographic IOP has round-by-round knowledge error `k_rbr`, its QROM adaptive knowledge error is

```
O(t^2 k_rbr + t^3 2^-kappa).                           (3)
```

The transformation has verifier overhead `O(kappa q log L)` for IOP query complexity `q` and oracle length `L`. For the paper's R1CS construction, the informal preprocessing-zkSNARK theorem gives online verifier time

```
O_kappa(|x_online| + log^2 m),                          (4)
```

after a public offline indexer preprocesses an `m`-constraint index.

This creates a concrete **interface candidate** for our statement-only setup: specialize the indexed relation to the fixed public NP statement during setup, so the large statement/circuit is in the preprocessed index and the online instance can be empty or only the small residual input. The setup is allowed to know the statement and need not know a witness.

However, I am not claiming that this automatically instantiates Jin 2026/2063. The full Jin manuscript was unavailable, so the exact meaning of its "input preprocessing" interface and its required subexponential-security convention have not been matched theorem-by-theorem. The result here is: the SNARK literature supplies the right **preprocessing + QPT knowledge-extraction shape**; exact Jin compatibility remains an explicit verification obligation.

## 4. Composition lemma: when an intermediate proof is enough

Let `R(x,w)` be the original NP relation for fixed statement `x`. Suppose a candidate release layer has the following property against a QPT final-key-recovery adversary `A`:

1. from `A`, a QPT reduction `E_rel` outputs with probability `eta` a classical proof `pi` accepted by a non-interactive argument verifier `V_x`; and
2. `(P_x,V_x)` is a QROM argument of knowledge for the relation `R_x(w)=R(x,w)` with extraction loss bounded by (1).

Then the composed extractor can invoke the argument-of-knowledge extractor on the proof-generating algorithm induced by `E_rel` and `A`. Let `T` be the **total** number of QROM queries made by that induced proof generator (including any queries made by `E_rel`, not merely the original adversary's queries). Subject to the black-box/state interfaces being compatible, the composed success obeys the same form

```
Pr[output w with R(x,w)=1]
 >= Omega(eta - T^2 k - T^3 2^-kappa).                 (5)
```

Thus a release extractor need not itself recover the original witness; recovering an **accepting proof for an AoK whose indexed relation is the original relation** is sufficient.

This is the constructive value of the result. It cleanly separates two jobs:

```
release layer:
    arbitrary QPT final-key recovery -> accepting proof pi
proof layer:
    QPT accepting-proof generator -> ORIGINAL witness w
```

The second job has a known QROM solution. The first job remains the central missing primitive.

### Important composition caveat

This is not yet a fully proved black-box composition for an arbitrary future release extractor.

The QROM AoK extractor expects black-box quantum access to a proof-generating adversary. A release-layer extractor may itself use, measure, rewind, or otherwise consume the original adversary. Quantum auxiliary state therefore cannot be ignored. Fractal explicitly notes that, in the quantum setting, knowledge soundness with auxiliary output is not known in general to be polynomially related to knowledge soundness without auxiliary output.

Accordingly, a surviving concrete construction must either:

* produce the accepting `pi` by a straight-line transformation that leaves a clean re-runnable proof generator for the AoK extractor;
* prove a compatible state-preserving/auxiliary-output composition theorem; or
* build one combined extractor from the original final-key adversary.

Equation (5) is a valid conditional interface, not permission to silently compose two arbitrary quantum extractors.

## 5. Parameter lemma: QROM extraction can remain polylogarithmic in an outer parameter

There is an apparent tension: the QROM loss contains a factor `t^3`, while the verifier feeding a small-circuit WE must stay polylogarithmic in an outer security parameter.

Let the outer parameter be `Lambda`, write

```
L = log_2 Lambda,
```

and let the **entire induced QPT proof generator** (original adversary plus the release-to-proof reduction) make at most

```
T <= Lambda^d = 2^(dL)
```

oracle queries for some fixed polynomial degree `d`.

Choose the **inner** QROM output length

```
kappa = L^2.                                            (6)
```

Assume, as a sufficient parameter target, that the underlying PCP/IOP knowledge error is amplified to

```
k <= 2^-kappa.                                          (7)
```

Then the two QROM loss terms satisfy

```
T^2 k        <= 2^(2dL - L^2),
T^3 2^-kappa <= 2^(3dL - L^2).                         (8)
```

For every fixed `d`, the log-base-2 exponents divided by `L` are respectively

```
2d - L  -> -infinity,
3d - L  -> -infinity.                                  (9)
```

Hence both losses are negligible in `Lambda`.

At the same time, any online verifier whose cost is polynomial in `kappa` and `L` remains polynomial in `L=log Lambda`:

```
kappa^a L^b = L^(2a+b) = polylog(Lambda).               (10)
```

This is a useful compatibility lemma: **superlogarithmic inner QROM security can coexist asymptotically with a polylogarithmic outer verifier**.

### Why `kappa = C log Lambda` is not universal

A fixed linear choice

```
kappa = C L
```

gives

```
T^3 2^-kappa = 2^((3d-C)L).                             (11)
```

No fixed `C` suppresses this term for every polynomial degree `d`. Thus a universal "QPT means arbitrary polynomial" theorem needs `kappa/L -> infinity` (or another parameterization with equivalent slack), not merely a fixed constant times `log Lambda`.

The accompanying checker validates (8)--(11) with exact integer exponent arithmetic.

### Scope relative to Jin's "subexponential soundness"

This lemma proves only what is stated: negligible QROM extraction loss against arbitrary polynomial-query QPT adversaries while keeping a polynomial-in-`kappa,L` verifier polylogarithmic in `Lambda`.

Because the full Jin manuscript was not available, I do **not** equate this sufficient parameterization with Jin's exact "subexponential soundness" definition. Jin may require a stronger quantitative convention for a different part of the generic-group reduction. Matching those two parameter systems requires the full theorem.

## 6. Exact security classification

### Honest algorithm model

The argument indexer/prover/verifier used in this source bridge are classical polynomial-time algorithms. Statement preprocessing is classical and may be performed during the allowed offline setup.

### Adversary model

The Chiesa–Manohar–Spooner and Fractal knowledge statements used here quantify over bounded-query **quantum** adversaries with superposition access to a quantum random oracle. This is genuinely stronger than a theorem quantified only over classical PPT attackers.

### Hardness distribution / QPT assumption

There is no LWE/SIS/MinRank hardness assumption in the QROM extraction theorem itself. Its security is proved in an **ideal quantum random oracle model**. A random oracle is not an independently justified standard-model QPT-hard assumption, and heuristic substitution of a concrete hash function is not a proof of the same theorem.

Fractal explicitly distinguishes the formal QROM construction from heuristic hash instantiation.

### Reduction model

The source bridge uses a polynomial-time **quantum extractor** with black-box access to the quantum proof generator. The proof accounts for superposition random-oracle queries. It is not a classical rewinding argument.

Compatibility with a preceding release-layer extractor, quantum auxiliary information, and state consumption remains to be proved for the eventual complete construction.

### Exact conclusion

This run establishes a **conditional original-source extraction bridge**:

```
QPT final-key recovery
 -> [STILL MISSING: concrete release extraction]
 -> accepting proof for a QROM AoK of R_x
 -> ORIGINAL witness for R_x.
```

It does not establish:

* false-statement QPT hiding;
* QPT extraction from arbitrary final-key recovery for any currently published release candidate;
* a standard-model construction from LWE/SIS;
* security of Jin's generic-group WE against arbitrary QPT attackers;
* malicious-setup composition; or
* practical final parameters.

## 7. Relationship to the targeted 2026 literature

### Jin 2026/2063

The paper's accessible metadata supplies the most relevant **compression architecture** after Run 89: arbitrary NP is funneled through a SNARG whose online verifier is polylogarithmic, then a new GapMDP Karp–Levin reduction handles small circuits. The new point of this run is that, for our stronger extraction target, that SNARG should be treated as an **argument of knowledge**, not merely a sound argument.

The full manuscript still needs a theorem-level audit before we can assert that swapping in a QROM preprocessing SNARK preserves every quantitative premise of Jin's reduction.

### Bartusek–Malavolta 2026/2040

Its advertised result is a succinct **argument** for QMA from collapsing hashes. Nothing verified in this run upgrades that result to the non-interactive source-extraction interface needed here. Argument soundness alone remains insufficient for the final arrow, exactly as above.

### Nassar–Waters–Wu 2026/1932

Its positional-obfuscation application assumes WE plus LWE; it remains downstream and cannot supply the missing base release.

### Gay–Jeronimo 2026/20780 and Hair–Sahai 2026/14529

Their local-to-global/code-gap and source-preserving hardness ideas may help design the compact relation, but neither by itself supplies a concrete full-public-output QPT release or converts worst-case NP-hardness into QPT-hard average-case LWE/SIS.

## 8. What to build next

The search should now split cleanly.

First, continue the **source-compression** side: obtain the full Jin 2026/2063 manuscript and audit the exact reduction arrows and parameters, especially whether an extractable/QPT-AoK preprocessing SNARG can replace the sound SNARG without destroying the `polylog` online circuit bound. Fractal's indexed preprocessing interface is a concrete candidate for specializing the statement into the offline index.

Second, attack the **release** side independently: construct a concrete public-output mechanism under an independently justified QPT-hard assumption such that arbitrary QPT recovery of the final key yields an accepting proof for that compact AoK relation. Run 72 can transport an already-existing capability under standard LWE, but it still does not create this source capability.

The ideal-oracle extraction of Run 76 remains conceptually useful but cannot be promoted to a concrete PQ endpoint.

## 9. Reproducible checker

`qpt_aok_source_bridge_run90_check.py` is deterministic and standard-library-only. It validates only the exact parameter arithmetic of Section 5:

* for `kappa=L^2`, `t^2 2^-kappa` has log2 exponent `2dL-L^2`;
* `t^3 2^-kappa` has exponent `3dL-L^2`;
* the latter is negative exactly once `L>3d`, and its exponent divided by `L` tends downward as `3d-L`;
* a fixed `kappa=C L` fails to suppress the cubic query term for all polynomial degrees `d`;
* polynomial cost in `kappa` and `L` remains polynomial in `L`, hence polylogarithmic in `Lambda`.

The checker is arithmetic validation, not cryptographic evidence.

## 10. Result / handoff

**New result:** the missing `accepting SNARG proof -> ORIGINAL NP witness` arrow has a credible QPT repair in the QROM using a non-interactive argument of knowledge, with an explicit QPT extraction loss and a parameterization that keeps the online verifier asymptotically polylogarithmic in an outer security parameter.

**What remains central:** there is still no concrete standard-PQ public release that turns arbitrary QPT early final-key recovery into such an accepting proof. Generic-group extractable WE is not a concrete PQ substitute, and QROM proof-of-knowledge is not a standard-model hardness assumption.

The complete practical generic-NP post-quantum witness-KEM stopping condition is **not met**.
