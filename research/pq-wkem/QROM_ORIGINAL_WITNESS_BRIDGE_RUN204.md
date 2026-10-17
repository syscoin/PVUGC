# Run 204: QROM knowledge extraction narrows the Jin ORIGINAL-witness gap, but does not compile into the public tiny circuit

**Status:** new literature/reduction checkpoint with an exact finite falsification of a tempting QROM-to-public-circuit step. This is not a completed WKEM, not a concrete PQ proof for Jin's generic-group tiny WE, and not a standard-model compilation of a QROM verifier.

## 1. Starting state and exact scope

Connected GitHub reads before research verified `syscoin/PVUGC#1`, branch `research/pq-wkem-validation-20260918`, open/draft/unmerged, at head

`c33ef82b6c4e77e0dfbaa87122d4582d802701eb`.

The latest substantive ordinary PR comment read was Run 196, issue comment `5913974235`. Exact-version committed input read for this pass: `research/pq-wkem/literature-20260924/ASSESSMENT.md`, blob `8a1bc1db08156c9ff6410f59963c1af3a0d5a924`. The prior Run-203 handoff was treated as a local research checkpoint, not as branch evidence.

This pass asks one narrow construction question: after Jin's tiny-WE extractor yields an accepted inner proof, is a one-copy/QPT ORIGINAL-witness knowledge layer itself missing, or does the real blocker lie elsewhere?

## 2. Correction to the Run-203 handoff: QPT knowledge layers of the required *shape* do exist in QROM

Run 203 correctly rejected the implication

`accepted SNARG proof -> ORIGINAL witness`

from ordinary soundness alone. But its handoff was too pessimistic if read as saying the needed quantum knowledge-extraction *shape* is unknown.

### 2.1 Chiesa-Manohar-Spooner gives succinct noninteractive QROM arguments of knowledge for the original relation

Chiesa, Manohar, and Spooner, *Succinct Arguments in the Quantum Random Oracle Model*, ePrint 2019/834, defines a QROM argument of knowledge using a polynomial-time **quantum extractor**. For a t-query quantum prover `P~=(A_1,...,A_t)` with initial state `|phi_0>`, their black-box model gives the extractor an auxiliary register containing that initial state and permits it to apply the adversary gates `A_i` (Definition in Section 3.3, PDF pp. 15-16 / extracted lines 793-810).

Their Theorem 7.1 and Corollary 7.2 give QROM zkSNARKs for NP from PCPs of knowledge. Lemma 7.4 explicitly reconstructs a PCP object from the compressed-oracle database and runs the PCP extractor; the output is a witness `w` satisfying the **original relation R**, not merely another accepting proof (PDF pp. 35-37 / extracted lines 3004-3028 and 3045-3087).

For the reduction target here this matters: a generic statement that quantum advice necessarily has to be cloned before a knowledge extractor can be used is false for this theorem's black-box model. The extractor is defined with one supplied initial-state register and adversary gates. This theorem does **not** state that the adversary's residual quantum state is preserved after extraction, but the WKEM security conclusion only needs an ORIGINAL witness or an independent break; residual-state preservation is not intrinsically required if the outer reduction terminates after extraction.

### 2.2 Majenz-Sharma supplies the stronger online/state-preserving shape

Majenz and Sharma, *Security of the Fischlin Transform in Quantum Random Oracle Model*, arXiv:2602.17307v2 (revised 8 June 2026), proves straight-line extraction for the Fischlin transform against QROM provers. Their definition expressly lets the dishonest prover output an additional, possibly quantum, auxiliary output `Z` alongside the proof. The online extractor simulates the oracle during the single prover/verifier execution and their main result gives perfect oracle simulation plus negligible extraction error for suitable parameters, assuming the underlying Sigma protocol has special soundness, unique responses, and commitment entropy.

This is closer than CMS to the strongest composition interface previously requested: it is online/straight-line and its definition compares the joint proof/auxiliary/verifier view. Thus a one-copy, non-rewinding QPT knowledge layer is not an unknown primitive **in the QROM**.

What this does *not* give automatically is a succinct input-preprocessed verifier for arbitrary NP that can be embedded as Jin's tiny ordinary Boolean circuit.

## 3. Conditional composition lemma

Suppose, for a precisely bound source statement x:

1. an outer key-recovery adversary A succeeds with probability p;
2. a QPT tiny-WE source extractor, using the same public view and A, outputs a classical proof pi accepted by an inner verifier V with probability at least `p - eps_tiny`;
3. V belongs to a QPT **online/straight-line** argument of knowledge for the ORIGINAL relation R, with perfect simulation and extraction error at most `eps_K` against the composed prover that runs the tiny extractor and outputs pi.

Then the composed extractor outputs an ORIGINAL witness `w` with

`R(x,w)=1`

with probability at least

`p - eps_tiny - eps_K`.

The proof is only event accounting. Perfect simulation preserves the accepted-proof probability. The knowledge extractor fails on an accepted proof with probability at most `eps_K`. No classical rewinding, advice cloning, witness privacy, or assumption that an accepting proof string itself encodes a witness is used.

For a CMS-style non-straight-line AoK the same conceptual composition is available under **its** black-box model, but the exact success expression is the theorem's extraction function `kappa(t,mu,lambda)`, not the additive formula above. Any use must inherit that model and its query bounds explicitly.

This lemma is conditional because the current tiny WE has not been proved QPT-extractable in a concrete implementation; Jin's theorem is classical GGM.

## 4. The actual blocker: Jin non-black-box embeds the verifier as an ordinary public circuit

Jin's current ePrint 2026/2063 makes the relevant interface explicit. The full-NP compiler assumes a SNARG with input preprocessing and defines

`C_{kappa,d_x}(pi) := Verify(1^kappa, d_x, pi)`

with `size(C_{kappa,d_x}) <= poly(kappa, log n)`, then encrypts under this circuit using tiny WE. The full-NP proof extracts an accepted `pi*` from tiny WE and invokes **SNARG soundness**. The paper's own footnote at the statement of the result says that one cannot directly instantiate the SNARG in the random-oracle model/GGM and claim WE in the GGM alone, because the construction makes **non-black-box use of the SNARG verifier**.

That footnote is exactly the obstruction to plugging either QROM knowledge theorem above directly into Jin:

- CMS verification contains quantum-random-oracle access;
- Fischlin verification contains quantum-random-oracle access;
- Jin needs the verifier's computation represented inside a public ordinary circuit consumed by tiny WE.

An oracle gate is not a public finite circuit for a truly random function. Replacing it with a concrete public hash is a separate assumption/theorem, not a consequence of QROM knowledge extraction.

There is a second fit issue for CMS specifically: its generic NTIME(T(n)) verifier is polynomial in `lambda`, the input length `n`, and `log T(n)`. Jin needs the **online verifier circuit after input preprocessing** to be polynomial in `kappa` and `log n`. A fresh preprocessing/digest construction with ORIGINAL-source binding would therefore still be needed even before removing the oracle.

### 4.1 An obvious post-quantum preprocessing candidate does not formally remove this blocker

I also checked FRACTAL (Chiesa et al., ePrint 2019/1076), because it is a post-quantum transparent **preprocessing** zkSNARK with very small online verification. This does not close the bridge either. Its formal post-quantum argument is in the QROM; the paper explicitly says that obtaining the implemented URS/hash version assumes that replacing the random oracle by a cryptographic hash preserves the relevant security properties, and calls this step heuristic. The paper further states that a secure instantiation must preserve proof of knowledge. Therefore FRACTAL is evidence that the efficiency profile is plausible, but it is not an independently justified standard-model/QPT ORIGINAL-extraction compiler for the present theorem.

## 5. Focused falsification: 2q-wise oracle simulation does not justify publishing a q-wise seed inside C

A tempting bridge is Zhandry's standard QROM simulation fact: a quantum algorithm making at most q oracle queries cannot distinguish a uniformly random function from oracle access to a uniformly sampled 2q-wise independent function. This is useful for simulators answering **oracle queries**.

It does **not** imply that the sampled function may be given to the adversary by its compact public description, or hardwired transparently into Jin's public verifier circuit.

Take the usual 2q-wise family of degree `<2q` polynomials over `F_p`, with `2q<p`. Under oracle access capped at q queries, the Zhandry theorem applies. If the evaluator/description is public, however, an ordinary polynomial-time adversary can simply perform `2q+1` local evaluations. Those evaluations always lie on a degree-`<2q` polynomial for the sampled family, whereas a uniformly random function passes the same interpolation-consistency test with probability exactly `1/p`. Thus description exposure yields distinguishing advantage

`1 - 1/p`.

With the whole function table, low-degree-family membership has advantage

`1 - p^(2q-p)`.

The accompanying checker exhaustively verifies the finite cases `(p,q)=(3,1),(5,1),(5,2)` and exact counts, and checks `(7,1)` algebraically. For `(p,q)=(5,1)`, only three local evaluations already distinguish with exact advantage `4/5`, while full-table membership has advantage `124/125`.

This is **not** an attack on Zhandry's theorem. It demonstrates a different experiment: full/public description or unrestricted local evaluation supplies strictly more access than the theorem's q-query oracle interface. Consequently the naive step

`QROM random oracle -> 2q-wise simulator -> hardwire simulator key publicly`

is invalid for the current application.

There is also no single polynomial q chosen by efficient setup that upper-bounds every polynomial-time adversary. Picking a superpolynomial independence degree would sacrifice the required polynomial-time setup/evaluation. A hidden simulator key would require some separate way to hide a public program, which would reintroduce exactly the sort of obfuscation/FE-like mechanism this research is not allowed to assume as the missing source gate.

## 6. Exact QPT/assumption ledger for this checkpoint

- **Jin tiny/full WE:** honest algorithms classical; proved extractor/security against PPT generic-group adversaries. Arbitrary-QPT/coherent-group-query security remains unproved. The current paper itself disallows a direct ROM/GGM substitution because of non-black-box verifier use.
- **CMS 2019/834:** quantum extractor in QROM, with one supplied initial-state register in the stated Unruh black-box model; outputs an ORIGINAL relation witness through the PCP-of-knowledge extractor. Succinct and noninteractive in QROM. No claim here of residual-state preservation or ordinary-circuit/random-oracle elimination.
- **Majenz-Sharma 2602.17307v2:** arbitrary q-query quantum prover in QROM; online/straight-line extraction, possibly quantum auxiliary output in the definition, perfect oracle simulation in the main theorem, and negligible extraction error under the stated Sigma-protocol/parameter conditions. No ordinary-circuit compilation established here.
- **2q-wise simulation:** QROM oracle-access fact only. Public-description compilation is explicitly rejected by the finite counterexample and by the change in access model.
- **Composition lemma above:** straight-line/online conditional theorem. It gives ORIGINAL extraction only if both the tiny source extractor and the inner AoK theorem apply to the *same complete public/auxiliary distribution*.

No QROM theorem is relabeled as a concrete standard-model/PQ theorem. No random-oracle hash deployment is assumed. No witness privacy is required.

## 7. Core handoff

The construction-side gap is now narrower than Run 203 stated:

**Do not spend another run merely looking for a one-copy QPT knowledge extractor. Such extractors exist in QROM.**

The actionable missing object is instead one of:

1. a **standard-model or explicitly instantiated** post-quantum argument of knowledge for arbitrary NP whose *input-preprocessed online verifier* is an ordinary public circuit of size `poly(kappa, log n)`, with extraction of the ORIGINAL witness under the exact CRS/checking-key/auxiliary distribution needed here; or
2. a new tiny-WE compiler that soundly supports the relevant oracle-verifier interface without publishing the oracle description and without assuming an ideal hidden evaluator/WE/iO/FE-equivalent mechanism.

Even solving that does not complete the WKEM: Jin's tiny WE/source extractor itself still needs an independently justified arbitrary-QPT theorem or a concrete-PQ replacement. False-instance full-public-output hiding and malicious one-honest N-of-N setup/abort/erasure composition also remain mandatory.

The practical stopping condition is therefore **not met**.

## Sources checked this run

- Zhengzhong Jin, *Witness Encryption for NP from SNARGs and Groups*, ePrint 2026/2063, current approved preprint: https://eprint.iacr.org/2026/2063 and PDF https://eprint.iacr.org/2026/2063.pdf . Relevant: Theorem 1.1 / footnote 1; Definition 2.1; Theorem 4.1 construction and proof.
- Alessandro Chiesa, Peter Manohar, Nicholas Spooner, *Succinct Arguments in the Quantum Random Oracle Model*, ePrint 2019/834: https://eprint.iacr.org/2019/834.pdf . Relevant: Section 3.3 knowledge definition; Theorem 7.1, Corollary 7.2, Lemma 7.4.
- Christian Majenz, Jaya Sharma, *Security of the Fischlin Transform in Quantum Random Oracle Model*, arXiv:2602.17307v2: https://arxiv.org/abs/2602.17307 . Relevant: straight-line-extractability definition, Corollary 1, Theorem 3.2.
- Mark Zhandry, *How to Construct Quantum Random Functions*, ePrint 2012/182 / FOCS 2012 / JACM 2021: https://eprint.iacr.org/2012/182 . Used only for the 2q-wise **oracle-access** simulation distinction; the public-description counterexample is new finite reasoning in this checkpoint.
- Alessandro Chiesa et al., *FRACTAL: Post-Quantum and Transparent Recursive Proofs from Holography*, ePrint 2019/1076: https://eprint.iacr.org/2019/1076.pdf . Checked specifically as a preprocessing/URS candidate; its hash instantiation is explicitly assumed/heuristic rather than a formal removal of the QROM.
