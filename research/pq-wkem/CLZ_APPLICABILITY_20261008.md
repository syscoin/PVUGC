# Canetti-Luo-Zhang applicability and current WKEM handoff

Date: 2026-10-08. Interactive literature/application assessment, not a numbered scheduled research run or a completed security proof.

## Decision

Prioritize a full proof audit of Canetti, Luo and Zhang. This is directly relevant to the local-mixing direction, not optional background to dismiss because it invokes iO. The useful question is whether its concrete circuit family and proof techniques can support a smaller relation-dependent release region under independently justified assumptions. This assessment does not answer that question affirmatively.

## Verified primary sources and an important correction

[S1] https://eprint.iacr.org/2026/1398 explicitly identifies itself as the first part of the CRYPTO paper. Its stated ingredients include indistinguishability obfuscation (iO), permutable pseudorandom permutations (PPRP), and a split-circuit pseudorandomness assumption for the random-reversible-circuit instantiation. Its homomorphic result uses subexponential security.

[S2] The merged conference paper is *How to Encrypt with Random Reversible Circuits: Functional, Homomorphic and CCA-Secure*, CRYPTO 2026, pp. 539-580, first online 2026-08-09: https://link.springer.com/chapter/10.1007/978-3-032-35367-2_18 . The accessible publisher notes also restrict retrieval of functional keys in the simulation-security game to after selection of the challenge plaintext. That order must be checked against our setup and adaptive-claim requirements.

[S3] Ji Luo's author-linked Simons slides: https://luoji.bio/assets/slides/CLZ26simons26.pdf . Printed slides 9, 11, 16 and 19 were inspected as images. The scheme exposes an obfuscated forward permutation, not the original transparent reversible gate list. Functional evaluation combines encryption, controlled evolution and restricted output. The linkage notion concerns permitted ciphertext transformations; it is not automatically knowledge of an ORIGINAL witness.

[S4] Yiding Zhang's author-linked CRYPTO slides: https://iacr.org/submit/files/slides/2026/crypto/crypto2026/777/777_slides.pdf . PDF pages 61-62 (zero-based 60-61) explicitly describe white-box CCA and say it implies quantum CCA. This was also visible in the image of printed slide 9 in [S3], although that text was absent from its parsed text. Earlier literature summaries omitted this quantum-specific claim. Do not describe the work as merely classical. Equally, the slide is not verification of concrete QPT-secure iO/PPRP/SCP assumptions or of quantum WKEM extraction.

Access limitation: the ePrint PDF could not be retrieved by the web tool; direct container retrieval encountered DNS resolution failure; the download tool failed; the publisher page exposed subscription preview rather than the proof text. The author presentations were accessible. Full theorem/proof, parameter-loss, version and errata audit remains pending. No paper PDF is redistributed here.

## What is potentially reusable

The promising contribution for our problem is joint security of correlated public programs, including a forward program and a punctured inverse-related program, together with controlled transformations. That is more relevant than checking each local mask or gate distribution separately. Audit the actual hybrid proof, its auxiliary input, and its computational assumptions rather than replacing it with a new ideal-mixer assumption.

The raw-gate inversion example from Run 368 does not refute obfuscation of the forward direction. It applies when an inverse is efficiently obtainable from the published representation. Security of an obfuscated forward representation requires a different analysis; it is not granted by the word 'reversible'.

## New application analysis: the witness-admission interface

Our target remains entirely off chain until native signing:

`ORIGINAL w -> witness-dependent state s_w -> protected common K_x -> ordinary branch signature`.

A useful way to examine the functional/homomorphic template is to place a hidden capability and an execution state in one encrypted object, and give an output function that discloses the capability only at an accepting state. This is a proposed application to analyze, NOT a construction supplied by the paper.

There is a specific unresolved interface before such an application works. A watcher learns a new witness after setup. How does the watcher incorporate that chosen witness into the protected state carrying the SAME hidden K_x, without the master secret, without an online issuer, and without enabling arbitrary modification of the acceptance state?

The advertised construction permits repeated application of one fixed unary function. This does not by itself specify an evaluator with an independently chosen witness input. A deterministic unary machine can evolve a witness already present in its initial state; that observation does not show how to insert a later witness alongside an unknown protected capability. Enumerating potential witnesses is not an established practical solution. This is an interface gap, not an impossibility theorem for the paper or for other encodings.

Ordinary public encryption is also not that interface: a watcher can encrypt a known plaintext but has not thereby encrypted the original unknown K_x together with the new witness. Conversely, issuing a new functional key for every witness requires a master-secret operation unless an additional public derivation mechanism is actually constructed. A fixed functional key may be prepared during the original ceremony; FE does not intrinsically require online approval. The unresolved point is late public witness admission, not a blanket objection to FE setup.

An attractive bounded next subproblem is therefore: derive or rule out a restricted public-input transition for this particular hidden-capability state using the paper's actual construction and proof. Require all valid witnesses to work; allow their intermediate states to differ. Do not assume a general public-input controlled-homomorphism primitive and call it the solution.

## What the paper cannot yet be credited with solving here

Even a verified ciphertext-linkage theorem does not immediately turn an arbitrary native signature into a supplied source representation. The attacker in our end-to-end game may output only a signature, not a ciphertext, proof or trace. The full paper's extraction/linkage definition, including when it may return bottom, must be checked before composing it with source binding.

Public native verification keys, existing graph pre-signatures, statement/UTXO/branch context, multiple capsules and setup transcripts all belong in the security view. The public evaluation programs must be treated as available to coherent quantum computation. Neither classical indistinguishability nor a classical oracle argument alone establishes the needed arbitrary-QPT result.

The original one-honest-party N-of-N setup and erasure model remains available. No retained-randomness keyless construction is established by this encryption template. Bitcoin still performs only the conditionally assumed native transaction verification and fixed graph conditions; it is not made into a VM/proof adjudicator.

## Current verified WKEM status

Starting live PR head: `d51d007439bae3ddbe3fe74d48436f675df40ce3`, branch `research/pq-wkem-validation-20260918`, PR `syscoin/PVUGC#1`, open/draft/unmerged. The last ordinary conversation comment is `5945825660`; it is older than the latest research commits.

The exact Run 259 source note is `GLOBAL_FINGERPRINT_SOURCE_BINDING_RUN259.md`, blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`. It supplies conditional source binding for a supplied complete representation, using an information-theoretic residual-family bound or the specified straight-line SIS reduction. Its source extractor and residual-map conditions must themselves be satisfied. It does not supply the protected release algorithm.

Run 369 is committed at the starting head. A live comparison confirms Run 368 and Run 369 are two successive commits after `7fec02b8102e49c23bc8e3be798eedbae4423967`, adding eight research artifacts. The latest work strengthens scoped failure tests; it does not supply a surviving practical local mixer, a complete QPT release reduction, or concrete 128-bit resources.

The essential missing implication remains:

`unauthorized capability recovery OR accepted pre-release authorization -> accepted ORIGINAL-source representation OR independent QPT break`.

The narrower-than-iO local primitive, all-witness common-capability correctness of an actual construction, full-public false-instance hiding, true-instance extraction, malicious setup/abort/composition and practical parameters remain unproved. No meaningful completion percentage follows from the number of runs or finite assertions.

## Missing-artifact boundary

The attached Run 370 archive was inspected and its SHA-256 verified as `ff470a253c5628d9930b45a59d588f2c0570fba8198403eea13683200ee46be2`. Its intended brief path returned 404 at the starting head. Its receipt records an explicit safety denial at the first publication write, with no returned tree, commit or comment. That is a publication block after successful reads, not a failure to access GitHub at all.

This new literature/application assessment is not a retry, renamed copy or reconstruction of that denied packet. The Run 370 packet and previously denied comments are not republished here. No historical backlog-completeness claim is made.

## Handoff

Obtain the full merged conference paper, with the full ePrint first part and current revisions where available. Audit the punctured-program proof, the quantum-CCA assumptions, the exact fixed-unary limitation, the FE key-query order and linkage/extraction definition. The first application target is public admission of a later ORIGINAL witness into a capability-bound state, not another generic mask counterexample. This is a promising audit direction, not a claimed practical WKEM or a new hardness assumption.
