# Run 559 — Public-binding target-pseudoentropy support barrier

Date 2026-10-16. Draft PR research only. Starting exact head `18073a44fa92ac789140c439b3002e8e6c6eae4f`. This is one bounded follow-up to Run 558, not an attempted practical WKEM.

## Focused source and new scoped lemma
Wichs–Zirdelis, *Obfuscating Compute-and-Compare Programs under LWE* (FOCS 2017), p.601 §I.A, https://ieee-focs.org/FOCS-2017-Papers/3464a600.pdf, distinguishes a **high min-/HILL-pseudoentropy target** given the public function and auxiliary data (basic LWE route) from a merely **computationally unpredictable** target (requiring additional assumptions, e.g. random oracles or extremely lossy functions). This exact distinction matters for the Run 558 injectively bound hidden-target relation.

**Public recognizer support lemma.** Let `(Z,Y)` contain the public function, source claim, public binding, public signature verification key, all other capsules and auxiliary outputs. Suppose a classical PPT predicate `Q(Z,y)` accepts the real `Y` with probability one, and its accepting set `{y:Q(z,y)=1}` contains at most `d` candidates for every `z`. For any substitute distribution `(Z',Y')` satisfying

`sum_z Pr[Z'=z] max_y Pr[Y'=y|Z'=z] <= 2^-h`,

we have `Pr[Q(Z',Y')=1] <= d*2^-h`. Proof: conditional union bound over at most `d` accepted values, then average over `z`. Thus the efficient distinguisher `D(z,y)=Q(z,y)` separates the real joint distribution from any such surrogate with advantage at least `1-d*2^-h`. In particular, when `d=poly(lambda)`, no HILL surrogate with superlogarithmic average conditional minentropy can satisfy computational indistinguishability. This is a conditional-entropy theorem, not a recovered-key attack.

For any public binding `P=G(Y)` with fiber sizes at most `d`, choose `Q((G,P,...),y)=[G(y)=P]`. With an injective `G`, `d=1`, **publicly bound Y cannot possess positive HILL target pseudoentropy in this sense, even if G is a QPT-hard one-way permutation**. A candidate-checking algorithm does not invert G on its own. Computational target **unpredictability** may still hold, but the FOCS paper's additional-assumption route—not its high-pseudoentropy/basic-LWE route—would be required and needs independent QPT assessment.

The support bound is tight for this one tester: when `G` has a fiber of `d` values, a target uniform inside that fiber has minentropy `log2(d)` and passes `Q` with probability one. That does not prove indistinguishability under other tests.

## Relation correctness scope
For `R_*((G,f,P),w)=[G(f(w))=P]` and `MBCC[f,Y,K](w)`, injective G implies all valid ORIGINAL witnesses have `f(w)=Y` and therefore recover exactly the same K. A public bound P simultaneously removes the **high-pseudoentropy premise**. Witness multiplicity does not increase entropy of Y given P. If G is noninjective, any second fiber member reached by f yields an ORIGINAL-valid witness that MBCC targeted at Y rejects, violating all-witness correctness unless independently excluded. Public exclusion tests may shrink the usable entropy support again.

The executed finite checker tests affine toy permutations with `f(w)=floor(w/2)`, hence two valid witnesses per target, and bounded-fiber maps `G(y)=y>>r` at widths 2..8. These are **not** one-way functions or cryptographic obfuscators.

## Attack and QPT ledger
(1-2) Seam/gauge cancellation: not applicable to this abstract MBCC primitive. (3) Public-recognizer fingerprint Q is the exact distinguisher. (4) Multiple views/capsules cannot restore pseudoentropy: D may ignore them; they may add leakage. (5) Chosen-input evaluation unnecessary. (6) Biased or malicious setup not addressed. (7) Cross-UTXO/branch replay needs independent binding. (8) Native verification key and its correlations are included in Z, but no signature forgery reduction follows. (9) The explicit classical D is also QPT, yet no coherent-only break or positive QPT security of a real obfuscator follows. All honest finite computations are classical polynomial time.

Run 259 still only extracts ORIGINAL witnesses from representations satisfying its exact accepted-representation interface; arbitrary capability recovery/native forgery is not such an interface. This lemma neither proves full-public false-instance QPT hiding nor unauthorized true-instance recovery-to-ORIGINAL extraction. N-of-N honest-erasure ceremony, keyless malicious-builder security, resource sizing and conditional P2MR/native-SLH endpoint are unchanged and unproved. The underlying intended source relation remains off-chain SYS/BTC fork and AuxPoW authentication, not the toy relation.

**Handoff:** Either justify the *unpredictable-target* WZ route with its additional assumptions and full auxiliary/QPT proof, or seek a different independently justified source-authenticating local release primitive. Do not claim standard-LWE-only security via HILL target entropy when a public singleton binding exists. No complete practical PQ witness-KEM is established.
