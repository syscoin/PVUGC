# Run 472 — false-instance capability one-wayness implies one-bit WE (conditional)

Starting live `syscoin/PVUGC#1`: open/draft, branch `research/pq-wkem-validation-20260918`, SHA `7ce5a63c9ddd4005f0c124639bb595d59f52cb4a`. Latest ordinary comment `6067040320`. Exact inputs: Run 259 source binding blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`; Run 470 gauge-seam blob `18c48d7e6773c138f5d488508fe42f0de300fef9`; CLZ applicability blob `c19d9d9cd515140e3ce62eac960cd548c0add622`.

## Conditional reduction (known Goldreich–Levin theorem, new applicability checkpoint)

For any NP relation R, suppose classical PPT `CapGen(x)->(P,K)` works even for false x, with explicit polynomial-length K. P includes every public program, native checking key, setup transcript and bound x/context. Every valid ORIGINAL w makes classical PPT `CapRec(P,w)` output the SAME K with overwhelming probability. Assume false-instance **exact K recovery** remains QPT-hard even given the complete P and permitted joint auxiliary view. Do NOT assume raw K is pseudorandom alongside its public native checking key: a candidate K can be tested by signing and verification.

Define one-bit witness encryption: choose random r in {0,1}^|K|, set c=m XOR <r,K>_2, publish (P,r,c). Given valid w, decrypt with `c XOR <r,CapRec(P,w)>_2`. If a QPT adversary distinguishes encryptions of 0 versus 1 for false x, on random c it predicts <r,K> with nonnegligible advantage. Classical-query Goldreich–Levin list decoding with independent QPT predictor invocations recovers K with inverse-polynomial probability, contradicting exact-key one-wayness. This is a standard hardcore-bit reduction, NOT a new hardness assumption, concrete mixer, or construction of practical WKEM.

**Quantum scope:** works for uniform QPT predictor circuits (and independently reproducible advice) with coherent access to all published classical programs. Uses no QROM programming or rewinding. The proof does **not** cover one unknown non-reproducible single-copy quantum advice state that the extractor must clone. It also does not establish arbitrary-QPT capability-to-ORIGINAL extraction or the full required multi-capsule game.

**Consequence:** a generic all-NP same-explicit-K release primitive with full-public false-instance QPT exact-key hiding already realizes bit WE as a black-box functionality. The protected *circuit region* may be smaller than a generic verifier and the algebraic assumptions may still be more structured; this result does NOT rule out such an implementation or prove equivalent assumptions. But it rules out claiming a genuinely weaker **generic-NP functionality** merely by renaming release as local mixing.

## Crucial independent failure game

Exact K secrecy is NOT enough for native authorization. For any secure signature Sigma, pad the secret as K=(SK,tau), let Sign ignore random tau, and let P reveal usable SK while concealing tau. Recovering exact padded K remains hard but signatures are trivial to forge. Thus `unauthorized native signature -> accepted complete ORIGINAL representation OR independent QPT break` must still be proved. Run 259 only supplies the downstream `accepted representation -> ORIGINAL witness` (statistical folding or stated SIS reduction), and cannot bridge this missing arrow.

Likewise isolated K1 hiding is not joint hiding: if K1=K2 and opening another capsule reveals K2, claim 1 is compromised without its witness. Bound relation/UTXO/branch and use distinct keys, but joint security still needs proof. Honest-erasure N-of-N is permitted; keyless retained-coins setup is unproven.

The exact finite checker demonstrates K in {0,1}^6 with P revealing a prefix: for hidden h=2,3,4,5 bits the optimal one-bit encryption distinguishing total variation and full-key guess both equal 2^-h, although literal K versus independent candidate K under P has statistical distance `1-2^{-(6-h)}`. It separately tests capsule key reuse and the padded signing-key separation. 610 assertions passed; two executions were byte-identical. These finite tests do NOT prove the QPT Goldreich–Levin reduction or cryptographic parameters.

Relevant attacks: checking-key fingerprint (8); multi-capsule key reuse (4,7); public coherent computation and classical-query reduction (5,9). Seam/gauge (1,2), statistical source classes (3), malicious setup (6) remain outside this reduction and not proved safe. No new local-mixing assumption was introduced.

**Unresolved:** implement genuinely public late ORIGINAL-witness admission; all-witness SAME native capability and actual false-instance QPT hiding; native forgery/recovery -> accepted COMPLETE representation; one-copy quantum auxiliary inputs; malicious setup/abort; multi-capsule; concrete 128-bit costs; conditional P2MR/native-SLH endpoint. No practical PQ WKEM, no Bitcoin/production change. Keep draft PR unmerged and automation enabled.

References: Goldreich–Levin (STOC 1989), https://doi.org/10.1145/73007.73010 ; Adcock–Cleve (2001/02) quantum variant https://arxiv.org/abs/quant-ph/0108095 . The classical-query lifting above is narrower than claiming arbitrary quantum-advice proof security.
