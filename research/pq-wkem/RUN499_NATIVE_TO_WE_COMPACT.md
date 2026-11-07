# Run 499 — native signing-key release implies one-bit witness encryption (conditional)
Live starting PR head: `ac5ff3ac6223e103acd43783cddc46ce40dd9d9a`; draft branch `research/pq-wkem-validation-20260918`. This is a known Goldreich–Levin deduction adapted to the specific same-capability release interface, not an implemented mixer or a practical WKEM.

## Exact theorem and scope
Assume a classical-PPT honest capsule generator (or centralized simulation of a complete honest N-of-N ceremony) produces public view `V=(P_x,VK_x,all public aux)` and the **specific** native signing secret encoded as `K_x in {0,1}^L`. Every ORIGINAL witness w with R(x,w)=1 permits classical-PPT `Open(P_x,w)` to recover precisely that same K_x. For false x assume no **uniform QPT** algorithm with repeatably preparable quantum auxiliary inputs can output that K_x with nonnegligible probability, even given the entire public view and coherent access to all public evaluation algorithms.

Build a one-bit WE ciphertext for bit b:
`(P,VK,K) <- HonestBuild(x); r <- U({0,1}^L); c <- b XOR <K,r>; output (P,VK,r,c)`.
Given a valid ORIGINAL witness, recover K and calculate `b=c XOR <K,r>`. All-witness SAME-capability correctness makes this correct without canonical intermediate states.

For a false statement, suppose D distinguishes encryption of 0 from 1 by gap epsilon. Predict `<K,r>` from `(V,r)`: choose independent uniform c, run D on `(V,r,c)` to guess the message bit, and return `c XOR D` (orient D appropriately). The predictor has success `1/2+epsilon/2`. Conditional on fixed (V,K), classical Goldreich–Levin Hadamard list decoding recovers a polynomial-size candidate list containing **exact K** on a nonnegligible fraction of views when epsilon is nonnegligible. Select a candidate uniformly, obtaining exact-K nonrecovery contradiction. Full public VK can contain literal bits of K or arbitrarily correlated information: it is frozen in V throughout decoding. No claim of raw-key pseudorandomness is needed.

The decoder makes polynomially many fresh invocations of D. It is QPT if D's quantum state can be re-prepared for each invocation; no rewinding or QROM programming is involved. **The reduction is NOT established for a single non-copyable non-reproducible quantum advice state.** Arbitrary auxiliary-input QPT security remains outstanding; no actual post-quantum release scheme has been proved.

False-instance native-signature security implies the required false K nonrecovery: recovered K immediately signs a fixed admissible challenge message. For polynomial payloads, fresh independently simulatable capsule/key instances per message bit and a standard hybrid imply a polynomial-overhead WE for the *supported* relation. If the compiler supports arbitrary NP, it is already WE-powerful under the stated QPT qualifier. If only syntactically funded Syscoin claims are admissible, the conclusion has only that restricted scope. This does not prove local mixing is impossible or settle relative hardness in stronger models.

## Focused falsification
Seam/gauge/fingerprint/related-capsule leaks that reveal K violate the premise; the theorem does not repair them. Public chosen inputs and coherent public evaluation are allowed to D. Corrupt dealer retaining K (Run 498) violates the premise; setup ZK cannot prove erasure. Cross-UTXO/branch relations require binding and independent keys. Native VK correlations are handled explicitly. No new genuinely quantum *attack* is claimed, and independent quantum advice is unresolved. The separate Run 259 source extractor starts only after an accepted COMPLETE source representation and cannot be substituted for this nonrecovery premise.

## Exact finite diagnostic
`run499_compact_hardcore_check.js` is the actual function executed to produce the captured JSON. It evaluates 18 exhaustive Walsh spectra for widths 5..10, with a **hypothetical oracle deliberately given K**. It verifies correlation equals IND distinguishing gap, exact Fourier reconstruction despite publicly exposed K suffix bits, and four valid source states returning the same K. Tests do not instantiate cryptography.

Literature: Goldreich–Levin, STOC 1989 (hard-core predicate); Adcock–Cleve, STACS 2002, https://cs.uwaterloo.ca/~cleve/pubs/goldreich_levin_stacs.pdf (Sections 2–3 on quantum GL query models). No full RIO implementation/security proof was established. No N-of-N ceremony, full QPT-advice theorem, 128-bit parameters, native SLH endpoint, or Bitcoin graph is implemented.

**Handoff:** The theorem exposes an essential hardness floor for a *generic* one-key release compiler. Constructing the release primitive and establishing the original true-instance unauthorized signature -> accepted representation/ORIGINAL (or independent QPT break) remain UNPROVED. Production unchanged; keep PR draft, unmerged and the research task enabled.
