# R199 — Pair-interpolated source shares as a fixed challenge capability

**Status: non-qualifying diagnostic, NOT a source-dependent Build/Open or PQ WKEM.** The exact identity is functional for hypothetical source shares. Actual Bitcoin/Syscoin evidence does not supply them. No routine user notification or ordinary PR comment is warranted.

## Continuity and provenance

- Existing draft/open PVUGC PR #1, branch research/pq-wkem-validation-20260918. Starting SHA: 1355cc2aeb069ef7829b00d276378fb1434fb910. Exact R198 prior research read at blob da4b6422998cbd881a4411e485a75e2ae0f9de39. Latest relevant ordinary comments query since 2026-11-10T00:00Z returned none.
- Genuine intermediate hypothesis checkpoint published first at commit 4520a495692e50d187bc6a5a637bd47cac903014, parent 1355cc2aeb069ef7829b00d276378fb1434fb910. Checkpoint publication is not research progress. Corresponding local checkpoint uses different formatting and is not byte-identical to published checkpoint.
- Full local Python stdlib checker actually executed twice, with byte-identical stdout, source SHA256 eb701d2d178c7f33faee9a6768aaa235ae35260ec4fa4cd77fb167cf61d9d624 and output SHA256 38fa7704a595a0df02f6a9ed39363e8af79a3bd5c06ce9053bb126d1641887f6. It records 6,425 arithmetic assertions, not security tests. This larger checker is LOCAL ONLY.
- Separately executed smaller published_checker.py was run twice with byte-identical output; source SHA256 52df324554404f0d4ca48e0007d0799cb18f278ef27c306251cda0c4d6e20ca5 and output SHA256 5d944fa275fc4a99aa881b1504aed2d95bfc32d435d6a1ac6eb988ad8aabc175. Captured output is published in published_captured.json. It tests 128 deterministic synthetic triples and nine isolated share-bijections.
- No external web or literature, real Bitcoin/Syscoin headers, mining, AuxPoW/PoB verification, quantum attack, native PQ signature, independent agent or production write. SHA256-derived byte strings are synthetic fixtures and NOT fake headers presented as source witnesses.

## ORIGINAL objective

One notary may activate a preauthorized withdrawal. One of three qualified finite ORIGINAL challenge witnesses (greater relevant BTC work, absent/invalid PoB for the bound withdrawal, or authenticated Syscoin claim-prefix/tag inconsistency with sufficient depth) must cause every honest N-of-N setup participant's capsule to release the SAME frozen claim/path-scoped cancellation signature OFF CHAIN. All original evidence must validate actual anchors, UTXO/burn/recipient, ancestor linkage, tag schedule and observation window. Different Bitcoin parent-work certificates of one pure Syscoin child are not forks. No Bitcoin original verifier, BitVM trace challenge, online release party or new signature opcode is assumed.

Full-public adversarial view includes relation/claim, complete capsule, checking keys, native VK, source commitments, setup and source auxiliary information, corrupted setup shares, sibling capsules and selective openings. Classical PPT Build and Open; arbitrary nonuniform QPT adversary and any coherent oracle queries in any expressly stated QROM. The present construction DOES NOT supply an extractor or joint simulator for that game.

## Named candidate: R199 source-pair Shamir intercept

Let p be a prime, z(o) be a NONZERO semantic source-outcome coordinate in F_p, and k in F_p be one frozen secret share. Build samples a uniformly random slope a and defines f(z)=k+a*z. If source certificates genuinely delivered y0=f(z0) and y1=f(z1) for z0 != z1, public interpolation gives

    Recover(z0,y0,z1,y1)
       = (z1*y0 - z0*y1)/(z1-z0) mod p
       = k.

This is an exact algebraic identity for ANY pair on the same line. It solves the *synthetic share* fixed-output problem regardless of which two different semantic outcomes are used. It DOES NOT solve ORIGINAL witness release, since authenticated AuxPoW/TAG histories give z0,z1 but no setup-correlated y0,y1.

**Isolated privacy lemma:** For fixed k and nonzero z, uniformly random a makes y=k+a*z uniform and independent of k. The map a->y is a bijection, so this is information-theoretic against any observer of that one classical share, including a quantum observer. z=0 is excluded since y=k. The lemma does NOT cover the public capsule, check key H(k), related openings, malicious retention of k/a or a joint multi-capsule QPT game. With two actual shares the key is deliberately reconstructible.

## Why original SHA/AuxPoW source does not instantiate the missing interface

1. **Public polynomial coefficients/evaluator:** Publishing k,a (or a freely evaluable f) exposes k=f(0) immediately; any two fabricated points also interpolate it. This is exact classical early recovery without an ORIGINAL witness.
2. **Use a public hash as y:** Actual source tag/hash bytes are publicly computable from source transcripts; they are not evaluations on a private line. Three independent synthetically hashed outcomes fail pair-key convergence. In an ideal model with y values uniform independent in F_p for three fixed distinct z, the third point lies on the line through two points with probability exactly 1/p. This is an idealized finite-field calculation, not a theorem about actual Bitcoin header distributions or SHA.
3. **Future-event table:** Enumerating or precomputing shares for all future qualified headers/source histories is not polynomial setup. Publishing rows indexed by arbitrary PoW digest allows the R198 bypass: a digest can be chosen without its actual source header/certificate.
4. **Keep one N-of-N participant's polynomial secret:** This can protect against corrupted setup participants while that participant's shares remain inaccessible, but it also means a future public challenger cannot compute that participant's evaluations from ordinary headers. A live evaluation service violates the no-online-authority requirement. Giving secret coefficients to the miners earlier permits retained-secret bypass.
5. **Proposed SHA-round-state repair:** A real SHA256d trace (round midstate, digest bits or coinbase hash) could define a public y, but absent a mechanism enforcing y=k+a*z across EVERY qualified future history, pair outputs diverge. Keying the trace derivation to the setup line merely restates the missing source compiler. A public verifier placed before decryption does not stop raw evaluation.

The synthetic deterministic checker confirms the first, second and zero-coordinate failures. It never authenticates a real Bitcoin/Syscoin claim, and has no oracle experiment or full-public QPT test.

## Exact unfinished equation and handoff

    Build_inc(R_ORIGINAL, x_W, sigma_cancel; coins) -> (C, CK) in PPT
    PublicDerive(C, w) == SAME sigma_cancel
       for EVERY qualified ORIGINAL challenge w
    arbitrary full-public QPT signature/key recovery without w
       -> ACTUAL ORIGINAL certificate or separately justified PQ hash/native break.

This candidate's arithmetic supplies only Recover(z0,y0,z1,y1). **The algorithm SourceDerive(original evidence)->y=f(z), including its source enforcement and joint QPT simulator, is MISSING, not proof polish.** Two different tags or work hashes are not such shares. It would require a noninteractive, setup-correlated, hidden evaluation generated by genuine consensus evidence, unavailable to fabricated transcripts and malicious-source retained coins. No current source format provides it.

Next constructive iteration should either instantiate that exact cryptographic source-to-share operation from actual SHA/AuxPoW bytes, or abandon this family and pursue a nonblackbox compact SHA/Boolean verifier compiler whose full-public simulator is specified alongside Build. Do not optimize field sizes, secret sharing, proof compression or enumerate work outputs while this interface is absent. R195 claim-prefix projection, the three original challenge branches and native endpoint caveats remain intact.

**Conclusion: no secure hash-only WKEM, no source-dependent Build/Open, no QPT extraction or standard-model SHA theorem.**
