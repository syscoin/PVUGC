# SAI110 — Independent trapdoor proof-token attempt for the ORIGINAL fork release (NONQUALIFYING)

## Source and selection
Read live open/draft syscoin/PVUGC PR #1 on branch \`research/pq-wkem-validation-20260918\`, starting at \`e9fc89737cfceecbeb5d573f76bdc6eae528680a\` (SAI109 checker-alignment head), base tree \`253ba46d43b22a729b2587836a14635371e6a462\`. Read the exact SAI109 / SAI108 / SAI107 / SAI106 / SAI105 / SAI103 / SAI102 notes at this head, and scoped ordinary comments since 2026-11-18T19:24:00Z returned []. No Core source, network certificate, Bitcoin signature, proof system, or FE implementation was run. Prior FE assessment at \`69d4a071\` remains conditional and supplies no compiler.

Previous failure: a future-witness hash/proof root is not a common precomputed token; explicit low-degree or public label carriers splice/leak. This attempt changes the source-release operation: builder holds an **independent setup trapdoor** permitting it to produce a purported *unique proof token* \`pi_i*\` before any future source witness; all future ORIGINAL witnesses are supposed to project back to precisely that token. This is not merely a relabeling of first-divergence categories, proof-root tables, or public GGM prefixes. Test the trapdoor/source correlation before encoding a full circuit.

## Proposed actual hash envelope, and missing projection

For one setup participant i with session/claim x and native fixed safe cancellation signature sigma_i, choose uniform hidden token tau_i, set

    pi_i* := tau_i
    Y_i := H_1(domain || sid || i || pi_i*)
    K_i := H_2(domain || sid || i || pi_i*)
    D_i := sigma_i XOR K_i
    C_i := (x, sid, i, Y_i, D_i, native VK/message, exact policy/version)

This Build envelope is efficiently serialized and hash-only, **but it is NOT an implemented release scheme**. A possible Open would first obtain, by a *public* source-dependent algorithm, a token \`pi_i(w)\` from an ORIGINAL qualifying certificate w; check \`H_1(pi_i(w))=Y_i\`, and return \`D_i XOR H_2(pi_i(w))\`. Merely appending \`VerifyOriginal(x,w)\` after finding pi by arbitrary hash inversion is not a source gate. The cryptographic projection must itself be bound to the actual authenticated source.

Exact unconstructed equation:

    PublicProject_i(C_i, w) = pi_i*     for EVERY ORIGINAL R_x(w)=1

while *all* public processing without qualifying source evidence cannot recover sigma_i or a native valid unsafe output without an independently justified hash/native break. Build knows pi_i* but future original certificates have unrelated mined parent hashes. Ordinary FS/SNARK proofs of different certificates produce different proof bytes/roots; their hashes do not reconstruct pi_i*.

This attempt also has an important one-honest setup property: if each party chooses independent pi_i*, the **same** original w must recover every independent pi_i* without any party online. Replacing all pi_i* by one publicly released shared token leaks all signatures; letting a colluding participant retain a common secret invalidates the one-honest security claim. A setup ZK proof of generation/graph binding can check capsule correctness but cannot supply PublicProject.

## Restricted independent-source calculation (not general impossibility)

In the **specific two-hash-envelope model** above, the only secret-dependent public bytes are (Y_i,D_i); no hidden program/correction coupled to original source facts exists. Let a source generator produce future qualifying W using the public C and independent source randomness, without private setup tau_i, and suppose the source/hash interfaces used by it are independent of the hidden-domain H_1,H_2 values except via public C. Then the causal Markov condition

    (tau_i, K_i, sigma_i) -> C -> W

holds in that restricted model. Consequently

    P(K_i,sigma_i | C,W) = P(K_i,sigma_i | C)

for every supported public transcript and W; this continues with arbitrary source selection P(W|C), including selection adapting to all **public** capsules, provided no additional private-setup correlation enters the source generator. This does not prove computational FE/WE impossibility: a real FE capsule could have a hidden source-coupling mechanism in C, and information-theoretically S can be a function of C while computationally hard to extract. It only states that attaching an independent source certificate to this *uncoupled hash-lock* creates no new conditional information on the hidden token. In a finite model with a nondegenerate conditional posterior, even an unbounded prescribed opener using W cannot identify sigma_i for every hidden setup state compatible with C.

A source miner can choose W adaptively after reading C, and source proofs can be computationally expensive; neither fact constructs a relation between *the hidden preimage pi_i** and W. To escape this restricted model one needs a real public, source-dependent coupling in C, e.g. a projective hash or protected global evaluator with ORIGINAL witness extraction and all-witness convergence. Declaring PublicProject an oracle, FE, NIWO, witness PRF, unique proof, or extractable simulation premise is not an independently instantiated advance. No "one-way hash implies source-projectivity" inference is made. Arbitrarily programmable SHA / QROM oracles are not concrete SHA security proofs.

## Actual finite checker

Ran \`check.py\` twice locally under Python3 with byte-identical \`output.json\`. It exhaustively enumerates a finite 32-state hidden token, an 8-value hash image, 32 secret states, and two synthetic source witness types. The synthetic source selection distribution **depends on both public Y and D**, not on hidden tau. For every posterior cell it checks exact integer cross-products for equality of P(K,S | Y,D,W) and P(K,S | Y,D): 1,984 equalities, zero difference. The entropy example deliberately has multiple hidden preimages for some public Y, unlike an arbitrary concrete 256-bit SHA instance. Its result is a mathematical finite-model crosscheck, NOT security for real SHA, an ORIGINAL source proof, actual BTC/SYS PoW, one-honest setup, native ECDSA, FE, or QPT.

SHA256(check.py): \`86a031343cd9f3d9630dcf1c82586272949b9015ea63d02ae48730ea983aefb1\`; Git blob SHA1 \`3d248558eb84258da79321dfdba5f836ad98ab1d\`.
SHA256(output.json): \`4dba2df91ec3343bf68016d1b53964aa8360c57571744909625ee061979463d1\`; Git blob SHA1 \`856b75b6af6a4a5cf7c268cb24ef001bbfe15bf3\`. Repeat output was identical.

## ORIGINAL requirements and next equation

This restricted countercheck does **not** alter the three independent OR grounds: qualified strictly greater Bitcoin work on the same relevant anchor; finite authenticated specific burn fault; qualified Syscoin incompatible history/tag fault at required LC depth. The R316 correction stands: strict post-PQ canonical tags can still reference a common pre-fork ancestor until the scheduled tag advances, while a proper LC can detect actual incompatible child history. Contextual modern chain ID, exact 41-byte canonical SYS tag, distinct child Merkle commitment, actual h_rel ancestors, all relevant source interval checks, work/anchors/windows, complete claim/UTXO/burn/amount/recipient, deadline/reset, native safe message/VK/capsule ID all remain mandatory.

Next genuinely constructive problem: implement a polynomial-size, classical, entirely public **original-source-coupled** projector or different \`Build_inc(x,sigma_i), Open_inc(C_i,w)=sigma_i\` in which arbitrary future valid evidence recovers the same frozen output without exposing direct invalid-input pads. Construct its **joint** full-public FALSE/hard-TRUE QPT simulator and arbitrary-recovery-to-actual-ORIGINAL-certificate / independent PQ hash break, including malicious source coins, native VK and multi-capsule selective opening, *before* another parameter/code-size pass. Independent traps and an ordinary ZK correctness proof alone do not do it.

**NONQUALIFYING**. No complete source FE, native forgery theorem, malicious-setup/useful-completeness theorem, Core tests, deployment or breakthrough. No user update or ordinary PR progress comment warranted. Do not repeat this trapdoor proof-token pattern as another proof-root or source-salt candidate absent a genuinely new public source-coupling equation.