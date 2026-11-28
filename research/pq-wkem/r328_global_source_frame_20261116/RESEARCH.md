# R328 — whole-ORIGINAL-certificate hash frame (NONQUALIFYING candidate screen)

## Verified starting state
PVUGC PR #1 remains open/draft, research/pq-wkem-validation-20260918 at start head `3c8020986a89d1dee43f000b1791df3ef098df44`, R327 note blob `ab7602bfc54403bf68294034557206f62d69a5dc`; R326 source blob `5d70530dd5f105aa4f78b3e9be45e01a9b5f3f44`. Recent top-level issue comments since 2026-11-14: none observed. No new Core code review or network test. R316 is a delayed-reference regression, not a failure of the strict-PQ history-consistency LC, and actual LC maturity was never tested in its synthetic fixture.

## New attempted mathematical change and explicit Build/Open
The candidate avoids R326/R327 low-degree public invalid-evaluation extraction and the earlier R289 local-gate splice by indexing each release pad by the *entire qualified ORIGINAL witness*, not by separate SHA constraints, gate labels, or source fragments. Let W_x be all canonically serialized w with VerifyOriginal(x_W,w)=1, with claim/outpoint/burn/recipient, exact safe native cancel message/VK/capsule, source baseline, actual relevant ancestors, BTC anchors, modern contextual AuxPoW, canonical tags, work/depth, windows/reset bound in x_W. For a *finite, fully enumerated* W_x, attempt:

```
Build_table(x_W, S):
  for each w in W_x:
    sample uniform r_w in {0,1}^lambda
    d_w = SHA256("ID" || x_W || canonical(w))
    e_w = S XOR SHA256("PAD" || x_W || canonical(w) || r_w)
    publish (d_w, r_w, e_w)
Open_table(C, w):
  if not VerifyOriginal(x_W,w): reject
  find row indexed by d_w
  output e_w XOR SHA256("PAD" || x_W || canonical(w) || r_w)
```

For collision-free row IDs, each enumerated original witness returns the SAME frozen S, and local mixing of partial witnesses cannot index a row. An invalid certificate cannot obtain its own row merely through an arbitrary PoW solution. With W_x empty, the empty table is exactly independent of S conditional on otherwise consistently fixed native checking data; this is trivial FALSE hiding of this *enumerative* format only, not a complete public original-capsule simulator. TRUE hard-case QPT extraction is unproved, including correlated source miner coins/native VK/sibling selective openings. Authentication is embodied only in which full certificates Build indexed, not a new implementable hash gate.

## Exact fatal resource gap and rejected repair
Build_table must know and enumerate every future qualified original source certificate BEFORE the future source observations, and may itself have to manufacture source forks or other evidence. It is not classical PPT for the original open-ended family, is not a practical finite bridge and violates the stated prohibition on exponential witness tables. In the explicit independent-ID table form, if N original witnesses have distinct IDs, at least N rows are required for every-witness completeness; T rows cover at most T/N of a uniformly sampled such N-witness family. Merkle roots authenticate rows but do not synthesize missing future rows. A shared public pad unrelated to full witness reintroduces unauthorized recovery; a public keyed row generator containing S reveals S unless independently protected, while a hidden generator is not publicly executable. A literal plaintext `if VerifyOriginal(x,w) then S` embeds S in public source. None is a new hash-only witness encryption.

The exact unresolved positive equation remains a **polynomial-size, classical-PPT public serialized compiler** Enc(x,S), with full-source globally consistent Eval(Enc,w)=S for all future qualifying original witnesses and a joint public QPT simulator/reduction against arbitrary hard-TRUE recovery/native forgery. Its generator must create the unknown witness-dependent release correlation without enumerating witnesses, using an independent instantiated cryptographic mechanism. Do not pursue larger tables, merely compressed Merkle roots or another R327 low-degree pad as this repair.

## Executed bounded check and exact limitations
Local-only Python checker `check.py` exhaustively enumerated a 16-bit toy universe, found 14 qualifying SHA256 threshold strings (NOT authenticated source work), emitted 14 hashlocked rows, checked every valid string opens the identical 256-bit synthetic S, and each invalid string lacks a row; it also recovered S by public brute-force enumeration of a row ID, and checked a trivial empty FALSE table. Checker SHA256 `6ee8fcd0643c74bebd4d37d05613ab94dcb83ee482ee88a6654cd4fbd6690479`, output JSON SHA256 `c48cf21fcc02ef9ac13fe5f8066608e55a5e524e044835bd8f07ee1ef2e42891`. Complete local derivation, checker and captured output are local only; do not claim GitHub published them, actual Bitcoin/Syscoin verification, native PQ signatures or quantum experiments.

**NONQUALIFYING ORIGINAL WKEM.** No new source-conditioned polynomial Build/Open, QPT proof, malicious setup solution or bridge deployment. No PR progress comment and no notification warranted; automation remains enabled.
