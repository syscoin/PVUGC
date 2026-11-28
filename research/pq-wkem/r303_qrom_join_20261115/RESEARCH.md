# R303 — Restricted joint-public QROM simulation for a nonlinear hash join (NONQUALIFYING)

## Exact continuity and source contract

Continue R302 (research blob `575302bd49853a5111aa7d5092d2d205fe070301`) and the exact SourceEarnedKey omission left by R301. Starting draft PVUGC PR #1 head: `18cb827a97695cad976d5d7d466711156f2665c3`, branch `research/pq-wkem-validation-20260918`. Read Core PR #609 metadata at `c91539de3c34937e57d7f5fda47c7b0502ff33f6` and its `src/auxpow.cpp` source read-only; modern contextual chain-ID and exact canonical tag rules remain prerequisites, not evidence of deployed activation. Ordinary source comment R225 #6796383617 still identifies the native signature/wtxid portability issue. No web or external research, real consensus tests, native signature generation or production changes.

Original three OR challenge branches are UNCHANGED: qualified strictly higher exact BTC cumulative-work alternative, finite authenticated defect of this withdrawal's burn, and qualified Syscoin relevant inconsistency/independently authenticated exact-parent tag fault at the required LC depth. Bind protocol and chain IDs, exact UTXO/claim, amount/recipient/authorization/replay, baseline/claim source/semantic ancestor at h_rel, anchors/window, modern AuxPoW child-merkle and 41-byte ancestor tag commitments, contextual target/height/lag, exact faulty wrapper, deadline/reset, capsule, exact safe native cancellation signature/message/VK. Same-child distinct parents are not a fork. One notary initiates, anyone with ORIGINAL evidence challenges, N-of-N is only offline preauthorization, and R225's slot-global-veto versus actually activation-bound native spend remains unresolved.

## Realized restricted classical Build and Open

This step revisits R295's nonlinear hidden-label join, deriving its *entire-public* coherent-query FALSE simulation rather than claiming source release.

Given a frozen exact native signature sigma on fixed message M and native verifying key VK, choose independent uniform n-bit R and independent hidden lambda-bit labels u0,v0, plus *public* independently sampled labels u1,v1. In a quantum-accessible IDEAL random oracle H with n-bit outputs, put

    X_ab = encode("join", x_W, capsule_id, M, VK, a, b, u_a, v_b)
    C_ab = R XOR H(X_ab),   (a,b) in {(0,0),(0,1),(1,0)}
    E = sigma XOR R.

Row identifiers and claim/capsule identifiers are encoded unambiguously and domain-separated. The FULL public capsule comprises x_W/capsule/M/VK/u1/v1/E/C00/C01/C10. The random hidden labels u0,v0 are NOT made public. An opener given both preissued labels for an eligible row returns sigma = E XOR C_ab XOR H(X_ab), checking its native message/VK. All three eligible rows open the SAME sigma. This is a **polynomial classical toy label-release mechanism**, not an ORIGINAL-source Build/Open: actual future source evidence does not furnish u0/v0. There is no valid fully public (1,1) row. Publishing C11 would immediately reveal sigma from public u1/v1 without any source witness.

## Restricted independently justified QROM simulation lemma

Let sigma and the entire native transcript (M,VK,source context, auxiliary A) have **arbitrary preselected joint distribution**, including VK correlated with sigma. Let R,u0,v0 and public u1,v1 be honestly independent of that distribution. Permit arbitrary nonuniform coherent advice determined from the context and base random oracle, provided it is *independent of the hidden target-label positions* and unpublished setup secrets. The adversary receives the entire classical capsule and has arbitrary quantum calls to H, and coherent computation including native verification. Denote its quantum-H query count by q.

Then the entire public view of the FALSE toy capsule differs in distinguishing advantage by at most

    4 q sqrt(2 * 2^(-lambda) + 2^(-2 lambda))

from the following **source-free** simulator: given only the public native context, sample public u1,v1, E and each C row independently uniformly and provide an unmodified independent ideal random oracle H. This is a theorem in the **QROM idealization only**; it does not assert programmed SHA, arbitrary SHA quantum security, general WE or ORIGINAL certificate extraction.

Proof: Couple the real game by first sampling sigma with its native context, sampling independent uniform E and setting R = sigma XOR E. Sample C00/C01/C10 uniformly and independently of E/context/hidden labels. Begin with an independent uniform random oracle H, then overwrite its three domain-separated values H(X_ab) with R XOR C_ab. Conditional on all hidden labels, this is EXACTLY the real Build distribution: the row outputs are independent random-oracle values before conditioning. The simulator omits the three overwrites. Its public E and C values are uniform even when VK is a deterministic function of sigma.

In the simulator/base oracle game, the quantum query state before query j is independent of hidden u0/v0, even if it depends on all public C/E and native auxiliary input. For any normalized query-address state the expected marked-address squared amplitude is at most

    rho = 2^(-2 lambda) + 2 * 2^(-lambda),

since row (0,0) guesses two hidden labels and each of (0,1),(1,0) guesses one. A direct quantum XOR-oracle hybrid bounds the final-state norm difference by at most twice the sum of query amplitudes on overwritten addresses. Taking expectation over hidden labels, and applying Jensen/Cauchy-Schwarz, bounds this by 2 q sqrt(rho). The displayed 4q factor conservatively absorbs trace/advantage conventions. There is NO quantum rewinding, adversary-supplied state/query log, or assumption about a concrete SHA oracle reprogramming.

For m independently generated, distinctly domain-separated unopened target capsules replace rho by m*rho (clamped at 1). More precisely, independent **opened siblings** may be given in full: condition on sibling revelations and their oracle correlations in other capsule domains, then run this same hybrid on the unopened target's independent hidden positions. The bound remains target-specific. This does NOT cover a sibling that reveals the *same* target sigma, shared/reused terminal labels, malicious correlated setup, advice that knows u0/v0, or native outpoint/activation portability. The independent-setup premise is actually realized by toy Build, but not by a malicious N-of-N protocol.

The simulator proves only that the ciphertext contributes essentially no information *beyond the existing native VK and auxiliary input*, in this FALSE hidden-label experiment. It does not prove the native signing algorithm hard. The actual sigma has already been generated at setup: EUF-CMA's fresh-message forgery game does not automatically cover extracting a signature for a message the reduction has itself asked to sign.

## Honest opening and exact non-progress boundary

When one matching label pair is independently delivered, any eligible C row returns exactly the same frozen native sigma. But the source network neither knows nor issues these setup-created private labels. Hashing future parent headers, knowing canonical SYS ancestor tags or taking the shared SHA compression midstate cannot derive them; R299–R302 already reject those substitutes. If the (1,1) row is added to give the public leaf-class a witness, R is immediately recoverable without a qualifying ORIGINAL certificate; hard-TRUE security fails. The toy's FALSE property is an artificial absence of the public row, not authenticated original source inconsistency. This iteration does NOT reduce the ORIGINAL-source foundation gap or provide a practical bridge.

## Executed reproducibility

Offline Python3 standard-library checker ran twice with byte-identical output, 643 assertions per run. It exhaustively compared the exact q=0 one-bit public transcript distribution for both fixed sigma bits (all 16 tuples uniformly supported), checked 384 correct matching preissued-label openings for 128 context/sigma surrogate setups, 128 absence-of-public-(1,1)-row controls and 128 immediate public extractions when a (1,1) row is added. Checker SHA256 `6c856655909cf1572671e61e4fe3ca2cdf4536ab95180b1db939acee07d9c2b8`; both output SHA256 `cf986e40b795aa712a22560e704e68e3a438459d44aa0b6b12d51eeaaa1b5a97`. Complete checker, outputs, longer proof and manifest in local reproducible archive `R303_qrom_join_20261115.tar.gz` SHA256 `fb229a4eaee3a6e7f6386f884fc97a13f4ea3462cc7fea76e4b57145272cd20c`. Toy execution did NOT run quantum algorithms, real native signatures, source validation, Core tests, actual best-chain proof or malicious ceremony.

**Disposition NONQUALIFYING.** Next equation must *construct* source-earned, cryptographically integrated labels or another real classical-PPT public Build_inc/Open_inc for EVERY authenticated ORIGINAL witness returning the same claim-safe sigma, with independent complete-public QPT FALSE/hard-TRUE recovery or accepted native forgery -> ACTUAL ORIGINAL certificate or independent PQ break under malicious setup, native auxiliary correlations and sibling selective opening. Do not optimize restricted toy components or claim release from a post hoc source verifier. No PR comment, user notification or automation-stop is warranted.
