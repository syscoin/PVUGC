# Rank-separated Macaulay SOURCE: lossless adaptive opening and same-key related capsules

**Status: positive restricted composition proof; NOT a generic post-quantum witness-KEM and NOT a recovery-to-ORIGINAL-witness reduction.** This is a direct continuation of `research/pq-wkem/macaulay_rank_pad_20261029/RESEARCH.md` (restricted rank-separated fixed-FALSE confidentiality) after the documented rank-degenerate FALSE counterexample in `research/pq-wkem/macaulay_rank_degenerate_false_break_20261029/RESEARCH.md`. We neither modify nor rehabilitate the broken rank-degenerate case.

## Specific previously incomplete interface

The predecessor's reduction guessed one unopened share index, incurring a factor `t` and covering only related capsules with independently generated native keys. This record gives an **explicit online, no-guess, exact joint-output simulator** for adaptively opened *whole shares including their full encryption coins*, and for polynomially many independently encrypted rank-separated FALSE capsules **sharing the same genuine native checking key**. The same-key extension is limited to rank-separated FALSE sources, and every capsule must retain at least one undisclosed complete share. It uses no SOURCE-opening oracle, no QPT rewinding, and no adversary-volunteered representation. The result follows from an exact coin-equivocation identity, not an unproved computational assumption.

## Honest classical distributions and ORIGINAL binding

For each claim/path `i`, let the publicly bound statement `x_i` include ORIGINAL relation identity, claim/UTXO, branch, authenticated anchor/window/context and the intended checking key and challenge path. The predecessor's classical PPT Boolean Macaulay compiler produces public `(A_i,U_i)` with `A_i in F_q^{n_i x m_i}`, `U_i in F_q^{n_i}`. In this theorem **each target and same-key related capsule is a fixed FALSE instance with a publicly checkable rank certificate**

`A_i^T z_i = 0`, `U_i^T z_i = 1` over `F_q`.

This is equivalent to `U_i not in Im(A_i)` and independently decidable by linear algebra. It does **not** cover every fixed FALSE instance, and the latest Pasch 3-XOR counterexample specifically lacks this certificate at degree 3. No ORIGINAL witness exists for these FALSE statements. On TRUE statements the predecessor's actual offline witness evaluator computes `Phi_D(W)` and deterministically recovers the same precommitted capability for every ORIGINAL witness; that TRUE correctness result is unchanged, but its hard-TRUE security is unproved.

Generate `(K,pk)` using an actual independently assumed QPT-EUF-CMA native signature scheme, with `K` the complete fixed-length encoded secret capability. `K` need not be uniformly distributed. For each capsule `i`, independently generate `t_i>=2` uniform bitstring XOR shares `Z_{i,j}` of length `|K|`, and set a public mask `M_i = K XOR Z_{i,1} XOR ... XOR Z_{i,t_i}`. All source/ciphertext coins are independent across every digit, share and capsule. Encode each share in base `T=floor(q/g)>=2`, with `g=2m_i+3`, `h=m_i`, and `q` an adequate odd modulus. For each digit `a`, independently sample `s <- uniform F_q^{n_i}`, `e <- uniform {-1,0,1}^{m_i}`, `eps <- uniform {-1,0,1}`, and publish the COMPLETE ciphertext

`c=A_i^T s+e`, `d=U_i^T s+eps+g*a` modulo `q`.

The public output includes `(R_i,x_i,claim/path,anchors/window,context,A_i,U_i,c,d,M_i,pk)`, all other authorized capsules, and independent/admissible auxiliary inputs. The off-chain release algorithm on a valid ORIGINAL witness and the native signature on the intended challenge path are exactly the predecessor's; Bitcoin verifies no NP statement, proof trace or Macaulay equation. Full on-chain PQ signing support remains only a conditional endpoint assumption.

## Exact ciphertext coin-equivocation lemma

For a fixed rank certificate `z`, let `Coins=(s,e,eps)` and `Enc_a(Coins)=(c,d)` above. For **any** two digits `a,a' in {0,...,T-1}`, define the classical polynomial-time bijection

`Eq_{a -> a'}(s,e,eps) = (s + g*(a-a')*z, e, eps)` over `F_q`.

Then **both published components are exactly unchanged**:

`A^T(s+g(a-a')z)+e = A^T s+e = c`,

`U^T(s+g(a-a')z)+eps+g*a' = U^T s+eps+g*a = d`.

The map is invertible and carries uniform `s` to uniform `s`, even conditional on independently sampled `e,eps`. It is a pointwise equality for the **entire** ciphertext, not a marginal pad-hiding hybrid. It remains true for every digit and each capsule's public statement, regardless of the content of other independent capsules or the actual checking key. It explicitly shows this FALSE-source encryption is perfectly equivocable, hence **not binding**; public hashes/commitments on coins, adversarial opening receipts, hidden-coin leakage or reuse are not included by assumption.

## The no-guess adaptive whole-share simulator

**Real experiment:** generate `(K,pk)` honestly; for each rank-separated FALSE capsule generate shares `Z_{i,j}`, mask `M_i=K XOR XOR_j Z_{i,j}`, and all honest ciphertexts and coins. A QPT adversary sees the full public view, can call a *classical authenticated Open oracle* that reveals the exact `Z_{i,j}` and ALL its encryption coins `s,e,eps`, and can adaptively choose openings based on public ciphertexts, masks, preceding openings, and ordinary signing-oracle replies. Within each capsule, it may open **at most `t_i-1` distinct whole shares**, including all their digits, but not the final share; opening the full native `K` or the protected share's coins is excluded. Other adversarial computation is arbitrary coherent QPT, with independent/nonuniform advice reproducible from permitted public inputs. A native signing oracle, if present, answers classical message queries. Related same-key capsules are honestly generated with independent shares and coins; adversarial statement choices are permitted only if their required public rank certificates exist. Other independently keyed capsules can be honestly simulated.

**Simulator given only native challenger `pk` (and its allowed signing oracle):** sample every `Z_{i,j}` and its encryption coins honestly and encrypt it; *independently sample* each `M_i` uniformly, rather than computing it from unknown `K`. Keep these sampled shares and coins to answer **any** adaptive admissible Open queries exactly, without predicting which share will remain unopened. Generate all publicly simulatable auxiliary data and independent-key related capsules honestly, and forward target signing queries to the native challenger. There is no challenge secret or SOURCE-opening oracle in this algorithm.

**Exact coupling proof:** Fix `K` and any completed permitted interactive transcript. In each capsule choose *after* observing the transcript any unopened index `J_i` (one always exists). The simulator's initially assigned share values need not XOR to `K`. Reinterpret exactly the hidden share as

`Z'_{i,J_i} = K XOR M_i XOR (XOR_{j != J_i} Z_{i,j})`.

For each radix digit, apply `Eq_{a -> a'}` to **only that hidden share's unexposed encryption coins**. Its complete public ciphertext remains identical; all opened shares and their entire original coins remain unchanged; the public masks, checking key, source, contexts and related capsules remain unchanged. The transformation is measure-preserving because the masks were uniform and every coin shift is bijective. For a transcript-dependent `J_i`, partition the execution by the public/adaptive opening trace: the transformation does not modify that trace, and hence preserves each partition. This proves identical distributions of **complete transcripts**, not only fixed opening subsets. Repeat independently per capsule, conditional on any fixed genuine `K` and `pk(K)`, so **polynomially many same-key FALSE capsules introduce no guessing factor**. Adaptive classical signing replies do not change the coupling; by induction the adversary's QPT state and any coherent processing of identical classical transcripts have exactly identical distributions. This does NOT assert security under quantum superposition access to Open or Sign or under signing-secret-correlated advice.

A naive attempt to fix one unknown unopened index beforehand yields a `t_i` (and possibly product-of-`t_i`) loss. The explicit simulator instead opens every requested share honestly, leaving one *post-hoc* equivocable ciphertext, and loses **zero guessing probability**. This is a genuine reduction improvement for this restricted but independently instantiated class.

## Complete-public native-security reduction, exact loss

Run the above simulator under the native scheme's QPT EUF-CMA challenger. If the adversary outputs a valid fresh signature on the intended target path, forward it as a native forgery. If it outputs the actual complete native signing capability `K` (or any alternative usable secret yielding a valid signature for the challenge `pk`), generate a fresh intended-path signature and forward it. This uses that `K` is the complete signing capability, the signing/message path admits a fresh message, and the native challenger uses the matching key-generation distribution. The simulator needs neither the target secret nor a witness. Because the simulated and real interactive views are **exactly equal**, for any polynomial number of independently randomized same-key rank-separated FALSE capsules,

`Pr[recover usable target native capability OR fresh valid native-path forgery] <= Adv_QPT-EUF-CMA(native, B)`.

**There is no factor `t`, no factor for the number of same-key capsules, no LWE reduction term, and no statistical approximation term** for these rank-separated FALSE sources. Native QPT EUF-CMA remains a genuinely independent assumption; no concrete PQ bit-security level or deployed Bitcoin opcode is claimed. Opening all `t_i` shares in *any one capsule* immediately discloses `K`; shared plaintext shares/coins across capsules, native-secret-correlated auxiliary leakage, malicious Build, fabricated opening receipts, or arbitrary related TRUE capsules are outside this theorem.

## Reproducible bounded finite checks and precise limits

`check.py` (Python standard library, no network) was executed twice with **byte-identical** `OUTPUT.json`. It constructs a real witness-free, rank-separated FALSE Boolean source `F=(x) AND (NOT x)` with `A` rows `(1,-1)`, `(0,1)`, `(1,0)`, `U=(0,0,1)`, and `z=(-1,-1,1)`; neither Boolean assignment satisfies ORIGINAL. It exhaustively checks full-ciphertext message-independence even with fixed nonzero errors, 2,916 exact coin-equivocation identities, and complete public-plus-adaptive-open transcript equality for `t=3` on each fixed mock native key bit (157,464 real worlds and 314,928 simulator worlds per key value). A second exhaustive test has **two independently encrypted capsules sharing one mock pk** with adaptively selected openings across both capsules, and matches 104,976 real worlds against 419,904 simulator worlds per key value. The checker also reconciles two complete 256-bit mock-key capsules by changing **only** 512 unopened ciphertext-digit coins (245 of the hidden bits actually change), leaving all public ciphertexts, opened coins, masks and shared mock checking key untouched. Finite tests use `q=3` to enumerate the distribution and `q=257,g=7` for full-key coin equivocation; they do not certify QPT hardness, native SLH signatures or Bitcoin enforcement. The formal lemma works with independently generated ternary noise for every permitted odd `q`.

**Exact checker SHA-256:** `06152c0223a555ccfaf44e3776bffc74b1fe284decec52c1675967eee41daa63`. **Exact captured OUTPUT.json SHA-256:** `aefbcd7cfbbdb2a7c21a944842809da84986653e92ce40fd3c279fa4dd55bc96`. All files are new research notes/checkers and captured output, not production artifacts.

**Crucial unresolved step:** There is still no classical PPT witness-free arbitrary-ORIGINAL-NP compiler `Comp(R,x,claim,context,pk) -> (A_x,U_x,capsule)` with a public `Phi(R,x,W)` giving every valid ORIGINAL witness the SAME precommitted `K`, every fixed FALSE instance (including rank-degenerate Pasch sources) hidden in the full public view, and **arbitrary** unauthorized hard-TRUE final-key recovery/native forgery reduced to an actual ORIGINAL witness or independently justified QPT break. The previous public pseudo-moment attacks remain fatal in excluded cases. The present perfect equivocation **must not** be mistaken for binding authenticated opening receipts, N-of-N preauthorization/abort/DA/graph security, SYS/BTC AuxPoW/coinbase/ancestor/window authentication, or the hypothetical native PQ-only Bitcoin endpoint. The automation stopping conditions are not met.

**Provenance:** Offline bounded research 2026-10-29. `syscoin/PVUGC` existing PR #1, open/draft/unmerged branch `research/pq-wkem-validation-20260918`, exact starting head `fe08965680e7e38ace086d88b2e2c9e3ff8980df`, latest substantive issue comment `6497524834`. Read the exact-version `macaulay_rank_pad_20261029/RESEARCH.md` and `macaulay_rank_degenerate_false_break_20261029/RESEARCH.md` and PR metadata/comments via the authorized connected GitHub repository; no web/external literature or unrelated repositories, no independent agents. Computation: local Python `check.py` twice and output comparison. All intended publication stays under `research/pq-wkem/` plus an ordinary top-level PR comment.
