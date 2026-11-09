# R178 — Source-Synchronized Hash Template (SSHT) trial

**Status: attempted hash-only construction and three concrete repairs; no ORIGINAL-dependent release construction, no full-public QPT security, and no cryptographic breakthrough.** This is a narrow result about work-digest-table and known-anchor hash-pad constructions; it does not rule out SHA-circuit-specific or arbitrary NP witness encryption. Do not promote it, post a PR progress comment, or treat synthetic PoW as deployed Bitcoin/Syscoin verification.

## Provenance and target

syscoin/PVUGC PR #1; branch research/pq-wkem-validation-20260918; observed starting head 94a3313a41da9e664d427d8749f733cd0749f0c1, open/draft/unmerged. Read exact R177 research checkpoint blob fbb04ac6be04d7b13d1b287b89c3d130bdeef425 and latest R176/R177 substantive ordinary comments. Initial R178 research hypothesis was saved during the pass at eb0e0618247e4a8d12588aef8cbf186a373e798d. No outside web/literature, other-repo write, independent subagent, or quantum experiment. Exact executed checker.py and actual stdout captured.json are sibling files, and byte-equivalent rerun was checked locally.

The original task remains a sealed, claim-scoped N-of-N native cancellation package, preauthorized before funding. One notary may start a withdrawal. Anyone with a finite authenticated qualifying witness for ANY of the three branches (strictly more BTC work on conflicting history, absent/invalid bound burn authorization, or sufficiently deep qualified Syscoin fork/tag inconsistency) must publicly obtain the SAME frozen native cancellation capability, with no online committee or second notary. Large evidence is off-chain; Bitcoin verifies ordinary native signatures only. A witness must bind exact claim/UTXO, source statement/anchors/window, target message/VK and capsule ID. Neither parent work alone nor a source tag hash alone establishes Bitcoin canonical inclusion. Distinct work certificates for the same Syscoin child are not a fork.

The frozen-key leaf goal is:

    Build_hash(x_W, sigma_cancel; setup_coins) -> C  in classical PPT
    Open_hash(C,w) = sigma_cancel                 for every R_cancel(x_W,w)=1
    arbitrary QPT recovery / native forgery before qualified release
        -> ACTUAL fully authenticated R_cancel witness
           or an independently justified QPT hash/native break.

The full public view includes C, x_W, source roots, native checking keys, honest/malicious setup data, sibling capsules, auxiliary advice and selective openings. A QROM lemma for independently sampled tokens cannot be transferred to source-correlated data absent an actual joint simulation.

## Concrete candidate SSHT

Let child be one pure Syscoin child-header identity and parent be one Bitcoin 80-byte parent work certificate for it. Parent digest Y=SHA256d(parent80) contains work-dependent randomness; define u(Y) as m digest bits beyond the leading work-constrained prefix. A future source witness would also carry complete parent coinbase, Merkle, child ancestry and tag validation, Bitcoin inclusion/anchor and window evidence; this candidate does not implement those checks.

Builder samples a 256-bit frozen secret K and publishes all small-bucket correction rows

    E_u = K XOR H_pad(context,u)   for u in [0,2^m).

A supposed Open first validates evidence, chooses u(Y), and returns K=E_u XOR H_pad(context,u), then unmasks the fixed native sigma from sealed_sigma=sigma XOR H_sig(context,K).

This gives common-key completeness for all u by construction, but it is classically broken: every row and every mask input are public. A QPT adversary can take any u, calculate K with no source witness, and recover the target sigma. A public conditional source check before the XOR is bypassable. This is a direct raw-output attack even when the ORIGINAL relation is FALSE, so neither a QROM simulator nor N-of-N wrapper can justify the leaf. Publishing 2^m correction rows is additionally exponential for large m, but the unconditional leakage already fails at every m.

### Three attempted repairs

**A. Full-work binding.** Replace bucket u by the complete future parent evidence P and use E_P=K XOR H_pad(context,P). Build cannot compute rows for unknown future parent certificates. If one P0 is selected at setup, opening on another valid P1 yields

    K' = K XOR H_pad(context,P0) XOR H_pad(context,P1),

which is not K unless the two pads collide or share a justified hidden correlation. Builder cannot arbitrarily select one canonical work certificate: every original qualifying P must work, even if parent miners or source actors choose different coins. A table of all 256-bit possible future evidence is not PPT. This is a specific correction-template failure, not a proof that all compact public encodings are impossible.

**B. Fixed anchor normalization.** Normalize all source witnesses to a claim-common ancestor tag, withdrawal context, source root, height or baseline work identifier a(x_W), then define E=K XOR H_pad(context,a(x_W)). If a is publicly computable from the bound statement, anyone opens E before any challenge. If a is a hidden independent setup preimage, obtaining it from every future original witness without exposing it earlier is exactly the missing source-to-common-secret compiler. Merkle commitment to that hidden preimage authenticates a byte string but does not cause the future PoW proof to reveal its preimage. Source-selected preimages retained by a malicious source actor cannot be treated as innocuous.

**C. Miner-issued designated ticket.** Let setup choose a hash-ticket t, require future parent work to carry its preimage or hit a particular extra m-bit digest class, and use that to correct E. If the ticket is published so any miner can include it, the raw opener also has it. If hidden, a miner cannot guarantee its inclusion without an online ticket issuer or an unrelated extra search. If mined from unpredictable future work, setup cannot precompute its K-dependent ciphertext. More fundamentally, requiring that extra selected class rejects otherwise ORIGINAL-valid headers. Under an ideal independent uniform m-bit free-digest-class experiment, one future digest hits a setup target with probability 2^-m, and q samples contain at least one target with probability 1-(1-2^-m)^q <= q/2^m. This is not every-original-witness completeness. The candidate cannot replace actual Bitcoin canonical admission by privately mined work.

The repairs show the exact *scope* of the defect: a fixed public normalizer gives premature release; a full future-certificate pad gives no setup computable correction for all witnesses; an extra secret ticket silently changes the ORIGINAL admissible evidence. There is no theorem ruling out a genuinely nonlinear, compact, nonblackbox SHA-dependent correlation.

## Source identity and double-work regression

Two independent valid parent Bitcoin work certificates may commit to the SAME pure Syscoin child identity and therefore represent exactly one semantic child outcome. Any release condition of the form WorkID_0 != WorkID_1 would incorrectly classify this as fork evidence. Conversely differing semantic child hashes may indicate a fork only after full source authentication, qualification, first-divergence and relevant-depth/tag rules; an arbitrary invented child hash is not an ORIGINAL witness. A shared height/slot is a label, not a common cryptographic SHA commitment, and two different tags are not two openings of one hash commitment.

The R177 claim-prefix reduction remains conditional: for forks affecting history at or below the bound h_rel, one sufficiently advanced anchored baseline and one alternate may establish incompatible history. For any-future-fork policy two later observations remain necessary. Neither source-witness normalization supplies an encrypted release key. R1 and R2 have distinct verification predicates and are not solved by this trial.

## Actually executed source, measured outputs and limitations

The published exact checker.py constructs syntactically sized 80-byte parent headers whose Merkle root is deliberately synthetic, mines SHA256d digest values with 12 leading zero bits for two toy child IDs, and derives 8 further digest-class bits. It does NOT validate nBits as a real Bitcoin target, DAA, timestamps, coinbase Merkle, AuxPoW child linkage, source context, real BTC best-chain inclusion, or tag applicability. Three toy work solutions for one child have distinct work IDs and buckets 79,73,18; the second toy child has buckets 151,126,112. The run used 36,939 candidate hashes. The raw table opens K on all 256 possible buckets, including ones not appearing in any mined fixture. Full-work correction succeeds only on preselected P0, not on other valid toy parents. Fixed-anchor correction opens K before a challenge.

For an independent uniform 8-bit digest class, a target is hit once with probability 0.00390625 and at least once in 16 tries with probability approximately 0.0607019041. At 128 free bits, a 16-sample union bound is 16/2^128 approximately 4.70e-38. These are ideal-class selection statistics, NOT source security or real Bitcoin mining probabilities. Local checker.py was executed twice and captured stdout was byte-identical. No native signature, full source verification, hashed secret-release primitive, quantum attack execution or QROM theorem was established.

    checker.py SHA-256 = ac1e23e0f556e9a2c41b0f199ddfde64e4cff3a3cc86dc1d8a02f997f66eff17
    captured.json SHA-256 = f2681146587ef74cfa0becfabb2d9b93e122e321a21efa95e04500c9174a3fb6

This is a regression on a specifically defined failed mechanism, not evidence that a successful witness-KEM has been found.

## Precise handoff

Do not repeat unconditioned work-digest tables, public anchor pads, or selected-bucket tickets. The next constructive step is a *source-dependent public release transition* that cryptographically enforces a complete authenticated SHA/AuxPoW history and common hidden terminal capability without a public bypass, an online issuer, a source participant retaining opposite labels, or exponential enumeration of possible work/state transcripts. A hash-sealed complete-state gate is only a candidate if it actually instantiates its polynomial classical compiler, allows all distinct witnesses, and supplies a full-public coherent QPT simulator/extractor. Earlier state-label closure and omitted-memory consistency tests remain mandatory. An ideal release helper or generic hardness assumption promising this exact feature is not a solution.

This run does not satisfy the threshold for an ordinary progress comment or user notification. Preserve the attempt and proceed in later bounded iterations. Do not disable the existing research automation.
