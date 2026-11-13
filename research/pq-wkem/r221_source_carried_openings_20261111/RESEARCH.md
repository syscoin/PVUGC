# R221 — SCOM: SOURCE-CARRIED OPENING of a native cancellation capsule

**Disposition: unsuccessful hash-only ORIGINAL-dependent Build/Open attempt. A narrow conditional source-transcript independence lemma was proved for commitment-only source integration. NOT a witness-KEM, QPT theorem, actual Bitcoin/Syscoin verifier, native PQ signature or deployable bridge. No routine notification or ordinary PR comment.**

## Continuity / provenance

Research run R221-SCOM-20261111; syscoin/PVUGC PR #1, open/draft, existing research/pq-wkem-validation-20260918 branch. Observed start HEAD 4efa6db13b841048ef12bef5dd1d2d1804a88d40 (tree acb425ab9ede091064f34458e9927fa604926aa4). Intermediate hypothesis published *before tests* in CHECKPOINT_01.md, commit bce9fb60ffc3797027c16ca5d557aa0c2819afe5, parent 4efa6db, checkpoint blob ac3084e189786bd60b3b2775cb0325157a681766. Read R220 proof-transcript failure, R219 raw public polynomial interpolation failure, and R211 independent-OR composition narrowly at their exact version. Recent top-level PR comment query after 2026-11-10 16:00 UTC returned none. No web/literature, independent agent, source-side mining of actual BTC, native BTC/PQ signing, production code or quantum experiment.

Original task remains: freeze claim/UTXO/path-specific native cancellation authorization before an N-of-N no-bypass graph is funded; one notary can later activate a source-bound withdrawal; any independent challenger with ORIGINAL authenticated R1 heavier contradictory BTC history, R2 finite refutation of the *actual admitted* PoB, or R3 qualified Syscoin claim-prefix fork/applicable tag fault recovers precisely the SAME authorization off chain. Exact source includes genuine SHA256d, BTC anchor/target/difficulty, AuxPoW coinbase/tag/header ancestry, required interval tags, burn/recipient/amount, activation witness/wtxid, window, fork depth, DA, permitted resets. Distinct BTC parent work certificates for the SAME child do not constitute R3 fork. This experiment isolates a proposed R3 subcarrier and changes none of those requirements.

## Actual attempted Build and Open

Classical Build chooses K uniform in {0,1}^256 and the already frozen native sigma, with public context x_W. Publish

    q = SHA256("R221/commit" || x_W || K)
    D = sigma XOR SHA256("R221/pad" || x_W || K)
    Croot = MerkleRoot(q, capsule_metadata, ...)
    C = (x_W, q, D, Croot, native VK, public checking fields).

Source-integrated hypothesis: a genuinely qualified future Bitcoin parent coinbase/Merkle/AuxPoW proof can be reused as a *source-certified opening* of q. Open would extract K from this proof, check SHA256("R221/commit",x_W,K)=q, recover sigma from D, verify native authorization and output sigma. All ORIGINAL witnesses must recover the same frozen sigma, not H(proof) dependent values.

This does NOT work. A Merkle proof authenticates the *leaf value q* relative to its parent root. It is not an opening of the **preimage K** in q=H(K). A miner/source generator can commit q in its coinbase and mine a parent with q alone; K is absent. The legitimate BTC witness contains q and hash siblings, not an unknown q-preimage. Merely sharing q between the setup capsule and future Bitcoin coinbase does not force the later independent source root to be Croot.

## A precisely scoped conditional lemma

Let K be uniformly sampled, Z be the complete public setup state including q=H(K), x_W, D, native VK, auxiliary/context/checking, related capsules, and public source commitments. Suppose source transcript T is generated as T=G(q,x_W;rho), with rho independent of hidden K **conditioned on Z**. G may construct source coinbases and SHA256d Merkle paths, and search parent nonce/work, provided it does not use K or setup secrets other than their already-public q. Then for any z and any k consistent with z,

    Pr[T=t | K=k, Z=z] = Pr[G(q(z),x_W(z);rho)=t | Z=z].

Thus K -> Z -> T is a Markov chain and I(K;T | Z)=0 in this exact classical distribution. Source membership authentication does not itself *add a K-preimage opening* beyond q. The assertion is only conditional independence; it is **not** a full-public computational QPT security theorem, proof of SHA preimage hardness, or impossibility of generic hash-based WE.

Critical boundaries: (a) if source coins/auxiliary state retain K or are adaptively correlated with K, the premise fails and a malicious source may open early; (b) genuine BTC mining can be expensive in the security parameter, so the independence identity does NOT automatically furnish a polynomial-time QPT simulator that can sample successfully mined T; (c) quantum oracle access, public native VK/signature-check correlations and sibling capsules remain unproved as hard-TRUE security; (d) independent source work may itself be a computational resource, but this is NOT an independently justified inverter or ORIGINAL-witness extractor.

## Repairs actually analyzed

1. Put plaintext K into the authenticated Bitcoin source leaf: a single ordinary source publication reveals K before any qualifying R3 fork or tag fault. It also requires miners to know a setup secret, which they do not receive from the standard tag.
2. Use public q as pad key, i.e. D=sigma XOR Pad(q): anyone decrypts D with the already-public q without any ORIGINAL witness. Honest-verifier checks after public decryption do not repair it.
3. Define K from future source Merkle siblings or parent roots: different genuine histories give different hash values, and Build cannot precompute the identical frozen K for all permitted future source roots. A public common prefix/root available before contradiction releases early if used directly.
4. Force future Merkle paths to open under fixed capsule Croot: arbitrary independently mined parent roots are not equal to Croot. Forcing a public leaf q into a source parent is possible only subject to source data/consensus policy and *still* authenticates only q. A shared authenticated root cannot fabricate a hidden K preimage.
5. Require a source participant to reveal K only upon contradiction: no cryptographic mechanism was supplied compelling such conditional revelation without advance K retention, premature disclosure, or a prohibited online authority. Current AuxPoW tag hash+height and parent coinbase do not contain these new secret labels.

This closes ONLY the commitment/Merkle-path as K-opening family, not the possibility of an actual non-blackbox SHA-circuit carrier. No source-specific release was instantiated.

## Executed computations

Full LOCAL standard-library checker.py (Python 3) was executed twice with byte-identical output.json / rerun.json; 416 functional assertions. SHA256 of exact source 90115482903366b6d99934ed18b58fda07602a55f83850cc1a58235fdf973d9f; of captured output 1b70b75821f486516c94d4aa51bedd0c18843e2f0c2ffc7811ba801cbab6b0df. These larger files were retained locally; not described as uploaded. They test 64 contexts for q membership without K, independent/frozen-root mismatch, public K/q early release, 16 intentionally 12-bit truncated-commitment same-q/different-hidden-K fixtures, and 16 Bitcoin-shaped 80-byte SHA256d headers using a compact target 0x1f3fffff with deterministic easy-work mining. The same q with independent source coins generates the exact same public source transcript regardless of which hidden setup key produced q. A deliberately truncated 12-bit collision is NOT a SHA256 collision break. A real authenticated Syscoin fork / Bitcoin consensus validator is NOT implemented.

The separately tested published_repro.py / published_output.json were each executed twice and outputs matched byte-for-byte: 64 functional checks (16 each: source Merkle authentication without K, public-q early pad opening, plaintext-K early opening, truncated-q equal mined Bitcoin-shaped header). Exact locally tested source SHA256 d52e6c9889a741a5e3d115916e33072f10e2e2b8219761393c45b3777fcfaaa7, output SHA256 f18869c450ae78099f2e40e888edae44096afcecf2fdf4d340337682039ffc1d. The code below/companion file uses real SHA256d but **synthetic** coinbase bytes, 80-byte headers, easy work and truncated commitments; no full AuxPoW, tag parsing, retarget, chain membership, native signature or QPT test.

## Next missing ORIGINAL-dependent algorithm

    Build_hash(R_cancel, x_W, sigma_cancel; coins) -> public C
    Open_hash(C, (j,w)) = exactly sigma_cancel
         for EVERY ORIGINAL authenticated qualifying R1/R2/R3 witness (j,w).

A viable next attempt must make the actual SHA/AuxPoW/PoB verifier computation a *cryptographic prerequisite of key recovery*, not merely authenticate a public leaf or check source syntax in honest Open. Investigate a nonfactorized hash/SHA Boolean-circuit encoding jointly with a full-public quantum simulator. Test arbitrary invented headers, aliasing of the semantic child under different work certificates, false instances, retained malicious setup/source secrets, native signature forgery, quantum-coherent related capsules. Never claim general NP impossibility from this scoped Merkle result, and do not restart prior failed proof-hash, low-degree polynomial, OTS token-table or independent PoW puzzles as though repaired.

No secure bridge constructed. Leave hourly research task enabled.