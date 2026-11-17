# R346 — cycle-secret-sharing screen for fork-triggered native cancellation (NONQUALIFYING)

## Provenance
One bounded offline construction/repair iteration from actual open, draft PVUGC PR #1 head `32e3c6b91c60e0c937434f256cbb3d63d610f160`, branch `research/pq-wkem-validation-20260918`. Read R345 exact note blob `d07a19082a3bddcc30e9fb3af553318a5209d1c0` and current Core #609 PR metadata (head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`) read-only. PR comments checked after 2026-11-17T18:44:57Z: none. No external literature or web search; no Core tests or real source certificates.

This is a new *graph topology* access-structure attempt, rather than another SHA prefix, degree, private polynomial, or fixed transcript pad. It attempts to make the SAME frozen capability reconstructible from any alternative fork path, while hiding it from disclosed acyclic subsets. The necessary SOURCE-EARNED edge release is the decisive interface test, not assumed.

## Precise, efficient graph layer (different credential relation)

Fix a setup-known finite graph G=(V,E), special reference edge e*=(u,v), lambda-bit frozen native cancellation capability sigma (possibly correlated with public native verifying key VK), and independent uniform vertex values r_z in GF(2)^lambda. Define edge shares

    L_e = r_{a(e)} XOR r_{b(e)} XOR (sigma if e=e* else 0).

For any alternative u-to-v path P, L_e* XOR XOR_{e in P} L_e = sigma by cancellation of vertex potentials. Every distinct path returns the SAME sigma. Build runs in O(|V|+|E|). This does not force one canonical witness.

If an external edge-access credential system already existed, Build could pre-enroll independent private edge tokens t_e and publish hashlocks

    Y_e=H_lock(x_W,e,t_e);
    D_e=L_e XOR H_pad(x_W,e,t_e).

A hypothetical Open decrypts only token-bearing edges, verifies an authenticated u-to-v alternative path for the exact claim, and XORs its labels with L_e*. This is an actual classical PPT graph/credential *toy* algorithm, but NOT Build_inc/Open_inc for the ORIGINAL source: Bitcoin/Syscoin histories DO NOT contain the dealer-generated t_e. Treating source validation as an if-check after decrypting labels does not bind release cryptographically.

## Exact partial-view secret-hiding proof

Let F be the set of disclosed edge shares and suppose it has no cycle containing e*. Equivalently, when e* is disclosed, u and v are disconnected in the graph induced by F\{e*}. For any delta in GF(2)^lambda, change sigma to sigma'=sigma XOR delta. Let A be the connected component of u in F\{e*}, and simultaneously change r_z to r_z XOR delta for z in A. Every revealed nonreference edge keeps its label (both or neither endpoints shifted); the reference edge crosses this cut, so its changed vertex pad cancels the changed sigma. This is a measure-preserving bijection on uniform masks. If e* is absent, all revealed labels omit sigma. Therefore the FIXED disclosed-label distribution is exactly independent of sigma, even conditional on publicly correlated native message/VK/claim if the pads are independently sampled. Any QPT postprocessing of only this classical disclosed-label distribution inherits the identity. This is NOT a security proof for the published hashlocks, adaptively opened labels, siblings, malicious token holders, or concrete SHA/QROM.

## Why this does not solve the ORIGINAL witness problem

The graph share is hidden only if the corresponding edge activation is a REAL cryptographic secret-credential delivery, not a publicly callable edge selector. Three attempted instantiations fail:

1. Publish all L_e for a prewritten graph: a source-free reader selects a template cycle and reconstructs sigma on a FALSE ORIGINAL instance. The ideal partial-view proof no longer applies.
2. Set t_e=SHA256d(source header/coinbase/parent certificate): the dealer cannot precompute future edge ciphertexts without knowing future t_e; for already public headers the token is public before any qualified challenge. Unauthorized source-coin retention is also fatal. A header-validity test after label recovery is too late.
3. Enroll private setup-selected t_e by height: arbitrary ORIGINAL Syscoin forks/greater-Bitcoin-work/burn-fault witnesses do not contain those tokens. Installing a release signer or requiring miners to publish them changes the ORIGINAL protocol. Mapping all actual histories to a small fixed graph also needs authenticated actual-ancestor inequality and complete LC depth; two parent work certificates for the SAME child are not a fork. The source graph's artificial terminal cannot silently certify that fact.

Strict PQ canonical parent-coinbase tags/modern chain-ID enforce contextual admission but do not produce dealer-chosen t_e. Different authenticated Bitcoin parents can certify the same child, and honest relevant forks need not yield a collision or double opening of ONE SHA commitment. R316's equal stale tags are not an LC failure; its fixture did not enforce the full maturity policy.

## Executed limited checker / exact evidence

Python3 standard-library `check.py` on a synthetic 5-vertex, 6-edge graph enumerated all 64 edge subsets and all 32 assignments of bit vertex pads for BOTH sigma bits. It checked identical FALSE histograms for 53 non-releasing sets, complete sigma recovery for 11 releasing sets, explicit cut coupling, and two independent 256-bit synthetic paths returning one frozen capability. It also verified recovery without source when all edge labels are made public. Two executions produced byte-identical JSON, 3,491 counted assertions per run.

Program SHA256 `f1ef7414df574e475bafc3814ae3cc54f0c377289dd27050386a9927464de2ba`; output1 and output2 SHA256 `521da07eabf6c8bb7f720b74eac81ee0568bed6f89cf8faf91875f8c495ab40b`. Complete local-only derivation, executable checker, paired outputs and provenance: `/mnt/data/R346_cycle_source_screen_20261117.tar.gz` SHA256 `c33021304d0cf44140a3481e1660349dbf3cf03fdf3fefa2e09d67a8701f54c5`. This was NOT a Bitcoin/Syscoin, source-authenticated, native PQ signature or quantum experiment. The checker/output files were NOT committed in this note.

## Result and next indispensable equation

NONQUALIFYING — no ORIGINAL-foundation advance. This graph component proves conditional all-path reconstruction and exact fixed-partial-view secret-sharing, but its source-activation credentials are UNINSTANTIATED and do not reduce to the approved three OR challenge grounds. Do not report it as a witness-KEM breakthrough or optimize its graph size. Do not import an ideal `ActivateEdge(w)` as an assumption: that merely renames the hard missing operation. R225 native signature activation portability remains separate.

Still required is an actual serialized classical-PPT `Build_inc(x_W,sigma_cancel)->C` and public `Open_inc(C,w_original)=sigma_cancel` for EVERY qualifying ORIGINAL witness, with independent full-public FALSE/hard-TRUE QPT security reducing unauthorized recovery/accepted native forgery to a genuine qualifying ORIGINAL source certificate or an independent PQ hash/native break. Binding includes exact claim/outpoint/burn/amount/recipient, historical BTC anchors/window/actual ancestor and LC depth, reset/deadline, capsule ID and exact safe native message/VK. One notary initiates; anyone can challenge by ANY of three OR grounds. No other signer goes online. No on-chain NP/source verifier. No production edit, review, PR comment, deployment or automation modification occurred in this research derivation.
