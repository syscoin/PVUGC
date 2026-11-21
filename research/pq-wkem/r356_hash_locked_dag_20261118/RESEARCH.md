# R356 — hash-locked edge DAG transport (restricted positive component; NOT original bridge WKEM)

## Provenance and status

Read syscoin/PVUGC PR #1 at draft head 995542273f29b0ac32738a361d7b9b602301850f (R355), branch research/pq-wkem-validation-20260918; read R355 note blob 817107ac68c5e2dedd125ee7cd76c0ae59d469d1 and R354 note blob 5f9b4515084e63267388f6441f5c54d5dda2ab15 and latest relevant PR comments. This is a single resource-bounded OFFLINE research pass. No new Core #609 code was fetched or tested; the prior post-PQ contextual rules remain background, not newly verified. NO ORIGINAL WKEM breakthrough, no user notification or PR progress comment.

R355's failed direct SHA path hashed each differing certificate transcript forward, so SAME-terminal convergence of two distinct valid paths would require a SHA collision. R354's linear public edge labels leaked by an eight-row XOR-flow identity. The new design chooses a **random hidden label for each shared graph vertex**, with separate SHA/RO-encrypted rows for each incoming edge. It gives collision-free path convergence without a public affine inverse. The remaining gap is the *source-dependent public compiler*, not another SHA mask width.

## Actual Build_DAG / Open_DAG for an explicit graph

For a public, finite directed acyclic graph G=(V,E,s,t), unique edge IDs e=(u,v), frozen L-byte S, capsule ID cid, and lambda-bit labels, Build samples independent uniform K_v in {0,1}^lambda for all vertices, and publishes:

  G, cid, K_s,
  C_e = K_v XOR H_edge("edge" || cid || e || K_u) for every e=(u,v),
  D = S XOR H_end("end" || cid || t || K_t).

H_edge emits lambda bits and H_end emits 8L bits, with distinct length-prefixed domains of a quantum-accessible ideal random oracle. A concrete SHA/SHAKE substitution is *not* covered by the QROM argument. Build is classical PPT in explicit |G|. Open follows a supplied directed s-to-t path, starting from K_s; for each edge e=(u,v), obtains K_v by XOR of C_e and H_edge(...,K_u), and at t outputs D XOR H_end(...,K_t). No private source-evaluation service or extra online signer is involved for this restricted graph.

**Every-path same-output correctness:** Each edge decrypts exactly the independently sampled label of its target vertex. Inducting along *any* path from s to t yields the single original K_t, regardless of path or merging; thus all paths return exactly the same frozen S without engineering SHA collisions. This is NOT correctness for an ORIGINAL BTC/Syscoin source certificate, because no original-certificate-to-graph compiler exists.

## Restricted full-public FALSE QROM game

Fix a graph with t unreachable from s. Let R be reachable vertices, U=V\R; assume G and all publicly disclosed auxiliary/nonuniform QPT advice were chosen independently of the honest random K_U and hidden oracle pads (VK/source claims may correlate with S but not with K_U). Adversaries get *every* row, D, K_s, G, cid and coherent joint random-oracle access, not just an honest Open API. The public view can reveal all K_R by graph traversal, but there is by definition no edge from R to U.

Define the reference world J by drawing a fresh uniform pad P_e for every edge with source in U, placing C_e=K_v XOR P_e, and drawing independent P_t for D=S XOR P_t. Rows from reachable sources use the honest oracle. In J the complete public transcript is independent of all hidden K_U: even an edge from U into a *known* reachable vertex has a uniform independent P_e, and distinct edge IDs isolate all row domains. D is uniform and independent of S, conditional on public checking material.

To couple real with J, program the *ideal* oracle at the hidden locations X_e=("edge",cid,e,K_u) for all edges whose source u lies in U, and X_t=("end",cid,t,K_t), to the independently drawn P_e/P_t. This gives the honest joint distribution. Let M=#(edges from U)+1. In J all locations are uniformly hidden from the QPT adversary even given the entire public transcript. For any q-query reference-oracle quantum state, expected query probability on the hidden set is at most M/2^lambda. By a direct q-query hybrid/telescoping argument and Cauchy-Schwarz, state distance to the programmed world is bounded conservatively by 2q sqrt(M/2^lambda) (and two-secret IND advantage has at most twice this distance, subject to advantage convention). This is an ideal-QROM, honest-independent-label restricted theorem, not a concrete SHA or ORIGINAL hard-TRUE/forgery theorem. It does not provide arbitrary auxiliary dependence on source secrets, malicious setup, sibling selective-opening or native activation-binding security.

Crucially, this coupling simulates **all** public ciphertexts together. It is not an inaccessible release oracle. The isolated hidden-domain programming occurs only in the *proof hybrid*; actual Build_DAG publicly serializes the rows and has no oracle-programming capability.

## Executed local checker

Executed CPython standard-library checker twice, with identical output SHA256 cc63492a7be72f7e126cac469a00748f6eb290a54c493d56ff2d602e4f73e654. Checker file SHA256 cc479bfe6ec02bfcb482b72ab925283a1e49abe1461f66240c2f7758a8c8fa84. The deterministic SHAKE256 table oracle is a reproducible synthetic fixture, NOT an actual quantum oracle security experiment. It checked two distinct true graph paths opening the same frozen synthetic 128-byte S, a false graph with six nodes/seven edges and three reachable nodes (t unreachable), and an S-to-S' punctured-oracle tape coupling leaving the ENTIRE public false capsule byte-identical. It also checked that adding one illegal reachable-to-target edge opens immediately and that reusing hidden target labels with a separately opened sibling exposes S_false even with cid domain separation; independently generated labels removed that particular direct attack. No native SLH signature, actual original BTC/SYS certificate, real SHA oracle-programming or Core consensus test was performed.

Complete expanded derivation, exact executed checker and two captured JSON outputs are LOCAL ONLY: /mnt/data/R356_hash_locked_dag_20261118.tar.gz (archive SHA256 d65fa42451629da89e88eb68971bc8d75ebd7d1230f5f6756aef450f12aae8b0). Local persistence across runtimes is not assumed. This repository note does NOT claim checker/output publication to GitHub.

## Why this DOES NOT construct ORIGINAL-source release

To use this for the actual bridge, a classical PPT pre-funding algorithm would need to compile *every future* qualifying ORIGINAL BTC/Syscoin witness w (all three OR branches, authenticated real headers/contexts, strict post-PQ AuxPoW, claim relevance, LC depth, specific burn fault, amount/recipient, BTC anchor/window, reset/deadline, native message/VK/capsule ID) into a path of a polynomial-size frozen explicit G, **and every** s-to-t path must correspond to one such authenticated original certificate. No such graph/compiler is implemented. Actual future PoW nonces and SHA/AuxPoW source histories are unknown at capsule setup, and exhaustive implicit graph enumeration would be exponential.

Because explicit graph reachability and path extraction are polynomial, a general polynomial compiler for arbitrary NP witnesses would itself decide NP existence in polynomial time. This does not prove the special ORIGINAL source language impossible, but it shows that treating a hard witness relation as a freely available polynomial explicit path graph is circular. A dishonest compiler that adds an accepting shortcut opens S even when there is no original challenge. An honest-code post-decryption VerifyOriginal check does not help: S has already escaped.

**Precise unfinished operation:** Public, polynomially serialized *implicit-source-edge* opening that uses a genuinely authenticated future original certificate e, a prior hidden state K_u and fixed pre-funding pp to output a vertex-consistent K_v, while invalid or spliced certificates fail to reveal any accepting key; no online issuer, secret evaluation oracle, reusable XOR flow, public inverse, exponential table, or source assumption already promising release. All valid original witnesses must open the SAME frozen, activation-safe capability with a full-public QPT simulator and hard-TRUE recovery/native-forgery reduction. This operation was not constructed or reduced.

Preserve R225's same-fixed-outpoint signature portability (slot-global veto or activation-bound native spend required) and the user's correction of R316: strict tags can be temporarily equal before their references cross a real fork; that fixture did NOT show a failure of a full-history light client and did not instantiate maturity policy. Public BTC best-chain membership is not implied by private parent PoW.

NONQUALIFYING restricted component. No PR comment, production change, source change, deployment or automation change. The existing research task remains enabled.
