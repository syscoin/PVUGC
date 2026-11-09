# R170 — A black-box QROM obstruction to generic hash-preimage witness release

**Status: major mathematical design constraint, not a witness-KEM.** No classical-PPT hash-only ORIGINAL-NP Build/Open with the demanded security was constructed; no fixed-SHA or real consensus impossibility is claimed.

Continuity: syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918. Start at 3ed1a91f857a6a277ad6240c9aa810127ef4becb (open/draft); read exact R169 Merkle-bound source-path note, blob 64ff963a9dff4bfad9ea393dbab40960be2aee77. No external sources or lattice/DLog tools. R166 establishes generic hard-TRUE WKEM => one-way transport for a hash-preimage relation. Here is a stronger **fully black-box source-oracle** test of that necessary subcase.

## Precise model

Take a quantum-accessible random function f:{0,1}^n -> {0,1}^n, public statement y=f(s), s uniform hidden, fresh uniform frozen capability K. ORIGINAL relation R_y^f(w)=[f(w)=y]. B^f(y,K) is public classical-PPT, receives no s, and makes at most q_B oracle queries including any public checking keys, native VK, auxiliary information, and related capsules it produces. O^f(y,C,w) is public quantum-polynomial-time with at most q_O source-oracle queries and ordinary off-chain verification. Its success for every honest witness (averaged over the ordinary random-oracle/setup distribution) is >=1-epsilon. Oracle dependence is genuinely **black box**; no SHA circuit internals, nonreprogrammable consensus functionality, secret trusted issuer, or oracle-specific public advice is granted. Auxiliary data may depend on y and the builder's polynomial oracle transcript but may not contain the unknown preimage s or a full oracle truth table.

## Explicit key-recovery adversary, no actual preimage

Given the *real* public C=B^f(y,K), choose an independent uniform z. Define local f_z(a)=y for a=z and f_z(a)=f(a) otherwise. Run the public Open with f_z and candidate z. The user-facing actual source oracle f is **not** changed; z is generally INVALID for R_y^f. The adversary only emulates the open algorithm's hash-oracle operations and outputs its recovered K. It can emulate the quantum oracle exactly: with delta=f(z) XOR y,

    U_fz |a,t> = |a, t XOR f(a) XOR ([a=z] delta)>.

This is one true quantum query to f followed by a reversible controlled-XOR, valid on arbitrary coherent states.

## Full averaged-QROM game proof (not merely a classical-rewind argument)

Let N=2^n. Independently sample a uniform random function U, secret s, fake z, and y, plus the same Builder/capability randomness in all games. Write F_s for U with value at s overwritten by y; F_z for U with value at z overwritten by y; F_sz for both overwrites. Marginals (F_s,s,y) and (F_z,z,y) each equal EXACTLY an honest random-oracle/function-preimage experiment.

G0 (actual attack): C=B^{F_s}(y,K) and execute O^{F_sz}(C,z).
G1: C=B^{F_sz}(y,K) and execute O^{F_sz}(C,z).
G2 (honest correctness): C=B^{F_z}(y,K) and execute O^{F_z}(C,z).

G0 vs G1: z is independent of the classical builder's adaptive query transcript in G0; coupling identical builder randomness makes the entire output identical unless B queries z. Thus event-distance <= q_B/N.

G1 vs G2: both use source-oracle algorithms B then O. They differ ONLY at hidden independent uniformly random address s. In G2, every pre-query quantum state psi_j is independent of s, so E_s ||Pi_s psi_j||^2 =1/N. A source XOR-oracle query difference acts with norm at most 2||Pi_s psi_j||. Telescoping Q=q_B+q_O queries and Jensen gives outcome-event distance <=2Q/sqrt(N), even with coherent superpositions and entangled workspaces. All other domains/fields/related capsules generated through the same oracle-calling builder are coupled unchanged. Correctness in G2 >=1-epsilon. Therefore:

    Pr[A recovers K in the ACTUAL challenge]
       >= 1 - epsilon - q_B/2^n - 2(q_B+q_O)/2^(n/2).

This is overwhelming for polynomial q_B,q_O and negligible epsilon. In the actual challenge z remains an f-preimage only with negligible probability. Producing ANY genuine preimage of y=f(s) from polynomially many quantum queries still contradicts the random-function search lower bound. Therefore any security extractor forced to produce an ACTUAL ORIGINAL witness from this A would break that quantum hash search assumption. In this **fully black-box oracle-relative model**, such a scheme cannot satisfy both averaged completeness and hard-TRUE capability security. This is a relative-oracle black-box obstruction, not a no-go theorem against generic NP with fixed explicit hash circuits.

The pointwise version is even simpler: for every fixed oracle where correctness holds, B^f and B^fz have identical output whenever B did not query z. The game proof above upgrades this to ordinary averaged QROM correctness and is the principal new result.

## Exact limits; not a no-go for all hash-based mechanisms

The source relation here is an **oracle-aided hash-preimage verifier**. A generic algorithm for ordinary classical NP does NOT automatically have to relativize to this random-oracle verifier; this theorem applies only to candidate builders/Openers that actually use the source hash as a replaceable black-box oracle (or explicitly claim oracle-relative generic correctness). A fixed SHA circuit can be compiled non-black-box and is NOT excluded by this argument. The argument does NOT exclude fixed SHA-256 bit-circuit non-black-box encodings, external genuinely authenticated best-chain state, a new cryptographic source/compiler that intrinsically binds the original computation trace, or assumptions beyond a purely accessible random function. It does NOT prove NP WE impossible in general, break SHA-256, or show that a forged PoW hash is an actual anchored parent-chain witness. It excludes treating black-box source-hash validation, Merkle roots, or an independently solvable raw PoW puzzle as an encrypted release gate.

All nonuniform auxiliary input in the theorem must be independent of the hidden original source preimage conditional on allowed public information; otherwise even the intended hard-instance security is vacuous. A malicious trusted release authority is not postulated. This theorem does not solve construction, malicious ceremony, or multi-capsule security.

## Reproducibility and regression

Actually executed two identical local runs of a Python standard-library 2,400-fixture q=32,n=12 adaptive-query coupling checker. A random fake z hit the 32-query transcript in 19 cases (expected 18.6807) and the builder result changed in exactly those 19; f_z(z)=y in 2400/2400, original f(z)=y in 1/2400. Exact reversible quantum-oracle identity checked on all 1,088 computational basis pairs across 17 small oracles. Exponential-table negative control: 20/20 fake preimages were absent from an old enumerated table, with 20,480 builder queries; it falls outside PPT. Toy SHA function checking does not prove QPT hardness.

A separately executed exact finite distribution checker enumerated all 256 functions on four addresses with four-symbol outputs: 1,024 honest/programmed joint events (expected factor 4), 16,384 single/double patch comparisons. Byte-identical rerun. Exact local source SHA256: main checker 40fed021f44b5c53114fca1e3348bb006c590460d58722c1dfbd875f414d2aea; its captured output 46fb0d075cb8e6028814c8a896ad4054e1436e9c8f3fa9c0e1f2e4776635b872; finite checker dcd5f27db6918a84e732dad711d472c2f460d9b5c55f1934df762ec3c15c5d2b; output dca6c990d286b007b10be375a3b04a72ba64d8c5a40ec70dbe8978dd12a285a1. Full research, tested scripts, captured output, exact manifest preserved in local R170 reproducible archive. No independent reviewer/tester or production environment.

## Exact constructive continuation

Attempt **non-black-box immutable SHA/AuxPoW trace correlation**, not another public black-box hash gate. The builder must create polynomially many protected source-dependent correlations without knowing any future valid w. Every actual ORIGINAL witness (complete claim, anchor, child, parent AuxPoW, coinbase tag, parent Merkle, history, height/window and required interval tags) must open the SAME frozen native capability; a merely fake one-point hash oracle must not. An arbitrary QPT release must yield a witness of the actual unmodified source relation or a justified PQ break. Previous Merkle-root repeated-read binding may enforce consistency of disclosed evidence, but is not a common-secret source compiler. No such compiler is available here.