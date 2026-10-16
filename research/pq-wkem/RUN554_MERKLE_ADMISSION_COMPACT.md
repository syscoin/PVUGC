# Run 554 — Merkle compression does not preserve statistical oracle soundness

Starting verified PR head: 522ceac338d8d9f14972c8eb610504cf78ae5611. Research-only, no practical WKEM.

## New exact falsifier

Let x be an ORIGINAL-false statement. An ideal immutable oracle supplies bits a[0..t-1] before the verifier samples uniform c[0..t-1]. Acceptance requires a[j]=c[j] for every j. Its soundness against even an unbounded prover is exactly 2^(-t).

Now replace the oracle by a short Merkle digest of indexed salted leaves h_j(b,s)=Trunc_k(SHA256('L'||j||b||s)), with internal nodes H('P'||left||right). Suppose a proposer finds for each j a *cross-value collision* h_j(0,s_j0)=h_j(1,s_j1)=d_j. It commits to the Merkle root of d[0..t-1]. For ANY later c, the proposer opens index j using bit c[j] and the corresponding salt. Every leaf and Merkle path verifies under the same committed root. False-statement acceptance rises from 2^(-t) to 1. This also works for a public deterministic Fiat–Shamir challenge derived from the root, because both openings were prepared before that challenge.

This is a toy source-admission protocol, NOT an attack on the full AIR/FRI verifier of any deployed STARK and NOT a general lower bound on noninteractive statistically sound proofs.

## Exact probability and quantum model

For ideal independent k-bit hash functions on the zero/one salted input classes, compare M independently sampled zero-branch salts to one fixed one-branch salt. Cross-value collision probability is 1-(1-2^(-k))^M >= 1-exp(-M/2^k). Thus M=2^k*(lambda+ln(t)) gives, by a union bound, failure <=exp(-lambda) to find all t pairs. This is an **unbounded-search/existence** result, not a classical-PPT attack at cryptographic sizes.

In the QROM, an arbitrary QPT attacker may coherently query the hash. Tabulating q zero-branch outputs and Grover searching the one-branch for a match costs O(q+sqrt(2^k/q)) ideal oracle queries and O(q) table storage. The minimum is O(2^(k/3)) queries with O(2^(k/3)) storage, up to polynomial/log factors for t targets. Thus 256-bit digests permit an idealized ~2^85.3-query claw-finding algorithm; 384 bits give ~2^128 queries. These are not physical gate costs or a proven SHA-256 exploit. This is exponential, so it is NOT an asymptotic QPT break as k grows.

The universal functional-encryption admission premise from Run 552 requires every alleged proof input for a false ORIGINAL statement to reject. The toy false accepting transcript EXISTS once the Merkle root is equivocal, even when finding it is QPT-hard. Statistical soundness of the underlying IOP alone cannot justify that FE premise; a computational-input FE theorem with the complete public view would be a NEW unproved obligation. Run 553's adaptive-CRS quantifier issue is separate.

## Scope, extraction and literature

Attack families: opening seam, dual-view hash correlation, adaptive challenges, retained malicious salts, and coherent chosen-input search. Leaf index is bound; this is not index replay. Published checking keys and other capsules must remain in the full-view security game. Perfect binding of an unrestricted L-bit transcript into k<L bits is impossible by pigeonhole, but this fact ALONE does not prove the required cross-value collision or any actual STARK forgery.

No accepted *complete source representation* is obtained here. Run 259's downstream ORIGINAL extraction lemma does not apply to a short accepted proof, an inconsistent oracle transcript or a native signature by themselves.

Primary literature considered: Ben-Sasson et al., Fast Reed–Solomon Interactive Oracle Proofs of Proximity (ICALP 2018, DOI 10.4230/LIPIcs.ICALP.2018.14); Scalable, transparent, and post-quantum secure computational integrity (ePrint 2018/046); Brassard–Hoyer–Tapp, Quantum Algorithm for the Collision Problem (arXiv quant-ph/9705002). Only abstracts/metadata and this exact toy derivation were checked; no complete paper proof audit is claimed.

## Executed evidence and handoff

Exact committed Python checker enumerates finite salted cross-value openings and verifies 16/256/256 distinct challenges under one unchanged Merkle root for toy truncated SHA-256 digests of 8/10/12 bits. A fixed bit vector accepts exactly one challenge. Total 8,346 assertions, repeat execution byte-identical, syntax check passed. The checker does not test cryptographic hash or QPT security.

Still absent: a practical classical-PPT, QPT-secure local release gadget, adaptive ORIGINAL-source authentication, all-valid-witness SAME-credential recovery, false-instance full-public-view key hiding, unauthorized recovery/native forgery to ORIGINAL witness or independent break, malicious N-of-N setup/abort/erasure, multiple capsules, 128-bit concrete resources, and conditional native-PQ Bitcoin challenge graph. No WE/iO-equivalent assumption is claimed solved. Production unchanged; PR draft/unmerged; stopping condition unmet.
