# R239 — single SHA/AuxPoW-source-indexed hash pad
**NONQUALIFYING. No actual secure Build_inc/Open_inc; no ORIGINAL-source WE or quantum theorem.** This is a precise rejection of a narrow source-indexed single-ciphertext pad family, not a general impossibility theorem.

## Continuity and execution
Existing syscoin/PVUGC PR #1 branch research/pq-wkem-validation-20260918, starting head c9ee0c1130ffee074d7a815414d14533d2702d57 (R238). Read the R238 affine-source-gate research note and PR ordinary comments since November 11 (R225 was the most recent). Core #609 canonicality verified previously and used as pinned code context, not claimed deployed. Local CHECKPOINT_01.md written before testing, CHECKPOINT_02.md after two local runs. No literature/web lookup, other repository mutation or independent agent. Full local Python model checker SHA256 fe69662ac2c06964b6472503ca8a312f6b118bcfb25fc07e697d2581ec14bdbd and captured result SHA256 73b7fa60b2ca75fbc8f9d8f78ed15367b1bfd475178c2fa5cabceb174daf678a. The separately published checker_min.py was also executed twice locally (SHA256 ee8ba4472f06b0c497a43627dc29be174560175b6c9cb9a14c21883fa2bd8736), with output SHA256 02408da13d70ece843a1ef01ec02e77221010f1088d4592b20d73b62d45b2d6b.

## Original relation (not replaced by a toy)
One notary activates a preauthorized delayed withdrawal; ANY qualified observer can cancel. N-of-N graph setup separate. Original OR challenges: (1) authenticated heavier conflicting BTC history; (2) finite authenticated burn fault; (3) authenticated relevant Syscoin claim-prefix/ancestor inconsistency with sufficient LC depth or separately defined tag fault. x_W binds exact claim/UTXO, activation/withdrawal, burn details, BTC anchors and window, baseline/source slot, fork-depth, cancellation deadline/message, native VK, and capsule ID. Post-activation Core #609 restricts canonical 41-byte parent SYS tag and modern chain ID, yielding at most one valid child per authenticated parent coinbase commitment subject to ordinary hash binding. Different parent work certificates of the SAME child are not a fork. Real original source admission remains a separate demanding condition: contextual difficulty and PoW, Merkle/AuxPoW expected index, Bitcoin best-chain anchoring, child ancestry and contextual tags, windows, resets/DA and relevance. Neither the toy checker nor this candidate supplies it. R225's slot-global versus activation-specific native cancellation portability remains unresolved.

## Named candidate and exact all-witness lemma
Freeze a native-cancel capability sigma at honest classical-PPT Build, publish one ciphertext c, attempt:
   Open_inc(c,w) = c XOR Hpad(I(x_W,w))
where I is a public SHA256d/AuxPoW-derived source index and Hpad is a domain-separated hash. Even GRANTING perfect authenticated original witness checking, for two accepted witnesses w0,w1, correctness requires:
  c XOR Hpad(I(w0)) = sigma = c XOR Hpad(I(w1));
therefore Hpad(I(w0)) = Hpad(I(w1)).
The fixed public c cancels from the equality. For m pairwise distinct FIXED indices selected independently of an ideal κ-bit Hpad, the probability all outputs coincide is exactly 2^(-κ(m-1)). This is an **idealized independent random-function statement**, NOT standard-model SHA or a full QROM/WE impossibility theorem. A builder cannot fix inequality of witness-specific pad values by selecting a different one-ciphertext c. Future actual SHA/AuxPoW certificate indices remain unknown to offline setup.

## Source-grounded attempt and repairs
1. I = SHA256d(parent_header). Parent work certificates vary even when they certify the same Syscoin child. It breaks same-output correctness on equivalent source witnesses.
2. I = PureChildHash(Ancestor(P,h_rel)), eliminating parent-work multiplicity. Distinct qualifying claim-prefix forks still give different indices. Thus different valid alternative histories return different values. This is a genuine normalization improvement but NOT a usable release.
3. I = a common already bound ancestor/baseline value in x_W. This repairs equality for all w but is publicly computable. An unauthorized **classical** attacker obtains sigma = c XOR Hpad(I_baseline) immediately, breaking full-public FALSE security even with native VK, sibling capsules, aux input and selective openings. A QPT attacker can run the same algorithm.
4. Sorting/hashing the two observed child IDs produces different indices for distinct qualifying pairs. A public height/slot selector is also known before source evidence. An exhaustive table for unknown future parent/child indices is not classical-PPT Build. An online secret issuer or hidden verifier program would change the model and is not a repair.

## Reproduction
Full local checker generated 4 alternative pure-child digests, 2 toy SHA256d 80-byte parent-work certificates per child (8 total), canonical-shaped OP_RETURN PUSH39 [sys,hash,height] scripts, and an artificially loose 8-leading-zero-bit SHA256d target. It is NOT real BTC coinbase serialization, contextual DAA/PoW, best-chain membership, Merkle/AuxPoW validation, Syscoin history admission or native PQ signing. Two local runs produced identical JSON.
  Parent index:   8 certificates / 8 distinct indices / only 1 common-ciphertext opening.
  Child index:    8 certificates / 4 distinct indices / only 2 common-ciphertext openings.
  Public baseline:8 certificates / 1 index / all 8 openings but public key leakage.
  Pair-digest:    six unordered alternative-child pair classes.
checker_min.py reproduces the algebra independently with ordinary SHA256; it is NOT a second consensus validator or QPT experiment.

## Joint public security / open obligation
The variable-source cases already fail all-original-witness same-sigma correctness; public auxiliary data cannot restore correctness. The constant public-baseline case fails FALSE secrecy through a trivial straight-line adversary returning sigma, with no original certificate, cryptographic break, or honest Open call. The test does not attempt hard-TRUE extraction or arbitrary coherent QPT forging. A hidden source-authentication compiler embedded cryptographically inside release, not a post-hoc Boolean check, is still missing. The remaining task is a classical-PPT Build_inc(x_W,sigma) and public Open_inc(C,w), same frozen claim-scoped native safe cancellation capability for every ORIGINAL qualified witness, with arbitrary-QPT final-recovery/forgery => ACTUAL ORIGINAL witness or independent PQ hash/native break in the full public multi-capsule malicious-source setup. Bitcoin must still see only native signatures. No source compiler, issuer, secret evaluator, lattice, obfuscation or exponential table is silently assumed.

No PR progress comment is warranted by this nonconstructive family rejection.