# R166 — Generic hard-TRUE hash WKEM implies one-way public-key transport

**STATUS: conditional reduction and toy check, NOT a secure practical hash-based WE, PoW compiler, or reportable breakthrough.** No lattice, public group, online release authority, or external literature was used. This is a mathematical requirement on a future *generic* ORIGINAL-np WKEM; it does not independently instantiate that WKEM.

## Continuity
`syscoin/PVUGC#1` open/draft/unmerged, research/pq-wkem-validation-20260918, observed starting head 99fa6c97bd5b2c5d807fc9f2a0b64def99917276. Read R165 at research/pq-wkem/r165_hash_ots_equivocation_20261108/RESEARCH.md (blob 10c0d887d0bd06eac47f6586704e9a6930a5b28d) and R166-predecessor research/pq-wkem/hpw_20261108/resumed_2353/CHECKPOINT_05_QROM_AND_PADDING.md (blob 2d48e1ad2cba4891546b10cbf0eb1b3f8a9dc7a3) by exact head. No ordinary PR progress comment warranted: generic source compiler is still absent.

## Theorem (one-way public-key transport implication)
Suppose a classical-PPT generic-NP hash-witness-KEM builder can, using only a public NP statement (no satisfying witness) plus a freshly chosen protected secret S, generate a public capsule C. Every satisfying ORIGINAL witness w causes public Open(C,w) to recover the **same** S. Further assume the requested hard-TRUE full-public QPT key-recovery security: an attacker recovering S on such hard sampled true instances yields a QPT extractor producing an ACTUAL ORIGINAL witness or an independently justified quantum-hardness break. This is **stronger than ordinary false-instance witness encryption**.

Let h:{0,1}^n->{0,1}^m be a QPT preimage-resistant domain-separated hash family. Define the ORIGINAL-NP relation R_y(y,w)=1 iff |w|=n and h(w)=y. Then

    Gen:  sk<-U({0,1}^n), pk=h(sk).
    Encap(pk): S<-supported high-entropy distribution;
               C<-Build(R_y,pk,S); return (C,S) to sender.
    Decap(sk,C): return Open(C,sk).

Honest correctness follows immediately. If QPT Eve recovers S from pk,C, the stipulated hard-TRUE extractor yields some w' with h(w')=pk, solving the hash preimage challenge, or an independent forbidden PQ break. Thus the hypothesized **generic** hard-TRUE WKEM yields one-way public-key secret transport/KEM-like functionality under its stated assumptions. This is not automatically IND-CPA encryption, and no indistinguishability claim follows from mere key one-wayness. If the original API transports only a fixed native signature σ, the sender can create fresh native signing keys and transport σ as the high-entropy secret; claims about a separately derived random key require that key itself to be covered by the recovery security notion. The setup for the reduction must be allowed to generate the requisite native signature/capability and public VK itself.

This direction is **WKEM ⇒ one-way transport**, NOT the converse. It neither constructs a public-key primitive from hashes nor proves its impossibility. A specialized Syscoin-fork-only source scheme need not imply this result, but it also does not meet the user's separately retained generic-NP requirement. The implication is a diagnostic for evaluating future generic hash candidates.

## Independent SHA-256 functional check (no hardness claim)
`checker.py` is the actually executed Python-standard-library source; captured.json is actual stdout, rerun byte-identical. It uses a toy 12-bit witness and SHA-256 truncated to a 16-bit public preimage image, then EXHAUSTIVELY enumerates all 4096 candidate witnesses per pk. The 24 seeded fixtures include 27 valid witnesses, all returning exactly the same 256-bit toy key for their respective capsule; each invalid witness is rejected; brute-force attackers also recover each key. 99 assertions and 98,304 enumerated candidate witnesses. This is intentionally insecure and EXPONENTIAL for generic n, so it does not fulfill the user's Build requirement or test quantum security. Source SHA256 = 829fa0c3dda461bfa1d33ddc5efb280bf41a5100745c17aa8c5c75ff291c6e68; output SHA256 = 6b13ec672c2d8f8cf63c1e13bc16af6ff3caeef69ab8de87cb59bf723057cbf3.

## Next constructive source-PoW obligation
Real source witnesses must include the ACTUAL claim/UTXO, anchored Syscoin child, parent AuxPoW, Bitcoin header, coinbase/Merkle proof, height/window and required tags, with semantic child-outcome ID distinct from parent-work certificate ID. No public root/tag, invalid-work hash puzzle, retained source signer label pairs, or post-hoc off-chain verifier may be treated as a hidden-token issuer. The candidate MUST instantiate an efficient correlated source compiler and full-public QPT recovery/extraction reduction jointly; each valid ORIGINAL witness must release the same frozen native capability. No polynomial-size construction has been obtained here. Do not spend work on compression of the old exponential table.
