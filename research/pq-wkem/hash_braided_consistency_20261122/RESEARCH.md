# Hash-braided global consistency attempt (NONQUALIFYING)

## Continuity
Read live draft PVUGC#1 branch research/pq-wkem-validation-20260918 at 66ada35e889fa82b8f905d29768394fc37e5cf19, SAI117 and predecessor SAI116. PR issue comments since 2026-11-21T00:00Z were empty. Core #609 was not reread or modified: no new source-admission claim is made. Preserve the original three independent OR challenge grounds, strict modern chain-ID/exact canonical parent tag, actual ancestry and required LC depth, exact claim/cancel/native-VK binding, and one-honest setup.

This pass attempted a genuine algorithmic change from SAI117's publicly exposed pre-power matrix: use source-fingerprint-dependent random matrix braiding, then replace reversible operations with non-invertible SHA256 chaining, seeking polynomial-time full-witness consistency **and** the same frozen release across different original certificates.

## A. Public source-indexed conjugation does not enforce secure global consistency
Let d(w)=SHA256(domain||canonical(w)). For gate index j let R_j(d) be a publicly computable SHA-derived invertible matrix. Present
T_j(w)=R_(j-1)(d(w))^{-1} M_j(w) R_j(d(w)).
On a single w, masks telescope. Using a different w_j for each gate breaks *prescribed* telescoping; unlike scalar cancellation, this can be noncommutative. However the attacker knows each d(w_j) and R_j. It computes
M_j(w_j)=R_(j-1)(d(w_j)) T_j(w_j) R_j(d(w_j))^{-1}
independently, then recombines the unmasked gate values. No SHA inversion is involved. Publicly derived conjugation is not a cryptographic barrier to mixed evaluations. This algebra does not alone show secret recovery for arbitrary M_j. Hiding R_j under a secret key removes this direct unmasking only if a genuinely public protected evaluator for T_j exists; no such serialized evaluator was constructed.

## B. Noninvertible SHA braid removes a group inverse but destroys universal opening
Use public s_0 and update
s_j(w)=SHA256("braid"||j||s_(j-1)(w)||d(w)||local_j(w)).
This polynomial-time hash computation binds all gates to one supplied w and is not algebraically peeled by the preceding formula. But different valid witnesses normally have different terminal digests. Encrypting once as C=S XOR SHA256("terminal"||s_m(w_0)) allows opening by w_0 and not by a different qualified w_1. A correction mapping every valid terminal digest to the same hidden S would have to be prepared before unknown future certificates exist. Enumerating all valid digests is impractical; publishing an explicit hidden constant reveals it; a secret-keyed but publicly executable correction is exactly the missing FE/WE-like mechanism. This diagnoses this candidate, not a general hash-only impossibility.

## Local executable check and precise scope
A standard-library Python3 checker actually ran with exit 0. It used only four-bit synthetic Ch predicates, with four satisfying assignments. Valid 0000 and 1111 yielded distinct SHA braided terminal digests. One fixed terminal pad opened only for 0000. Separately, three public source-indexed noncommutative 2x2 matrix conjugations over F_257 were removed exactly even when their whole-witness inputs differed.
- Local-only check.py SHA256: ecd3163e38a696a1a704666ab87398df4f0cfd1c5c557e51ce622440e6791f46
- Local-only output.json SHA256: 417a47117c38474d81b76686c5881517a8969023616e05f61b1cdced6531fa4d
- Local-only complete derivation, checker, output archive SHA256: 68cf050d663a97a96d75697789958f55e9bb6c30614e69749862b6020b048365

The checker is not real Bitcoin/Syscoin source authentication, Core admission, native signing, FE, ZK, a full-public simulator or QPT experiment. The executable and captured output are **not committed** with this note; the recorded hashes refer only to executed local bytes.

## Remaining ORIGINAL equation
A classical PPT serialized Build_inc(x_W,S)->C, with PUBLIC Open_inc(C,w)=S for every qualifying ORIGINAL authenticated witness, is still absent. Full-public FALSE and unauthorized hard-TRUE QPT recovery/native-forgery -> actual ORIGINAL certificate or independent justified break, including native checking keys, auxiliary data, sibling capsules and malicious source/setup coins, remain wholly unproved. Neither public masking nor noninvertible braiding supplies a source-conditioned secret. No ideal SourceOpen, normal external if-check, private signer, unrelated PoW puzzle or renamed FE assumption is counted as a repair.

**NONQUALIFYING:** no progress comment, breakthrough alert, production/Core change, activation, deployment or automation change.
