# R377 — Path-dependent native signatures without common-terminal convergence (NONQUALIFYING)

## Exact continuity
Read open draft syscoin/PVUGC PR #1 at branch research/pq-wkem-validation-20260918 head c12ca7caae5ff8cf2ba80410ebedaa7171aeb500. Its R376 note had blob bdb108366fd37f7a89115656fb0b95306f0da52e. The recent ordinary comments request since 2026-11-18T19:24:00Z returned an empty array. No Core #609 source was reread, and no active-PQ deployment or network test is claimed.

## Specific constructive change attempted
R376 had public hashed DAG state traversal: a common accepting token permits inexpensive public exploration of its polynomial-width state graph; per-path SHA capabilities avoid deduplication but each valid future witness ends at a different token and cannot unwrap a single frozen key. This iteration attempted a genuinely different exit: allow each qualified witness to produce DIFFERENT native signatures for the SAME fixed safe cancellation message m and public key Q, thus representing one frozen native authorization class without demanding identical terminal-key bytes.

That is a speculative weakening of the approved stronger Open(C,w)=same frozen sigma_cancel, not an authorized scope change.

Proposed path Open: take a publicly derivable terminal scalar t(w), and try to rerandomize a one-time presignature (R,s) to (R+t(w)*G, s+t(w) mod n). If the resulting pairs verified under Q,m, terminal capabilities could remain distinct. The proposed operation is explicit; it was tested before attempting any large original-source compiler.

## Native algebra rejects this particular repair
A BIP340 base signature satisfies sG=R+eQ, with even-y R and e=H_challenge(x(R)||x(Q)||m). The additively tweaked pair satisfies s'G=R'+eQ using the STALE challenge. But Bitcoin computes e'=H_challenge(x(R')||x(Q)||m). For even-y R', success requires (e'-e)Q=0 and so e'=e for nonzero Q of prime order. For odd-y R', the even-y lift of its x-coordinate is -R', and success instead requires 2R'+(e-e')Q=0. Neither equality is guaranteed by deriving t from a valid SHA/AuxPoW witness.

Even if this native transform succeeded, publishing (R,s) would already reveal a valid cancellation signature and defeat source gating. Keeping it private makes the proposed Open nonpublic: its inputs R,s are missing. A protected operation that computes a signature from a hidden base key is exactly a functional-signature/FE task whose independent hash-only public compiler and full-public simulator have not been supplied.

Known native ECDSA admits verification-level (r,s) -> (r,n-s) from an ALREADY VISIBLE signature, not a useful public witness-conditioned release. The latter may be restricted further by Bitcoin low-s policy. There is no assertion that all rerandomizable signature constructions are impossible.

## Actually executed bounded negative control
The Python checker uses public TEST secp256k1 keys, pure point arithmetic and a full x-only BIP340 tagged-hash verifier. It verifies an initial valid test signature, constructs 64 independent SHA-derived public path scalars, confirms the stale-challenge algebra for each, and tests the real challenge after each rekey. None verified in the test. It also uses cryptography ECDSA to verify a known signature and its (r,n-s) transformation while testing 64 simple additive s modifications, none verified. This is a small algebraic regression, not cryptographic security evidence.

Executable check.py exact git blob 0fda610c8697f1879b28a4befa5f724c59069731; local SHA256 b2fba6583a6a64392b441cc4aed5293c6c2cf90654f40cad9dbe77eb47c28ec8. Captured output.json exact blob 47aaf1982dcca5ca608a259669befa4b5c5e7cc4; local SHA256 741398f6a5c29713b2ffd66a84efdb0a75e37a3b08d60f7173e5995d2f858f4b. Generated in this execution with Python and cryptography; these test secrets are public and MUST NOT back funded Bitcoin outputs.

No original Bitcoin/Syscoin witnesses were produced; no FE/WE, setup ZK, Bitcoin VM acceptance, native transaction, quantum algorithm, simulator or actual work-reduction experiment was performed. The 64-trial absence of a signature is not a generic hardness theorem.

## Security and precise next equation
The original release relation remains a disjunction of (i) qualified greater exact Bitcoin chainwork, (ii) finite authenticated specific burn fault, and (iii) relevant strict-modern-tag Syscoin fork/inconsistency at actual required LC depth. No greater Syscoin work, source winner, extra notary or new challenge restriction is imposed. Preserve all claim/outpoint/anchor/window/reset/deadline/native-VK/message/capsule binding, malicious setup/source and sibling auxiliary correlations.

A genuinely new compiler must still instantiate CLASSICAL polynomial-time Build_inc(x_W,sigma_cancel)->C and PUBLIC Open_inc(C,w)=sigma_cancel for every qualified ORIGINAL w, plus independent full-public FALSE and hard-TRUE QPT recovery/accepted native-forgery -> actual ORIGINAL witness or justified hash/native break. Merely changing the native signature bytes, testing malleability, or treating a source verifier as a public wrapper does not supply that compiler. One-honest N-of-N setup and FE verification remain conditional on this missing primitive. The first-release Bitcoin native signature may be classical, but that does not establish full end-to-end QPT security.

Nonqualifying: this is a rejected specified native path-rekeying candidate, not source-release progress. No PR progress comment, user announcement, production/Core change, deployment or automation change. Next useful research must instantiate an actual source-authenticated PUBLIC global gate, not this endpoint trick.
