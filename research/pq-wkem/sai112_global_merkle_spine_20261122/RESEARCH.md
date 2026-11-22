# SAI112 — global Merkle input-spine repair of the public BP, SOURCE RELEASE STILL MISSING (NONQUALIFYING)

## Live provenance and reason for selection
Started at live open/draft syscoin/PVUGC PR #1 branch research/pq-wkem-validation-20260918, head 3e09396652f7aa31e6ac94812ef0bf1370278e3d, tree 426a4abc97b788dc09f265930151d602cb4383b0. Read exact preceding SAI111 note blob eb3b65a56c591092e29ae64ce1f45d4553fbc43f and SAI110 note blob 1f0f67a2ae77155a8fde55d6a2d8d6e901ca30e7. Recent top-level comments since 2026-11-18T19:24:00Z were empty. No Core source was needed/read; no live source claim or native signature was tested.

SAI111's public noncommutative branching program allows independent choices for repeated occurrences of the *same* global input bit. Before considering any larger SHA/AuxPoW compilation, screen a mathematically different proposed repair: bind every occurrence to a single CRH-authenticated global assignment via SHA256 Merkle openings. Unlike merely renaming local gates, this adds an actual collision-reduction tying contradictory openings to one root.

## Candidate: public globally committed input spine
For a fixed claim/session sid, a witness assignment w=(w_0,...,w_{n-1}) and its fresh public nonce eta, define canonical Merkle leaf
  L_j=SHA256("V1LEAF\0" || sid || uint32be(j) || uint8(w_j) || eta),
and internal node
  N(a,b)=SHA256("V1NODE\0" || a || b).
The claimant provides one root r, plus canonical per-variable openings pi_j. For each occurrence gate requiring variable v, the prescribed evaluator checks VerifyMerkle(r,v,b,eta,pi_v) and then selects the corresponding BP transition. The same r must be used for *every* occurrence, in addition to verifying the complete ORIGINAL Bitcoin/Syscoin source relation against the same whole assignment. The Merkle root is not a replacement for authenticated Bitcoin best-chain/parent/child source facts.

**Restricted positive binding lemma**: for a fixed canonical tree with fixed indices/depth/encoding, if one root accepts two different bits for the same indexed leaf, trace both authenticated paths toward the root. The first convergence of distinct child pairs to the same parent, or the distinct leaf encodings hashing equal, produces a SHA256 collision. This statement requires collision resistance and canonical parsing. It remains valid against QPT collision finders only to the extent SHA256 collision resistance holds for those resource bounds. It makes no claim about secrecy, issuance, or source work.

For the FALSE relation f(x)=(x=0 AND x=1), no root with a canonical opening can pass both conditions. Roots committing x=0 and x=1 can separately open their own bits, but one cannot substitute the other root's opening without breaking the hash binding. This closes the precise *honest prescribed-evaluator* inconsistency in SAI111.

## Crucial full-public gate check: still insecure
The SAI111 serialized public BP publishes both M_j^0 and M_j^1, where M_j^b=R_(j-1)^(-1) U_j^b R_j. The adversary can multiply them directly, without invoking the prescribed Merkle verification at all. For S5, a=(0 1 2), b=(0 1 3), the two contradictory selections return [a,b]=(0 1)(2 3) != identity. So if the encryption key is derived as H(R_0^-1 [a,b] R_L), the attacker learns the frozen pad from public transitions on a FALSE instance. The separate Merkle commitment does not alter those public bytes or their source-independent exposure. No FALSE joint-public simulator can erase this distinguishing recovery while keeping the same revealed key/ciphertext distribution.

To genuinely repair this, a transition must be cryptographically *unavailable* until the same global root's authenticated opening and ORIGINAL source evidence pass, e.g. a sought source-conditioned gate
  LockedTransition(C_j, r, pi, w) = M_j^(w_v)   iff R_original(x,w)=1 and pi authenticates v under a single r.
But this is presently a missing public serialized FE/WKEM operation, not an independently instantiated hash-only routine. Encrypting transitions under keys H(r,pi) for individual future roots requires knowing every unpredictable future r at setup, or a polynomial-size protected evaluator producing those decryptions. With a public unprotected evaluator, fabricated roots and independently selectable inputs reappear. Using a single setup-known r either excludes future witnesses or exposes both transition choices. Making one public "proof accepted" flag is bypassable. Adding a proof verifier after raw transition recovery is also bypassable.

## Executed bounded checker
check.py implements SHA256 domain-separated two-leaf Merkle openings for global bit x with a public nonce. It verifies both honest openings, rejects both cross-root substitutions, confirms no x satisfies x=0 AND x=1, and separately computes the exposed S5 commutator by selecting contradictory local occurrences. Run once using python3, exit status 0. This is not an original source, FE, QPT, native signing, or real Core test.

SHA256 check.py: 55e8a8a22b8760701751e5b2acaf8a77868925f1d01a2ff3e28de1a6561082e7
Git blob SHA1 check.py: 558b34502c87e4b2cc6cd8ad69d2b9e53bbe00f5
SHA256 output.json: 2e330a33ef060f3defe7d8b132f491a46c6cc30d35bf43a1fd25d05832d9857f
Git blob SHA1 output.json: 5dd838503e0eea8ccce016594028105042365c4a

## Outcome / exact next equation
There is a proved **input-binding** subcomponent for future cryptographically protected evaluation, but the exposed-transition BP does not become a secure construction. No public classical-PPT Build_inc/Open_inc for the full original three-branch relation, same frozen native capability, FALSE/hard-TRUE full-public QPT source-recovery reduction, malicious-setup/auxiliary/sibling composition, or actual work bound was constructed. The one-honest N-of-N native setup remains conditional on one independently secure honest capsule.

A qualifying continuation requires an *actual serialized* public coupling
  Build_inc(x_W,sigma_cancel;r) -> C
  Open_inc(C,w) = sigma_cancel  for EVERY authenticated R_original(x_W,w)=1,
whose public bytes do NOT expose the locally selected BP transitions/keys to arbitrary inconsistent paths, together with a joint-source simulator and extraction to an ACTUAL qualifying original certificate or separately justified hash/native break. Reusing external Merkle checks, an ideal LockedTransition, more BP frames, or another local basis cannot count as progress.

NONQUALIFYING. Research-directory-only checkpoint; no user breakthrough notification or ordinary PR comment; no Core/production changes, deployment, merge or automation mutation.
