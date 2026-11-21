# SAI98 — whole-witness commitment versus raw public transition mixing (NONQUALIFYING)

## Scope and start

Read actual open/draft syscoin/PVUGC PR #1 on research/pq-wkem-validation-20260918 at 8b9e2144a0459385c6a669d4beeffc5bf9566b08 (SAI97) and its exact parent SAI96. Targeted top-level issue-comment read since 2026-11-18 returned no new comments. Source facts from Core #609 were NOT rechecked, Core tests were NOT executed. This is a mathematical pre-screen of a candidate global cryptographic release representation, NOT a claim that the bridge or FE is constructed.

The exact missing operation remains a classical practical, serialized, hash-only Build_ORIGINAL(x_W,S;rho)->C and PUBLIC Open_ORIGINAL(C,w)=S for EVERY qualifying authenticated ORIGINAL certificate. Every branch of the authorized BTC-greater-work OR specific-burn-refutation OR relevant-Syscoin-history/tag-fault relation stays independently sufficient. Strict modern contextual AuxPoW, the actual claim-prefix/LC policy, safe native message/outpoint, one-honest N-of-N setup and no Bitcoin NP verifier are unchanged.

## Candidate: full-witness-root-scoped public matrix flow

A different *structural* repair to local R289/R366 splicing is to bind every occurrence of the same original evidence bit to ONE collision-resistant global witness commitment r=MerkleRoot(w). Repeated values would be checked against the same root, rather than treated as independent local input labels. This improves **prescribed checked evaluation**: under binding of H, two valid openings for the same leaf index and root cannot expose opposite bits without a hash collision. It does not yet show that public source-conditioned release is possible.

Consider the smallest abstract inconsistency, R(b)=(b=0 AND b=1), which is FALSE. This is a pre-screen fixture, not actual Syscoin source evidence. A proposed full-program linear-flow encoding chooses random invertible 2-by-2 matrices G0,G1,G2 in GL_2(F_p), and a public nonidentity invertible J=diag(2,3), p>3. Local transitions are
  M_A,0=I, M_A,1=J,
  M_B,0=J, M_B,1=I,
and publish all four "garbled" transition matrices
  P_A,b = G0^{-1} M_A,b G1;
  P_B,b = G1^{-1} M_B,b G2.
Setup knows the accepting product T=G0^{-1} G2 and publishes D=S XOR SHA256("flow-pad"||encode(T)). The prescribed Open takes one global b, its root r and two root-consistent openings; after authenticating the root and all real source conditions, it evaluates P_A,b P_B,b, checks whether it represents acceptance and returns D XOR SHA256("flow-pad"||encode(product)) only upon acceptance.

For consistent b=0 and b=1, the product is always G0^{-1} J G2, not T, so prescribed Open never releases. This does NOT establish secrecy of the public bytes.

## Full-public attack and why the root repair is insufficient

An attacker possessing the *actual serialized public factor matrices*, even if it knows NONE of G0,G1,G2, can compute
  P_A,0 P_B,1
    = (G0^{-1} I G1)(G1^{-1} I G2)
    = G0^{-1} G2 = T.
It then calculates S=D XOR SHA256("flow-pad"||encode(T)) without providing a common bit b, any Merkle opening, or any original source certificate. The same construction remains insecure in a TRUE fixture against unauthorized early recovery, because free-access factors permit an inconsistent local path whether or not a real valid source witness exists.

Putting a root r into a *publicly computable* conjugating matrix U(r), for example
  P_A,0(r)=G0^{-1} I U(r)G1,
  P_B,1(r)=G1^{-1}U(r)^{-1} I G2,
does not fix this: arbitrary raw evaluation at any common r still yields T. Enforcing r=H(w) and index-consistent inclusion checks only in a public wrapper does not constrain a malicious reader of the factors. A SHA-based KDF of T does not help because the adversary obtains the exact T bytes.

One could demand that each P_A,b(r) be *cryptographically unavailable* unless a valid, original-source-authenticated global opening exists, while still enabling arbitrary different qualifying future witnesses. But that is the missing secret-bearing public release/input-label gate in another form. Replacing the public matrices by an *ideal* checked matrix oracle is not a serialized classical-PPT Build/Open. Publishing the entire checking program with its hidden masks as inspectable constants also fails.

Thus the global Merkle root is a valid compact *data consistency* repair, NOT a cryptographic release repair. This is a known-attack pre-screen; no larger experiments or reparameterized tensor tests were undertaken. In particular it is not evidence of a novel generic impossibility for hash-only original-source WE, and not an attack on SHA256 or the strict Core AuxPoW fix.

## Joint-public/security disposition

The public joint view would include (all P_A/P_B matrices,D,r policy, hash code, source verifier, native VK/message, setup proofs, siblings and adversarial source coins). The explicit algebraic attack recovers S from this view with no oracle programming or local source authentication at all. Consequently there is no FALSE-instance simulator preserving native hidden-message security for this candidate and no hard-TRUE accepted signature -> ORIGINAL certificate reduction. It already fails classically, so QPT protection is also absent; a setup correctness ZK merely certifies generation of this insecure capsule.

No code was implemented and no test was invoked for this prescreen because the symbolic extraction is exact for every invertible choice of G0,G1,G2. This obeys the anti-spinning rule: known raw-factor mixing was checked before performance experiments. The original source-specific nonblackbox encrypted *global gate*, public serialization and joint-public security still need construction, without an invented source signer, source-independent puzzle, generic FE oracle, or a changed OR relation.

## Next nonredundant decision

A follow-up candidate must first give actual *public byte-generation and evaluation algorithms* that hide at least the source-conditioned accepting transition **even from an adversary who ignores every prescribed wrapper**. It must explain how every heterogeneous original AuxPoW/burn/BTC-work certificate supplies the SAME release capability without new miner/ChainLock secrets, and must provide a full-public simulator/extractor or independently justified cryptographic reduction. Another Merkle root, public matrix gauge, high-degree polynomial basis or local validation wrapper alone is not a new candidate.

**NONQUALIFYING: no ORIGINAL-source release or independent QPT theorem.** No user breakthrough notification, PR comment, Core/production edit, deployment, approval, automation change or transfer.
