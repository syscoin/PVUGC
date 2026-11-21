# Run 408 — publicly chosen second-slot randomness normalizes local pairing masks

Starting exact live PR head: df7c770e8c2bc4558a3498e71852e337c3688172 (syscoin/PVUGC#1, research/pq-wkem-validation-20260918, open/draft/unmerged). Predecessor blobs: Run407 055a87d3c1c14350a0bd27a03e04a4b7c965739d; Run406 cb5ec5144694669d7134d3759a18972745e1530f. Last substantive ordinary comment: 6067040320.

## Source and exact scope
Audited Agrawal–Yadav–Yamada, CRYPTO 2022, *Multi-Input Attribute Based Encryption and Predicate Encryption*, publisher PDF https://crypto.iacr.org/2022/papers/530630_1_En_21_Chapter_OnlinePDF.pdf , §1.2 pp.595–597 and §6 pp.615–617 (Enc1/Enc2/Dec). The source explicitly defines secret-key encryption for multi-input ABE. The displayed three-slot scheme uses pairings; it is NOT PQ. Its lattice two-slot variant is explicitly heuristic. This note does NOT break the actual symmetric-key construction; it tests an unauthorized conversion that makes the second slot publicly encryptable by arbitrary later witnesses.

## Chosen-randomness normalization lemma
Work in a prime-order bilinear group: e([a]_1,[b]_2)=[ab]_T. The selected second-slot position in §6 pairs a first-slot term [t1 A_(i,b) W_(i,b)]_1 with an independently formed selector [t2 / W_(i,b)]_2. The nonselected position is [0]_2. Bilinearity yields a group element [t1 t2 A_(i,b)]_T. If Enc2 is made PUBLIC, its malicious caller knows t2 (even when it follows a deterministic public-coin derivation), and computes the public target-group exponentiation

  [t1 t2 A_(i,b)]_T ^ (t2^-1 mod q) = [t1 A_(i,b)]_T.

The attacker can form one chosen second-slot ciphertext for b=0 and another for b=1, normalize their different coins separately and obtain TWO target-group label encodings in the SAME first-slot frame: [t1 A_(i,0)]_T, [t1 A_(i,1)]_T, plus their group difference [t1(A_(i,1)-A_(i,0))]_T. This does NOT reveal any numeric discrete logarithm and does NOT require guessing t1, W or an ORIGINAL witness.

Proof: the pairing cancels W against W^-1. Multiplication by the publicly known inverse t2 cancels the remaining second-slot scalar. Group subtraction yields the difference. All operations are classical polynomial time.

The result is more precise than claiming the attacker must force the same encryption coin twice: even DIFFERENT known nonzero coins permit the same-frame projection. A classical public encryption interface cannot rely on encryption coins being unknown to the encryptor itself. This is a local-seam, global frame-alignment and adaptive multi-view leakage lemma; it does NOT show that the complete three-slot/lattice-masked system leaks its final payload, because the other slot, function key and noise were not modeled. The original scheme's Enc2 requires the secret msk and is OUTSIDE the hypothesis.

## Security assessment and next constructive target
Attack families: (1) mask cancellation by bilinearity, (2) t2 normalization aligns independent branch views, (3) no payload fingerprint proven, (4) two chosen views suffice within one claim but no cross-claim result, (5) malicious chosen coins essential, (6) honest secret-key setup not attacked, (7) no UTXO replay result, (8) no public native-key correlation used, (9) attack is classical hence QPT-executable, not a quantum algorithm. The source's bilinear interface is not PQ and no QROM theorem is claimed.

Exact executed standard-JS algebra checker (separately reproduced by independent local Python finite tests): 36000 assertions across 1800 deterministic small-field fixtures; source and captured output attached. The checker simulates GROUP EXPONENT arithmetic, not a pairing implementation, SIS/LWE hardness, key recovery or signature forgery. No generic WE impossibility or concrete full-system break is inferred.

Useful next primitive must withstand an arbitrary public watcher who chooses input witnesses and knows ALL coins of EVERY ciphertext it creates. It must hide K against every joint chosen-input view and prove unauthorized key recovery/accepted forgery -> ORIGINAL representation or an independently justified QPT break. Run259 only proves accepted complete representation -> ORIGINAL under its own assumptions. Remaining: concrete secure local release, all-witness SAME-K, full-public false-instance QPT hiding, true-instance ORIGINAL-source extraction, malicious N-of-N setup and erasure, multi-capsule security, 128-bit parameters and conditional native Bitcoin PQ signing. All UNPROVED. Production unchanged; PR stays draft/unmerged.
