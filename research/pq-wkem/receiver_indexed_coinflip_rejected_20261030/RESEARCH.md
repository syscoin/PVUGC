# Receiver-indexed one-honest shared SOURCE coinflip — rejected

**Status: NO positive witness-KEM construction advance.** This offline attempted composition was broken by a concrete malicious-receiver cancellation. It is NOT a secure one-honest distributed source, does NOT replace the uniform-target batched dual-LWE predecessor, and does NOT supply an ORIGINAL-NP witness lift. No deployed Bitcoin functionality is claimed.

## Exact context and selected step

Repository: syscoin/PVUGC, open/draft/unmerged PR #1, branch research/pq-wkem-validation-20260918, starting SHA 006239e0831b14a10f30830f2bf9bc8b307bea28. Latest ordinary substantive comment read: 6516965374; predecessor comment: 6516094195. The only exact research files inspected were signed_unit_repetition_no_go_20261030/RESEARCH.md (blob 5e46166daac64ef44bd2485a1b63f8f3272ffffe) and uniform_target_batched_lwe_20261030/RESEARCH.md (blob d1bc72cf6b2692ee73783d086931014917631859). No external research or full diff.

The attempted step was to generate a **single shared** uniform matrix M=[A|U] with any one unknown honest participant, and simultaneously simulate a standard decisional-LWE challenge matrix and all malicious setup transcript correlations. Ordinary QPT DecLWE was to remain the independent assumption for the subsequent full-length batched ciphertext; native signature and SETUP-domain authentication were to use the genuine checking key. The experiment addresses only source generation, not ORIGINAL evidence release or funded graph composition.

## Attempted classical protocol and QPT proof opportunity

Let q be odd prime. Encode every entry of the matrix in canonical binary, Q bits total. Have N receiver-indexed sessions j=0,...,N-1; participant i supplies S[i,j] in F_q^{n x (m+L)}. Receiver j publishes one pair of public ternary-style PRG offsets per bit, here just binary sigma[j,k]. Each i commits to each bit b of S[i,j] by

    C[i,j,k] = G(r[i,j,k]) XOR (b * sigma[j,k]),

with G: {0,1}^kappa -> {0,1}^t an independently assumed nonuniform-QPT-secure PRG. All commitments are sent before any openings. In each session, all senders i!=j must open before receiver j opens its own commitment. Accept only a complete authenticated set of canonical valid openings, and publish

    M = SUM_{j=0}^{N-1} SUM_{i=0}^{N-1} S[i,j] (mod q).

A REAL honest receiver h samples uniform independent sigma[h,k]. Across every commitment using the same sigma[h,k], different-bit double opening would imply sigma[h,k]=G(r0) XOR G(r1), a globally bad event of probability at most Q * 2^(2*kappa-t). (The event bound says NOTHING about commitments in malicious receivers' sessions.)

To embed a uniformly distributed external LWE challenge M, a prospective straight-line simulator instead chooses FAKE sigma[h,k]=G(r0[k]) XOR G(r1[k]) and C[h,h,k]=G(r0[k]), then, after other session values are opened, sets the receiver's share to M minus the sum of other shares and opens to the programmed bits via r_b. The scheme has exact two-way opening functionality. The standard QPT PRG hybrids can support single-opened commitment simulation under their exact classical-interface and independent-advice restrictions, but they cannot establish the security of the entire source transcript when a DIFFERENT receiver can equivocate its own commitments.

## Concrete malicious receiver (classical, no cryptographic break required)

Take N=2, honest h=0, malicious j=1. The honest participant publishes uniformly random REAL sigma[0,k], commits honestly to S[0,0], and opens last in session 0 after the corrupt S[1,0] opening. The malicious receiver 1 generated its own CRS before the commitments, using privately known seeds (a_k,b_k):

    sigma[1,k] = G(a_k) XOR G(b_k);
    C[1,1,k] = G(a_k).

These commitments open to 0 using a_k or to 1 using b_k. All four sender/receiver commitments exist before any opening. Session 1 happens after session 0, so the corrupt receiver sees S[0,0], S[1,0], and honest nonreceiver S[0,1] before making its final receiver-last opening. For ANY selected target M_bad, including M_bad=0 or a nonzero M_bad=[A|U=A*z_bad] with a retained short opening, the corrupt receiver chooses

    S[1,1] = M_bad - S[0,0] - S[1,0] - S[0,1] (mod q),

and opens C[1,1,k] to every selected bit. Every commitment verifies and receiver-last chronology holds. Final M=M_bad, despite the honest participant's independent uniform contribution. This permits a retained-source-opening early-release bypass when the source is later used to encrypt the honest participant's native signing key. No honest signature forgery or SOURCE certificate falsification is necessary.

The attack is generic for any PRG because its malicious receiver knows both opening seeds by construction. Choosing longer t or changing q does not remove it; the REAL honest receiver's good CRS only binds the source contributions in its own session. A test-only checksum of M=0 is not a repair, because the corrupt receiver can choose any ordinary-looking M with a known preimage.

## Repair attempts and why no positive result was claimed

Cross-committing every receiver's final contribution under every CRS could bind malicious final shares under one honest receiver's real CRS. However, the honest survivor's own cross-commitments are then also under malicious CRSes, and the ordinary LWE-challenge simulator cannot program those values after observing corrupt openings using the specified PRG commitment. A fresh independently justified jointly simulatable, one-honest multi-CRS commitment/coinflip compiler remains missing. An alternative fixed session order merely changes which unknown honest positions can be followed by a corrupt cancelling receiver. Hashing or publicly rerandomizing the final matrix without proving the entire QPT challenge distribution is not a repair. The old source-separated *independent* M_h solution avoids this particular shared-source cancellation, but still does not compile ORIGINAL fork evidence.

## Executed reproducible evidence and honest limits

Published check_compact.py is the exact locally executed source. It ran twice with byte-identical JSON, passing 1,840 assertions each over 80 complete two-party transcripts. Its corrupt last receiver opens an explicitly equivocable binary commitment to either zero or a fixed nonzero target. All four commitments verify, with receiver-last chronology intact. SHAKE-based toy G and seeded RNG are FUNCTIONAL mocks, not PQ parameter validation. The additional local-only attempted functionality checker check.py passed 17,099 assertions twice, verifying fake-source embedding for four possible honest indices **under a non-equivocating corrupt-receiver policy**, which is precisely why that first result did not prove malicious safety. Full local notes, both checkers and captured outputs were preserved separately.

For illustrative q=16777213,n=256,m=6800,L=52,N=4,kappa=256,t=898, the bitwise proposed ceremony would publish about 94.51 billion **bytes** of CRS plus commitments and 21.55 billion bytes of opening seeds. These are prohibitive, uncalibrated component costs, not a practical advantage. Even perfect QPT PRG security does not save the protocol.

## Exact handoff, unchanged primary obligation

A future shared-source reduction would need both (i) actual binding of ALL malicious final contributions before the unknown honest source contribution becomes usable, and (ii) straight-line simulation of ALL honest commitments/openings conditioned on the full external LWE challenge matrix, its ciphertext, checking key, context, auxiliary information and related capsules, **without guessing a designated honest-last verifier or invoking SourceOpen**.

More importantly, the primary generic-NP WKEM remains unbuilt: a witness-free classical PPT Comp(R_original,x,claim/UTXO,branch,anchors/window,context,pk) and public offline Release(D,W) that recovers the SAME precommitted native capability for EVERY valid ORIGINAL witness; fixed-FALSE full-public QPT secrecy; hard-TRUE unauthorized key recovery/forgery -> ORIGINAL witness or independently justified QPT break; complete malicious unknown-one-honest N-of-N pre-funding graph, safe abort/completeness, source authentication and conditional PQ-native Bitcoin endpoint. Do not count this rejected attempt as research success, merge or deploy it, or disable the research automation.

Provenance: Offline local computation plus connected GitHub metadata, recent-comment and exact-version research-file reads only. No outside literature, independent agents, production writes, review or deployment.
