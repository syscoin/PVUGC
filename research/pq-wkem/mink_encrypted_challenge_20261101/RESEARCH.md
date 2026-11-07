# MINK-ECZK: encrypted-edge setup proof, straight-line malicious-verifier QPT simulation

Run: MINK-ECZK-2026-11-01-T18.
Source: syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, starting head 4ec6ff1ff7c6aa03b3268985d1b1d79f8b71093c. Exact predecessor: mink_independent_challenge_20261101/RESEARCH.md blob 420295d80d73b6deeead27edee215b8f843973be.
No external research. NOT a complete generic-NP PQ witness-KEM, deployed protocol or funding recommendation.

## New component and exact trust boundary

MINK-IVEC obtains a genuine post-commit honest-verifier challenge, but cannot simulate a verifier who chooses its edge after examining the coloring ciphertexts. This iteration changes the chronology: the verifier encrypts its edge challenge BEFORE the prover commits to graph colors, and reveals its actual encryption coins afterwards. A straight-line simulator retaining a special, normally ERASED private key can decrypt the edge early, commit only a color-consistent edge, and simulate an honest transcript without knowing the real witness.

Crucial: the public CRS must contain two INDEPENDENT honestly generated QPT-secure encryption public keys, one for graph-color commitments (pk_col) and another for encrypted verifier edges (pk_ch). In the real setup both corresponding private keys are erased/protected from ALL adversaries. In two different proof reductions, the security experiment secretly retains sk_col (soundness) or sk_ch (zero knowledge); this is not a public ability. An unknown-one-honest malicious distributed CRS generation/erasure ceremony is NOT supplied.

## Exact finite underlying LWE encryption

Let q be odd prime, A uniform in Z_q^(m x n), s uniform in Z_q^n, and e sampled independently from error distribution chi supported on [-eta,eta]^m. Publish pk=(A,b=A*s+e), keep sk=s. For bit mu and independent r uniform in {0,1}^m:

    Enc(pk,mu;r)=(u=A^T*r, v=b^T*r+g*mu) mod q, g=(q-1)/2.
    Dec(sk,u,v)=nearest-center-decode(v-s^T*u, centers 0,g).

Open by revealing exact bit mu and canonical binary r and recomputing the whole ciphertext. If 4*m*eta<q-1, for ANY honest key and ANY accepted binary r the decryption noise has absolute value at most m*eta and the correct bit always decodes. Therefore an arbitrary ciphertext can never have valid openings to both 0 and 1, irrespective of the attacker's computation. Encode each of colors 0,1,2 as two independently randomized bit ciphertexts (11 is invalid), and an edge index by ceil(log2 d) independent bit ciphertexts, rejecting out-of-range values.

QPT assumption: decisional (A,A*s+e) LWE for this exact q,n,m,chi and QPT adversaries with independent, polynomial quantum advice; no witness-encryption-like assumption is introduced. For a UNIFORM b rather than a real LWE pk, r -> (A^T*r,b^T*r) is two-universal over {0,1}^m into Z_q^(n+1); pairwise universality follows because a nonzero difference of binary strings has a +/-1 component invertible modulo prime q. The leftover hash statistical bound is epsilon_LO <= 0.5 sqrt(q^(n+1)/2^m). The normal LWE key-hybrid and public-data processing give a conservative multi-ciphertext QPT IND-CPA loss 2 Adv_DLWE + 2k epsilon_LO for k independently randomized ciphertexts. This is a conditional standard encryption proof, NOT a concrete 128-bit parameter assessment.

## One proof round on the ACTUAL setup-consistency statement

Freeze the authenticated statement X including the relation identity, ORIGINAL claim/UTXO/branch, source and ancestors, anchors/window/context, exact Build/KeyGen algorithms, genuine native vk, intended path/capability, ALL related capsules, and admissible auxiliary public data. Its setup NP statement L_setup(X) asks for honest native KeyGen and Build coins consistent with all those published outputs. Compile L_setup to 3-colorability G_X=(V,E), d=|E|>=1, using a deterministic polynomial-time NP-to-3COL compiler (full compiler not yet included in checker).

For EACH unique (sid,X,prover,verifier,round) tuple:
(1) Honest verifier uniformly samples an edge a, encrypts its binary index under pk_ch, freezes/authenticates C_a with the tuple, and keeps a and all encryption coins secret.
(2) Prover, AFTER receiving C_a, independently permutes a correct 3-coloring and encrypts EVERY vertex color freshly under pk_col. It freezes/authenticates the complete vector of vertex commitments. No previously used graph commitment is reused.
(3) Verifier reveals a and ALL encryption coins; prover verifies exact canonical re-encryption to C_a. Wrong value, invalid encoding, unexpected second request or missing opening aborts.
(4) Prover opens just the two vertex colors at edge a with their actual pk_col encryption coins; verifier checks exact values and distinct colors. All messages classical and off-chain.

Funding requires separately established N-of-N preauthorizations, no bypass graph edges, all presignatures and DA. This proof is of setup consistency, not the ORIGINAL NP fork statement, and Bitcoin executes neither proof.

## Quantum malicious-PROVER soundness: direct efficient extracted-color test

For false L_setup, G_X is not 3-colorable. In the soundness security reduction, generate the public pk_col honestly while retaining PRIVATE sk_col. Obtain independent pk_ch from a chosen-plaintext encryption security challenger. Given ANY malicious prover's classical batch of vertex ciphertexts, privately decrypt every two-bit vertex commitment using sk_col, interpreting the invalid fourth value as invalid. This is an efficiently computed total assignment; at least one graph edge has identical or invalid endpoint colors. Acceptance on an opened edge necessarily implies that the extracted colors at that edge were valid and distinct, by deterministic correctness of Enc and the canonical opening check. No adversary-supplied representation is required.

At round r, construct an IND-CPA distinguisher for encryption of the sampled uniform edge index a versus encryption of fixed dummy index 0 under pk_ch. Run all earlier genuine challenge rounds using publicly generated encryption randomness and full prior transcripts. The distinguisher HALTS IMMEDIATELY AFTER the target round's vertex commitments and uses private sk_col to test whether the extracted assignment is good on the ORIGINAL sampled a, including all prior extracted-pass conditions. In the dummy branch, a is independent of the current committed assignment even with arbitrary previous QPT computation, so the target test passes with probability at most alpha=1-1/d. The difference is bounded by multi-bit QPT IND-CPA advantage epsilon_edge, including auxiliary classical view and QPT internal state.

Writing P_r for probability all first r extracted-graph edge tests pass:
    P_r <= alpha P_(r-1) + epsilon_edge.
Hence actual false-setup-proof acceptance is at most:
    alpha^ell + epsilon_edge*(1-alpha^ell)/(1-alpha)
    <= alpha^ell + ell*epsilon_edge.
This avoids quantum rewinding, false extraction from a SNARG, and secret-key recovery assumptions. Honest verifier encrypts the challenge BEFORE the fixed graph batch and reveals its coins only after. Repeated sessions require fresh sid/challenges and finite union bounds. Security fails if a corrupt prover is given sk_ch.

## Quantum malicious-VERIFIER straight-line ZERO KNOWLEDGE

A simulator gets full public X but NOT the native signing secret, original setup witness, capsule Build coins, or graph coloring. It generates both honest public CRS keys with the EXACT real public-key distribution and secretly retains sk_ch. On ANY classical challenge ciphertext from the arbitrary internally QPT malicious verifier, it decrypts the index before creating any vertex commitments. If it is a valid edge a=(u,v), choose its two colors uniformly among the six ordered unequal pairs, choose arbitrary colors for other vertices, and encrypt every color with genuine fresh pk_col coins. Later validate the verifier's exact challenge ciphertext opening; invalid or inconsistent openings abort exactly as in reality. Reveal only the selected two vertex coins. Use a fresh independent commitment batch for every round/verifier.

For any TRUE setup graph, a uniform global color permutation makes the two endpoint colors at every FIXED edge uniform among those same six pairs. Thus opened endpoint colors and all coins have the genuine distribution. The unopened vertex ciphertexts, though correlated through a true coloring, can be replaced one by one by the simulator's arbitrary colors using ordinary QPT IND-CPA under pk_col with independent randomness. Because the malicious verifier's ciphertext was provided BEFORE the current vertex commitments, the edge is fixed for the purpose of this hybrid; sk_ch lets the simulator learn it, without rewinding or equivocating. All public native vk, source/capsules/context, independently permitted auxiliary data, multiple rounds, authenticated malformed requests and aborts can be part of the classical view, but leakage of sk_col, sk_ch, honest unrevealed encryption coins, or secret-correlated out-of-game advice is excluded. QPT internal attacks are covered; fully quantum protocol messages are NOT.

For RESTRICTED FALSE signed-XOR SOURCE, MINK's exact public A_source^T delta=e0 gives a capsule generated without the native sk yet inside the honest Build support for ANY genuine signing sk corresponding to vk. The resulting L_setup remains a TRUE statement, so its setup-proof transcript can be simulated via this component without a SourceOpen oracle. It does not give a generic-NP SOURCE simulator or an arbitrary hard-TRUE final-key/native-forgery -> ORIGINAL witness reduction.

## Still missing and efficiency boundary

The independent two-key public CRS MUST be generated/erased with the real N-of-N threat model, unknown one honest participant and malicious contributions, including proof keys retained by corrupted parties. This note does NOT instantiate that ceremony. Malicious retained sk_ch reveals future secret verifier challenges to a colluding prover; retained sk_col reveals a prover's entire coloring to the verifier. Merely combining malformed public keys, XORing seeds, or adding a hash is no proof of the required simulation. Key-correlated auxiliary information needs explicit composition.

The finite protocol is VERY LARGE: N(N-1)*ell*|V| color ciphertexts plus opened coins, with ell roughly d ln(1/target_error). For an illustrative, security-UNASSESSED tuple n=256,m=4800,q=65537,eta=3, each public key uses 3,700,800 raw bytes, each bit ciphertext 771 bytes and each 2-bit vertex color ciphertext 1542 bytes. The leftover statistical term is below 1.4e-104 but QPT LWE hardness of this tuple is NOT established. Neither near-term practicality nor Bitcoin native PQ support is claimed.

Next exact obligations: malicious one-honest CRS/erasure and abort composition, practical compact proof, complete KeyGen/Build-to-3COL compiler, generic NP source-dependent Build/Lift, full-public FALSE source distribution with genuine vk and all related capsules, arbitrary unauthorized hard-TRUE final key/native forgery -> actual ORIGINAL witness or independent QPT break, actual SYS/BTC qualified evidence and a conditional native Bitcoin PQ endpoint. The original stopping criteria remain unmet.

## Executed evidence

Published checker.js is ACTUALLY executed twice with byte-identical results, with 1,619 deterministic assertions covering exact toy Regev ciphertext/opening/decryption algebra, 96 honest and 96 simulator graph rounds, K4 false-graph enumeration (81 assignments), and endpoint distinctness. Its q=257,n=3,m=40,eta=1 toy parameters are CRYPTOGRAPHICALLY INSECURE and do not test QPT hardness. A separate larger local Python checker passed 4,265 assertions twice identically; its full derivation and results are preserved in the offline archive MINK_ECZK_20261101_OFFLINE.tar.gz. No external research, production writes, merges, approvals or deployments.