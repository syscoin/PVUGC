# MINK — independently protected native signing keys, with exact setup-proof support on FALSE XOR sources

**Research run:** MINK-2026-11-01-T15. **Starting PR:** syscoin/PVUGC#1, open/draft/unmerged branch research/pq-wkem-validation-20260918, exact head b402d9707a8c6e411405a2c237b7ac27082fd0c2. Previous restricted construction: AXLR file research/pq-wkem/axlr_f2_exact_20261101/RESEARCH.md, blob c577354f1a27f4c4cbea20f45ca67fae975a993e. Previous failed nonlinear scalar carrier: BLSC-NOISE, blob d71eabfa5ad2005334a279ce2aaa024fb4ff96a8. No web, paper retrieval or other repository research.

**Scope:** This is a concrete *restricted* release/ceremony composition and a new exact source-proof-support lemma. It is NOT generic-NP witness encryption, an independent LWE/QPT security proof, a completed ZK proof system, or a deployed native Bitcoin PQ path.

## 1. The multi-independent native-key construction

Avoid one separate distributed native-key-generation problem as follows. For each authorized challenge path p, each setup party j in {1,...,N} independently creates a native keypair (sk_j,vk_j). The proposed future no-EC-key-path native script requires **all N independent ordinary native signatures** on the SAME committed claim/path-specific sighash. No signature aggregation, adaptor algebra, NP verifier, or extra opcode is assumed. A signed immutable N-of-N preauthorization graph binds all vk_j and every permitted/forbidden edge, relation/claim/UTXO, branch, anchors/window, and context. In particular no bypass edge may omit the honest party's authorization.

Each party independently publishes a capsule P_j = Build(R_original,x_p,sk_j;r_j). Every valid ORIGINAL witness W runs sk'_j=Lift(P_j,W), checks Native.VK(sk'_j)=vk_j off chain, and uses all recovered keys to form N ordinary native signatures. The common capability is the ORDERED VECTOR (sk_1,...,sk_N); distinct valid W may have distinct computation traces but MUST recover exactly that same vector.

This removes the *separate* requirement to compute a joint public key Native.VK(XOR_j sk_j) by MPC without revealing the XOR signing secret. It does NOT solve Build, prove its security, or permit a small native aggregated signature. Native N-signature size and scripting costs may be substantial. The coordinator holds only public material; individual parties still handle signing secrets until secure erasure, so this is not a proof of the optional stronger keyless Build threat model. Preauthorization authentication keys must be separate from protected native signing keys. A quorum with N-1 retained secrets cannot execute a protected path that actually requires all N, assuming the remaining honest key is secure.

## 2. Off-chain pre-funding wellformedness is indispensable

Before any irreversible funding, each party must prove the following actual NP statement without disclosing its native signing secret:

L_setup(vk_j,P_j,x_p) :=
  EXISTS keygen_coins,sk_j,r_j:
    Native.KeyGen(keygen_coins)=(sk_j,vk_j)
    AND P_j=Build(R_original,x_p,sk_j;r_j).

The proof and authenticated manifest bind all capsule identifiers, exact x_p, native vk_j and intended path. All N proofs, capsules, graph edges, relevant presignatures, and DA material must be available/checked before honest preauthorization. An invalid or missing proof causes a pre-funding abort; no forced post-funding reliance on a dishonest signer.

There is a concrete necessity: a dishonest signer may publish a perfectly syntactic TRUE-source capsule encoding sk_wrong and separately commit a public key for sk_real. Every valid ORIGINAL witness then recovers sk_wrong, so an after-the-fact Native.VK check rejects and the challenge path is unusable. The exact checker demonstrates this. Verifying ordinary capsule syntax does not establish the hidden key matches vk_j. A **QPT-sound and QPT-zero-knowledge** proof for the actual Build+KeyGen relation is therefore a separate requirement. No concrete such proof, malicious-CRS ceremony, or QPT proof simulator is instantiated or tested here. The setup proof is not an ORIGINAL source proof, and Bitcoin is not asked to verify it.

## 3. Exact FALSE-source support lemma: genuinely correlated checking keys and capsules

Instantiate *only the already understood signed-XOR AXLR language*, over F2. From the signed-XOR graph form the public source matrix A with rows b_e e0+e_u+e_v. For each bit of each native signing seed, split into three independent XOR lanes (r0,r1,r2) satisfying r0+r1+r2 = seed_bit, and publish each C=A^T s + m e0 for fresh uniform s. On any valid ORIGINAL signed-XOR witness W, v=(1,W) gives Av=0 and v^T C=m. Thus every valid W recovers the same precommitted seed vector across every party and related capsule.

When x is FALSE signed-XOR, public linear algebra gives delta satisfying A^T delta=e0. A simulator with only the actual native vk_j (not sk_j) samples independent uniform s0 for each ciphertext and publishes C=A^T s0. Now consider **any actual sk corresponding to that vk**, unknown to the simulator. Choose the two first lane bits arbitrarily and set the third to their XOR with each sk bit. For each lane with intended bit m set

    s_real = s0 + m*delta,
    A^T s_real + m*e0
      = A^T s0 + m*(A^T delta + e0)
      = C.

The identity is exact for every party, lane, key bit, capsule, and every possible compatible native secret. Thus **the zero-mode public capsule built without sk is in the honest Build(x,sk) support for the actual unknown sk**, even when vk is a genuine challenge verification key. The full combined setup statement L_setup(vk,P,x) is TRUE, not a statement for which one has to fabricate a sound proof of falsity.

This reduces a particular full-public-view proof-simulation obstacle: with a separately instantiated QPT-ZK NIZK and compatible simulated CRS, its TRUE-statement proof simulator could provide the honest pre-funding proof *without learning sk*, and the public capsule can be replaced by zero-mode ciphertexts with exactly the same restricted FALSE-source distribution. No SourceOpen oracle is used. The fixed classical view, including native vk, source/context and independently simulatable auxiliary data, has the same distribution even for arbitrary coherent QPT processing of those bytes. The only computational hybrid losses are from the **uninstantiated** QPT ZK/CRS simulation and independent native/authentication assumptions.

For classical-adaptive disclosure of at most two of three lane plaintexts AND actual encryption coins per seed bit/capsule, each disclosed pair is uniform independently of the secret. Respond with s_m=s0+m*delta, memoize prior responses, and leave the third share unopened. For any actual secret the unopened share supplies a consistent complete Build witness. If all three shares are disclosed this fails. No quantum-superposition opening or signing oracle, arbitrary secret-correlated advice, malicious CRS or other independently unsupported leakage is included.

**Crucial restriction:** this exact simulator exists only because FALSE signed-XOR is efficiently refutable and A^T delta=e0. It is NOT an LWE challenge simulator for an arbitrary hard FALSE NP instance. NIZK statement support is not a QPT-ZK proof. It neither proves true-instance extraction nor extends AXLR through an AND gate.

## 4. Conditional straight-line native graph composition

Fix an honest setup party h whose protected sk_h is not retained by the adversary after the erasure boundary. Every accepted protected path must contain an accepted signature under vk_h on the exact target challenge sighash, not a signature on another path or an earlier permitted preauthorization. A straight-line reduction strips that native signature component from any accepted N-signature bundle. When the SINGLE-KEY public-capsule/native-forgery security game is already solved for honest h, this gives a public full-view attack against that single-key game: either it extracts an actual ORIGINAL witness, or it breaks an independently justified native/PQ assumption. It does not ask the adversary to supply its internal representation and requires no quantum rewinding; if the reduction must guess h it loses a factor at most N.

This **only composes a missing theorem**: a practical generic-NP single-key hard-TRUE witness-recovery/native-forgery theorem is not known or proved here. A sound pre-funding Build consistency proof is additionally needed for useful completeness: otherwise malformed malicious capsules can make a funded challenge impossible. Related capsules, permitted signatures and malicious participant interaction must be included in the full-single-key game, not assumed independent when they are secret-correlated. Native EUF without capsule leakage is not by itself sufficient.

The endpoint is conditional on future native SLH-like signatures and a no-EC-key-path script capable of N independent checks. No Bitcoin NP verifier, PCP dispute, CAT, aggregation or BitVM proof checking is assumed. BitVM may separately provide covenant-emulation plumbing. SOURCE still needs actual Bitcoin/Syscoin header, AuxPoW, coinbase tag, ancestor, interval/window, fork-qualification, data-availability and inclusion rules. One-of-N observers and source ChainLocks are distinct from N-of-N setup.

## 5. Executed bounded evidence and exact remaining equation

The published self-contained checker.js is the EXACT JavaScript function executed in the current V8 research tool. It verifies 4 independent 32-byte seeds, 2 related capsules per signer, 2 distinct valid ORIGINAL XOR witnesses, 6,144 actual zero-capsule coin equations that simultaneously support 4 arbitrary bound secret choices, exact FALSE bit-0/bit-1 distributions, explicit delta, opened-two-share uniformity, a malicious TRUE capsule bound to the wrong signing secret, and the symbolic no-bypass constraint. **8,239 checks passed.** A separate independent local-only standard-library Python checker passed **8,277 check events twice with byte-identical outputs**. Local archive SHA-256: 4c543c90c9c2fa62d38c59698a2b7a8153164e4553f187ef03e74c267fea4271. No actual native PQ signature, NIZK, QPT experiment or Bitcoin bridge test was executed.

**The next original release obligation is unchanged:** instantiate a finite polynomial-size classical-PPT Build(R_original,x,K) and Lift(P,W)=K for every valid ORIGINAL NP witness; give its full-joint arbitrary-QPT FALSE-source simulator including genuine vk, checking/auxiliary correlations, related capsules and proof transcripts **without the secret or SourceOpen oracle**; and derive arbitrary unauthorized hard-TRUE key recovery or a native forgery into an **actual ORIGINAL witness or independent PQ break**. No such generic source-dependent LWE challenge simulator, NIZK implementation, setup ceremony proof, or secure native endpoint has been established. The benefit of this note is removing a separate native distributed-keygen dependency **if** the eventually secure single-key primitive and hypothesized N-check native path are available.
