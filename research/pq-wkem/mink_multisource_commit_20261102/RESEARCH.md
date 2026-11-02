# MINK-MULTISOURCE-COMMIT-20261102-R16: one-honest masked commitments

Status: A concrete, restricted repair of R15's malformed verifier-slot *color leakage* and a statistical false-graph soundness improvement. NOT generic PQ witness encryption, a false-intermediate-Build simulation, original-witness extraction, 128-bit parameter certification or Bitcoin deployment.

## Exact predecessor / assumptions

Actual PR #1 head initially 897554f973b6e6d6e5f028ac2267394163f6bec4 (open/draft/unmerged). R15 RESEARCH blob 49adfd9cc5f5dd303e8fd0a481c50b07eacd84ce showed exact straight-line honest-slot CRS embedding, but per-slot FWT encrypted colors leak under malicious A=b_col=0. The exact R12 ordinary-LWE stream proof is blob b02cb4f8ac8522e29cb831a71ba6d94e196df439. Our replacement affects only an interactive off-chain 3COL setup-consistency proof, not SOURCE release. The circuit-to-3COL transformation and its ORIGINAL witness decoding are not implemented here.

At least one of N static, authenticated setup participants is honest (unknown index h), fresh random coins are independent of prior public transcript and correlated QPT adversary state, all messages are classical. A participant can abort; no irreversible funding before accepted full transcripts and DA. We prove unconditional completed-accept events, not liveness or completion-conditioned distribution. A user-level statement includes relation ID, claim/UTXO, branch, source anchors/window, path, session, vertex, and intended native verification-key identifier. Honest evaluation/setup is classical polynomial time.

## Algorithms and exact joint public checking keys

In N separately designated-last slots, all non-designated participants fix and reveal additive shares before the designated participant contributes. Use this to generate public matrices A_j in Z_q^(m*n). If h is honest, A_h is exactly uniform even conditioned on previous classical transcript and QPT advice, while all other A_j may be arbitrary, even correlated with A_h. Freeze every matrix before receiver challenges or hidden seeds are sampled. Later corrupt slots can be arbitrary efficient postprocessing of A_h but cannot depend on its as-yet-unsampled secret mask seed.

Reuse R12's explicit ordinary-LWE distribution, illustratively q=65536,n=256,m=4096, e_i uniform on [-512,511], secret s uniform in Z_q^n. A uniform seed length kappa=16n+10m=45056 bits parses exactly as s and errors. Single step G_A(seed)=LE16(A*s+e mod q) emits O=65536 bits; keep first kappa bits as next state, emit remaining delta=20480 bits, and iterate 14 stages with the SAME public A. This defines Stream_A(seed) of D=286720 bits. Under the *specified-distribution* QPT decisional LWE assumption, (A,Stream_A(U)) is QPT indistinguishable from (A,U_D), with a straight-line at-most-14-hybrid reduction. The q=2^16 and error distribution security are unassessed; no automatic QPT lifting or security from mere algebra is claimed. With independently sampled kappa-bit S_j, define F_A(S_1,...,S_N)=XOR_j Stream_(A_j)(S_j). Its image has <=2^(N*kappa) possibilities for EVERY public A, even malicious. Because honest A_h is uniform and S_h fresh, F is computationally pseudorandom under ordinary QPT-LWE against arbitrary quantum postprocessing of the full classical public view with independent quantum advice, even if every other A_j is malformed. Replacing W independently seeded masks costs <=14W Adv_QPT-DLWE. Malicious inputs may depend on A_h but NOT the hidden seeds or their outputs.

After all A freeze, generate per-vertex, per-proof-round receiver keys T_(j,v,1),T_(j,v,2) in {0,1}^D using the same designated-last authenticated-share schedule; T_(j,v,0)=0. At least h's T pair is independently uniform given all frozen A and the earlier adversarial cq transcript. Others can be zero or malicious. All A, T, share transcripts, context, graph and verification keys are PUBLIC.

For each verifier slot j and proof round, prover chooses a fresh random permutation of one honest 3-coloring. For each vertex v of color c choose fresh independent multi-source seed tuple S_(j,v), and freeze C_(j,v)=F_A(S_(j,v)) XOR T_(j,v,c). One edge challenge per slot/round follows after ALL commitments are fixed; honest h samples an independently hidden uniform edge. Open two endpoint colors/seeds, check both C equations and distinct colors. AND all slots and independent rounds. Never reuse these commitments for a second edge challenge; all large proof work is off-chain.

## Statistical binding theorem — arbitrary malformed keys, any QPT prover

For ANY fixed frozen A and independently uniform honest-slot T1,T2, two accepted openings of one C to distinct colors c,c' with arbitrary seeds S,S' force:
  T_c XOR T_c' = F_A(S) XOR F_A(S').
For each of the three distinct color pairs, left side is uniform D bits. There are at most 2^(2N*kappa) ordered seed pairs, including all adversarial seeds. Thus
  delta_bind <= 3 * 2^(2N*kappa-D).
This is an information-theoretic existence bound and survives even an unbounded, coherent quantum cheating prover that outputs classical openings. At N=3,kappa=45056,D=286720 it is <=3*2^(-16384), for each commitment. With V vertices, ell fresh rounds and Q authenticated sessions, add at most Q*V*ell*delta_bind.

If the bound holds, each honest-slot vertex commitment has at most one acceptable color (or none). For a non-3-colorable graph with E edges, any fixed assignment violates at least one edge. Every completed h-slot false proof therefore passes one fresh honest hidden challenge with probability <=1-1/E. Across ell independent rounds:
  Pr[completed all-slots accept FALSE graph]
   <= (1-1/E)^ell + 3*V*ell*2^(2N*kappa-D)
per authenticated session (multiply by Q for bounded retries). This does not depend on corrupt verifier-slot soundness or QPT-LWE hardness. It depends on A freezing before honest T, C freezing before honest edge, authenticated classical messages and no uncontrolled reruns. Selective abort can destroy conditioned uniformity and liveness; no funding on abort.

## Quantum hiding theorem — fixed unopened commitments only

For a genuinely unopened target commitment whose mask seeds are freshly sampled independently of auxiliary information and all other opened coins, replace honest Stream_(A_h)(S_h) by an independent uniform D-bit string in at most 14 straight-line ordinary QPT-LWE hybrids. XOR with all corrupt slots' functions and with T_c is efficient postprocessing; so target C is uniform and independent of its color, even with malicious A_j or T_j=0. For W pre-fixed unopened targets, the joint classical public output (all A/T checking keys, authenticated context, independent related capsules and independent fixed opening transcripts) has QPT distinguishing advantage at most 14W Adv_QPT-DLWE. This fixes R15's explicit **unopened-all-color direct disclosure**. It is NOT a theorem about unrestricted adaptive selective openings, entangled auxiliary secrets, or coherent opening/signing oracles. Each graph slot must use fresh colors/masks.

## Programmable honest-slot algebra (not a simulator)

For one per-vertex commitment, choose independent seed vectors S0,S1,S2, put Yc=F(S_c), C=Y0, T1=Y0 XOR Y1 and T2=Y0 XOR Y2. Each (c,S_c) opens the same C. Before any opening, the triple of masks is QPT-pseudorandom under the same ordinary LWE multi-sample hybrid, and its transformed (C,T1,T2) is QPT-indistinguishable from three independent uniform D-bit vectors. Using R15's honest designated-last slot, the h actor can program *its own* challenge shares to that target after corrupt earlier shares are known.

**Fundamental missing interface:** The AND verifier also uses N-1 malicious slots, whose adversarial T may be binding and not equivocable. A simulator that needs to prove an actually FALSE intermediate Build-consistency graph cannot in general forge those slots. Nor does pre-opening indistinguishability prove adaptive post-opening selective opening. DO NOT use this algebra as an all-slot false-statement simulator or a released-key-to-ORIGINAL-witness theorem.

## Resources, executed checker, release gaps

D=286720 bits =35,840 bytes per color commitment; 2D=71,680 bytes per vertex per proof-slot receiver key; N=3 public LWE matrices cost 6,291,456 bytes before N^2 share contributions. A challenged vertex opens 3*5632=16,896 bytes of seeds. Each stream requires 14 matrix-vector LWE computations, and every vertex/slot uses N streams; this is prohibitively heavy at practical graph sizes, despite polynomial complexity.

Exact published JS checker (checker.js) executed and output captured in checks.json. It tests q=7 honest-share target embeddings, full ideal-mask distribution for arbitrary corrupt masks/receiver keys, exhaustive N=2/kappa=2/D=11 binding failure counts, genuine toy q=16 matrix-error streams with a malicious all-zero key and three programmable openings, and all 81 false K4 colorings. A separate offline Python checker ran twice with 5,734 assertions and byte-identical output. Neither tests QPT cryptanalysis or concrete 128-bit hardness.

The user-required generic Build(R,x,K), Lift(R,x,C,w)=K for **every** valid ORIGINAL witness, full-public all-adversarial-FALSE security, and arbitrary unauthorized hard-TRUE final-key/native-forgery -> ORIGINAL witness or independent QPT break are still NOT established. Setup malice/abort, SOURCE headers/AuxPoW/tag intervals, off-chain evidence DA, Bitcoin's conditional native PQ path and actual parameter feasibility remain unfinished. This is a setup-proof subcomponent only.
