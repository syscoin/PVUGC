# Slotwise-last, source-separated LWE ceremony — restricted constructive repair

**Result:** A concrete, straight-line, unknown-one-honest SOURCE-generation simulator with N independent honest-native-key slots, without a globally designated honest-last verifier, programmable oracle, CRS, quantum rewinding, or retained planted SOURCE opening. This is **NOT** a generic NP witness-KEM, an ORIGINAL-evidence lift, a fundable Bitcoin construction, or a concrete 128-bit PQ calibration. The essential novelty relative to the rejected shared-SOURCE receiver-indexed coinflip is *separation*: the malicious receiver's SOURCE only protects its own corrupted native key and cannot decrypt the independently protected honest receiver's key, provided a real graph requires ALL native keys.

## Provenance

Run slotwise_last_sources_20261030 (automation turn 10; no execution UUID supplied). syscoin/PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, starting SHA 10d847e2d851933a165eca692d7f5b5ccd0ab409, latest substantive ordinary comment 6521064731. Exact predecessor files: adaptive_public_source_coinflip_20261030/RESEARCH.md (blob 5755c168feda57c53281c7f3181d06485e0cae94) and uniform_target_batched_lwe_20261030/RESEARCH.md (blob d1bc72cf6b2692ee73783d086931014917631859). No whole PR diff, historical archive sweep, external literature or web.

## Exact classical algorithms, distribution and native correlation

Let q be odd prime; n,m,L,w,N,J polynomial, N>=2; chi efficiently sampleable bounded error in [-B,B]. Let T={z in {-1,0,1}^m: weight(z)=w}, spacing g=floor(q/2^ell)>2B(w+1). L is the number of ell-bit digits in the exact canonical genuine native secret serialization. Each participant j independently creates its REAL native signature pair (sk_j,pk_j), plus a separate QPT-secure setup authentication key. Authenticate the ORIGINAL relation identity/x, claim/UTXO, branch, anchors/window, scope/context, intended native challenge message and path, bearer/owner mode, identities, all N genuine native checking keys, source/capsule identifiers and all related-capsule identifiers. No protected target-path native signature is issued by the setup-signature interface. Native pre-signatures, when unavoidable, are limited to exact authorized nonchallenge graph messages. Honest sk_j and honest LWE coins are erased/protected after an independently verified pre-funding graph.

Phase 1, authenticated seeds: For EACH ordered i!=j, party i sends a canonical 256-bit seed t_{i,j}, authenticated against one fixed session/slot and manifest. Define the full matrix contribution S_{i,j}=Expand(i,j,t_{i,j}) in F_q^{n x (m+L)}, with a deterministic public expansion and unbiased field encoding by rejection. Expand does NOT need PRG security: the last honest receiver share supplies true uniformity. Adversarial participants may choose their seeds and correlated public state arbitrarily, after observing other stage-1 public data; they must fix every seed before phase 2. An honest party will not proceed on missing/invalid/late-replaced seed, missing signatures, or a different manifest. Abort MUST be before irreversible funding. All parties can submit their NONRECEIVER seeds in parallel; there is no deadlock when everyone is honest.

Phase 2, per-receiver LAST uniform contribution: AFTER the whole phase-1 signed manifest is fixed, honest signer/receiver j freshly samples U_j uniformly from F_q^{n x (m+L)} using full-sized independent randomness, publishes U_j signed against the manifest, and defines

    C_j = sum_{i != j} Expand(i,j,t_{i,j}) mod q;
    M_j = U_j + C_j mod q.

There are N SEPARATE matrices M_j and N SEPARATE native signing pairs. A malicious receiver may choose its U_j adversarially, including a SOURCE with a known short preimage; this does not open the honest h SOURCE M_h. The actual native path must enforce every genuine pk_j and exclude bypass branches. This native N-of-N endpoint/graph is presently only a **required premise**, not a deployed or verified Bitcoin capability.

Phase 3, independently randomized related native-secret capsules: For each slot j and capsule k=1..J, sample r_{j,k} uniformly in F_q^n, eta_{j,k} from chi^{m+L}, and let a_{j,l} be the genuine sk_j digit. Publish

    Y_{j,k} = M_j^T r_{j,k} + eta_{j,k}
              + (0,...,0,g*a_{j,1},...,g*a_{j,L}) mod q.

Publish the full authenticated session including individual signed seeds, U_j, all M_j (or canonical recomputation), native checking keys, authenticators, context, honest source/key scopes, auxiliary data, pre-signatures and related capsules. Honest participant h refuses to authorize funding until the agreed full graph, data availability, session identities and its own required signing edge are checked. A nonresponse/abort cannot be treated as an authorized funded state. One honest participant can veto bypass edges before funding; this is NOT a proof of the whole graph or useful malicious-party completeness.

For a SOURCE opening Z=(z_1,...,z_L), where M_j=[A_j|V_j], all z_l in T and A_j*z_l=V_{j,l}, compute

    d_l - z_l^T*c = g*a_{j,l}+eta_{j,m+l}-z_l^T*eta_{j,1:m} (mod q).

The centered error is <=B(w+1), for EVERY valid source opening tuple, including distinct z_l and distinct tuples. Because g>2B(w+1), nearest-center decoding yields exactly the SAME canonical sk_j for every valid SOURCE witness in every related capsule; verify Native.PK(sk_j)=pk_j. This is a real algebraic release algorithm for SOURCE witnesses; NO map from an arbitrary ORIGINAL W to such a SOURCE witness has been constructed.

## Exact joint-public one-honest lemma and straight-line challenge simulator

Fix any h who stays uncorrupted; h was not publicly elected as a globally honest-last verifier. Let F be the FULL classical phase-1 transcript and adversarial quantum state after all seeds are frozen, including native checking keys, signatures, scope, x, auxiliary data generated before phase 2, arbitrary adaptive malicious seed choices and all other valid independent slots. The honest U_h is sampled fresh independently after F. For every admissible prefix f,

    Pr[M_h=M | F=f] = q^{-n(m+L)},  M_h=U_h+C_h(f).

The distribution is exact for coherent QPT adversaries as a classical uniform mask independently post-sampled against their quantum state. With an ordinary LWE challenge (M*,Y*) whose M* is UNIFORM and is independent of F, the simulator runs the adversary once to fix all phase-1 shares, sets U_h = M* - C_h(f), publishes that exact signed h-last share and uses Y* as ONE complete honest capsule vector, shifting its last L positions by the genuine native-secret digits. Other honest capsules are generated honestly and corrupt receivers/sources are produced by running the QPT adversary, including adaptive choices based on M*. The real vs simulated full source transcript is **identical** jointly, including all public checking-key correlations and the adversary's then-current quantum state. No SOURCE-opening oracle, trapdoor, commitment programming, quantum rewinding, public basis change or adversary-supplied representation is used.

The LWE game must be EXACTLY

    (M, M^T*r + eta) vs (M,uniform_vector),
    M <- uniform F_q^{n x (m+L)}, r <- uniform F_q^n,
    eta <- chi^{m+L};

assume independent nonuniform-QPT decisional LWE for those parameters, QPT EUF-CMA for the ACTUAL native signature, and QPT security of all authentication keys. By J straight-line complete-vector hybrids, replace all honest h related capsules with uniform vectors. In the final game, embed a GENUINE native EUF-CMA challenger pk_h, with ONLY authorized classical setup/nonchallenge signing-oracle calls; a recovered usable sk_h yields a fresh target native signature. For any FIXED h, assuming polynomial bounded sessions and no honest h encryption-coin/secret leakage,

    Pr[funded unauthorized h key recovery or fresh native signature]
       <= J Adv_QPT-DecLWE + Adv_QPT-Native-EUF-CMA
          + Adv_QPT-SetupAuthForgery.

An unknown honest position costs at most N in the standard guessing/union reduction; polynomial restarts add their standard losses. Selective openings of other N-1 corrupt keys, seed coins and capsules, adversarial source choice and arbitrary joint QPT postprocessing are included. The honest signer h remains protected across capsules; its LWE coins are NOT exposed. Inputs/advice may depend on public x and genuine pk but NOT secretly on fresh h r/eta/sk; only classical APIs, no superposition signing/decryption queries. Unbounded grinding, quantum-query interfaces, bypassed graph keys or secretly key-correlated arbitrary auxiliary data are OUTSIDE the theorem.

This repairs the **actual unknown-one-honest chronology/simulator for honest SOURCE h** from the previous shared-SOURCE attempt without adding an ideal commitment or honest-global-last verifier. It does NOT provide key release from Syscoin fork evidence.

## Non-negotiable missing ORIGINAL obligation

Uniform M_h cannot be combined with an efficient public short-preimage Lift(x,W,M_h) for a KNOWN valid (x,W) while retaining the preceding ordinary-QPT-LWE security: such a Lift would efficiently provide a short SOURCE preimage of a fresh uniform M and distinguish a genuine LWE ciphertext from uniform by checking its decrypted noise. This is a concrete separation, not a requested SourceOpen oracle. Hence the NEXT task must construct a truly relation-dependent source/opening distribution *together* with its challenge simulator:

    Comp(R_original,x,claim,branch,anchors/window,context,pk*) -> D_x
    Lift(x,W,D_x) -> state_Z(W)
    Release(D_x,W) = the SAME precommitted native capability
                     for ALL valid ORIGINAL W.

It must prove every fixed FALSE original x hides the capability in the FULL view (relation, statement, public capsule/source/checking keys, context, auxiliary and related capsules), and unauthorized hard-TRUE final-key recovery or a fresh accepted native forgery -> an ACTUAL ORIGINAL witness or independent QPT break, without asking the adversary to volunteer an internal representation. The qualified pivot/SIS supplied-representation extraction and the restricted ordinary LWE source are not this reduction. Malicious source early safety alone does not make usable NP-WKEM.

Unproved: ORIGINAL Syscoin/BTC fork evidence with correct work-vs-best-chain separation, all interval coinbase tags, AuxPoW/header/Merkle/ancestor, fork qualification, DA/censorship/window/reset conditions; one-honest native preauthorization graph and abort/useful completeness; deployed no-EC/PQ Bitcoin endpoint. A hypothetical native N-of-N SLH-like path must not be treated as a real opcode, threshold signature, aggregation or keyless production builder. Bitcoin cannot be asked to run NP verification, PCP or VM/BitVM trace disputes.

## Exact bounded checks and cost

Exact committed standard-library checker is intended to be run twice. The executed local checker passed **562 assertions twice with byte-identical output**, including 120 exact whole-source/frozen-seed transcript coupling laws, 25 source values each, 6 adaptive corrupt-share policies and all 4 honest indices, 60 prefunding abort checks, and three related SOURCE-only ciphertexts decoded with multiple independently valid short preimages. The checker uses toy finite algebra, deterministic seeded sampling and tiny capability digits: NOT a QPT, genuine native signature, or real Bitcoin test. A preliminary local illustrative variant had a field-modulus mismatch; that was corrected before the final checker.

Unvalidated illustration: q=16777213, n=256, m=6800, L=52, N=4, 3-byte field encoding: each uniformly sampled receiver-last matrix is 5,262,336 bytes; four final receiver shares total 21,049,344 bytes; twelve 32-byte nonreceiver seeds total 384 bytes; four independent batched ciphertext vectors per related capsule total 82,224 bytes. Does not include signing keys, auths, framing, graph, native witness, execution/storage overhead or 128-bit security calibration. Zero claims of end-to-end practical PQ security.

Research-only authorization: no main/production/workflows changes, other repos, approvals, merges, deployments or transfers. This is a restricted source-ceremony construction advance, NOT automation completion.
