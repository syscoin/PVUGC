# MINK-CRS-SLOTS-20261102-R15: exact one-honest CRS embedding for soundness only

**Status:** A concrete repair of one *soundness* part of the one-honest CRS challenge-programming obstruction in R14. It is not a full malicious-setup proof, zero-knowledge result, original witness-KEM, or safe funding protocol.

## Exact checked predecessor

PR #1 was open/draft/unmerged on research/pq-wkem-validation-20260918 at 877d9164f67a47d076447a2f90d1f28194121668. Exact predecessor files: R14 whole-vector Toeplitz lock blob b3d5425a9352d2031507d5e95c11005ed70c9cd7; R11 native LWE SOURCE blob e2e47d88cc54f16478eaee8638df98c9ea4245bd; FWT proof blob 64d2df7c7ee04fbf7833c8af0f4dc03406565933. R14 cannot extract corrupt committed messages before embedding a challenge or equivocate honest openings. We replace the *single* public-coin CRS with N separately generated CRSs, rather than claiming to extract/equivocate.

## Actual protocol, classical PPT

Let N be polynomial, and at least one static honest actor h keep fresh coins private until its designated turn. FWT's real public-coin CRS is Theta=(A,b_col,b_ch), A uniformly in F_q^(m*n), b_col and b_ch independently uniform in F_q^m. No LWE secret keys exist in the real public CRS. Let d=m*n+2*m, and canonically encode Theta as a vector in F_q^d. Bind all messages to exact relation/statement, claim/UTXO, branch/path, anchors/window, intended native-vk identifier, session, actor, slot and round; use authenticated classical full-byte transcript agreement before any funding.

For every slot j=1..N: FIRST, all non-designated i != j publish their canonical signed contribution u_(i,j) in F_q^d, with an enforceable barrier that rejects missing, replaced, or equivocated messages. Corrupt senders may select arbitrary shares from any previous public history, but cannot revise an accepted h-slot share once h is about to act. SECOND, designated j samples u_(j,j) uniformly in F_q^d **only after that barrier**, if j is honest; it authenticates the completed slot transcript. Set Theta_j=sum_i u_(i,j) mod q. Run an independently domain-bound FWT interactive setup graph proof under EACH Theta_j, with designated j as that proof's verifier. An honest j uses a fresh independently hidden uniform edge challenge after the graph/statement is fixed and reveals it only after color commitments freeze. Accept the overall consistency check only when all N individual verifiers accept the same setup statement and all pre-funding parties certify the exact transcript. Otherwise abort before funding. No original NP verifier/VM/PCP runs on Bitcoin.

A dishonest designated slot may have invalid or adversarial A,b. Its transcript must still pass canonical checks, but no soundness or privacy claim is made for it individually.

## Exact uniform CRS and LWE challenger embedding

Fix h honest and condition on arbitrary prior authenticated classical history H and correlated QPT adversary state rho_H. By the h-slot barrier, S=sum_(i!=h) u_(i,h) is already fixed before h chooses U uniform and independent of (H,rho_H). Hence Theta_h=S+U is exactly uniform over all F_q^d, even conditioned on H and rho_H.

Given a uniform externally supplied whole-CRS target Theta*, a straight-line QPT reduction simulates all pre-h corrupt contributions WITHOUT showing Theta*; it then sends u_(h,h)=Theta* - S (mod q). This is *exactly* the honest h's conditional uniform distribution, and the revealed complete Theta_h equals the challenge. The adversary can carry an arbitrary quantum private state and can compute any subsequent classical/quantum function of the transcript; identical classical inputs induce identical final cq states. There is no extraction, equivocation, random-oracle programming, rewinding, coherent decryption interface or SourceOpen assumption.

The SAME deterministic wrapper embeds an ordinary decisional-QPT-LWE challenge in which only b_col (for soundness) or b_ch (for the prior malicious-verifier simulation) is switched from uniform to As+e. The resulting structured-world honest share need not look uniform: the indistinguishability of the whole transcript follows by quantum-efficient postprocessing of that **exact** independent QPT-LWE challenger, with no additional reduction loss. The actual error law, q,n,m and independence requirements remain exactly FWT's: q=65537, n=256, m=4800, eta=3, all illustrative/unassessed. Independent auxiliary quantum advice may be present but must not depend on the unrevealed challenge secret. Everything exchanged with the challenger and the protocol is classical.

## QPT soundness only, with malicious other slots and aborts

Assume the exact single-CRS FWT false-graph proof is QPT sound against arbitrary polynomial-time classical-message provers, for the actual setup statement and adaptive classical auxiliary data, with a uniformly honest CRS and honestly hidden fresh edge. For an E-edge false graph and ell challenges its predecessor conservative bound is:

  eps_slot <= Adv_QPT-DLWE_col + (1-1/E)^ell + 2*k_edge*eps_edge,
  eps_edge=(1/2)*sqrt(q^(n+1)/2^m).

Accepting the R15 conjunction implies accepting slot h. The straight-line reduction embeds the honest CRS challenger into slot h as above, simulates all corrupt CRSs/proof slots as part of the QPT adversary's environment and outputs its accepted false h-slot transcript. Thus Pr[complete transcript AND all N proofs accept FALSE] <= eps_slot. This does NOT multiply soundness by N or rely on corrupt key validity. If a reduction cannot fix the honest index, guessing incurs <=N loss. For Q independently fresh authentic sessions, total unconditional false acceptance is at most Q*eps_slot, assuming the original single-slot game supports the relevant adaptive statement/auxiliary context. Fresh unpredictable hidden edges are essential. Delayed/missing contributions or signatures must abort before funding.

An attacker can inspect Theta_h and selectively abort. The distribution CONDITIONED on completion is therefore NOT necessarily uniform and useful liveness under malicious abort is NOT proved. We only bound the **unconditional** event of a completed false acceptance (including polynomially many independent attempts). No adaptive corruption of h, reuse, external censorship or unlimited grinding is covered. The original FWT scope and all conditional QPT assumptions remain in force.

## Material privacy and release limitations

Other malicious slots can deliberately choose A=0,b_col=0, causing FWT ternary ciphertext (u,v)=(0,g*c) to reveal each committed color. The N-fold conjunction therefore does NOT preserve malicious-verifier ZK or sensitive setup-witness privacy. In R11's protected-capsule hybrid the setup-consistency statement becomes FALSE; a simulator can fake the honest slot with its own b_ch trapdoor but CANNOT in general fake proofs under all N malicious slot keys. This precisely prevents any full-public-output claim. One-honest AND soundness is useful but is not a malicious-private one-honest ceremony and cannot authorize funding.

The adversarial FALSE SOURCE A=0,b=(10,0,...) still exposes the protected capability. The exact unsolved release requirement remains a classical-PPT arbitrary-original-NP compiler and every-valid-ORIGINAL-witness same-capability Lift with the joint (x, capsule, checking keys, genuine native vk, context, auxiliary data, related capsules, audited openings) QPT simulator, plus arbitrary hard-TRUE recovered K/native forgery -> actual ORIGINAL witness or independently justified QPT break. No special-signature-only substitution, canonical witness, presumed SourceOpen or fake NP verifier is allowed. No native Bitcoin PQ functionality or security-parameter claim is implied.

## Resources and exact executed check

The illustrative FWT d=1,238,400 field elements costs 3,715,200 bytes per full share at canonical three-byte encoding. There are N^2 signed contributions and N graph-proof copies, for N=3: 33,436,800 bytes just of share contributions, exclusive of proofs and signatures. This is not an efficiency improvement; it trades the previous unsolved single-CRS extraction/eq issue for expensive separately programmable slots. Honest setup/evaluation remains polynomial-time classical.

The exact Python3 standard-library checker.py was executed twice with 15,192 assertions/run, byte-identical output. It exhausts all 49 targets for q=7,d=2 against 97 nonlinear corrupt partial-sum histories, checks exact subtraction and uniformity, all 81 K4 three-color assignments (one hidden uniform honest edge accepts at most 5 of 6), N=2..8 conjunctive-verifier positions, the multi-round 5^ell/6^ell upper count, and the malicious-zero-key color leak. These are algebra/finite-distribution checks, not quantum tests or a real setup-proof implementation.

**Next indispensable obligation:** retain the extract/eq-free soundness embedding while constructing a protocol in which all malicious verifier slots remain QPT-private and simulatable even when the protected-source hybrid makes Build consistency false, and couple that with an independently instantiated arbitrary-original-NP SOURCE release and complete source-correlated checking-key simulator. Nothing here closes the latter core gap.