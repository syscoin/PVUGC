# CORN — clause-integrality SOURCE release attempt (offline, 2026-10-31)

**Status: NO POSITIVE SECURE WKEM ADVANCE.** A compact witness-free 3CNF-to-binary-ISIS representation is mathematically complete and sound **only for accepted binary source vectors**; the concrete public source-dependent LWE release is fatally insecure on every formula, including FALSE. An attempted one-hot/norm-gap repair is also insecure in a bounded-error setting. This note is a regression barrier and research handoff, NOT a viable KEM or an independent QPT security result. No external research was performed.

## Exact old component and chosen unfinished step

Starting checkpoint: syscoin/PVUGC PR #1 at 7c6f3be4a1fb46218f9a43969a915294ce02a999, open/draft/unmerged, branch research/pq-wkem-validation-20260918; substantive comment 6549027267. Read exact previous research/pq-wkem/shared_source_matrix_20261031/RESEARCH.md, blob 067883adc59a54de214017f0f86a45da53910f97. That construction proves only a restricted uniform random SOURCE view. This iteration attempts a generic ORIGINAL-dependent SOURCE compiler without a witness and a concrete release. **Its ordinary QPT-LWE hybrid does not automatically transfer to the structured source below.**

## Attempted release v1: sparse binary ISIS

Let F be a 3CNF on n Boolean variables and m clauses, each containing exactly three literal occurrences (repetition and opposite polarities allowed). Let p_ci and r_ci denote positive/negative occurrence counts of variable i in clause c, and r_c=sum_i r_ci. Define the public matrix A over F_q, q>6, with m rows and n+2m columns:

A[c,i]=p_ci-r_ci, A[c,n+2c]=1, A[c,n+2c+1]=2, all other slack coefficients zero; t_c=4-r_c.

For ORIGINAL assignment w in {0,1}^n, its satisfied-literal count is k_c=r_c+sum_i(p_ci-r_ci)w_i. If F(w)=TRUE then k_c in {1,2,3} and 4-k_c in {1,2,3}; uniquely represent this with the two binary slack bits (a_c,b_c) of weights 1,2. The vector z=(w,(a_c,b_c)_c) is binary and Az=t. Conversely a binary solution Az=t modulo q must solve it over integers (all clause sums in [0,6], targets in [1,4], q>6); k_c=0 cannot reach 4 with binary slack max 3. Thus the prefix is a valid ORIGINAL witness. This is a proof of **accepted-binary-representation soundness** and every-ORIGINAL-witness completeness, not an arbitrary-key-recovery extractor. It gives a sparse semantic compiler for supplied 3CNF; a full universal-verifier circuit compiler and SYS/BTC statement binding were not implemented or tested.

For every protected q-ary byte u, independently choose s uniform in F_q^m, error e∈[-B,B]^(n+2m), e*∈[-B,B], and publish beta=A^T s+e and tau=t^T s+e*+g u modulo q, g=floor(q/256). A binary source witness z recovers u from tau-z^T beta if B(1+n+2m)<g/2. Independent coins per byte, XOR share lane, and related capsule would still reproduce the same precommitted key for every ORIGINAL witness.

## Exact universal public attack, not merely toy evidence

Set every original variable w_i=1, whether or not F is satisfiable. Then k_c=3-r_c, so the needed slack is 1+r_c. For r_c=0,1,2,3, take the PUBLIC nonbinary slack pairs respectively (1,0),(0,1),(1,1),(0,2). Call the resulting integer vector z_bad. Direct substitution gives Az_bad=t over integers for every formula, while ||z_bad||_1 ≤ n+2m, precisely the upper budget for genuine binary witnesses. Therefore

tau-z_bad^T beta = g u + e* - z_bad^T e (mod q),

with magnitude of the extra error at most B(1+n+2m). Whenever honest all-witness correctness is deterministic by the stated bound, **the same bound guarantees successful adversarial decoding**. No ORIGINAL witness, internal representation voluntarily revealed by an adversary, oracle, or signature forgery is required. With F=(x∨x∨x)∧(¬x∨¬x∨¬x), F is FALSE and yet z_bad decrypts. This also decrypts every independent share and related capsule; a genuine checking key can verify the stolen capability but cannot stop the public decryption. Public invertible row transformations A'=UA,t'=Ut preserve A'z_bad=t' and thus do not repair it.

This invalidates the concrete release even in a purely classical setting, before worrying about quantum attacks, aux data, native signatures, or malicious setup. It is NOT a blanket impossibility theorem for every PQ witness-KEM.

## One bounded repair: one-hot slack with an explicit normalization row

For every clause replace the two binary slack bits by three one-hot bits u1,u2,u3 and impose TWO equations:
sum_i(p_ci-r_ci)w_i + 3u1+2u2+u3 = 4-r_c;
u1+u2+u3 = 1.
For satisfying k_c=1,2,3 choose respectively (1,0,0),(0,1,0),(0,0,1). The accepted binary vector remains exactly sound/complete. For k_c=0, the small PUBLIC integer completion (2,-1,0) satisfies both equations: 3·2+2·(-1)=4, 2-1=1. In particular any original assignment has an integer SOURCE opening, including any FALSE instance. Its l1 norm is sum_i w_i+m+2u(F,w), where u(F,w) counts its unsatisfied clauses. This yields an exact 2-per-violation **semantic norm gap**, but no cryptographically enforced release gate: in the checked small-error regime every such opening still decrypts. Enlarging the noise or gap requires a new full joint-security proof, not an appeal to an accepted-binary API or to ordinary LWE nomenclature. This is a repair attempt, not an instantiated secure successor.

## Executed reproducibility and assumptions

The exact attached checker.js is the JavaScript function run() executed in the offline tool runtime and then serialized unchanged by run.toString(); Node can execute the resulting file. It executes 4,204 assertions on 34 3CNF instances (one explicitly FALSE), both encodings, exhaustive ORIGINAL assignments for those n≤5, q=65537, g=256, errors exactly uniform on {-1,0,1}, and actual source-dependent ciphertext and cyclic decoding arithmetic. It verifies 816 unauthorized symbol recoveries including public invertible row mixing. Native signature keys are NOT instantiated in this checker.

Separately the local Python v1 checker passed 4,742 assertions twice identically over 62 formula instances, with three XOR-share lanes, two related capsules and a 24-byte precommitted key. The distinct v2 one-hot checker passed 3,979 assertions twice identically over 43 formula instances. The full scripts, captured outputs, exact SHA-256 identities, and additional derivation are preserved in the local downloadable archive WKEM_CORN_SOURCE_INTEGRALITY_20261031_LOCAL.tar.gz, SHA-256 edb0eab2bd608230fb486b19e8b37b6aef530a13f0ad421ad9632facf1fdff1b. These are finite arithmetic checks and do not test coherent QPT attacks or native PQ security.

## Exact next missing obligation

Construct a witness-free classical-PPT Comp(R,x,claim/UTXO/branch/anchors/window,vk) and public Lift for every valid ORIGINAL W, recovering precisely one precommitted K, **whose nonlinear integrality/global-consistency restriction is enforced by the public cryptographic release itself** (not by an optional software precheck). For the full view (R,x,capsule,vk,context,aux,related capsules), prove adversarial FALSE key hiding and arbitrary unauthorized hard-TRUE final-key recovery/native fresh-signature -> actual ORIGINAL W or independently justified QPT break, with a simulator that generates the actual structured SOURCE and every public correlation jointly from its challenge without SOURCE-opening oracles. No such secure release or full-public reduction was constructed this run. The earlier uniform-random binary-ISIS LWE hybrid does not discharge this structured statement obligation. Malicious one-honest preauthorization, abort/funding/DA, SYS/BTC source qualification and hypothetical Bitcoin PQ-native signatures remain unresolved. Do not disable the research automation.