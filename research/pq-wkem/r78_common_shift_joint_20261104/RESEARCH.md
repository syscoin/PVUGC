# R78 — Fixed-common-shift safe reuse of source coins in certified-FALSE related capsules

**Run:** R78-COMMON-SHIFT-SOURCE-COIN-REUSE-20261104. **Status:** restricted, algebraically proved joint-public-view source-coin-reuse repair; NOT generic witness-KEM and NO hard-TRUE key-recovery-to-ORIGINAL extractor.

## Continuity and exact starting version

syscoin/PVUGC PR #1, open/draft/unmerged, branch `research/pq-wkem-validation-20260918`, starting head `520718da6027fffb5eef5bb31aeea171bb4b0041`. Latest ordinary substantive comment `6648480787`. Predecessor R77 `research/pq-wkem/r77_torsion_shift_false_20261104/RESEARCH.md` at this commit, Git blob `36577c90842c6787ab9fa3cbe00ee9641c0e66bd`. Earlier R75 disallowed all shared source coins between related capsules; R77 proved single-capsule equality under `A_x t_x=Delta*e0 (mod q)`. Individual certificates do NOT justify sharing coins. No external literature research or production edit.

## Release algorithm

Use the scope-bound ORIGINAL Boolean moment compiler `x -> A_x in Z_q^(M_x x D)` and its normalized constant row `e0_x`. For every valid ORIGINAL witness w, a short evaluation vector r_w obeys `r_w^T A_x=0`, `r_w^T e0_x=1`. Different witnesses may have different r_w, and the ORIGINAL claim, relation, path, UTXO, anchors, window/context, native key/capability are all bound into x and public scope.

Let `q=2^k`, `p|q`, `s=q/p`, `Delta=s*Lambda` with `0<Delta<q`, and `mu_j(K)` be the jth b-bit word of one precommitted root K. **Before allowing related-capsule source-coin reuse**, fix ONE public `t in Z_q^D` and check for EVERY related statement i:

`A_(x_i)*t = Delta*e0_i (mod q)`.

The checker must use the actual scope-bound compiler A, not an unrelated proposer-supplied matrix. For each word index j sample ONE uniform `z_j <- Z_q^D` independent of K and independent across different j, and fresh bounded errors `e_(i,j) <- chi_src^(M_i)` for each capsule. Publish

`C_(i,j)=Round_(q->p)(A_(x_i)*z_j + e_(i,j) + Delta*mu_j(K)*e0_i)`.

The very same z_j is shared across admitted SAME-root siblings at that word index. Do NOT reuse z across different word indices; do NOT reveal z or error coins in CK/Aux/advice. Honest Build/Open and every-ORIGINAL-witness SAME-K correctness for genuine TRUE statements remain R77's independently coined scheme, with sufficient conservative bounds `B=M(E/s+1/2)`, `Lambda>2B` and `p-(2^b-1)Lambda>2B`. This reuse group is deliberately FALSE: a valid original row would give `0=r_w^T A_i t=Delta*r_w^T e0_i=Delta mod q`, impossible.

## Pointwise joint distribution proof, including adaptive QPT processing

The simulator does NOT know K, any source witness, any native secret or SourceOpen. For each word index j independently sample one uniform `z'_j <- Z_q^D`, and issue for all eligible siblings:

`C'_(i,j)=Round_(q->p)(A_(x_i)*z'_j + e'_(i,j))`.

For fixed K, set `z'_j=z_j+mu_j(K)*t (mod q)`. One and the SAME z' applies to every sibling at word index j, and z' is uniform independent of K. The common certificate gives the exact pointwise identity

`A_i*z_j + e_(i,j) + Delta*mu_j(K)*e0_i = A_i*(z_j+mu_j(K)*t)+e_(i,j) (mod q)`.

Rounding preserves byte equality. For statements chosen adaptively after previous ciphertext, CK, Aux or arbitrary adversarial public outputs, coupled transcripts and the adversary's retained QPT state are identical at each step; the adversary selects the same next matrix, whose accepted common certificate preserves the identity. Induction through polynomially many *classical* messages and arbitrary coherent QPT processing proves equality of the ENTIRE correlated source transcript and final quantum state, not marginal ciphertext hiding. Honest Build is classical PPT; no coherent superposition-query interface to Build, no quantum rewinding and no supplied representation. Abort has zero success payoff; this does not claim the setup remains uniform *conditioned on completion*.

For the full public view `V=(R,x,capsules,CK,scope,Aux,related_capsules)`, use only R71/R75's separately instantiated ordinary decisional-QPT-LWE PRG `U=H_(A_com)(K)`, independent common `A_com`, exact LWE secret/noise distributions and quantum advice independent of challenge/root/source coins. The ordinary LWE challenger supplies U*, and the simulator builds *together* Dsig=`sigma XOR U*[:|sigma|]`, checking key, auxiliary fields, related-capsule references, public context and the above key-blind jointly shared source. CK/Aux are domain-separated deterministic functions of this same U*, scope and available public transcript, never raw K/z/e. The R71 conditional two-hybrid bound on exact-seed recovery remains `2*epsilon_LWE+2^(ell-L)` under those assumptions and opening exclusions; separate native QPT-EUF-CMA and checking-key/source-binding terms must be charged. No automatic conclusion for forged native signatures or hard-TRUE generic claims follows.

## Necessity diagnostic and independently compiled ORIGINAL fixtures

For degree-1 ORIGINAL integer polynomial equality `c*a+c*b-1=0` with binary evidence and c=4,8,12, all statements are FALSE and compile to `A_c=(-1,c,c)^T`. With `q=4096,p=256,Delta=1024,t=3072`, each has **the SAME** certificate. The exact JavaScript checker validates 147,456 pointwise equalities under every source z in Z_4096, all four mu values, three noise patterns and three distinct matrices, plus 512 adaptively selected second statements and their correlated public view. A separate genuine TRUE equation `a+b+c=1` permits three distinct ORIGINAL witnesses to recover the SAME word.

**Counterexample to allowing individually certified but misaligned siblings:** for `q=32,p=16,Delta=8`, individually FALSE `4a+4b-1=0` has `A1=(-1,4,4)`, certificate t1=24; `4a+4b-3=0` has `A2=(-3,4,4)`, certificate t2=8. NO common t exists. With one z improperly reused, raw first rows satisfy `Y1=-z+Delta*mu+e1`, `Y2=-3z+Delta*mu+e2`. Thus public `3Y1-Y2=2Delta*mu+3e1-e2` cancels z; exhaustive rounded/error enumeration shows **TV=1** between full joint distributions for mu=0 and mu=1, despite individual FALSE certificates. Sharing z across DIFFERENT word positions likewise exposes their difference. These are concrete unsafe cases, not ordinary-LWE attacks.

Resource result under this exact restricted class: if S related capsules carry J word indices each with D source coordinates, independent source coins consume `S*J*D*log2(q)` bits while safe group reuse consumes `J*D*log2(q)`; save `(S-1)*J*D*log2(q)` random bits. It does not reduce ciphertext sizes or fresh independent error coins and is not a viable generic WKEM efficiency claim.

## Executed evidence, security limits, and next decisive equation

The separately published `checker.js` is the precise tested JavaScript logic; `checker-output.json` is its captured result, including 147,456 exhaustive pointwise checks, 512 adaptive whole-view checks, 1,536 true ORIGINAL openings and the *negative* TV=1 diagnostic. An independent **local-only** Python checker was also executed, passed 152,072 assertions, and is available as a separate archive; it is not passed off as the GitHub JavaScript file. Both are insecure toy algebra, not QPT hardness, parameter calibration or independent review.

This closes ONLY R75's excluded coin-reuse behavior for an aligned, publicly certified FALSE subclass. No new result for arbitrary-FALSE, arbitrary hard-TRUE, malformed/malicious ceremony and abort completeness, DA, selective opening beyond stated exclusion, practical 128-bit PQ security, Bitcoin-native endpoint, or R58/R63/R67's broken sources.

The **still missing** equation for an arbitrary QPT attacker on hard-TRUE ORIGINAL x is:

`Pr[A(V_x) recovers accepted native capability or forges intended path] <= Pr[R_ORIGINAL(x,Ext^A(V_x))=1] + Adv_independent_QPT_break + negl(lambda)`.

The extractor cannot demand a representation, and the actual statement-dependent source, opening data, LWE challenge, checking key, context, Aux and related capsules must be generated *jointly*. R78 does not instantiate that extractor and is NOT a completed witness-KEM.
