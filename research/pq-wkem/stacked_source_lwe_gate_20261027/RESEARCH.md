# Stacked-row source-dependent LWE gate: exact simulator and opening obstruction

**Status (offline, 2026-10-27 America/Vancouver): NO qualified positive generic-NP witness-KEM advance.** This is a self-contained source-dependent simulator lemma and an exact counter-reduction for its proposed public opening. It is a supporting diagnostic, not a secure successor.

Provenance: PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, prepublication SHA 9d0aff032324504d916f24531c2ca9796672c668. Predecessor research/pq-wkem/unplanted_hard_true_20261027/RESEARCH.md at blob df442f4bc3013d8cb62dddc0d6cc3d06140b8d35. Latest substantive comment inspected 6460186598. No internet/literature, other repository, production, workflow or independent-agent work.

## Explicit candidate

Let lambda be the security parameter, q odd prime, d,n,r,ell polynomial, chi independent symmetric bounded integer noise with |epsilon_i| <= beta; e in F_q^n public anchor; C_x in F_q^(r x n) any classically PPT public compilation of bound ORIGINAL relation/statement/context x. C_x may depend on the *public* native checking key, but must be computable without secret setup coins and without the LWE challenge secret or native signing seed. A <- uniform F_q^(d x n) is independent of x and target secret. Per digit j sample s_j <- uniform F_q^d, t_j <- uniform F_q^r, epsilon_j <- chi^n, independently, and publish

    B_x = [A ; C_x]
    p_j = A^T s_j + C_x^T t_j + epsilon_j + g a_j e (mod q).

Choose independent uniform kappa-bit K,U,Z; generate the ACTUAL native signing key/checking key from K; publish native pk(K), D=U xor Z, V=K xor U and only LWE encapsulations p_j of radix-m digits a_j of Z. The public view includes R,x, claim/UTXO, branch, anchors/window, intended native pk and path, A,C_x, all columns, auxiliary data and related capsules. Strings alone do not authenticate SYS/BTC evidence. All algorithms are classical PPT.

## Exact stacked-row LWE challenge simulator: proved sublemma

Given a standard decisional-LWE challenge (A,y_j), where y_j is A^T s_j+epsilon_j or uniform in F_q^n, the reduction samples t_j and publishes

    p_j = y_j + C_x^T t_j + g a_j e.

In the real branch this is pointwise IDENTICAL to the candidate distribution for every x,C_x, including all public source and native-pk correlations. In the uniform branch p_j is exactly uniform even conditional on A,C_x,t_j,a_j, by translation. Other columns may be generated honestly because their s_k are separately sampled. A column-by-column target-only hybrid uses ell standard ordinary-QPT-DecLWE games, no SourceOpen oracle, no adversarially supplied representation, no rewinding, no classical-to-quantum extraction inference.

When all p_j are uniform, for FIXED real native K the map (U,Z) <-> (D=U xor Z,V=K xor U) is a bijection. Hence D,V are jointly uniform even conditional on real pk(K). A straight-line simulator may now use a native QPT EUF-CMA challenge pk and its classical signing oracle. Any usable seed yields a fresh signature; an accepted fresh challenge-path forgery is itself an EUF-CMA forgery. For one unopened target with independent sibling keys, no target pad/seed leakage through auxiliary data, and classical adaptive openings/signature interfaces:

    Pr[unauthorized target seed recovery or fresh signature]
        <= ell Adv_QPT-DecLWE(d,n,q,chi) + Adv_QPT-EUF-CMA(native).

QPT may process the whole classical view coherently. Auxiliary data must be classically efficiently generated without extra hidden target seed advice. Do not hybridize opened sibling ciphertexts. Multiple targets incur ordinary target-hybrid sums. This theorem is source-dependent HIDING ONLY and would hold even if nobody could ever OPEN.

## Missing linear opener and exact negative theorem

A proposed ciphertext-independent f(A,x,W) for every ORIGINAL-valid W would output classical z satisfying

    A z=0, C_x z=0, e^T z=1 (mod q)
    |center(z^T epsilon)| <= E for ALL epsilon in supp(chi)^n
    2E+1 < q.

Then z^T p_j = g a_j + z^T epsilon_j permits SAME-K bounded-distance off-chain decoding, provided code centers are separated by 2E+1. The problem is constructing such z for every W without knowing W during setup.

**Known-witness short-kernel theorem (proved):** Fix any valid pair (x,W) independent of uniform A, with polynomial-length description. Let classical PPT or QPT f(A,x,W), independent of challenge ciphertext y, return a checked normalized, bounded-error z as above with probability p over uniform A and f randomness. A straight-line QPT decisional-LWE distinguisher hardcodes (x,W) as polynomial classical advice (or uses a uniformly computable explicit valid family), runs f before inspecting y and, when it passes, tests center(z^T y) in [-E,E]. For real y=A^T s+epsilon, Az=0 implies acceptance with probability 1 conditional on f success. For uniform y, z !=0 and is independent of y, so z^T y is exactly uniform F_q and accepts with probability (2E+1)/q. Reject on f failure. Exact advantage:

    p * (1 - (2E+1)/q).

For 2E+1 <= (1-c)q, any nonnegligible p directly breaks standard nonuniform QPT-DecLWE. Since a generic all-ORIGINAL-witness compiler must also handle one easy, explicit true instance, this defeats the *independent uniform A + public ciphertext-independent short-kernel opener* architecture even under uniform LWE hardness. It does not rule out ciphertext-dependent nonlinear opening, source-correlated nonuniform setups with independent QPT assumptions, or witness distributions intrinsically correlated with A. The hardcoded W here is a proof tool, not a claim that unauthorized users normally know a hard witness.

A tested repair idea added publicly decodable gadget columns allowing short compensation u for -A_0 f_x(W). If every valid W can compute a bounded-noise normalized kernel z=(f_x(W),u) independently of ciphertext, it triggers the same LWE distinguisher. Noiseless gadget coordinates abandon ordinary LWE and can leak its secret. Concealing compensators without an explicit public W-to-opening procedure does not restore completeness. **No repaired release was found.**

## Exact offline checks

The separately published check.py (Python 3 standard library) was actually executed twice byte-identically, 1,580 assertions per run. It tests 1,500 exact source-row real-challenge couplings; 75 finite-field null-translation bijections for three source-row families; complete 15,625-matrix census for known z=(1,1,0), q=5,d=2 with Pr[A z=0]=1/25; and exact q=17,d=1,n=5 anchored weight-two search census. The latter finds short z with probability 17985/83521, producing an exact LWE distinguishing advantage 215820/1419857 for error radius E=2. These are finite algebra, not QPT security tests, deployed SLH, BTC endpoint, or 128-bit certification.

## Exact handoff

The simulator is solved for arbitrary public C_x, but its every-ORIGINAL-Witness opening cannot be simultaneously instantiated with independent uniform A under ordinary LWE in this linear form. The next candidate MUST genuinely replace either (i) source-independent uniform A plus ciphertext-independent short kernel, or (ii) this linear release, and prove jointly:

    For every ORIGINAL R(x,W)=1, Release(x,W,full public capsule)=the SAME K;
    for all false x, full-public QPT indistinguishability;
    for hard-true unauthorized native recovery/forgery, ORIGINAL W extraction or independent QPT break.

No source-dependent compiler, fixed-false generic-NP proof, native-SLH implementation, malicious N-of-N setup, PoW/DA/ChainLock evidence, Bitcoin conditional native output or graph safety was completed. **No qualified positive advance; do not disable the ongoing research task.**
