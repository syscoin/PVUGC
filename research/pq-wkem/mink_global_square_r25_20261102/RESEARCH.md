# MINK-GLOBAL-SQUARE-R25 — exact scalar repair, full-public break

**Research-only supporting note. NO positive construction advance and NO secure generic post-quantum witness-KEM.** The exact PR #1 starting SHA was cb147ac872f94cce74e6e1bf73a2125f7da4c62e, branch research/pq-wkem-validation-20260918; it was open, draft, unmerged, latest ordinary substantive comment 6590564185. Continuation uses exact-version R24 blob 5c25b629ff639e31781994a038a00c2ed2b1b56f and R19 blob c5288b50604f735f940429b0cfd6df8346e87b6b. No external literature or web search.

## Candidate and full view requirement

Work over A_n=F_q[z_1,...,z_n]/(z_i²-z_i) with odd prime q. The ORIGINAL (R,x) and compiler bind relation identity, claim/UTXO, branch, BTC/SYS anchors/window, intended native verification key, challenge path and all context. Compile a generic ORIGINAL NP verifier into 3CNF with clause failure indicators g_j. A valid ORIGINAL witness extends to a Boolean assignment a with all g_j(a)=0. The explicit candidate, for every protected precommitted capability bit mu, samples independent r_j uniform in F_q, forms P=Delta*mu+sum_j r_j*g_j, and publishes square-free coefficients of F=P²+e (with fresh independent post-square coefficient errors e, or e=0 for the exact break). Build does not require a witness. For fixed 3CNF width and multiplier degree zero, F has degree at most six and a polynomial-size O(n^6) expansion (not practical for large n). The support must be recomputed; R24's linear source projection cannot automatically transfer.

Every valid ORIGINAL witness a evaluates F(a)=Delta²*mu+e(a); different witnesses retain different states but reconstruct the SAME precommitted K. In the noiseless model correctness is exact; with centered independent bounded post-square noise, circular decoding succeeds if the honest evaluation error is less than half the distance between 0 and Delta² mod q, and the R23 all-assignment concentration strategy applies with the new support. The example q=65537, Delta=128 gives centers 0 and 16384; this is **not** a QPT-security parameter set.

This local theorem does not handle the genuine native vk, source-dependent checking key, challenge signer, public context, arbitrary auxiliary/quantum side information or related capsules. There is **no** ordinary-LWE source-challenge embedding and no joint-output simulator.

## Lemma 1: narrow statistical repair of the R19 short-dual leakage

For R19's explicit nine-clause FALSE 3CNF (see exact checker), set g0,...,g8. Coefficientwise in the Boolean quotient,

    1 = (g0+g1+g2+g3+g4+g5+g6+g7+g8) - g4*g7 - g5*g8.

Only the two pairs (4,7) and (5,8) have nonzero products. Let l be ANY F_q-linear functional on this polynomial space with l(1)=1 and l(g_j)=0 for every j. Define A_l[i,j]=l(g_i*g_j). Since g_i²=g_i, all A_l diagonals are zero. The identity forces -A_l[4,7]-A_l[5,8]=1, so A_l is nonzero. Over odd characteristic a nonzero symmetric zero-diagonal form has rank at least two and contains a nonsingular hyperbolic plane. For uniform independent r, l(G²) for G=sum r_j*g_j is a sum of 2cUV and an independent residual quadratic form, with c!=0 and U,V uniform in F_q.

The product 2cUV has mass 2/q-1/q² at zero and (q-1)/q² at every nonzero field value. Its total-variation distance from a nonzero additive translate is exactly 1/q. Convolution cannot increase TV. Therefore each **INDIVIDUAL** public normalized linear pseudo-decoder l sees l(P²+e) conditioned on mu=0 vs mu=1 with TV at most 1/q, provided e is independent post-square noise. This exact scalar theorem is valid against arbitrary QPT postprocessing of that ONE scalar only; it is not full-view security, simultaneous many-l security, quantum-opening security, or checking-key security.

For the original R19 short dual L(P)=[constant]P-[z0*z2]P, direct symbolic multiplication gives

    L(P)=Delta*mu,
    L(P²)=Delta²*mu - 2*r4*r7.

Thus the deterministic zero-witness linear disclosure is replaced by single-projection statistical leakage exactly 1/q, **without proving SOURCE security**.

## Lemma 2: disqualifying full-public attack on the noiseless nonlinear carrier

Append two honest 3-literal clauses on six fresh variables to the FALSE nine-clause core, with failure bits h and k, independently selectable to zero or one by the attacker. The original formula remains FALSE. The published noiseless polynomial is

    P(z,y,v)=P_core(z)+t*h(y)+u*k(v),  F=P²,

where t,u are independent uniform field values. From the public coefficient representation, evaluate the four polynomial restrictions F00,F10,F01,F11 for h,k in {0,1}. Applying the public R19 functional L to the restricted four-core-variable polynomial gives

    alpha=L(F10-F00)=t²+2*Delta*mu*t,
    beta =L(F01-F00)=u²+2*Delta*mu*u,
    D(z) =F11-F10-F01+F00=2*t*u,
    delta=D(0000).

The attacker returns bit zero if delta²=4*alpha*beta modulo q and bit one otherwise. For mu=0 it is ALWAYS correct. For mu=1 it fails only on t=0, u=0 or t+u=-2*Delta; exact failure probability for uniform independent t,u and nonzero Delta is (3q-3)/q². This attack is classical, straight-line, polynomial in the public representation and needs NO ORIGINAL witness, SourceOpen, independent lattice break or native signing key. It is a valid full-public attack on the **noiseless** construction. Taking q larger improves its success. The post-square-noise version perturbs the exact equations, so this calculation alone does not break or establish security of that version.

A one-scalar statistical theorem is not a full-public QPT simulator. Neither the specific attack nor this failure is claimed as a positive construction advance.

## Tested telescope fallback and exact remaining equation

For a 3CNF, first-violation indicators h_j=g_j*prod_{i<j}(1-g_i) obey sum_j h_j=1-prod_j(1-g_j). At every FALSE assignment the sum equals 1, and at every valid TRUE assignment each h_j vanishes. A full 2^n-row coefficient table with only c mask scalars therefore gives an exact FALSE pad-shift simulation without a separate public refutation certificate. This is **not a solution**: creating/publishing the full table is exponential rather than classical PPT, and an adversary polynomial in the table length can enumerate and locate a valid TRUE witness. A short public arithmetic circuit instead exposes the embedded protected constant unless a new, independently constructed secrecy-preserving encoding is supplied. Merely postulating such an encoding would rename witness encryption/obfuscation.

Exact executed standalone JS checker: CHECKER.js, 6,550 assertions twice with byte-identical results, OUTPUT.json. Independent offline Python checker: 54,132 assertions twice, byte-identical output SHA-256 1a91471bb986f6975089c34daaf1c34890d58380214d1b1da08b2024a8f8a2ed; the separate Python checker and extended derivation are local-only. Finite algebra and experimental witnesses, **not** QPT hardness testing. No external research, independent agent, deployment or production change.

**NO positive advance.** Exact remaining obligation: construct an actual classical-PPT, polynomial-size SOURCE Build(R,x,K;r) and Lift(C,w)=K for every valid ORIGINAL witness, an instantiated simulator for the COMPLETE correlated public view of every adversarial FALSE x, and for any arbitrary QPT attacker returning final K or an accepted genuine native forgery (without supplying any internal representation), a valid reduction to an ORIGINAL witness or independently justified PQ break. The original N-of-N ceremony, abort/useful completeness, challenge path and conditional native-PQ Bitcoin endpoint remain unfinished. Never mistake this scoped test for construction security.