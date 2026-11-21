# R63 — ORIGINAL short-kernel compiler, and a complete FALSE-source bypass

Run: R63-ORIGINAL-SHORT-KERNEL-20261104 (2026-11-04).
Continuity: syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918, initial checked SHA 8ded1608c91c60364bd59e9248e53e3186c18ebc, previous substantive comment 6631276713.
Subproblem: R62's missing generic ORIGINAL-NP-to-source compiler, including actual source encryption and the complete public challenge-simulator correlation.
Status: exact polynomial NP-to-bounded-kernel representation lemma proved, but the resulting actual source is explicitly broken on ORIGINAL-FALSE inputs. NO positive secure WKEM construction advance. No external internet/literature research.

## 1. Constructed compiler, no hidden witness required at Build

Let x be an arbitrary 3CNF with v variables and c clauses (1–3 literal occurrences each, duplicates allowed); N=1+v+c. Construct public A_x in Z_q^(m x n), m=1+2v+3c, n=v+2c, q=2^t>8N. Its rows are indexed by a distinguished coordinate r0, a pair (Ti,Fi) for every variable, and a triple (Sj1,Sj2,Sj3) for every clause. Its n columns encode these equations:

    Ti + Fi - r0 = 0
    Sj1 + Sj2 + Sj3 - r0 = 0
    sum over literal occurrences (Ti for positive i, Fi for negative i)
        + Sj1 + 2*Sj2 + 3*Sj3 - 4*r0 = 0

Build computes A_x from x alone in deterministic classical polynomial time. For EVERY original satisfying assignment w, let r0=1, choose one variable row Ti or Fi as dictated by w, and in each clause j with k true literal occurrences (1<=k<=3) choose exactly slack Sj(4-k). All other coordinates are zero. Then A_x^T*r=0 mod q, r is binary, and ||r||_1=N. Distinct ORIGINAL witnesses retain distinct representations. This solves exactly the existence and deterministic witness-to-representation directions without a canonical witness, common hidden preimage or an online authority.

Exact bounded-representation soundness theorem: if an integer vector r, represented canonically modulo q, has r0=1, ||r||_1<=N, and A_x^T*r=0 mod q, then an ACTUAL ORIGINAL satisfying assignment is extractable from r in classical polynomial time. Proof: every column coefficient has absolute value at most 4, hence every integer column sum has absolute value <=4N<q. Modular zero therefore equals integer zero. Each variable pair and each clause triple sums to one. By the triangle inequality the l1 norm of each group is at least one; counting r0 gives a global lower bound 1+v+c=N. Thus every group must have norm exactly one, and an integer group summing to one and with l1 norm one is a nonnegative one-hot vector. Variable groups determine w. A clause with zero true literal occurrences would require a one-hot slack of weight four, although the available weights are only 1,2,3; impossible. All clauses are satisfied. Conversely the explicit construction supplies a representation for each satisfying assignment. The reduction is polynomial-size, with at most O((v+c)^2 log(v+c)) naive public matrix bits. This lemma covers a SUPPLIED norm-bounded representation, not arbitrary native forgery or secret recovery.

## 2. Actual attempted release, full view and simulator

Use R62's dual-LWE source but substitute this A_x. The honest classical Build independently samples uniform s_i in Z_q^n and centered errors e_i from chi^m, with |e_ij|<=E, and privately chooses the precommitted common root K and independent checking secret Kbind. For their binary source bits mu_i, publish:

    C_i = A_x*s_i + e_i + Delta*mu_i*e0 (mod q),

where e0 selects row zero. Also publish Dsig = sigma_star XOR G(K), where sigma_star is the preauthorized native challenge-path signature for immutable context-bound m_star. Let Base canonically bind x, its ORIGINAL relation identity, claim/UTXO, branch, anchors/window, native vk and m_star, source A_x and all ordered C_i, Dsig and related capsule scopes. Define CK=F_Kbind("CK",Base) and Aux=F_Kbind("Aux",CK,Base); these are CORRELATED public values, not independent random-oracle marginals.

Any genuine ORIGINAL witness r gives r^T*C_i = Delta*mu_i + r^T*e_i mod q, with |r^T*e_i|<=N*E. Therefore Delta>2*N*E and q>2*(Delta+N*E) ensure all ORIGINAL witnesses decode exactly the SAME K,Kbind, reproduce CK/Aux and recover the identical Build-precommitted native signature off chain. No NP verifier is imposed on Bitcoin. Preauthorization/erasure and hypothetical native PQ signature/P2MR functionality remain separately unproved.

The exact honest source distribution is (A_x deterministic, s_i uniform, e_i independently distributed as above), together with genuine correlated Base/CK/Aux/vk/context/related capsules. A simulator given an actual *x-structured* sample (A_x,Y_i), Y_i=A_x*s_i+e_i or uniform, can generate C_i=Y_i+Delta*mu_i*e0, choose K,Kbind and independent related source coins itself, and recompute the complete correlated CK/Aux from the actual new Base. The checker tests this exact-source identity and complete public recomputation, 72 times. But an ordinary uniform-A QPT-LWE challenge does NOT supply the actual x-dependent A_x; the structured challenge is not supported by a QPT hardness reduction and in fact is classically distinguishable on the FALSE fixture below. There is no SourceOpen oracle, quantum rewinding, or volunteered representation, and there is NO valid QPT security proof.

## 3. Constructed FALSE attack defeats even an exactly sound bounded verifier

For ANY assignment w, define h0=1 and one-hot variable rows from w. Use the legal one-hot clause slack if the clause is satisfied. For each unsatisfied clause choose the *signed* triple (Sj1,Sj2,Sj3)=(0,-1,2). Its sum is one, its weighted score is 0-2+6=4, and its norm is three instead of one. Thus the efficiently computed integer h has:

    h0=1, A_x^T*h=0 (mod q), ||h||_1=N+2*u(w),

where u(w) is the number of unsatisfied clauses. For u>0, h is NOT an accepted ORIGINAL representation. But no attacker need submit h to the verifier: the public ciphertext itself obeys

    h^T*C_i = Delta*mu_i + h^T*e_i (mod q).

Let B=N+2*u(w). If Delta>2*B*E and q>2*(Delta+B*E), each hidden source bit is recovered by the same deterministic public nearest-center calculation, for EVERY possible bounded-error draw. Consequently an ORIGINAL-FALSE x with an assignment missing only one clause yields K and Kbind and therefore the full masked native signature, complete checking key and auxiliary correlations, even though there is NO ORIGINAL witness. This is an actual full-public-output security failure, not a counterexample to representation-level soundness.

The concrete FALSE x=(z) AND (NOT z) has N=4,m=9,n=5,E=1,Delta=13,q=64, and the attacker computes a signed h of norm B=6. All 32 independent deterministic toy trials recovered two separate 16-bit secret seeds, reconstructed SHA-256 CK/Aux and unmasked every byte of a 48-byte synthetic signature. Adding eight tautological clauses keeps x false; N=12,m=33,n=21, Delta=29,q=128,B=14, and all eight additional trials again recovered the complete capability. A separate TRUE instance with two satisfying assignments yielded 64 correct full-witness openings for the SAME capability. The exact executed and published Node.js checker passed 121,956 assertions. Those toy parameters and synthetic signature/SHAKE stream are NOT QPT-secure cryptography.

## 4. The required full-view structured-LWE assumption is itself false here

Take the SAME public FALSE A_x and h. Given an alleged decisional structured-LWE challenge Y, test whether dist_q(h^T*Y,0)<=B*E. For real Y=A_x*s+e the test accepts with probability one. For independent uniform Y, h0=1 guarantees h^T*Y is uniform in Z_q, so acceptance probability is at most (2*B*E+1)/q for B*E<q/2. Therefore a purely classical distinguisher has advantage at least:

    1 - (2*B*E+1)/q.

It is >=0.796875 on the original FALSE fixture and >=0.7734375 on the tautology-extended fixture, approaching one as q grows. This invalidates any use of the x-structured challenge distribution as an independently justified QPT-LWE hardness premise. The failure is prior to, and unaffected by, correlations with CK/Aux/native vk/related capsules. Public right-column changes A_x -> A_x*U preserve h^T*A_x=0, and adding source error in the public column span A_x does not remove the bypass. Checking r is binary or norm-bounded in Open also cannot prevent an attacker from independently computing h^T*C.

## 5. Assumptions, access model and missing equation

Honest compiler/Build/Open are classical PPT. Security would have to resist arbitrary nonuniform QPT adversaries, including coherent processing of all CLASSICAL public values, with quantum advice independent of target setup coins and no assumption they volunteer any internal representation. The complete security experiment must include relation/claim/scope, checking key, auxiliary inputs, multiple related capsules and permitted classical selective openings; no post-legitimate-target-opening secrecy is promised. Neither this finite checker nor the verified representation lemma establishes arbitrary-FALSE QPT security, hard-TRUE security, actual 128-bit parameters, secure malicious N-of-N setup/abort, data availability, or any deployed Bitcoin native-PQ path. R58's earlier public trace also still breaks the old TRUE quotient; it is not repaired here.

The indispensable outstanding proof/construction is a genuinely nonlinear or otherwise independently justified, statement-bound SOURCE whose ACTUAL classical-PPT setup/opening data and all public checking-key/aux/related correlations can be simulated together from a REAL QPT challenge, and for which arbitrary unauthorized capability recovery or accepted native forgery obeys:

    Pr[A(V_x) recovers precommitted K or produces an accepted native forgery]
      <= Pr[R_original(x,Ext^A(V_x))=1]
         + Adv_independently_justified_QPT_break + negligible(lambda).

No supplied-representation assumption, generic witness-release/iO oracle, unsupported classical-to-quantum lift, or structural-LWE assumption already contradicted above is acceptable. This attempt proves a *supplied-bounded-representation -> ORIGINAL* lemma but decisively fails the required *arbitrary-recovery -> ORIGINAL or independent break* direction. It is a completed bounded diagnostic iteration, NOT a secure WKEM advance. The project must remain in research.

## Provenance

Exact executed Node checker: CHECKER.js (SHA-256 68b441365c265b96bd679c1dccff015c6ba2d9afb65a69dccac14f985e516d65, Git blob 96aeaf3e97a1177e9fd0d847977da476340cc14e).
Exact captured output: OUTPUT.json (SHA-256 d6893c884da110fc14ee0445914b60be6fd0b301382455b49523afd0eeaf91c0, Git blob cacc355365a5879cdb88a558d5ced7345ad3b872).
To reproduce with Node.js 22 or comparable: node CHECKER.js > OUTPUT.json.
The extended local mathematical record includes the same equations and checks in more detail; it is NOT represented as byte-identical to this published research note.
