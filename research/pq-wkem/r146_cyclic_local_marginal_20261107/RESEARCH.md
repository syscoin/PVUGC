# R146 — Cyclic complete-local-marginal SOURCE trial

**Status: rejected ORIGINAL-dependent source candidate, NOT a constructive security advance and NOT a generic NP WKEM.** This is a bounded offline mathematical iteration, without encryption-size optimization, external research, production edits, or any assertion of QPT security.

## Continuity / exact starting point

Repository syscoin/PVUGC, draft PR #1, existing branch research/pq-wkem-validation-20260918, observed initial SHA \`8a73c60fa23e5b46b811a4c1ef97597eddb6bb8f\`. The exact R145 note at that SHA has blob \`0773ddeb4e6949acc36b59fba181d023240cb219\`. Its direct even/odd parity-factor counterfeit can be rejected by an *entire factor* triple-moment constraint, but that observation does not enforce global existence. R146 tries the stronger variant: complete local truth-table factors and all available shared-variable overlap consistency, not just moments of bounded degree. It does not reuse any failed R119 packing optimization.

## ORIGINAL instance and complete-local-factor source

Let n>=3 and x be a cyclic XOR system on ORIGINAL Boolean variables v_0,...,v_(n-1):

    v_i XOR v_(i+1 mod n) = beta_i,   0 <= i < n

Each XOR constraint is exactly two 2-CNF clauses (and therefore 3-CNF-compatible via standard padding), so this is an NP relation with an ordinary Boolean witness, not a newly defined credential relation. Set beta_0=...=beta_(n-2)=0, beta_(n-1)=1. XORing every equation gives 0=1, hence x is FALSE. For a satisfiable control, all beta_i=0, with two distinct ORIGINAL witness assignments (all 0 and all 1).

Factor i has *all* its locally accepted assignments indexed by t in {0,1}: (v_i=t,v_(i+1)=t XOR beta_i). Introduce local coordinates z_(i,t) for the two one-hot states, total 2n coordinates. Define an explicit 2n by 2n integer matrix H and target b:
- Normalization row i: z_(i,0)+z_(i,1)=1.
- Overlap row n+i: sum_t t*z_(i,t) - sum_t (t XOR beta_(i-1))*z_(i-1,t)=0 (indices modulo n).
- b_i=1 for the first n normalization rows, otherwise b_i=0.

Because each local factor's two entries enumerate its *complete* local truth table, all local degree-0, degree-1 and degree-2 Boolean moments are fixed by z_(i,t). Equality of singleton overlap moments is complete on each shared single-variable intersection. The issue is global gluing, not an omitted within-factor moment.

Every genuine ORIGINAL witness w for a compatible instance induces the integral one-hot z(w) with H z(w)=b. Different valid witnesses have disjoint local choices but are mapped to the *same* capability K.

## Explicit source law and honest opener

For this finite bounded experiment let q=65521, Delta=4n+10, with n in {3,5,7,11,23}. Independently sample s uniformly in Z_q^(2n), e_j and eta uniformly in {-1,0,1}, and K uniformly in {0,1}. Publish the ORIGINAL relation/statement and claim-context binding, H,b, and the source bytes:

    c_j = sum_r H_(r,j) s_r + e_j (mod q)
    p   = b^T s + Delta*K + eta (mod q).

Off-chain Open(w) computes z(w) from the ORIGINAL Boolean assignment, checks the actual ORIGINAL XOR constraints, and evaluates

    T_w = p - z(w)^T c = Delta*K + eta - z(w)^T e (mod q).

As |eta-z(w)^T e|<=n+1, nearest-center decoding at centers 0 and Delta yields exactly the same precommitted K on *every* permitted setup tape for every valid w. This is source-level correctness, not a signature-capsule or malicious-setup proof. H is structured; ordinary decisional QPT-LWE is NOT established for this law.

## Direct public counterfeit for every odd cycle

The FALSE instance has a fractional global pseudo-certificate zbar_(i,t)=1/2 at every factor entry. Each factor normalizes, and the shared-variable marginal is exactly 1/2 on each incident factor. Hence H*zbar=b even though no global ORIGINAL witness exists. The public integer vector Z=2*zbar has every coordinate equal to 1 and satisfies H*Z=2b exactly.

Using the actual public ciphertext only, an attacker computes

    U = 2p - Z^T c
      = 2Delta*K + 2eta - Z^T e (mod q).

Every error tape obeys |2eta-Z^T e|<=2+2n. Because min(2Delta,q-2Delta)>2(2+2n), nearest circular decoding at centers 0 and 2Delta reveals K with probability ONE, with NO witness, no source secret, no LWE challenge secret, no decryption oracle and no supplied representation from the adversary. Any full-public CK/J/Aux, related capsules, or advice only add information; cannot remove this exposed phase. The result is a classical public leak, not a QPT-LWE break.

## One attempted repair and why it does not establish security

Adding *all local moment rows* is already encompassed by the complete local truth table, and overlap equality remains satisfied by zbar. One could add a global cycle-parity row to reject this very easy XOR contradiction, but that uses a special polynomial-time parity solver and is not an ORIGINAL arbitrary-NP compiler. Adding a public software check that Open(z) rejects fractional z also fails: the attack never calls Open, but directly evaluates the public phase.

A genuine generic repair must make valid *global Boolean* assignments usable while preventing public arithmetic interpolation of the final phase, and it must instantiate both the source-dependent encryption and an exact joint-output QPT simulator. Merely adding more local LWE constraints, label switching, or downstream hash/pad binding does not close this missing cryptographic interface.

## Executed bounded checker and scope

The exact V8 checker \`checker_code_mode.js\` was executed in the connected tool runtime. It tests five odd-XOR cycles and their satisfiable all-zero controls, the integer identity HZ=2b, both genuine witnesses on controls, explicit n<=11 Boolean nonexistence checks (for n=23 the 0=1 parity proof applies), deterministic independent uniform {−1,0,1} noise samples, 256 public-only key recoveries per FALSE instance, and 512 true-path recoveries per satisfiable control. Total 5,145 successful assertions. \`captured.json\` records the counts. These are finite functional checks; the universal public-counterfeit identity and deterministic error bound are the mathematical arguments.

## Precise handoff

Retire this complete-local-marginal affine source as a generic-WKEM candidate. Do not report it as a construction advance. The missing mechanism must be a *nonlinearly enforceable* relation-to-release compiler, classical PPT in setup and honest opening, without public affine pseudocertificates; every ORIGINAL witness must recover one frozen capability. It must jointly instantiate source openings, the source-dependent QPT-LWE challenge simulation with all public checking/auxiliary correlations and related capsules, and a straight-line or otherwise QPT-valid reduction from arbitrary unauthorized final native-signature recovery to an actual ORIGINAL witness or an independently justified PQ break. Neither this run nor the prior restricted LWE-credential proof provides that construction. N-of-N ceremony, abort, pre-funding DA and hypothetical Bitcoin-native PQ endpoint remain additional unproved obligations.
