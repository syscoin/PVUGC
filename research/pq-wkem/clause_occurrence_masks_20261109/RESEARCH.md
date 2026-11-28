# Clause-occurrence mask correlation — two-point extractor against full-degree repair

**Research-only, 2026-11-09. NOT a secure WKEM, generic ORIGINAL source compiler, or QPT theorem.** No lattice, public group, online issuer or external research. Continuity: syscoin/PVUGC PR #1 branch research/pq-wkem-validation-20260918; observed starting head 7f74a6854afdf5809132b611525fc5fb1dd5d876 (open/draft/unmerged). Read exact hash_sealed_states_20261109/RESEARCH.md blob fd6576b982733e9ff7065f34b2a6cfe20f2e4820 and native_forgery_pke_20261109/CHECKPOINT_01.md blob 71ed711c9a248ea795480f64e92ee12464382835; bounded recent PR comments were empty. Intermediate note committed de8fd958f5479628ccf59fd4522113c8a117d80d. No independent verifier or PR progress comment.

## Candidate: source-dependent polynomial public mask correlation

Use a 3CNF statement x with m clauses c_j (each three distinct witness variables) as an NP-complete ORIGINAL-verifier subproblem, NOT a replacement for actual Syscoin/AuxPoW evidence. Let f_j be the unique three-bit assignment violating clause c_j. Setup samples independent 256-bit secret shares s_j, per-occurrence-bit pads r[j,i,b], degree-three words T_j; define the SAME precommitted K=XOR_j s_j, and freeze a native-path signature sigma to be separately hidden under a domain-separated mask of K with context claim/path/VK/anchors. The native layer does not repair disclosure of K.

For every locally satisfying tuple a!=f_j, publish

    A_j(a)=s_j XOR XOR_{i in c_j}r[j,i,a_i] XOR T_j*g_j(a),

where g_j(a)=1 iff a is bitwise complement of f_j, and zero otherwise. Its Boolean algebraic normal form has degree 3. Publish for every variable and bit

    B_i(b)=XOR_{j:i in c_j} r[j,i,b].

The attempted nonlinear repair additionally provides an unrestricted public polynomial-time evaluator

    D(w)=XOR_j T_j*g_j(w projected onto c_j).

For EVERY globally satisfying ORIGINAL witness w, PublicOpen computes

    K'=XOR_j A_j(w projected onto c_j) XOR_i B_i(w_i) XOR D(w).

Every occurrence pad and each T_j*g_j term occurs twice, so K'=K regardless of which valid witness. Setup/evaluation O(m+n), no witness enumeration or source-selected secret. This is an explicit polynomial construction *attempt*, not a protected full-public hash circuit: securely realizing D is a separate missing interface, and an unrestricted D is fatally public as shown next.

## Exact key extractor with no ORIGINAL witness

Choose ANY n-bit baseline z, including a false assignment. For each clause define a publicly reconstructible virtual local value V_j(z):

    if z|c_j != f_j: V_j(z)=A_j(z|c_j)
    else:             V_j(z)=XOR_{a!=f_j}A_j(a).

Write q_j(a)=s_j XOR_i r[j,i,a_i]. This function has Boolean degree <=1, so XOR over its 8 inputs equals 0. Since g_j is nonzero on exactly ONE of seven satisfying tuples, in both branches

    V_j(z)=s_j XOR_i r[j,i,z_i]
           XOR T_j*[g_j(z|c_j) XOR 1_{z|c_j=f_j}].

But 1_{z|c_j=f_j}=g_j((NOT z)|c_j). Thus

    XOR_j V_j(z) XOR_i B_i(z_i)=K XOR D(z) XOR D(NOT z),

and the public adversary returns

    K=XOR_j V_j(z) XOR_i B_i(z_i) XOR D(z) XOR D(NOT z).

It makes TWO public D queries and O(7m+n) XOR operations. NO satisfying assignment, SAT solver, ORIGINAL source certificate, secret labels, SHA preimage, chain verifier, quantum query or internal representation is needed. This holds also for false 3CNF instances. It defeats this *precisely specified* local mask/full-degree/public-correction class, NOT all nonlinear hash constructions or witness encryption.

## Evidence

The actual executed compact_checker.py (in this directory) uses 256-bit GF(2) words and deterministic Python random.Random for toy reproducibility, NOT cryptographic entropy or a real QROM experiment. It exhaustively checks honest opening for each satisfying assignment and raw public key extraction at EVERY assignment over 240 TRUE sampled 3CNF formulas (n=3..6), and 12 FALSE formulas consisting of all eight sign patterns on three variables. 10,128 assertions succeeded; all 252 cases leaked K, including all false cases.

Executed source SHA256: 7fb5320c6398a1ce54940475e93445e1707e2ce4f17ccd196b522b855751029d; exact source Git blob: 0c516c04e58e531bf02015f67660401773f61a34. Captured JSON SHA256: a48c9ae19cca771a99d9b3bb7d17f0714fb2c6777f691a0c546e50eed35e4ee5; exact JSON Git blob: 06da380febfc2861c42f71028d5c46bbc2cf156f. No independent agent was invoked. Two larger preliminary local checkers remain local only (linear row-span 256/256 sampled fixtures; degree-3 interpolation 340/340, including 20 false and 132 nonunique T representations). Do not count these as independent QPT evidence.

## Why this does not solve the user's original requirement

Replacing unrestricted D with an interface that yields D(w) only when R_ORIGINAL(x,w)=1, while preventing extraction of its T_j from *full public code*, already assumes the cryptographically protected ORIGINAL-dependent release that we are attempting to build. An ordinary readable program with a post-hoc conditional verification does not hide its literals. Keeping T_j private without a public evaluator instead violates same-capability completeness across distinct valid w. Publishing T_j plainly restores the leak.

A viable new candidate must realize global protected cross-witness correlation in classical polynomial time from x alone, with full-public arbitrary QPT final-key recovery or accepted native forgery yielding ACTUAL ORIGINAL witness or independently justified PQ hash break. Neither this scheme nor its test provides it; the mathematical finding is a scoped rejection and next-candidate regression test, NOT a reported breakthrough. Actual source must bind claim/UTXO, child outcome, complete parent AuxPoW header/coinbase/Merkle evidence, height/lag/ancestor/window/tag constraints, real work inclusion and censor/reorg assumptions. Two different parent-work certificates for one child do not alone establish a conflict. N-of-N honest erasure, pre-funding DA, auxiliary/multi-capsule simulation and native PQ endpoint remain separate gaps. Do not resume lattices or optimize this rejected component.
