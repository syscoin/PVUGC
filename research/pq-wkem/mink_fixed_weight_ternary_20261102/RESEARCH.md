# MINK-FWT-20261102 — fixed-weight ternary graph commitment, no generic WKEM claim

Status: substantive efficiency improvement to the existing MINK-DENSE pre-funding proof component, under its SAME unassessed decisional-QPT-LWE assumption and honest public-coin CRS model. This does not solve generic-NP SOURCE Build/Lift or hard-TRUE unauthorized recovery to ORIGINAL witness. Offline derivation and exact checker; no external research.

## Exact predecessor and purpose

Predecessor: research/pq-wkem/mink_dense_crs_20261101/RESEARCH.md at exact blob b667b8d155f90e39718bc521de1e21161b5fa02a, checked against PR #1 head fb874ea19adbadde95e5562fea029cc5f6125d5a. Its public proof CRS is A uniform in Z_q^(m x n), and independent b_col,b_ch uniform in Z_q^m. Genuine private keys DO NOT exist in real CRS. Soundness analysis privately switches b_col to a genuine LWE sample, while malicious-verifier simulation instead switches b_ch to a separately sampled genuine LWE key. A false setup statement X is compiled to graph G_X with d edges; the full source-dependent compiler remains unfinished. Honest prover color commitments freeze after verifier precommits an encrypted edge and before edge/coin revelation.

MINK-DENSE stores each vertex color as two independently encrypted binary bits. A naive ternary encryption with unrestricted binary randomness is WRONG: at q=65537,m=4800,|e|<=3, the worst-case 14400 noise exceeds half the ternary center separation 10922.5. This run repairs that via fixed-weight coins and proves the statistical hiding and unique-decryption conditions together.

## Real algorithm (classical PPT)

Use the predecessor's identical illustrative q=65537 prime, n=256, m=4800, eta=3, g=floor(q/3)=21845. Independently generate A uniform in Z_q^(m x n), b_col,b_ch uniform in Z_q^m; they remain public. For each color c in {0,1,2}, sample r uniformly from all binary m-vectors of EXACT Hamming weight t=2400. Return one ciphertext

    C_col(c;r)=(u=A^T r mod q, v=b_col^T r + g*c mod q).

An opening reveals (c,r), checks c in {0,1,2}, canonical binary r, weight(r)=t and exact recomputation of u,v. Bind each ciphertext to the authenticated transcript key (session, ORIGINAL relation identity, claim/UTXO, branch/path, anchors/window, context, actual SOURCE capsules, genuine native verification key, prover, verifier, round, vertex). Reject replay and noncanonical inputs. The verifier's hidden edge STILL uses the original independent b_ch and unrestricted uniform binary r in the dual encryption; its full reveal MUST match the prior ciphertext. The graph proof stays off-chain.

## Unique color extraction in the genuine-key soundness hybrid

Replace real b_col with b_col=A s_col+e_col, where s_col uniform in Z_q^n and e_col has the predecessor's EXACT bounded i.i.d. LWE error law, each |e_i|<=3. Any accepted public opening satisfies

    v - s_col^T u = g*c + e_col^T r mod q
    |e_col^T r| <= t*eta = 7200.

The circular centers 0,g,2g have minimum distance min(g,q-2g)=21845. Their radius-7200 neighborhoods are pairwise disjoint since 2*7200 < 21845. The soundness referee knowing s_col maps EVERY committed arbitrary (u,v), even from a QPT malicious prover, to its unique nearest center within radius 7200 or to invalid. Therefore any later accepted opening MUST equal its pre-extracted color; no adversary-provided representation, extraction by classical rewinding or volunteered opening is needed. A false 3-color graph has at least one inconsistent edge for every assignment (including invalid vertices). The honest verifier's edge remains unknown until after the batch freezes.

Under the SAME decisional QPT-LWE assumption distinguishing uniform (A,U_m) from (A,A s+e), a conservative bound for ell independent authenticated rounds with d edges, k_edge hidden edge bits and polynomial classical-message QPT attackers is

    Pr[FALSE accepted] <= Adv_QPT-DLWE_col + (1-1/d)^ell + 2*k_edge*epsilon_edge,

where epsilon_edge=(1/2)sqrt(q^(n+1)/2^m). The single LWE hybrid covers the entire polynomial transcript. For T authenticated attempts, account for all hidden bits and union-bound T independent round-failure opportunities. Aborts cannot be treated as successes.

## Fixed-weight two-universality and QPT hiding

Let S_t be all binary length-m vectors of weight t, N=binom(m,t), and define F_(A,b)(r)=(A^T r,b^T r). For any distinct r,r' in S_t, their difference has a coordinate equal to +1 or -1 (invertible mod q). With uniform A,b, F(r)-F(r') is uniform in Z_q^(n+1); F is pairwise independent on S_t. The collision/second-moment leftover-hash bound is

    Delta(((A,b),F_(A,b)(r)), ((A,b), U(Z_q^(n+1))))
      <= epsilon_FW = (1/2)*sqrt(q^(n+1)/binom(m,t)).

The last-coordinate shift g*c leaves the uniform reference distribution unchanged, so any two real color ciphertext distributions differ by at most 2*epsilon_FW. Exact illustrative values:

    log2 binom(4800,2400) = 4793.559767450
    log2 epsilon_FW        = -341.777054976
    log2 epsilon_edge      = -344.997171251.

These are STATISTICAL hiding numbers averaged over honestly independent uniform public keys, NOT concrete QPT-LWE hardness estimates or guarantees for malicious keys. Fresh independent r across vertices/rounds supports polynomial classical transcript hybrids and arbitrary coherent QPT postprocessing of those classical samples, with independent quantum advice. Only precommitted challenge-endpoint openings are covered; arbitrary post-commit selective openings, quantum opening oracles and setup-secret-correlated auxiliary states are excluded.

## TRUE proof straight-line simulation

The predecessor's malicious-verifier simulator switches independent b_ch to genuine b_ch=A s_ch+e_ch and privately retains s_ch. From an encrypted edge precommit it decrypts the edge BEFORE constructing vertex commitments. A later authentic reveal with unrestricted binary r is forced to agree with this decryption because |e_ch^T r|<=14400 < floor(q/2)/2=16384. The simulator chooses its two challenged endpoint colors uniformly among the six ordered distinct pairs, chooses arbitrary other colors and uses independent weight-t coins for all ternary ciphertexts. After a valid edge/coins reveal it opens only the challenged endpoints.

A genuinely uniformly permuted full coloring has the same six-pair endpoint distribution. In the REAL uniform b_col world, other color ciphertexts are hidden by epsilon_FW, while the QPT-LWE b_ch hybrid enables straight-line early decryption in the simulated world. For k_col unopened color commitments a scoped conservative bound is

    Dist_QPT(Real,Sim) <= Adv_QPT-DLWE_ch + 2*k_col*epsilon_FW.

This assumes authenticated classical protocol messages, a TRUE setup graph with witness independent of proof CRS, fail-closed malformed challenges, independent fresh color coins, and the same restricted auxiliary/advice model as MINK-DENSE. No QPT rewind, SourceOpen oracle or random-oracle programming. It is NOT a full joint SOURCE/native-key/setup checking-key simulator.

## Exact resources and unchanged obligations

The public matrix/vector sizes and original q,n,m,eta distribution remain unchanged. A field element uses canonical 3-byte encoding. Previous two bit ciphertexts: 2*(n+1)*3=1542 bytes per vertex per round. New one ternary ciphertext: (n+1)*3=771 bytes, exactly 50% less. Savings are 771*|V|*ell bytes per prover/verifier before transport. Endpoint openings now reveal one fixed-weight m-bit r rather than two binary m-bit r vectors. Sampling r uniformly from S_t is classical PPT. The fixed-weight entropy is only 6.4402 bits below the original 4800-bit unrestricted r entropy, leaving epsilon_FW < 2^-341.7.

The earlier MINK-EVC proposed a different equivocal CRS component and is NOT validated by this improvement. One-honest malicious CRS generation with aborts and programming, complete setup statement compiler, full related-capsule and secret-correlated source outputs, native Bitcoin PQ endpoint, authentic SYS/BTC source evidence and 128-bit QPT-LWE concrete analysis remain unfinished.

Most importantly, the missing ORIGINAL witness release is still:

    For every R(x,w)=1: Lift(x,Build(x,K,rho),w)=K,
    with precommitted common K and a simulatable JOINT (x,capsule,setup proof/checking key,
    actual native vk,context,auxiliary inputs,related capsules,selective openings).

For hard TRUE x, arbitrary unauthorized recovered K or accepted native forgery must imply an ACTUAL ORIGINAL witness (not a representation or unextractable inner proof) or an independently justified QPT break. The construction here does NOT solve that equation; the original signed-XOR source remains easy. No Bitcoin execution, deployment or funding recommendation.

## Exact executed evidence

Published checker.js executed twice under Node 22.16.0 with 72,913 identical assertion events per run. It exhaustively verifies 7,290 bounded-error toy ternary openings; all 1,024 public keys in a fixed-weight two-universal q=2 toy with 11,520 pair collisions exactly; all 81 K4 three-color assignments; and center uniqueness over all 65,537 residues. The expanded OFFLINE standard-library Python checker ran twice identically with 126,806 checks each, including three actual q=65537,n=256,m=4800 encrypted color fixtures and a 72-round honest TRUE-edge opening test. These checks validate equations and implementation, NOT quantum security. No external research or production edit.