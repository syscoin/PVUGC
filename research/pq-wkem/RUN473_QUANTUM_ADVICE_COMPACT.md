# Run 473 — single-copy quantum advice and fixed-key reuse scope

Starting verified live PR: syscoin/PVUGC#1, open/draft/unmerged, branch research/pq-wkem-validation-20260918, SHA b41c4f1f8a3382c75aae6cb34e1834f8f87836a9. Latest substantive ordinary comment 6067040320. Exact Run 472 blob 7118d863c6a7e90d2720c2d556d9be7b3f762731; Run 259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2; CLZ applicability blob c19d9d9cd515140e3ce62eac960cd548c0add622.

## Result A: statistical reverse for one unrepeatable quantum advice copy

Classical PPT setup produces exact n-bit secret K and complete classical public P, including context, checking key and programs. An arbitrary side-information preparer may leave the adversary ONE copy of quantum E jointly correlated with K,P. Choose fresh uniform r in GF(2)^n independent of K,P,E. Define H=<r,K> mod 2. Let p_guess(K|P,E) be the optimal single-copy exact-K POVM guessing probability, even if optimal measurement is computationally inefficient. The quantum leftover hash lemma, two-universal hash case, gives

D = (1/2)||rho_{H,r,P,E} - U_1 tensor rho_{r,P,E}||_1 <= (1/2) sqrt(2 p_guess(K|P,E)).

A single-copy parity predictor with advantage epsilon implies p_guess >= 2 epsilon^2. An IND raw distinguishing gap delta between c_m=m XOR H for m=0 versus 1 implies p_guess >= delta^2/2. Thus the one-copy quantum-advice gap left by Run 472 is NOT an information-theoretic loophole: large bit advantage forces a nonnegligible optimal exact-key guessing probability, even for non-reproducible advice. **It remains a COMPUTATIONAL gap:** no QPT algorithm implementing that optimal POVM follows from this inequality. No advice cloning, rewinding or QROM programming is assumed. If E contains K, p_guess=1 and no hiding follows.

Proof basis: Tomamichel, Schaffner, Smith and Renner, Leftover Hashing Against Quantum Side Information, IEEE TIT 57(8), 2011, Theorem 6 and operational conditional min-entropy; https://staff.science.uva.nl/c.schaffner/mypapers/TSSR11.pdf . Original theorem/proof, including collision-entropy steps, were inspected. This is an application of EXISTING theory, not a new quantum algorithm or positive WKEM construction.

## Result B: same-key multi-mask known-plaintext attack

If q ciphertexts c_i=m_i XOR <r_i,K> expose independent uniform public r_i under ONE retained signing secret K and the m_i are known or chosen, the attacker computes b_i=c_i XOR m_i and solves the linear equations A K=b over GF(2). For q>=n the exact full-rank success probability is product_{j=0}^{n-1}(1-2^(j-q)); failure < (2^n-1)2^(-q) < 2^(-(q-n)). With q=n+128 recovery fails with probability < 2^-128. Complexity O(q n^2) bit operations, entirely classical. If K is the actual authorized native signing secret, this exposes authorization without an ORIGINAL witness.

This does **not** invalidate the strictly single-ciphertext fresh-CapGen one-bit WE conversion of Run 472; a fresh key per call defeats this particular linear system. Nor is this an attack on the original bridge unless it actually exposes repeated known-message linear masks under one K. Unknown independently random message bits do not supply the equations. Domain separation cannot rescue the same recovered signing key.

## Checker and scope

The exact JavaScript checker computes two-by-two quantum density-block trace distances for K=(U,V), where U contains t independent uniform unknown bits, and one qubit E encodes V using nonorthogonal states |0> and c|0>+sqrt(1-c^2)|1>. It verifies the analytical p_guess and D=p_guess/2 for c in {0,0.6,1}, t in {0,1,2,3}. It also exhaustively counts full-rank binary matrices for n=1,2,3 and q=n,n+1,n+2, comparing the closed rank formula. The independent longer Python checker with 114 assertions is preserved locally. These are finite identities, not practical parameters, a QPT security proof, or quantum-hardware execution.

Attack taxonomy: multi-capsule reuse (4), chosen-known public evaluation (5), complete checking-key/auxiliary view (8), genuine quantum single-copy side information (9); malicious retention (6) makes entropy collapse. No seam/gauge/statistical source attack (1–3) or cross-UTXO replay theorem (7) is claimed. No new local-mixing assumption.

**Unresolved:** a practical public late-ORIGINAL-witness admission/release gadget; all-witness SAME native key; full-public false-instance QPT hiding; arbitrary native authorization -> accepted complete source representation; Run 259's downstream extraction interface; malicious N-of-N setup/abort, multiple capsules, 128-bit costs and conditional native-SLH/P2MR. Neither result makes a practical PQ witness-KEM. PR draft/unmerged; production unchanged; automation remains enabled.
