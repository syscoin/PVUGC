# R156 — Gate-local one-hot ORIGINAL release; false-source key bypass

STATUS: REJECTED. One bounded offline construction+repair attempt, NOT a secure generic witness-KEM, QPT proof, performance optimization, or a new general no-go theorem. Expanding local Boolean gate representations does not defeat the affine fractional attack once a publicly projectable phase remains. This direction is stopped.

Continuity: syscoin/PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, observed initial head ea55de450f71d61f2f9b51b78adf2d1f43f53198 (R155). Latest substantive ordinary PR comment 6718361572 (R153). R155 exact note blob fe6369d3de7f6c38c2223f76da7a6f5bdc7f70df was read. No external internet or literature.

## Concrete candidate and exact distributions

Restrict the ORIGINAL relation to 2-XOR parity gates; failing a subclass fails a generic-NP release. Bind the instance x to relation identity, actual claim/UTXO, branch, anchor/window, context and intended native VK; fresh independent capsule coins. For a ring of m parity gates g=(u,v,b_g), create local truth-row indicators lambda_(g,0), lambda_(g,1), and shared wire values y_i. The two permitted row tuples are (a,a XOR b_g), a in {0,1}. Form an integer matrix M_x and public RHS b_x with for each gate:
(1) lambda_(g,0)+lambda_(g,1)=1;
(2) lambda_(g,1)-y_u=0;
(3) b_g*lambda_(g,0)+(1-b_g)*lambda_(g,1)-y_v=0.

The vector z has dimension 3m; M_x has 3m rows. A satisfying ORIGINAL Boolean assignment yields z_w with one hot row per gate, M_x z_w=b_x, ||z_w||_1<=2m. Distinct valid witnesses may yield distinct internal z_w.

Choose q=65521, Delta=4096, K uniformly in {0,1}, independent r uniformly in Z_q^(3m), independent e_i,e0 uniformly in integers [-3,3]. Publish:
  c = M_x^T r + e (mod q);
  t = b_x^T r + Delta*K + e0 (mod q).
Open with an ORIGINAL valid witness computes t-<c,z_w> = Delta*K + e0-<e,z_w> (mod q), hence nearest-phase K exactly whenever |e0-<e,z_w>|<Delta/2. In tested m<=9, the deterministic bound 3(1+2m)<=57 proves every-valid-witness SAME-capability correctness. For a multi-bit pad, use independent corresponding phases and then release the same frozen claim/path-bound native signature; failure of a single pad bit already refutes the source. Honest generation/evaluation are classical PPT.

Full public output includes relation/statement, M_x,b_x,c,t, claim/UTXO/branch/anchors/window, native VK, checker J/CK, auxiliary fields, N-of-N graph, context and sibling capsules; any additional independently generated public fields or deterministic functions of the actual bytes cannot hide K already computable from c,t. The candidate has no independent QPT-LWE security proof: M_x is a structured x-dependent matrix, not a uniform LWE matrix; calling this an LWE-style syndrome is not an ordinary QPT-LWE reduction.

## Universal local-marginal attack for parity gates

For ANY 2-XOR instance (including FALSE), set lambda_(g,0)=lambda_(g,1)=1/2 and all y_i=1/2. These locally consistent marginals solve the entire *real rational* affine system M_x z_half=b_x. Their squared L2 norm is 3m/4 for m gates and m wires, smaller than any integral one-hot norm >=m. Such marginals are not ORIGINAL Boolean witnesses.

The attacker does not need a fractional modular representation or to submit a representation to a verifier. Multiply by two: z2=2z_half is the PUBLIC all-one INTEGER vector, and M_x z2=2b_x. The released bytes give directly
  2t-<c,z2> = 2 Delta K + 2e0 - <e,z2> (mod q).
For any allowed honest noise tape, |2e0-<e,z2>|<=3(2+3m)<=87 for m<=9. Since 2 Delta=8192 and q=65521, nearest phase recovers K unambiguously. On an odd ring with one XOR=1 and the remaining XOR=0, XORing the equations yields 0=1, so there is NO ORIGINAL witness, yet this public classical attack outputs the exact K on every noise tape.

This breaks fixed-FALSE hiding, including the entire full-public output, and applies to arbitrary QPT adversaries (classical algorithms are a subset). It is a direct phase attack and does not require the R155 same-pp known-key sampler. The R153 statistical NP-in-SZK observation is not needed either. It does not attack general LWE, generic witness encryption, or a genuinely nonlinear public release distribution.

Requiring a Boolean/short representation INSIDE legitimate Open does not fix a publicly linear c,t: an adversary evaluates the phase directly without running Open. Nor can a public nonlinear term added only to Open, e.g. sum_i(z_i^2-z_i), remove that direct projection. A genuine repair must alter the source distribution, not merely a checker or a threshold.

## Executed checker, provenance, next step

Exact separately published checker.py was executed locally with Python standard library and fixed seed 15620261108. It exhaustively checks SAT assignments and original parity equations for m=3,5,7,9 with SAT and UNSAT variants, checks the exact rational 1/2 solution, publishes genuine sampled (c,t) and computes the attack using no r/e/K knowledge. 8,240 assertions passed, including 1,024/1,024 FALSE ciphertext recoveries; a second execution reproduced byte-identical captured output.json. All checks are functional finite evidence, NOT quantum experiments. Local SHA-256: checker.py 1a3dfb9b9ed9601e2339f433f6c76e15568d15b88c57449ebec8affa03ed19dd; output.json 1119b3c0467fe08a509aa8e2232d410af1f3040eb4e0fec8118c1ae6c1b12cbb.

The next required construction is a nonlinearly secured, classical-PPT arbitrary-ORIGINAL-NP-dependent *source distribution*, with jointly instantiated actual LWE keys/openings/challenge simulator for the FULL public J/CK/Aux/context/multi-capsule/selective-opening quantum-advice view. The exact obligation is every w with R_ORIGINAL(x,w)=1 opens SAME frozen capability, while arbitrary unauthorized QPT recovery of that capability or accepted native forgery yields an actual ORIGINAL witness or a concrete independently justified QPT assumption break; no SourceOpen oracle or adversary-volunteered representation. FALSE output security, hard-TRUE extraction, malicious N-of-N setup/abort/erasure, pre-funding DA and conditional Bitcoin native PQ endpoint remain unresolved. No optimization or deployment.
