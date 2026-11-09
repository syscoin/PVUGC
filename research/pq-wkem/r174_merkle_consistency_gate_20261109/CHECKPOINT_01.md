# R174 — Merkle-authenticated witness consistency, checkpoint before full source-coupled release test

Status: intermediate research only; NO practical hash-only WKEM, no source-bound release, no QPT security. This checkpoint records an explicit hypothesis for improving the actual cryptographic source-evidence compiler and its falsification plan, not a progress PR comment.

## Exact continuity
syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918, current start HEAD 44032a05e4362e5831a24084c6154c3266c58988 (open/draft/unmerged). Read R173 source-retained-key equivocation research, Git blob 24810e09dd09d3670c0be2bc687783081a66a6b5; R172 full verifier-state lower bound and R170 oracle-transplant theorem were checked by exact ref. R173 source signer knows both label families, thus early source-equivocation release or online honest signer is unresolved. R172 explicit read-twice DFA needs 2^n states; this is NOT a lower bound on all hash-authenticated dynamic witness consistency checks.

## New SHA/Merkle consistency gate (partial component)
A prospective ORIGINAL witness w has a canonical fixed-length bit encoding. At first use, a public evaluator binds to rho=MerkleRoot(H_leaf(i,w_i)) using domain separated full SHA256. Each later repeated use of bit i supplies (b,pi) and verifies MerkleVerify(rho,i,b,pi). Under hash collision resistance, two conflicting bits for the same (rho,i) cannot BOTH verify without a collision in a leaf/internal Merkle node. This stores a 256-bit rho and processes O(log |w|) hashes/read, instead of enumerating the 2^n full prefix-state graph in R172. Distinct valid witnesses legitimately use distinct rho. Full source evidence bits may include complete AuxPoW/coinbase/ancestor/interval proof; this gate is merely commitment consistency and NOT source-history or Bitcoin canonical-chain authentication.

## Integrated release hypotheses to test
H1: select one hidden terminal-pad index rho0 at Build, publish D=sigma XOR H_mask(rho0). Open using authenticated rho derives the same frozen sigma for EVERY ORIGINAL-valid w. Expected failure on any second valid witness with rho!=rho0.
H2: replace rho with public zero residual vector of original verifier constraints so all valid witnesses share H_mask(0). Expected raw-public bypass, with no witness or SOURCE evidence.
H3: use common public Syscoin ancestor/anchor as pad input. Expected raw-public bypass.
H4: publish per-root corrections for every satisfying witness; expected correctness only with exponential Build in general.
H5: attempt a genuinely new **cryptographic** root-to-common-secret correlation, neither table enumeration, publicly readable acceptance gadget, private online issuer, programmable token oracle, raw PoW puzzle, nor an assumed public constrained PRF. This is the OPEN construction problem.

## Proof and experiment scope
Check H1-H4 with actual SHA256 Merkle paths and small CNF; tests do not establish SHA QPT collision hardness. For H5 demand a polynomial-time Build(x,frozen sigma) and PublicOpen(C,w) with same sigma for every ORIGINAL w, while any raw unauthorized QPT recovery yields a FULL ORIGINAL witness or independently justified quantum hash break. Explicitly include checking-key/native-VK/related-capsule correlations. If H5 remains missing, record failures without claiming a breakthrough. Distinguish semantic OutcomeID from WorkID; neither parent-work nonce nor root inclusion proves canonical source membership.

No full PR diff, unrelated Github, web/literature, lattice, groups, online release authority, production changes, or invented experiments.
