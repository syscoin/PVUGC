# Hash-only ORIGINAL compiler attempt: clause-occurrence cancellation, intermediate checkpoint

**Status:** Candidate tested; not a secure hash-only witness-KEM. No breakthrough claimed. This experiment tests a polynomial-size *source-dependent* mask correlation for generic 3SAT witnesses (an NP-complete verifier subrelation), not an independent PoW puzzle. The resulting public correlation is attacked below. No lattice, DLog, online secret issuer, optimized restricted LWE credentials, or external search.

## Exact candidate

For 3CNF instance x with m clauses and n witness bits, honest pre-funding setup chooses independent random k-bit clause secrets s_j and for every occurrence (j,i) two random k-bit one-time pads r_{j,i,0}, r_{j,i,1}; define the SAME intended frozen secret K = XOR_j s_j. This K may mask an already frozen native-path signature sigma; the byte/claim/VK context must be domain-bound but is not material to this first algebraic test.

For each clause j and locally satisfying tuple a of its literals, publish

    A[j,a] = s_j XOR (XOR_{i in clause j} r[j,i,a_i]).

For each variable i and bit b publish the consistency correction

    B[i,b] = XOR_{j: i occurs in j} r[j,i,b].

Honest Open with an ORIGINAL globally satisfying assignment w computes

    K' = (XOR_j A[j,w|clause_j]) XOR (XOR_i B[i,w_i])

and gets exactly K, independent of which satisfying w. This requires only O(7m+2n) k-bit public words, and setup is classical polynomial. All pads remain unlisted individually. The intended candidate was to force conflicting local bit choices to leave uncanceled pads, so the key would require a consistent ORIGINAL witness. Hashing K' and masking the native signature adds checking but cannot change public linear disclosure.

## Executed exact attacker

A new local Python standard-library checker models every public table word as a linear form in hidden s_j and r_{j,i,b}, and performs GF(2) row-span extraction of the target vector representing K, **without providing any satisfying assignment**. It verifies honest completeness for each enumerated satisfying assignment. In a deterministic 256-formula fixture (n=2..5, n+2 clauses each), all 253 true and three false formula instances exposed K as a public XOR of table entries; examples included x with no satisfying witness. 2,071 assertions passed across the four named examples and those 256 formulas. This does **not** establish a statistical security theorem for arbitrary formulas, or any native Bitcoin/GitHub/CUDA/QPT test.

Source SHA256 a2e634cf519716a4cdbcb4f9bd0c04304456063fad8d0300ae859ee22b089643; captured stdout SHA256 f2ec544c640b274b92d84ad6da417752246fc2f2b3a8dfc6e26c2fa12af9889a. No independent verifier run. Raw source/output currently local; subsequent complete checkpoint should include the exact files.

## Next exact repair, not yet claimed

For any width-d clause, test whether the unsatisfying tuple's public *virtual* table entry can be reconstructed via XOR of the 2^d-1 satisfying tuple entries, under masks of Boolean algebraic degree <d. If so, choosing one global baseline assignment and all corresponding virtual clause rows plus B variable corrections extracts K, even when the baseline violates the original relation and the 3CNF is FALSE. Try full-degree clause-local hash interaction and test whether preserving every-witness same-key recovery forces an additional public correction which simply restores the leak. Distinguish this class from arbitrary nonlinear public-output QPT attacks.

Missing release algorithm remains generic-PPT Build_hash(R_ORIGINAL,x,sigma) / Open_hash(C,w) that yields the same precommitted sigma for every genuine ORIGINAL certificate yet does not expose it for a FALSE or source-unqualified certificate. PoW authentication must be inside release, not post-hoc verification; no online issuer, Merkle commitment alone or future-work magic key is assumed.
