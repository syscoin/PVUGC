# Source-path weighted automaton — full-public extraction screen (NONQUALIFYING)

## Continuity and exact new candidate
Started from open/draft syscoin/PVUGC PR #1 on research/pq-wkem-validation-20260918 at `1bb63568354254fa9e3acef6a65c1ae0943b1bde` (2026-11-22), current note research/pq-wkem/r_nilpotent_global_gate_20261122/RESEARCH.md blob `0974f905ab3410e993edd770bfc81036e3cab7d0`. Also read the directly preceding global-projector note blob `30a363a66716fe7bf00b1003398f56a572fa2318`. The issue's top-level comment search since 2026-11-18T19:24Z returned no new comments. No Core source, external site, or unrelated repository was read. This is ONE resource-bounded construction-and-repair test of the exact missing step from the nilpotent globally correlated boundary family.

R_nilpotent made the secret scalar statistically invisible in an unconstrained nilpotent conjugacy class, including TRUE, but could only open it by publishing a witness-specific K-correlated boundary gauge. Explicitly enumerating all 2^n full assignments was exponentially large. This run tries to replace the exponential global index with a compact deterministic path-state machine while keeping every-witness same-output correctness and preventing local per-clause splice: the *same word* drives every transition along one path.

## Candidate public weighted state-machine compiler (not a release solution)
Assume an exact finite-state verifier of the approved ORIGINAL relation over an ℓ-symbol witness w, with s states and transition matrices T_(j,b) over a prime field F_q for each step j and symbol b. Let e_start be the initial row and e_accept the terminal column, such that

    e_start T_(1,w1) ... T_(ell,well) e_accept = R_x(w) in {0,1}.

This assumption is NOT a verified small-space representation of SHA256d/AuxPoW. Actual exact ORIGINAL relation is the OR of qualified greater BTC work, finite authenticated particular-burn refutation, and qualified incompatible Syscoin histories/tag fault at LC depth, with all chain/claim/native-cancellation binding. Nothing here changes those branches or the activated contextual AuxPoW requirements.

Choose independent invertible gauge matrices G_0,...,G_ell. Let K be a nonzero scalar, S the scalar payload, and publish

    A_(j,b) = G_(j-1)^(-1) T_(j,b) G_j,
    L = K e_start G_0,  R = G_ell^(-1) e_accept,  D = S K.

Then the public scalar evaluation is

    P_C(w) = L A_(1,w1)... A_(ell,well) R = K R_x(w).

A prescribed Open on ANY satisfying whole word w returns D/P_C(w) = S. Every accepted original word would use the SAME K, with no canonical witness. Invalid whole words return zero; unlike independent local gate factors, a path is one globally selected string. Build has O(ell s^2) published field elements and classical polynomial time IF the exact T matrices and gauges can be constructed in polynomial time and s is polynomial.

**This is a substantive algebraic compression idea, not an actual source-specific compiler:** no polynomial-width DFA/weighted automaton is constructed for full SHA256/AuxPoW and no native signature is encoded. More importantly, the completely PUBLIC matrix representation has the following decisive extraction behavior.

## Exact full-public witness-finding theorem: random gauges do not conceal paths
Let an arbitrary adversary obtain ONLY L, R and every A_(j,b), not any G_j, T_(j,b), internal source tables, private coins, or a representation supplied by an attacker. It need not know K. For fixed symbol set {0,1}, define suffix vector spaces:

    U_ell = span{ R },
    U_(j-1) = span{ A_(j,0) v, A_(j,1) v : v in a basis of U_j }.

Each U_j has dimension <=s, and all bases can be computed by Gaussian elimination in polynomial time O(ell s^4) field operations (a conservative bound). The existence of any accepted word is EQUIVALENT to L having nonzero inner product with some vector of U_0.

If that pairing is nonzero, set current row h_0=L. At step j choose a bit b such that

    exists v in basis(U_j): (h_(j-1) A_(j,b)) dot v != 0,

and put h_j=h_(j-1) A_(j,b). At least one choice exists by the defining span recurrence. After ell steps, h_ell R != 0. The resulting *explicit word* satisfies R_x(w)=1 whenever the program is correct. This is deterministic, classical, polynomial-time, and uses the **complete public matrices and boundaries only**. It needs no oracle queries to SHA during extraction. The attack is a QPT attack as a special case of QPT, and is insensitive to all local GL gauge choices.

In other words: an explicit polynomial-width publicly readable matrix program with scalar nonzero iff a qualifying certificate exists gives an ORIGINAL witness finder, not merely a restricted decoder. If the source relation remains hard to satisfy, this candidate cannot simultaneously be a practical classical compiler, publish all transitions, and preserve its claimed semantics. This does not prove any general hash-only FE/WE impossibility, or rule out obfuscated nonlinear source encodings.

## Random-oracle resource calculation for the simplified PoW slice
For a pure (n)-bit nonce slice with M=2^n possible queries and an independent random-oracle predicate accepting with p=2^(-d), let the classical honest compiler query the oracle at most q_B times and output the above public automaton with correct acceptance semantics except probability delta. The public span extractor uses no oracle queries and makes one oracle query to verify the recovered nonce. Since a valid nonce exists with probability 1-(1-p)^M, the combined algorithm's success probability is at least 1-(1-p)^M-delta. By the adaptive union bound for independent random-oracle results, it is at most (q_B+1)p. Therefore

    q_B >= [1-(1-2^(-d))^M-delta] 2^d - 1.

Thus for M >> 2^d and small delta an exact polynomial-width public automaton would force essentially the ordinary expected ~2^d hash work into Build, *before the challenge exists*. The reduction assumes a black-box random oracle and finite nonce slice; it is NOT a statement about concrete SHA shortcuts, current Bitcoin difficulty, qualified Bitcoin-best-chain evidence, or all three original OR branches. Any source-copying or precomputed/retained source coins must also be included in a bridge-specific attack experiment.

## Actual finite tests and what they establish
A Python3 standard-library exhaustive builder and DAG minimizer was run twice on SHA256d of a fixed synthetic prefix and 10/12/14/16-bit nonce fields with 7/8/10/12 leading-zero bits. The minimized public accept automata used respectively 50/114/136/155 states, despite the builder performing 1,024/4,096/16,384/65,536 SHA256d evaluations. Once published, graph search yielded valid nonces with a single verifying hash. This demonstrates work relocation rather than practical compiler speedup.

A second independently executed script constructed full field-matrix automata with dense randomized invertible gauge changes for 6/8 nonce-bit fixtures, then passed ONLY the published matrices and boundary vectors to a suffix-span extractor. It recovered a valid SHA256d-short-nonce witness with **zero hash calls before extraction** and evaluated the same scalar K=41 for the accepted word. No hidden gauge, plaintext DFA, hash oracle, or known witness was provided to the extractor. Two runs produced byte-identical outputs.

Executed script hashes:
- `check.py` SHA256 `97da53a491d8b422377136edb6a2b7e1460630585812b4c6bbd9268b09a9870c`.
- `output1.json`, `output2.json` SHA256 `4048f33a9abcd68cd7280c7871b06882b6b9c28b879337eebad695d2efd83ad6`.
- `check_gauge.py` SHA256 `d0d2d03334b9bfea332dd587e597796dcdaca20785308858f1e542d49fbea0`.
- `gauge_output1.json`, `gauge_output2.json` SHA256 `bcbc1a62eba70f76daf8dde63b3c1a361795e03d75d98402f1479082aa365dd8`.
- LOCAL-ONLY tar archive `/mnt/data/R_source_weighted_DFA_20261122.tar.gz`, SHA256 `d9b20d861f12035714f91b976fc6614019fbc20242edbff439a27005bfa9b0ed`.

The scripts did not read actual Bitcoin/Syscoin blocks, contextual work/retarget/coinbase/authenticated source commitment, native signatures, or the original claim/UTXO. They do not implement FE, KEM, malicious setup or a quantum security proof. The generated tests are **synthetic** and the archive remains local-only; do not assume sandbox persists in another execution.

## Attempted repair and exact unfinished equation
Concealing the state transition matrices so the public suffix-space algorithm cannot run is a genuine different interface, but this iteration supplied **no independently instantiated hash-only hidden-transition evaluator**. Merely replacing public matrices with a named private SourceOpen, FE functional key, cryptographic iO, online source signer, or an opaque oracle would reintroduce exactly the missing primitive. Publishing scalar local gate pieces reintroduces earlier mixing/finite-cover attacks. A candidate must instead provide actual polynomial serialized Build/Open and jointly simulated public bytes, allowing each qualifying original source certificate to recover the same safe capability while making every successful unauthorized native cancellation yield an actual original certificate or independently justified cryptographic break.

A separate joint-public FALSE and hard-TRUE simulator for this public matrix scheme is **not** established. Its hard-TRUE source-work property has already failed from the exact public witness extractor, so independent FALSE hiding would not rescue it.

**NONQUALIFYING.** No source-dependent hash-only public release foundation, practical original verifier in the gate, independent QPT reduction, malicious N-of-N setup, or BTC native cancellation was delivered. This checkpoint is not a breakthrough notification. No PR comment, Core/production edit, deployment, transfer, or automation change. Continue from the missing hidden-global transition operation only if a concrete implementable new mechanism bypasses the public-span extraction; do not run another basis/gauge/degree variant.
