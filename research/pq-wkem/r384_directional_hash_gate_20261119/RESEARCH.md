# R384 — Directional hash-capability graph: a bounded source-gate screening (NONQUALIFYING)

## Provenance and question
Started from the actual open draft PR #1 branch research/pq-wkem-validation-20260918 at f7148a3051d9555ece9120888639df6d22213df4, R383, note blob 03228b96b57b4a7594135de856fd684302c1bc88. New ordinary comments since Nov 18: none. No Core source reread or source network tests, no external web. Only research paths are written.

R366's commutative finite-cover leak suggests testing noncommutative source-state factors. R383 rejects field interpolation from arbitrary unauthenticated points. This attempt changes the *cryptographic operation*, using one-way directed hash-encrypted key transfers instead of invertible path products. One complete accepted path should give the SAME frozen capability S without a canonical witness.

## Failed invertible noncommutative gate
Let G_v be independently hidden invertible elements of a NONCOMMUTATIVE group; publish M_(u,v)=G_u^(-1)G_v per directed edge. In the directed graph r->a, c->a, c->t, no directed root-to-target path exists. Yet public matrices reveal
 M_(r,a) * M_(c,a)^(-1) * M_(c,t)
 = G_a * (G_c^(-1)G_a)^(-1) * G_c^(-1)G_t
 = G_t,
without commutation. This undirected zig-zag attacks the noncommutative repair even though no accepted directed path exists. The checker verified this using genuinely noncommuting GL(2,F_101) matrices.

## Directional hash-only transfer
For an EXPLICIT finite directed acyclic graph G=(V,E), source r, terminal t and sid, Build samples independent 256-bit state labels k_v. For each directed edge e=(u,v) it publishes
 C_e = k_v XOR SHA256("edge" || sid || edge_id || k_u).
It publishes k_r and a fixed-payload ciphertext
 D = S XOR SHA256("out" || sid || k_t).
Open supplies a complete accepted DIRECTED path and repeatedly decrypts the next state label using the current one, finally decrypting D. This is a fully serialized hash-only construction for an explicit graph. By induction along the path, every accepted path opens the same S. The inverse of an edge is not supplied. The graph itself must represent the exact source relation before any path can be called an ORIGINAL certificate.

### Joint-public security obligation, NOT a theorem for SHA or QPT
On a FALSE graph let R be nodes reachable from r and U=V\R. No edge from R enters U. Under an *already-replaced independent random-pad hybrid*, every public edge ciphertext with tail in U is uniform and simulatable, including edges into R where the head label is known. Target t in U remains hidden, so terminal D can be simulated uniformly. This is only an exact hybrid distribution identity; no reduction for concrete SHA, coherent QROM queries, sibling capsules, source-authenticated states, or malicious setup has been supplied. No independent QPT theorem is claimed.

### Hard-TRUE and practical source obstruction
If G is polynomial-size explicit, anyone can BFS from r and recover all reachable labels and an accepted r-to-t path in O(|V|+|E|). The resulting path must encode an ACTUAL original certificate, or the gate is irrelevant. Authentic future Bitcoin/Syscoin source histories, coinbase/target/contextual checks, and all three OR grounds are not an explicit polynomial graph.

For a fixed n-bit toy header suffix and a SHA256d difficulty predicate, a literal prefix-state graph needs 2^(n+1)-1 prefix nodes plus terminal, ~2^(n+1) edge ciphertexts, and 2^n builder-side SHA checks; this enumerates possible future certificates. It is not practical at original work security. The executed n=10, 7-bit toy predicate enumerated 1,024 candidate strings, four accepting leaves, 2,048 total nodes and at least 2,050 edge ciphertexts. These are SYNTHETIC hashes, not qualified original source certificates.

A related ideal random-function explicit-state calculation: split input into a prefix of a bits and suffix of b bits, with target fraction p=2^-d. Each prefix's residual acceptance vector has 2^b independent Bernoulli(p) entries. Two prefixes share the same vector with probability (p^2+(1-p)^2)^(2^b); union-bound any equality by binom(2^a,2) times this value. When negligible, exact deterministic finite-state recognition needs >=2^a distinct prefix states. This is limited to the stated explicit-DFA/random-function model, NOT an impossibility proof for succinct protected programs or concrete SHA.

The missing algorithm is precisely a polynomial-size SERIALIZED transition compiler that authenticates ORIGINAL SHA/AuxPoW source-state transitions and returns secret next labels only in valid, mutually consistent source histories. Publishing the hidden state key seed trivially leaks S; retaining the seed in a private evaluator is unimplemented FE/WE. Do not revisit explicit full-state graphs, interpolation, relabeling, hash placement or parameter optimization as advances.

## Actually executed local checker
Python3 standard library check.py ran twice with byte-identical outputs. It checked the false noncommutative zig-zag, correct directed hash edge path release and enumerated the finite SHA256d nonce toy. checker SHA256 0358acda7cd8977f40e393b20a79f555c9e2f532ef7f3677d459098158869bf9; both JSON outputs SHA256 fae303e77c255af696dbe501fbba1b55c3f3b8752ae20d784bfe0e043bf20d63. Local-only complete archive R384_directional_hash_gate_20261119.tar.gz SHA256 2f94bddfbc4322536ab1e7a6891bb20d6c636e58c0061b5f6e0080137181aa4f. The checker uses reproducible PUBLIC synthetic seeds. Its success is not proof of hiding or original-source work bounds.

## Outcome / next exact equation
NONQUALIFYING. The one-way directional encoding repairs invertible reverse-edge leakage for an explicit-state model, but requires exponential original-source enumeration, and no concrete SHA/QROM simulation is proved. The REAL classical-PPT Build_orig(x_W,S)->C and public Open_orig(C,w)=S for every ORIGINAL qualified BTC-greater, burn-fault or Syscoin inconsistency/tag-fault witness remain missing, as do full-public FALSE/hard-TRUE QPT extraction or native-forgery reduction, malicious N-of-N setup/auxiliary/sibling composition, source authenticity and native claim binding. A practical first-release Bitcoin ECDSA endpoint is classical, not QPT-secure. No progress comment, production change, deployment or automation change was made.
