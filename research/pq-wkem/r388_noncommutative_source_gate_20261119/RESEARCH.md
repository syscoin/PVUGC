# R388 — Noncommutative whole-trace release candidate and public occurrence attack (NONQUALIFYING)

## Live continuity and candidate selection

Read current open draft syscoin/PVUGC#1 at head e0275fd14e2847b4357773c4b5c3035e74c54987, branch research/pq-wkem-validation-20260918, tree 4629b54c87d2a20f808053c092c6079bf2fb33b0. Read its latest R387 note, blob 74977b3e127f9b1ea567f1cb5c0ebedf07189046, and saw no ordinary comments since 2026-11-18T19:24Z. The R387 sender-unknown source-root transport is still unconstructed. No Core source, Bitcoin network or original source certificate was consulted in this algebra-only step.

**Explicit candidate**: a completely serialized, public, noncommutative finite-state gate, with the same hidden terminal value for all accepting global witness assignments. The change from R366 is replacing commutative scalar copy-gauges (which leaked through finite covers) with independently conjugated noncommutative transition matrices. Check the full-public distribution, not just prescribed Open. Because the global occurrence-switching regression was already known, the very first test is whether independent locally allowed branch choices can recover the terminal group element without a globally consistent witness. This candidate is rejected; it is not a solved hash-only FE.

## Candidate Build/Open and exact public algebra

For a Boolean source-checking formula with a group-branching program, let G_{j,b} be permutations (or invertible group elements) attached to program occurrence j and bit b. The compiler has a public target word g_* formed from base generator instructions. A consistent global witness w selects the bit for every occurrence of the same variable and yields

    G(w) = product_{j=1}^L G_{j,w_var(j)} = g_* if R_x(w)=1; e otherwise.

This is a *restricted formula/branching-program premise*, not a proven compilation of full variable-length original Bitcoin/Syscoin certificate checking into a practical size. In particular no SHA/AuxPoW circuit was constructed here.

Setup samples random independently invertible frames U_0,...,U_{L-1}, sets U_L=U_0, and publishes BOTH branch matrices

    M_{j,b} = U_{j-1}^{-1} G_{j,b} U_j.

It also computes k=SHA256(serialize(U_0^{-1} g_* U_0)) and D=S XOR k, then publishes (all M_{j,b},D,context). Prescribed public Open evaluates the branch product chosen by one fully consistent witness w, hashes the final permutation and XORs D. Every accepting witness gets S because all valid products telescope to U_0^{-1}g_*U_0. This uses a public SHA digest only as final pad; the source predicate still needs to be cryptographically enforced.

### Public extraction without any ORIGINAL witness

Assume for each occurrence j a *locally* selectable branch b_j has G_{j,b_j}=e. These choices need not correspond to a common global variable assignment. Define the public baseline prefix

    B_i = product_{j=1}^i M_{j,b_j} = U_0^{-1} U_i.

Then the fully public quantity

    V_{j,b}=B_{j-1} M_{j,b} M_{j,b_j}^{-1} B_{j-1}^{-1}
           =U_0^{-1}G_{j,b}U_0.

Since the target g_* is a known word W in the original instruction generators, everyone can evaluate that SAME word on public V's:

    V_* = W({V_{j,b}}) = U_0^{-1} g_* U_0.

Consequently

    S = D XOR SHA256(serialize(V_*))

is obtained *without* a consistent global assignment, accepted source certificate, or hidden frame U_0. This is a deterministic classical, polynomial-size operation for a polynomial-length target word. Noncommutativity, large permutation width, the private frames and SHA preimage resistance do not address it. It immediately breaks full-public FALSE secrecy and hard-TRUE early release in this construction, hence any QPT security claim as well.

One concrete branch-program counterexample uses x AND NOT x. With noncommuting permutations a,b, the four occurrences select (e,a), (b,e), (e,a^-1), (b^-1,e). Both actual assignments x=0 and x=1 multiply to identity. The independently selected sequence (1,0,1,0), which is NOT one global assignment, instead multiplies to the nontrivial commutator g_* = a b a^-1 b^-1. It recovers the pad. The public baseline can also recover the conjugate via V_{1,1} V_{2,0} V_{1,1}^{-1} V_{2,0}^{-1}. This is a noncommutative analogue of the prior global-occurrence-switching regression, not a new generic WE impossibility.

The FALSE joint public simulator is impossible for this proposed capsule because an adversary simply computes V_* from its published matrices and tests D XOR H(V_*) against the native verification key (or distinguishes known challenge payloads). No random-oracle programming, native forgery or witness extraction is involved.

## Attempted structural repair: one global source-conditioned input label

To prevent inconsistent per-occurrence choices, the compiler would need to deliver ONE hidden, consistent choice per variable, shared across all occurrences. A natural proposal is to bind labels to a full ORIGINAL witness digest t(w)=SHA256(sid||Serialize(w)), with labels L_{v,b}(w) for each variable bit. Two concrete hash-only interfaces fail:

* L_{v,b}(w)=SHA256(sid||t(w)||v||b) is computable for BOTH b and for arbitrary synthetically selected w, so independent occurrence switching is still available; authenticity is an optional external if-check.
* L_{v,b}(w)=SHA256(kappa||t(w)||v||b) with a hidden kappa prevents the above computation but Build cannot prepare all future source-witness-dependent wrapped labels, and public Open cannot evaluate them. Publishing kappa restores the attack. A protected evaluator for kappa is FE/obfuscation, not a concrete hash-only serialization.

A hash-only scheme must thus replace these labels with *actual* source-authenticated, globally coherent, nonspliceable hidden delivery, built as a public classical-PPT artifact and reduced to obtaining qualifying original evidence. Neither a group program nor a hash of the global witness does this. Do not iterate other permutation widths, hash choices, scalar orders or larger synthetic formulas without a new reason the public generator-word extraction is invalid.

## Actual bounded checker and limits

A standard-library Python3 script check.py was executed, then run again to capture output.json, both successful. The script uses deterministic public test permutations in S_9, four instructions, x AND NOT x as FALSE, and x AND y as a TRUE control; it confirms every consistent false input rejects, independently inconsistent instructions recover the target/key, and the true control behaves as expected. This is an algebra/code sanity check, **not an actual authenticated AuxPoW/Syscoin certificate, a full SHA256 Boolean circuit, a Bitcoin native signature, FE, or a QPT test**.

check.py SHA256 5ff295a3721b10fc42925871c145607428c288c9ec9392a59fe2ee18deaae5b3; Git blob 7d65daa80ce7e52e925c6f3e7b3ae7b0a2ade119.
output.json SHA256 754d5b7b51afd75ec9977080b5b415ceb4df6a4c6d1f5a8acbb822bb9007ee64; Git blob 647041b0cbae5baefac11ada20d40d1d1999b6a7.
Both are included in this research-only checkpoint.

The full ORIGINAL goal remains classical-PPT Build_inc(x_W,S)->C, public Open_inc(C,w)=S for every qualifying original OR witness, with complete-public FALSE/hard-TRUE QPT recovery-to-ORIGINAL or independent hash/native break, malicious setup, source-coin retention, sibling capsules, and actual source/claim/UTXO/LC depth/deadline/activation binding. This iteration implements NONE of that foundation. No publication is a cryptographic progress claim. No user notification, PR comment, Core/production modification, deployment, automation or transfer is authorized by this checkpoint.
