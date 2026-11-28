# Run 514 — conjugacy-invariant terminal fingerprints

Research only, 2026-10-14 UTC. Draft syscoin/PVUGC#1, branch research/pq-wkem-validation-20260918, starting SHA 2a8f1ba16c0610fa38c44fc205e5681f72bf76c2. Scoped new falsifier of direct random-circuit/PRP modeling, NOT a break of WE-like key release, not a secure WKEM.

## Theorem

For the Run-512 terminal B_i(u,z,t)=(u,z,t XOR ((u_i XOR delta_i) AND f_x(z))), with h-bit u, n-bit z, Boolean ORIGINAL predicate f_x and marker t, let m be the number of accepted z, N=2^(h+n+1). Let A_i=P B_i P^-1 for ANY permutation P, including an ideal random hidden frame. For every delta, P and x:

1. Every A_i is an involution: A_i^2=Identity.
2. Every pair commutes: A_i A_j=A_j A_i.
3. Each action moves exactly 2^h*m points, in 2^(h-1)*m transpositions, with fixed-point probability 1-m/2^(n+1)>=1/2 on uniform input.
4. For ORIGINAL-false x (m=0), all terminal actions are identity.

Proof: B_i changes only the marker and the XOR flip condition is independent of the marker. All B_i thus have order 2 and commute. For each accepted z, half the 2^h u values and both marker values move. Simultaneous conjugation preserves cycle type and group equations.

## Two-forward-query distinguisher

Compare oracle access to any A_i against a uniform random permutation pi on N points. For fixed arbitrary y, compute O(O(y)) and accept the guarded family iff O(O(y))=y. This always holds for A_i. For uniform pi, y must be a fixed point or a 2-cycle member; each has probability 1/N, so Pr[pi^2(y)=y]=2/N. The distinguishing advantage is EXACTLY 1-2/N. A one-call random-input fixed-point test has guarded success >=1/2 versus 1/N for a uniform random permutation.

This applies to honest or malicious setup and to arbitrary QPT attackers (already a classical PPT distinguisher), with all public native checking keys, arbitrary auxiliary input, and other capsules. It does NOT recover K_x or an ORIGINAL witness, and says nothing about whether the specified release is secure as witness encryption.

## Why this matters for local mixing

Functionality-preserving local mixing CANNOT turn these order-two, commuting terminal functions into pseudorandom permutations. The Canetti–Chamon–Mucciolo–Ruckenstein ePrint 2024/006 random-circuit RIO task is a different input ensemble. Its additional conditional route to general circuit obfuscation is NOT refuted, but cannot be silently replaced with the random-circuit argument. The publicly described obfustopia O1 demonstration uses random reversible circuits conjectured to be SPRPs, not this guarded family.

Changing to separate input/output frames or a protected aggregate decoder can remove this PARTICULAR permutation test; such a redesign needs a new honest algorithm and a full-public-output arbitrary-QPT security proof. This theorem introduces no new assumption.

## Executed checks

The exact published JS source was executed, with status PASS: exhaustive S8 conjugation with all 4 Boolean guards and both masks; additional 16-point two-terminal tests, 323,328 involution and fixed-point checks, 384 commutation checks, 648,192 true-witness same-bit checks, 80,832 false-instance identity checks, and exact cycle-law checks on S3-S6. Local independent Python checks are preserved separately in the run archive: 326,208 frame cases, 329,344 involution/fixed checks and 690,176 valid-witness bit checks. Neither checker implements a cryptographic obfuscator or quantum hardware.

Attack audit: (1) XOR cancellations; (2) conjugacy invariance independent of gauge recovery; (3) fixed-point fingerprint; (4) unchanged by extra views; (5) two chosen input calls; (6) even ideal honest setup is affected; (7) branch tags do not change cycle type; (8) checking keys irrelevant to this distinguisher; (9) classical attack also works against QPT, no new coherent algorithm asserted.

## Handoff and source scope

This checkpoint rules out only the DIRECT PRP/RIO-random-input shortcut for separately published guarded terminals. It does NOT refute RIO itself, nor extract any key. Keep Run 509 oracle-extraction only with simulator-held P^-1, and Run 259 source extraction only for complete accepted representations. A practical classical-PPT protected terminal, arbitrary-QPT full-public output hiding and arbitrary native authorization-to-ORIGINAL extraction, malicious N-of-N setup/erasure, multi-capsule binding, practical 128-bit estimates, and the conditional native-SLH Bitcoin graph remain UNPROVED.

Primary background: https://eprint.iacr.org/2024/006 ; authors' implementation description https://github.com/phantomzone-org/obfustopia . Full proof of either RIO system not audited. Exact live source refs: Run 513 blob 959eac9b0c9ab2ec17319da3639cd1c980fe2c06; Run 512 blob 321c8f9993441841acfffeed99ec759fe4733f57; Run 509 blob 44fe66f6265fd93b2e21ddd0f70b991b916948bc. Production unchanged; PR remains draft/unmerged.
