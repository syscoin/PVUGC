# R396 — Prefix-bound SHA labels: nonspliceable opening with an unimplemented universal sink (NONQUALIFYING)

## Continuity and selection
Read live open draft syscoin/PVUGC PR #1 at `c44bc2e2039f2aaa9bc1eed78bc5cdedb3d0a039` on `research/pq-wkem-validation-20260918`. Read R395 `research/pq-wkem/r395_public_state_reachability_20261120/RESEARCH.md` blob `90a692a7e1c3e8557091564ea2979a8c05f2ba74`, plus exact R393/R394 notes as relevant. Top-level issue comments since 2026-11-18 were empty. No Core source or tests were rerun; no external search. This is a substantive **preflight construction** with an exact algebraic correctness condition and joint-public security obligation. It does NOT implement ORIGINAL-source FE/WKEM. No executable checker or output is claimed for this pass.

R289's defect is mixing locally valid labels from different witnesses; R394 excludes explicit polynomial-width read-once linear machines; R395 excludes enumerable polynomial-state representations faithful to hard-TRUE ORIGINAL evidence. The distinct candidate here uses **nonlinear, cryptographically path-bound, implicitly exponential SHA labels**: local values from different prefixes no longer share the same state label. The objective is to retain this global binding and build a *single* public, compact, secret-carrying accepting sink for **all** future source witnesses. We construct the former and examine the missing latter in the same full-public model, rather than merely replacing a field/basis or re-running the known span attacks.

## Actual hash-only finite-leaf Build/Open candidate (NOT practical for ORIGINAL)
Fix statement x and canonical, bounded n-bit witness representation with no ignored padding. Let W_x={w in {0,1}^n : R_orig(x,w)=1}. The toy enumerating builder samples public root `ell_0` and a hidden uniform `t` in {0,1}^lambda. Define public SHA-domain-separated labels:

    ell_j(w[1:j]) = H("R396/step" || x_id || j || ell_(j-1)(w[1:j-1]) || w_j).

Let `I_w=H("R396/index"||x_id||ell_n(w))` and `P_w=H("R396/wrap"||x_id||ell_n(w))`. With an agreed frozen *native safe cancellation capability* S, set

    D = S XOR H("R396/payload"||x_id||t)
    E_w = t XOR P_w   for EVERY w in W_x
    C = (x_id, ell_0, D, { (I_w,E_w) : w in W_x }).

Public Open(C,w) computes ell_n(w), looks up I_w and, if present, obtains
`t'=E_w XOR P_w` and `S'=D XOR H("R396/payload"||x_id||t')`.
Every listed accepted witness returns the SAME S, with no shared witness hash/preimage, and no mixing of independent local gate labels: each edge is bound to the entire canonical input prefix through a collision-resistant chain. Nonlisted inputs do not invoke a source-verifier after recovering a raw key; they lack the specific cryptographic sink edge. In the QROM, finding a different full path with the same leaf label has collision-search limitations, not a proof for concrete SHA. All short tags, local caches, and different witness encodings must be included in the identifier and canonicalization.

This is a REAL finite-table algorithm, but `Build` explicitly enumerates W_x. For general n it costs Omega(n*|W_x|), is not classical PPT for the original bridge distribution, and can require enumerating future authentic headers/coinbases and parent histories that were unknown at setup. A public capsule root would only authenticate that enormous table; it would not generate the missing edges. A malicious builder's retained t can open early, so the original one-honest erasure boundary remains, and this construction does not solve malicious setup or collusion.

## Joint-public FALSE / hard-TRUE checks
If W_x is empty and the builder publishes no edges, the capsule consists of (ell_0,D) with `D=S XOR H("payload"||x_id||t)`. Under a fresh, hidden uniform t and an independent RANDOM ORACLE, this is a conventional hidden-point mask: a QPT algorithm's ability to distinguish S values can be bounded through search for t; the natural quantum-query scale is O(q^2/2^lambda) under the stated oracle and independent-auxiliary model. This is explicitly a QROM idealization, not a full simulator for concrete SHA, native VK, N-of-N setup proofs or sibling capsules; a precise bound/proof is not asserted.

When W_x is nonempty, the published edge table and D are correlated through t. A valid w opens. Stronger unauthorized/hard-TRUE security would require any successful public-key recovery to yield an actual source-certified w or an independent hash/native break, including quantum joint processing, source-generated coins, sibling openings and malicious setup. Merely saying 'a table entry was used' would not extract a source certificate from an arbitrary adversary and is not a theorem.

## Why a polynomial cutset is not yet a repair
The natural repair compresses leaf edges into an accepted-prefix cutset: publish one sink edge per prefix cylinder whose EVERY extension satisfies R_orig, and allow a path to use an edge when it reaches such a cylinder. The same cryptographic full-prefix binding then prevents simple local splicing. But it does not help a source SHA predicate whose valid inputs are scattered rather than prefix-complete.

Quantitative sanity under an **idealized random-work predicate only**: for 2^n equally canonical candidate nonces, each independently accepted with probability p=2^-d, the expected number of accepted leaves is 2^(n-d). The expected number of fully accepted subtrees at depth n-k (each covering 2^k leaves) is

    E[N_k] = 2^(n-k) * p^(2^k) = 2^(n-k-d*2^k).

For an illustrative n=256, d=40, there are 2^216 expected accepted leaves, whereas E[N_3]=2^(253-320)=2^-67 complete 8-leaf accepted prefix cylinders. This is an elementary expectation and Markov upper bound for THIS random-oracle prefix-cover model, not a Bitcoin difficulty estimate, a measured SHA property, a general FE impossibility theorem, or an accepted source-certificate population calculation. It shows why this kind of terminal-table compression does not create polynomial Build for random-looking SHA conditions.

**Crucial separate gap:** even a polynomial-size Boolean circuit that publicly recognizes `R_orig(x,w)` is NOT an accepting-edge compiler. Turning `if R_orig(x,w) then t else bottom` into a *publicly evaluable, secret-hiding* compressed sink without leaking t on invalid inputs is precisely the cryptographic FE/WKEM operation still unimplemented; using it as a hypothetical primitive would be circular. A public raw t and an external validity check fail immediately. A hidden private terminal oracle fails public Build/Open.

## Decision / exact next equation
Retain the path-bound hash-label idea only as a global-consistency regression component; do NOT develop its table, prefix-cover optimizations, serialization or parameter sweeps. It is not a surviving ORIGINAL source-release construction, and no new client, Core, Bitcoin Script, real AuxPoW verifier, native signature, or quantum test was implemented.

The next genuinely constructive object must instead supply a practical, independently instantiated, cryptographically protected **universal terminal join** for all ORIGINAL source certificates:

    J_x(ell_n(w), C_public) = t   for every R_orig(x,w)=1,

with no public computation or joint public attack yielding t for invalid/unrelated w, *and* an actual PPT compiler for C_public without enumerating W_x, *and* an independently grounded full-public QPT FALSE/hard-TRUE proof. The same fixed claim-scoped safe cancellation signature must emerge, including the separate BTC-greater, finite authenticated burn fault, and contextually valid qualified Syscoin inconsistency/tag-fault OR grounds. Source authentication must be inside release. Retain activated strict modern AuxPoW rules, R316 coverage correction, LC depth/deadline/reset, R225 native outpoint binding, and malicious one-honest N-of-N setup.

No user breakthrough notification, PR progress comment, production/Core write, deployment, or automation change. **NONQUALIFYING.**
