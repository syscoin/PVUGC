# Run 631 — Public-verifiable frontier density: a quantum-search lower bound

2026-10-19; research-only for syscoin/PVUGC#1; branch `research/pq-wkem-validation-20260918`; verified starting head `382a68bc66c01727827fb4583d9e6693df67738b`. Classification: **conditional necessary parameter bound**, NOT a practical WKEM, attack on CCMR/RIO/Gaussian SOURCE, or full QPT secrecy/extraction theorem. The Grover/BBHT algorithm is established literature, not new cryptography.

## Explicit model
Honest classical PPT setup outputs the full public package P_x containing exact relation/claim/UTXO/branch/anchors/context, native challenge verification key pk, preauthorized digest d, all related capsules and checking-key correlations. Fix one honestly generated good package. A public deterministic polynomial-size classical circuit F(P_x,s,r,d), with complete b-bit frontier input s and rho independent uniform signing/release coins r, either emits an ordinary native signature (under the conditional native-PQ endpoint) or fails. No other secret service, private witness, hidden oracle or trusted computation input may be required by F. Its public Boolean predicate is

    g_P(s,r) = [Verify(pk,d,F(P_x,s,r,d)) = 1].

The fixed digest and graph branch are the intended challenge path; Bitcoin verifies only an ordinary signature under the explicitly conditional endpoint. An attacker may inspect all public bytes and implement F and Verify coherently as reversible quantum circuits. Permitted QPT auxiliary advice may be arbitrary; this attack uses none. Quantum access is to the local public computation, not to an invented private release oracle.

Assume that M>=1 **distinct** complete frontier states (potentially obtained from different valid ORIGINAL witnesses) each cause native acceptance for >=(1-epsilon) of uniformly chosen r, with 0<=epsilon<1. An unknown/unsamplable frontier-state distribution is permitted; the adversary never needs to sample it. If preprocessing is randomized, high average correctness yields at least one good state under the appropriate independent random-tape model, not a claim that every possible state is good.

## Exact conditional search theorem
At least M(1-epsilon)2^rho of the 2^(b+rho) pairs (s,r) are publicly marked, hence

    p = Pr_{s,r}[g_P(s,r)=1] >= M(1-epsilon)/2^b.

The public F/Verify circuit implements a reversible phase oracle. BBHT unknown-marked-count search and amplitude amplification find an accepting pair (and consequently an accepted native signature for the intended digest) in O(sqrt(2^b/[M(1-epsilon)])) coherent public-predicate evaluations, with standard constant overhead and independent output verification. For p near one the bound is understood as at least constant work. Classical uniform search takes expected 1/p evaluations. This is an accepted **signature** attack, not necessarily recovery of the erased signing key K.

In particular, if b-log2 M=O(log lambda) and 1-epsilon>=1/poly(lambda), the attacker is QPT for polynomial-size public F. A necessary brute-force search-work condition for **128-bit quantum query hardness** within this model is

    b - log2(M) - log2(1-epsilon) >= about 256 bits,

not a sufficient post-quantum security claim or measured cryptographic parameter. An honest valid state may be computationally inaccessible, but this search does not attempt to generate it from a SOURCE witness: it searches all complete public frontier inputs and uses native acceptance as its oracle.

## Irrelevant input entropy does not help
Appending u ignored frontier bits or independent accepted signing coins multiplies both the marked-set cardinality and search space by 2^u. The marked fraction and the Grover recurrence stay exactly unchanged. A free witness choice unrelated to authentication is similarly ineffective. Multiple valid-witness states increase M and reduce brute-force hardness. The complete frontier input must include every indispensable secret witness-derived value; if F still requires an unmodeled SOURCE witness, the theorem does not apply with the alleged small b.

## Scope and falsification taxonomy
Unlike Run 629, the attacker needs **no PPT simulator of an honest frontier-state distribution**. Unlike Run 630, no hidden period, ideal random permutation, or shift is assumed. (1) seams, (2) gauge alignment, and (3) gate fingerprints are not required; (4) related views may increase successful states, (5) arbitrary chosen-input and coherent evaluation are essential, (6) the theorem already holds under honest setup, (7) it attacks the correctly bound claim/path without replay, (8) the public native checking key is the membership tester, and (9) coherent amplitude amplification gives the precise quantum query saving. A signature from this search does not automatically constitute the **complete accepted Run-259 representation**; invoking Run-259 ORIGINAL extraction needs a separate proven conversion from arbitrary native acceptance to its exact predicate.

False-instance full-view QPT hiding, hard-true unauthorized recovery/forgery -> ORIGINAL evidence or QPT break, malicious one-honest N-of-N setup and erasure, unrelated capsule composition, all-witness same-K correctness, unrestricted future histories, 128-bit PQ parameter accounting and actual native Bitcoin graph enforcement remain UNPROVED. The theorem is an interface-level search-density barrier, not a working release gadget, proof of security or impossibility theorem.

## Executed checks and references
The standard-library checker `run631_grover_frontier_check.py` runs exact-rational full-vector phase flips and diffusions on 7 finite acceptance predicates, tests normalized amplitudes, exact two-amplitude recurrence, and irrelevant padding invariance. Captured `run631_grover_frontier_validation.json` reports 222 assertions. Two executions matched byte for byte; Python compilation passed. Toy mathematics is not cryptographic verification.

Quantum search sources: Boyer–Brassard–Høyer–Tapp, *Tight Bounds on Quantum Searching* (arXiv:quant-ph/9605034); Brassard–Høyer–Mosca–Tapp, *Quantum Amplitude Amplification and Estimation* (arXiv:quant-ph/0005055). No new full CCMR/RIO proof/errata audit performed.

**No complete practical PQ WKEM. Keep production unchanged; PR remains draft/unmerged; research must continue.**
