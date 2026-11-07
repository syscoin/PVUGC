# Run 546 — Relative-frame conjugacy leakage in local reversible mixing

**Bounded negative checkpoint, not a witness-KEM.** Verified live syscoin/PVUGC#1 head before research: 25e14aefc6181e79ad692afe37ce25d91e677045, branch research/pq-wkem-validation-20260918, PR draft/open/unmerged. Read exact Run 545 note blob 1f6d911c1654f9cf17e72f2b1eb43abf8241f1a2 and CLZ applicability blob c19d9d9cd515140e3ce62eac960cd548c0add622; latest substantive ordinary comment 6067040320.

## Targeted minimal local-mixing family

Assume honest **classical PPT** setup samples independent uniform left and right masks L,R in a finite group G of *publicly represented invertible permutations*. It publishes *all* alternative witness-sensitive local transitions A_b=L T_b R for b=0,...,t. Relative bare gates T_b may encode a secret capability. Common endpoint frames make alternative transitions composable with the same neighboring states. An arbitrary QPT attacker gets the complete public tables, native checking key, relation/claim/UTXO/branch context, other public outputs, arbitrary auxiliary information, multiple capsules and coherent public evaluation. The attack below uses only classical table algebra and one capsule. If the actual transitions are obfuscated rather than public group elements, or inverses cannot efficiently be derived, this theorem does not apply.

## Exact orbit theorem (not a new hardness assumption)

Let D_b=A_b A_0^{-1}, Delta_b=T_b T_0^{-1}. Then D_b=L Delta_b L^{-1}. Given uniform independent L,R, A_0 is independently uniform and the tuple (D_1,...,D_t) is uniform over the simultaneous conjugacy orbit of (Delta_1,...,Delta_t). Thus the **complete distribution of the public tables** depends exactly on this simultaneous-conjugacy orbit. Two bare transition tuples from the same orbit have *identical* public-table distributions. Tuples from different orbits have *disjoint* public support (a perfect orbit distinguisher if orbit testing is feasible). This follows because R makes A_0 uniform independently of L, and the group action partitions tuples into disjoint orbits with uniform orbit-stabilizer multiplicities.

For G=S_d and only one alternative, relative cycle type completely determines the distribution; each A_b marginal remains uniform. For three alternatives, testing each base/alternative pair separately can miss joint leakage from other relative words.

## Executed 4-state/3-alternative counterexample

Set G=S4, T_0=identity, T_1=(01) in both secret-bit cases. For secret bit 0 set T_2=(23), a disjoint transposition. For bit 1 set T_2=(12), an overlapping transposition. Publish A_0,A_1,A_2 with freshly sampled independent uniform L,R.

Each individual table has exactly the same uniform distribution for either bit. The pair (A_0,A_1) has exactly the same distribution for either bit, and so does (A_0,A_2): in both cases the relative bare operator is a transposition. But

A_1 A_2^{-1} = L (T_1 T_2^{-1}) L^{-1}.

For bit 0 this permutation has cycle partition (2,2); for bit 1 it has partition (3,1). The attacker recovers the protected bit from a public cycle-count with **probability 1** for every honest mask pair. The two full-triple distributions and the two alternative-pair (A_1,A_2) distributions have disjoint supports. This is a genuine joint-view/relative-frame fingerprint, **not** a one-gate inversion or independent per-table distribution attack.

Exhaustive counting over all 24^2=576 possible masks per secret gives 144 distinct triples with multiplicity four for bit 0, and 576 with multiplicity one for bit 1. Repeating this secret-dependent switch bitwise leaks a 256-bit capability in O(256) small-table operations; the demonstration uses public deterministic fixture bits, not a cryptographically generated hidden deployment seed.

## Explicit attack taxonomy and boundaries

(1) Seam: multiplying A_b by A_c^{-1} cancels a common frame. (2) Gauge: the relative word is conjugated, preserving cycle structure. (3) Fingerprint: independent tables and even both base/alternative pairs are statistically identical; the joint branch fingerprint is decisive. (4) Multi-view: one capsule suffices; more alternatives or reused frames give more relative words. (5) Adaptive evaluation: unnecessary because full tables are public. (6) Malicious setup/retained randomness: irrelevant to the attack; **honest** masks already leak. (7) Replay: correctly binding x, branch and UTXO cannot repair a within-context leak. (8) Native public checking key: not needed, but remains an adversary-visible correlation. (9) Quantum: this is a classical polynomial-time perfect distinguisher, so arbitrary-QPT hiding fails for this specific encoding without needing Simon, Grover, quantum advice, or QROM rewinding.

**Necessary but insufficient local design criterion:** A transparent, shared-frame, alternative-branch mixer must avoid capability-dependent simultaneous-conjugacy orbits across public alternatives. Matching individual local gate distributions is insufficient. Orbit equivalence does not imply security of a larger capsule and does not provide witness admission.

## Exact scope relative to earlier runs

Run 545 concerned public hash-compressed witness admission and padding; this run uses no witness hashes, no rank/canonicalization collapse and no chosen false statement. It attacks a narrower local seam left open by single-gate randomization. The live CLZ applicability note correctly distinguishes obfuscated forward permutations; this public-table result is **not** a security refutation of CLZ, RIO or iO, and no full primary-paper proof audit was performed here. Run 259's downstream extraction remains limited to its actual accepted complete representations. Recovering secret bits from table cycle structure is not such a representation.

No end-to-end source relation, public late-witness admission compiler, all-valid-ORIGINAL-witness common-key correctness, false-instance QPT security or unauthorized native-signature-to-ORIGINAL extraction is established. No alternative assumption is introduced. The N-of-N honest-erasure ceremony, multi-capsule QPT proof, practical 128-bit parameters, and conditional P2MR/native-SLH endpoint remain unresolved. Bitcoin does not evaluate any source circuit in the target design.

## Reproducibility and handoff

Exact committed V8 checker: run546_frame_holonomy_compact_check.js. It enumerates all S4 left/right frames, verifies equal marginal distributions and disjoint joint support, verifies all five S4 conjugacy classes and recovers 256 deterministic fixture bits. It was executed **twice** with byte-identical JSON output: run546_frame_holonomy_compact_validation.json. A separate extended Python 3.13.5 standard-library checker was executed twice with byte-identical JSON, 1020 assertions, and an extended mathematical note are local-only unless separately published. The compact checker reports 1014 assertions.

**Next constructive handoff:** Avoid encoding protected release semantics in secret-dependent, publicly composable relative branch types. Seek an independently justified *public late-ORIGINAL-witness-to-secret-capability* correlation without online issuing and without imposing a common witness. The quantum-security and ORIGINAL-extraction guarantees remain **UNPROVED**. Production unchanged, PR draft/unmerged; stopping condition unmet.
