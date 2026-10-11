# Run 397 — Unary-orbit late-witness admission barrier

**Scope:** One bounded research iteration, October 2026. This is a falsification of a *specific public interface*, not a break of Canetti–Luo–Zhang (CLZ), a WE construction, or a QPT-security proof. The starting live `syscoin/PVUGC#1` draft head was `bba5c4bb4e37144a390b40f0b58a7ff633d7a1f1`, branch `research/pq-wkem-validation-20260918`. The most recent substantive ordinary PR comment read was `6067040320`. Exact source readbacks include Run 259 `GLOBAL_FINGERPRINT_SOURCE_BINDING_RUN259.md` (blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`), Run 393 `ZERO_WORLD_QUERY_EXTRACTION_RUN393.md` (blob `7ee3cc73f1115a2788a4d54021ca808f865405dd`), Run 394 `SIGNATURE_RELEASE_IMPLIES_QROM_WE_RUN394.md` (blob `7afc59866028fef93728d6c3da766d7c9deafdc6`), and CLZ applicability (blob `c19d9d9cd515140e3ce62eac960cd548c0add622`). No entire PR diff or archive reconstruction was performed.

## Narrow question and interface

The CLZ controlled-homomorphism construction advertises public iteration of **one fixed unary** plaintext transformation, alongside functional-decryption keys. Does that unary feature alone permit a watcher to add an **arbitrary later** ORIGINAL witness to a pre-existing hidden-capability ciphertext and publicly extract a branch signature?

We study the following intentionally narrow interface; it is **not claimed to capture all CLZ functionality**. Classical PPT `Build(x)` creates a public capsule `P`, an initial protected ciphertext `c0`, and a native verification key `vk`; hidden `K` is only used during honest setup under the original N-of-N honest-erasure baseline. Every public ciphertext transition after setup is an independent application of the *same* publicly callable unary `U`, with plaintext effect `g`; the only public extraction interface is `Rel(P,c)`, which outputs a candidate branch credential. It is callable on `c0` and every descendant. Honest `Recover(P,w)` can choose **when to stop** along this publicly reachable chain, but cannot inject witness data as another plaintext input, choose a new `g_w`, supply a per-witness functional key, or exploit witness-coded rerandomization bytes. Each honest execution uses at most `T(λ,|x|)` unary steps, for a public polynomial bound `T`. Public checking `Auth(vk,x,cred)` verifies the candidate, e.g. native Sign/Verify for the already bound Bitcoin challenge message. The honest evaluator is classical PPT. Attackers may be arbitrary QPT and have all public keys, capsule bytes, other capsules, auxiliary states, retained nonsecret setup data, and coherent access to public algorithms. The attack below needs only **classical** access and does not depend on the private state being inspectable.

## Theorem A — exhaustive unary orbit attacks true-instance release

Assume that for fixed `P`, `Rel(P,U^j(c0))` (with canonical public coins) is defined and is publicly executable for every `0<=j<=T`, and every valid ORIGINAL witness `w` causes honest recovery of a candidate accepted by `Auth` at *some* such position `j(w)` with probability at least `1-ε`. Assume for this theorem deterministic `U` and `Rel`, or, for randomized algorithms, a public polynomial amplification schedule that reproduces the same success probability as honest independent coins. Then a witness-free classical attacker can return an accepted native credential with probability at least `1-ε` by evaluating all `T+1` descendants and checking `Auth`. Its cost is `O(T*(cost(U)+cost(Rel)+cost(Auth)))`, with no ORIGINAL witness, no quantum algorithm, no gate-list inversion and no use of Run 259. If `Rel` outputs the *same key* for all valid witnesses, the attacker recovers that key. If it outputs only a fixed pre-signed native transaction, the attacker still obtains authorization for the challenge path; the original key-recovery requirement would independently remain unproved.

**Proof:** Fix the setup and a valid `w` for which honest recovery succeeds at `j(w)`. By the interface definition, the released candidate at `j(w)` is a public function of `P,c0,j(w)` (and publicly simulatable coins), not of the witness. The adversary's exhaustive scan includes this position. It identifies successful credentials using `Auth`. Average over setup randomness. ∎

The randomness qualification is essential: a witness-dependent auxiliary **input** disguised as a rerandomization coin is outside the theorem. If coins themselves carry a hidden witness-bound authorization token, calling this operation ordinary plaintext-preserving rerandomization is inadequate; its full public-code/auxiliary-input security needs independent proof.

## Theorem B — complexity barrier for generic NP via this interface

Suppose the above interface is implemented by public classical PPT `Build(x)` for **all** statements in language `L`. Assume (i) all-witness correctness on yes-instances and (ii) full-public-output false-instance QPT authorization hiding for no-instances, including public `Auth` and any setup auxiliary material. A classical probabilistic algorithm can build `P`, scan the at-most-polynomial unary orbit, and accept iff any candidate satisfies `Auth`. By (i), it accepts yes-instances with overwhelming probability. By (ii), it rejects no-instances with overwhelming probability. Therefore **`L ∈ BPP`**. If `L` is NP-complete, the existence of this restricted interface would imply `NP ⊆ BPP` (not a proven impossibility absent a complexity separation assumption). This is stronger than the Run-394 WE-power implication solely because the admitted unary-orbit interface is much weaker than general public witness input. It does **not** apply to a late-witness encryption or functional-decryption scheme with any additional input-sensitive operation.

## Input noninterference lemma

If ciphertexts are obtained solely by unary `g` applied to the initial plaintext `m0` (plus validity-preserving rerandomization that does not change the plaintext), every reachable plaintext is `g^j(m0)`. Proof: induction on the number of unary operations. A separate public ciphertext `Enc(w)` cannot alter a protected descendant of `Enc(m0)` without a binary combiner or other input-dependent transition. This is a **reachability/interface fact**, not ciphertext secrecy: CLZ's FE/CCA constructions are not refuted. A fixed unary g may already contain a witness initialized *before* setup, but that does not admit an arbitrary new witness. A watcher may choose `j` based on its witness; Theorem A shows the public polynomial-length chain can be enumerated, even if finding that index by witness search would itself be hard.

## Escape routes and exact remaining obligation

To escape, a proposal must provide a separately proven **late public witness admission** operation: for example a genuine binary way to bind `Enc(w)` into the same protected state as hidden `K`, a public `w`-parameterized update with a rigorous cryptographic definition, a secure release region that jointly evaluates source-dependent input, or a fast-forward operation supporting superpolynomial iteration counts in polynomial work. None is supplied here. Public standard FHE can compute with later encrypted witness data, but Run 387's IND-CPA barrier still prevents plaintext release without additional independent source-enforcing cryptography. Public universal verifier outputs or zero residuals do not themselves authenticate the source (Run 259, Section 6). Merely postulating an update that releases one pseudorandom `K` for every valid `w` is WE/WPRF-circular unless independently justified.

### Attack-taxonomy ledger

1. **Local seams/cancellation:** not necessary; orbit bypass operates without mask disclosure.
2. **Gauge/global synchronization:** not necessary; no frame reconstruction.
3. **Statistical fingerprints:** not necessary; no distributional test.
4. **Multi-capsule:** one capsule already breaks this restricted interface; related capsules can only enlarge public scan surface; joint security unproved.
5. **Adaptive chosen-input/public evaluation:** **attacked directly** by sequential public enumeration.
6. **Malicious setup/retained randomness:** honest setup is already broken in this restricted interface; malicious setup is not analyzed.
7. **Cross-UTXO/branch replay:** contexts must be bound, separate native credentials; not needed for the attack.
8. **Public checking key:** **essential to the attack** as a recognizer for candidate credentials.
9. **Coherent quantum attack:** not necessary because classical polynomial-time enumeration succeeds; genuinely quantum joint leakage remains untested for any surviving construction.

## Source-binding / security ledger

- Honest setup and evaluation: classical PPT; target conditional Bitcoin endpoint `P2MR` + native SLH-like signature verification **not activated/implemented by this work**; no CAT assumption.
- Adversary: arbitrary QPT, but the witness-free break is classical; arbitrary public auxiliary inputs and related capsules can be added without removing the attack.
- QROM: not used. No quantum rewinding or oracle programming.
- All-witness same-key correctness: premise in a restricted interface, **not established for a secure WKEM**.
- False-instance QPT hiding: when combined with this restricted interface over arbitrary NP, yields the `L∈BPP` implication; **not proved by this checker**.
- True-instance source extraction: the attack intentionally supplies a signature without an accepted Run-259 representation; hence Run 259 cannot supply ORIGINAL extraction.
- Crypto assumption: none for Theorem A; Theorem B uses the stated false-instance operational-security premise, not an LWE/SIS security inference.
- Practical 128-bit resources, malicious N-of-N ceremony/erasure/abort, related capsules and unconditional one-honest watcher inclusion: **UNPROVED**.

## Reproducible finite checker

`unary_orbit_admission_run397_check.py` is deterministic Python 3 with standard library only. It exhausts all nonempty accepted-position subsets on public unary orbits of lengths 2–8, six signing seeds each, checks all selected witness-dependent stopping times recover a single usable native signer, scans the public orbit without a witness, checks plaintext-preserving rerandomization, and tests a narrow reused-vs-independent-branch native-checking-key control. It contains 3,006 fixtures and 44,072 assertions; py_compile and repeated byte-identical execution passed. The native signature function in this **toy** checker is trivially invertible; it is only a syntax-level authorization recognizer and makes **no** cryptographic-security claim. These checks do not implement CLZ, native SLH-DSA, local mixing, Run 259's actual extractor, or a post-quantum WKEM.

## Literature and provenance

- Canetti–Luo–Zhang, *How to Encrypt with Random Reversible Circuits: Functional, Homomorphic and CCA-Secure*, CRYPTO 2026, https://simons.berkeley.edu/talks/ji-luo-mit-csail-2026-07-13 . The author abstract advertises one fixed unary g and functional keys. It does not state the extra late-input capability ruled out *for unary-only access* here.
- Canetti–Chamon–Mucciolo–Ruckenstein, *Towards General-Purpose Program Obfuscation via Local Mixing*, https://simons.berkeley.edu/talks/ran-canetti-boston-university-2025-06-23 . This iteration did not audit its full security proof and does not claim any RIO break.
- Live GitHub exact source note for CLZ applicability, blob `c19d9d9cd515140e3ce62eac960cd548c0add622`, identifies the unary-interface gap. Theorem A is a formal bounded-unary black-box attack on a newly specified subset of that gap, not a claim about an implemented CLZ update.

## Core handoff

Do not promote CLZ's unary controlled homomorphism into permissionless late witness input by syntax alone. A substantive next construction must introduce and justify an input-sensitive, cryptographically source-bound update into the same protected capability state, then prove full-public-output false-instance QPT hiding and unauthorized native authorization -> accepted Run-259 representation. **Practical WKEM unsolved; draft PR/production unchanged.**
