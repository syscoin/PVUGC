# Run 695 — Cofactor-free spectral release: an all-witness correctness component

**Status:** constructive algebra/correctness lemma, **NOT** a practical or QPT-secure witness-KEM. Date: 2026-10-21. Repo: syscoin/PVUGC#1 draft, branch `research/pq-wkem-validation-20260918`, starting SHA `88c90ca6929c47ac0786e0ec4097eb27b3917ba1`.

## Constructive delta and precise dependency

Run 593's typed AADP matrix source guarantees **singularity** for every valid source representation, but its rank-one key perturbation (M(w)+K E_{nn}) requires the last cofactor (D(w)\ne0). This was only pointwise with a setup-dependent failure bound; no uniform guarantee was given for all potentially adaptive valid witnesses. This run makes the protected key an **eigenvalue** using a publicly invertible perturbation, eliminating that cofactor requirement for *every* valid original witness and preserving witness-dependent intermediate matrices. It reuses exactly the Run-593 source-rank lemma, not its unproved security.

Let (𝔽_q) be a finite field and (M_x(z)=\sum_{j=0}^{v} z_j M_j\in\operatorname{Mat}_n(\mathbb F_q)) an affine/homogeneous secret-masked source pencil whose public encoding is encrypted. For every genuine complete SOURCE representation (z=\operatorname{Encode}(x,w)), require (z_0=1) and ({\rm rank} M_x(z)<n). Run 593 obtains this from scalar quadratic gate checks: for (m) nondegenerate gates with block size (b), the rank is at most (2bm), so (n=2bm+1) suffices. Its degenerate source tuples must still be treated under the *rank upper bound*; this new correctness argument does not require exact corank one.

### Honest Setup / Encode / Recover

1. **Setup (classical PPT).** In the existing one-honest-party N-of-N setup/erasure model, construct the masked coefficient family (M_j) according to an actually specified source pencil. Generate a native signing-capability seed (K\in D\subset\mathbb F_q), with the native signing public key (pk=\operatorname{NativePK}(K)). Choose an **invertible public** (E\in\mathrm{GL}_n(\mathbb F_q)); the simplest choice is (E=I_n). Publish ({C_0=M_0+K E,\ C_j=M_j\ (j>0)}), (E), (pk), a 512-bit context-bound public checker (h=H(\texttt{WKEM}||x||K)), and the exact bound claim/UTXO/branch/context. **No setup factors, coins, or K are public.** The native public checker is part of the adversary view.
2. **Encode (public/off chain).** From any valid ORIGINAL witness (w), construct its complete source representation (z), with (z_0=1) and (\rho_x(z)=0). The Run-259 fingerprint/SIS predicate can check the global representation before proceeding, but is only a source-binding check.
3. **Recover (classical randomized PPT/off chain).** Form (C(z)=\sum_j z_j C_j=M_x(z)+K E). Compute the generalized characteristic polynomial (p_z(T)=\det(C(z)-T E)∈\mathbb F_q[T]), and factor it over (𝔽_q) by a standard finite-field polynomial-factorization algorithm. At most (n) distinct field roots exist. Decode each root into the native seed domain (D), check its derived (pk) and context-bound (h), and return the **unique** matching (K') (otherwise reject). Then sign the intended native challenge-branch message with the recovered signing seed. Ordinary Bitcoin verification remains conditional on the declared native-PQ/P2MR endpoint; there is no on-chain NP verification.

For the exact SLH-DSA-like endpoint, (K) may denote the sufficient private signing seed, with other signature-randomizer inputs handled according to its specified API. This is conditional; no deployed Bitcoin opcode is asserted. The check (h) is a public correlation, **not** a proved hiding mechanism; testing (K) offline remains possible and affects concrete quantum parameters.

### Theorem — simultaneous/all-witness recovery, independent of cofactor

For **every** fixed setup with invertible (E), and **every** valid ORIGINAL witness (w), (\det M_x(z)=0). Consequently

\[
p_z(K)=\det(C(z)-K E)=\det M_x(z)=0.
\]

Since (E) is invertible, (p_z(T)) has degree **exactly** (n), with leading coefficient ((-1)^n\det E\ne0), even when every rank-one probe has an identically zero determinant polynomial. Thus (K) is one of at most (n) candidate field roots, and the recovery algorithm finds it in randomized polynomial time in (n,\log q), subject to the standard finite-field factoring success probability.

If the public checker uniquely identifies the honestly chosen (K) within supported native seed domain (D), *the same K is recovered for every valid witness, simultaneously, including witnesses selected after the public setup*. The proof does not union-bound individual cofactor events, does not require canonical witnesses or common intermediate states, and does not require source privacy. For a modeled independent random 512-bit checker and (D) of size at most (2^{256}), the probability that the **chosen** (K) has a second checker preimage in (D) is at most ((|D|-1)2^{-512}<2^{-256}), globally over all witnesses. This random-function example is a **correctness-only** idealization, not a QROM/hiding proof for a concrete hash or for its correlation with native (pk).

The change does not add another source ciphertext/capsule: it replaces a rank-one perturbation with the invertible (K E) term in the same coefficient (C_0). The field-root method is more computationally expensive than extracting a single linear determinant root and requires a practical characteristic-polynomial/factorization implementation.

### Reproducible negative-control and positive result

An exact deterministic finite-field checker (published alongside this note) enumerates source-gate Boolean witnesses, computes the encrypted public coefficient matrices, and checks that all valid witnesses recover one filtered (K). It then constructs a **global invertible right shear** for which a particular valid witness has zero last cofactor: the old rank-one root polynomial becomes identically zero while the full-rank spectral polynomial continues to contain (K), and *all* valid witnesses still recover the same (K). The toy checker uses an openly invertible cubic map as its key selector, solely to verify algebra; no toy hiding is claimed. An independently executed larger Python checker was preserved locally with 1,203 assertions across 160 valid-witness cases.

### Security interface: what is and is not solved

This is a **genuine correctness repair** to a previously conditional constructive component. It does **not** repair scalar AADP's attacks or establish security of the full-matrix variant. In particular:
- A malicious attacker is free to evaluate (C(z)), factor (p_z), and test public (pk,h) for arbitrary (including invalid) (z). A public `SISAccept(z)` check in the honest recovery algorithm does not prevent bypass. False-instance full-output QPT hiding remains **UNPROVED**.
- Arbitrary true-instance capability recovery or accepted signature forgery has **NOT** been reduced to an accepted SOURCE representation. Run 259's exact source-binding theorem (blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`) can be invoked only **after** such a representation has been supplied. This new spectral adapter does not supply the missing arrow.
- The perturbation's public scalar (KE) is exposed in correlations across all coefficient matrices; local seams, global frame synchronization, statistical fingerprints, chosen-input spectral evaluations, related-statement views, setup-coins compromise, cross-UTXO replay, public (pk,h) correlations and coherent QPT evaluation remain **unproved security obligations**. No positive security claim follows from the tests.
- Setup must be classical PPT and erase/protect secrets with one honest N-of-N participant; malicious setup/abort, presignature graph, availability and independent statement/branch credentials are not implemented. Native SLH-DSA-like verification and P2MR are explicitly conditional.

### Cost and exact handoff

For (v+1) source coefficients and (n=2bm+1), the same naive public density is ((v+1)n^2\lceil\log_2q\rceil) bits plus (E,pk,h). (E=I) costs no matrix to transmit. Using Run 593's illustration (m=15,000\), (v=15,000\), (b=1\), 32-byte field values gives approximately **432 TB**, decidedly **not practical**. The new method avoids a potentially much larger field chosen to union-bound exponentially many witnesses, but it does not solve ciphertext compression or QPT security.

The next constructive task is to use the **full-rank spectral recovery interface as a small local frontier**, *not* to return to a full dense NP/AADP ciphertext. Find an independently secured compact masked (M_x(s_w)) retaining source-specific singularity with full-public-view QPT security, and produce an arbitrary-capability-recovery/accepted-forgery to accepted complete SOURCE-representation reduction (or independent QPT-hardness reduction). Do not substitute a new release oracle or assume this missing step.

**Stopping condition unmet. Production unchanged. PR draft/unmerged.**