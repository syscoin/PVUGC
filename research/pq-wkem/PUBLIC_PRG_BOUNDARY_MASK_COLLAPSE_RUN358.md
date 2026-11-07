# Run 358 — transparent PRG-masked release boundary collapses

Live source: syscoin/PVUGC#1 draft/open/unmerged at `bd725ff1a919714b2e713d332b1fefb56832feb4`. Exact dependencies: Run 357 note blob `93cb228e91f4323307057fc141a874da4db6f945`; Run 259 source-binding blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`.

## Exact candidate and no-go theorem

Let `(x,w)` be a classically efficiently sampled true ORIGINAL relation instance. Honest classical-PPT setup produces public capsule `P_x`, native branch checking key `pk_x`, secret branch credential `K_x`, and the complete correlated public auxiliary view. Let `G:{0,1}^k -> {0,1}^d` (`d>k`) be a classical efficient candidate QPT-secure PRG. The ordinary public source prefix computes a witness-dependent offset `a(P_x,x,w)`, independent of a *fresh* uniform PRG seed `rho`. The **entire** protected boundary input is `S=a(P_x,x,w) XOR G(rho)`. No separately authenticated source-bearing token is passed.

Let `T(P_x,pk_x,S)` be the public PPT predicate that runs the advertised release algorithm and tests the resulting candidate credential or branch signature against the intended native verification key/message/path. All claim, UTXO, relation, branch, and related-capsule public data must be inside `P_x`. If every valid ORIGINAL witness succeeds with probability at least `1-epsilon`, write `sigma=Pr[T(P_x,pk_x,U_d)=1]`, averaged over the same setup distribution and independent public uniform boundary state.

**Theorem.** There is a straight-line QPT distinguisher against `G(U_k)` versus `U_d` with advantage at least `1-epsilon-sigma`. Therefore, under `Adv_PRG^QPT <= negl(k)`:

`sigma >= 1-epsilon-Adv_PRG^QPT`.

**Proof.** The PRG distinguisher classically samples the honestly generated pair `(x,w)` and setup; it keeps `w` internally. Given a classical PRG challenge `y`, it computes `a=a(P_x,x,w)` and returns the public test `T(P_x,pk_x,a XOR y)`. Under the PRG challenge, correctness gives acceptance at least `1-epsilon`. Under a uniform challenge, XOR by any fixed independently generated offset preserves uniformity, so acceptance is exactly `sigma`. The reduction is classical PPT (hence valid against arbitrary QPT security), straight-line, and has no rewinding, oracle programming, or quantum-advice extraction.

Consequently a **public attacker**, given only the capsule and native checking key, draws `U_d` and runs release. Its success is `sigma`, almost one if the PRG is QPT secure and correctness is high. This happens without presenting an ORIGINAL witness or an accepted Run-259 representation; the downstream SIS/global-folding theorem cannot be invoked. Distinct valid witnesses can use distinct offsets and still share one `K_x`; the attack applies to each fixed valid offset.

## Exact scope and correction

This eliminates only a *transparent, independently freshly PRG-masked boundary state*, not all nonlinear or authenticated local mixing. A separately cryptographically authenticated token `tau`, capsule/seed dependence, malicious setup correlations, or witness-only secret boundary frames fall outside the premise and require independent analysis. The complete QPT auxiliary input and multiple-capsule view must remain seed-independent for this reduction. The attacker is already classical; no coherent quantum speedup is claimed. Source hardness, arbitrary-QPT recovery-to-ORIGINAL extraction, false-instance hiding, N-of-N erasure/abort and practical 128-bit parameters remain unproved.

Run 357's TV=1 comparison between reversible programs having *different public decoded functions* is algebraically valid but **does not by itself violate equivalent-function obfuscation security**. It becomes a WKEM break only when a usable unauthorized public input/state sampler exists; this run exhibits one explicit class.

## Reproducibility and literature

Standard-library checker `public_prg_boundary_mask_run358_check.py`: Python syntax pass and two byte-identical outputs, **22,064 assertions**. Deliberately insecure injective toy expansion gives legitimate-state success 1, public-uniform success `2^-k`, exact distinguishing advantage `1-2^-k`; multiple-witness offsets and exact finite total-variation testing inequalities are checked. These are finite identities, NOT evidence of QPT-PRG hardness or of a practical WKEM.

Canetti–Chamon–Mucciolo–Ruckenstein, *Towards general-purpose program obfuscation via local mixing*, ePrint 2024/006, examines a more elaborate conditional RIO framework. Only its primary-source abstract was inspected this run (PDF fetch 403); this theorem does **not** refute their complete construction: https://eprint.iacr.org/2024/006 .

**Handoff:** A viable minimal local release must carry a genuinely source-enforced boundary object not efficiently samplable from the complete public view; do not merely relabel that missing object WE/RIO/WPRF. Every valid ORIGINAL witness must still derive the same `K_x` off-chain for an ordinary native challenge-path signature, with arbitrary-QPT unauthorized recovery/forgery implying an accepted Run-259 representation or an independent QPT break. Full practical PQ WKEM remains **UNSOLVED**; production unchanged.
