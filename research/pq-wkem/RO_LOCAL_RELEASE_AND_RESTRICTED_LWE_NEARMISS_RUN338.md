# Run 338 — no-retarget `R_work`: relativizing local-release barrier and two standard-LWE near-misses

## Checkpoint

Live state was read before research through the connected GitHub integration:

- repository/PR: `syscoin/PVUGC#1`
- branch: `research/pq-wkem-validation-20260918`
- starting SHA: `b3fdb58941ce490cc1ed3be150056c93e37ed5b9`
- PR: open, draft, unmerged
- latest substantive ordinary PR comment found: `5945825660`
- exact dependencies read at that SHA:
  - Run 259 note blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`
  - Run 115 note blob `cf2ec9575948e16b58acbd870208686759f14e44`
  - Run 122 note blob `c6bb41bf172001ca0c882e84051911ffae35e342`

This bounded pass studies only the no-retarget `R_work` core left by Run 337. In its smallest one-step form, the setup-known public statement fixes a prefix/context `p` and target `T`, while a future witness contains a header suffix `u` with

\[
R_{p,T}(u)=1\iff H(p\|u)\le T.
\]

For a linked chain the same issue repeats with each fresh child header. Difficulty/retarget arithmetic is deliberately excluded in this pass.

## 1. New exact barrier: black-box RO-local release can be forked

The most tempting minimal local mixer is a public evaluator whose only witness-sensitive state is a small neighborhood of public-hash answers around the candidate PoW witness. In the random-oracle abstraction this is not sufficient.

### Model

Let `H:D -> Y` be a random oracle. `Build^H` is classical PPT, runs before the future PoW witness is known, and outputs a public capsule `P` and a hidden capability `K`. Consider a future candidate `u` for which the release evaluator's witness-sensitive oracle queries form a finite set `Q_u` that was not queried or otherwise cryptographically committed by `Build`. Conditioned on the setup transcript, the answers `H|Q_u` are therefore fresh.

Let `A_u` be the nonempty set of assignments to those fresh oracle answers for which the public PoW/local-validity predicate accepts. Assume a strictly black-box local evaluator

\[
  \mathsf{Eval}^{H}(P,u)
\]

whose dependence on the future witness is only through those fresh oracle answers and public data. If correctness requires that every accepting local completion recover the same `K` (except error `eps`), then a party with no real PoW witness can run the public evaluator against a privately simulated local oracle sampled from the fresh-oracle distribution conditioned on `A_u`.

Because `Build` never saw those oracle entries, the simulated accepting local view has exactly the same conditional law as an honest fresh local view given that it is valid. Therefore the simulator recovers `K` with the same correctness probability, without finding a valid input under the real oracle.

### Consequence

A secure release mechanism cannot be merely **relativizing black-box hash gating** on future, setup-unbound SHA/RO values. It must introduce a nonlocal cryptographic correlation that distinguishes *the actual fixed hash computation* from a privately simulated accepting one. Examples of mechanisms outside this theorem's scope include a non-black-box circuit encoding, obfuscation, FE/WE-like encoding, or a relation-specific algebraic trapdoor. The theorem is intentionally not an impossibility result for those mechanisms.

This sharpens Run 337's independent-local-state theorem. Run 337 showed that independent witness-local states which must agree for all cross-products collapse to a public constant. Run 338 adds that even a one-witness public oracle gate cannot safely treat a future uncommitted hash answer as the secret release source: the public evaluator can be run on a privately simulated accepting oracle completion.

For a multi-block no-retarget chain, the attack already applies at the first fresh child-header hash neighborhood unless a nonlocal protected object cryptographically binds the evaluator to the actual hash computation. Adding further linked headers does not repair the first fresh seam.

### Exact scope

This theorem assumes the relevant future hash neighborhood is setup-unbound and used black-box. It does **not** say that an LWE encoding of the SHA-256 circuit, a special-purpose obfuscation, or another non-relativizing construction can be forked this way. Such an encoding is precisely where the remaining cryptographic burden must live.

## 2. Standard-LWE compute-and-compare is an exact functional near-miss, not an instantiation

Wichs–Zirdelis construct LWE-based obfuscation for

\[
CC[f,y](x)=\mathbf 1[f(x)=y]
\]

and a multi-bit form `MBCC[f,y,z]` which emits a payload `z` on equality. Functionally this looks ideal: set `z=K` and try to make equality mean “valid PoW.”

The published security premise, however, requires the target `y` to have sufficient pseudo-entropy/unpredictability given `f` and auxiliary information. The direct PoW encoding

\[
f(u)=\mathbf 1[H(p\|u)\le T],\qquad y=1
\]

has a deterministic public target. Its conditional min-entropy is zero, so the theorem does not apply.

Two obvious repairs fail at exact scope:

1. **Hide a random equality target.** If `f` is independent of that target, equality selects one output value. When the threshold-valid hash set contains more than one value, a single equality target cannot accept every valid PoW witness. All-witness correctness is lost.
2. **Bake the hidden target into `f`.** If `f_y` contains enough information to output `y` on every valid PoW witness, then the target is determined by the program description `f_y`; the required target pseudo-entropy given `f` again collapses. Hiding that embedded constant is exactly the non-black-box protection being sought, not a free reduction.

Thus LWE compute-and-compare gives an extremely close *functionality template* for single-block `R_work`, but its proven security condition excludes the direct public-threshold encoding.

## 3. 2026 LWE range-constrained PRFs are also a near-miss because outputs vary with the witness

Cheng–Goyal (CRYPTO 2026 / ePrint 2026/1874) construct collusion-resistant constrained PRFs from standard LWE for compute-and-compare and predicated range constraints, with an almost-key-homomorphic feature. A range constraint is structurally much closer to `H(p||u) <= T` than equality obfuscation.

But an ordinary constrained PRF authorizes evaluation of a pseudorandom function **at an allowed input**. Its value is generally `F_s(u)`, not one statement-wide constant. If one tries the obvious Run-336-style public offset

\[
C=K-F_s(u)
\]

with a single setup-time `C`, all satisfying witnesses recover the same `K` iff `F_s` is constant over the entire satisfying set. For a uniformly random function into a group of size `q` on `m` satisfying inputs, the exact probability of constancy is

\[
  q^{1-m}.
\]

The checker exhausts this law. Likewise, almost key homomorphism does not by itself create a key difference whose PRF evaluation is a constant on the whole PoW-valid set. For two arbitrary functions, their pointwise difference is constant on an `m`-point set only for the same restricted family; this is exhaustively checked for small groups.

This pass therefore does **not** reject the Cheng–Goyal machinery as a possible ingredient. It rejects only the direct inference

`range CPRF from LWE -> same-capability PoW release`.

A new programming theorem would still be required: some key direction/correction must force one hidden constant over every satisfying PoW input without exposing that constant publicly. Assuming such a theorem would simply name the missing primitive.

## 4. Finite exact checks

`ro_local_release_run338_check.py` is deterministic and standard-library only. Two executions were byte-identical.

It performs 40,102 assertions covering:

1. one-local-query exact forked-oracle tables for output alphabets of size 2 through 6;
2. a complete two-local-query enumeration over all `2^16` Boolean evaluator tables for a four-symbol oracle alphabet;
3. equality-target coverage of threshold-valid output sets, showing a single equality target covers every valid hash value only in the singleton case;
4. the exact CPRF one-offset constancy law `q^(1-m)` for groups `q=2..7`, valid-set sizes `m=1..5`;
5. exhaustive small key-homomorphic difference tables, confirming that constant recovery requires a constant difference function on the valid set;
6. conditional freshness of an unqueried oracle location after a disjoint setup query.

Final hashes:

- checker SHA-256: `4bfeab9a1e31e5eb96ea001efda26a7b864ff5c768df19b5a5b05b15dba3964b`
- captured output SHA-256: `cd2a44b0d533014fb30785b5da22e5c4bf8eb16e2d0c76ebb8ba3bd1f447c501`
- repeat output SHA-256: identical.

These finite checks validate combinatorics and interface logic only. They are not evidence for LWE hardness, SHA-256 random-oracle behavior, or a full cryptographic security theorem.

## 5. Relation to existing positive pieces

### Run 259

Run 259 remains downstream and useful. Once a recovered branch hash/capability yields an accepted source-bound representation `z`, Run 259 supplies either information-theoretic residual binding or its stated straight-line SIS reduction:

\[
\text{accepted }z\Longrightarrow \text{ORIGINAL witness / stated SIS break}.
\]

Run 338 does not alter that theorem. The missing arrow remains the release-side one.

### Run 115

The noisy short-preimage HPS remains an algebraic candidate only when the statement supplies an affine common target with a genuine short-preimage source-soundness gap. The fixed-prefix SHA-256 threshold relation does not currently provide such a representation. Replacing SHA-256 with a public linear surrogate would abandon the actual bridge relation.

### Run 122

The VTDH pad layer has a straight-line QPT-LWE hiding lift under its exact assumptions, but its unresolved fixed-digest/source-opening problem is the same semantic fault line seen here: setup can create public material before the future source witness exists, while unauthorized key recovery still needs to imply a source-bearing object. Run 338 does not reopen the already-settled pad-hiding proof.

## 6. Attack taxonomy

This pass directly tests:

- **(1) local seam/cancellation:** a future hash-local seam can be privately re-simulated if it is not cryptographically bound to setup;
- **(3) statistical/function-class fingerprint:** equality-target and range-output semantics are distinguished exactly;
- **(5) adaptive/chosen-input/public evaluation:** the attack explicitly reruns the public evaluator on a privately simulated accepting local oracle;
- **(7) replay/context:** `p` is statement-bound in the model; replay across another prefix is outside the accepting relation;
- **(9) quantum:** the new seam attack is information-theoretic/classical and therefore applies to QPT adversaries a fortiori, but it is not a quantum-specific attack.

Still unresolved are multi-capsule correlations, malicious retained builder randomness in the optional keyless model, auxiliary checking-key correlations for any actual construction, and genuinely coherent attacks against a concrete non-black-box LWE encoding.

## 7. QPT/security ledger

| Component | Model | Status |
|---|---|---|
| black-box fresh-RO local-release barrier | classical public algorithms; arbitrary postprocessing | information-theoretic within stated relativizing scope |
| Wichs–Zirdelis CC/MBCC | standard LWE, target pseudo-entropy premise | direct PoW target violates premise; no instantiation claimed |
| Cheng–Goyal range CPRF | standard LWE per paper; outputs PRF values on allowed inputs | direct same-key wrapper fails unless values/difference are constant |
| Run 259 source binding | classical setup; arbitrary QPT outputting classical representation | unchanged: IT fold or exact stated QPT-SIS route |
| full `R_work` release | classical build/eval; arbitrary QPT attacker | **UNPROVED** |

No PPT theorem is relabeled QPT. No generic-group or ideal-mixer statement is promoted to concrete PQ security.

## 8. Core handoff

The no-retarget `R_work` branch is now narrower than “generic NP,” but not yet narrow enough for a known standard-LWE primitive to solve directly.

The surviving object can be stated precisely as a **non-relativizing constant-payload range release** for one hard-coded hash predicate:

\[
\mathsf{Release}_{p,T,K}(u)=
\begin{cases}
K & H(p\|u)\le T,\\
\perp & \text{otherwise.}
\end{cases}
\]

It must be built before `u` exists, reveal the same `K` for every valid `u`, hide `K` from arbitrary QPT attackers lacking a valid source witness, and make recovered `K` yield a source-bearing representation or an independently justified QPT break. Calling this object an obfuscator, range payload token, or local mixer would be circular unless it is instantiated from a narrower standard assumption.

The next bounded pass should therefore inspect whether Cheng–Goyal's **predicated-range + almost-key-homomorphic construction** contains an algebraic programmable direction that can realize a constant payload on a whole range, not merely variable PRF evaluations. If the full proof shows no such direction, the standard-LWE CPRF route is closed at direct-composition level. If it does, the candidate must immediately be attacked for multi-token zeroizing, malicious setup, checking-key correlation, and arbitrary-QPT extraction.

The practical PQ witness-KEM stopping condition remains unmet.

## Primary literature consulted

- Daniel Wichs, Giorgos Zirdelis, *Obfuscating Compute-and-Compare Programs under LWE*, FOCS 2017 / ePrint 2017/276.
- Jiaqi Cheng, Rishab Goyal, *Collusion-Resistant Constrained PRFs for Compute-&-Compare Predicates from LWE*, CRYPTO 2026 / ePrint 2026/1874.
- Boaz Barak, Nir Bitansky, Ran Canetti, Yael Tauman Kalai, Omer Paneth, Amit Sahai, *Obfuscation for Evasive Functions*, TCC 2014.
- Malavolta et al., *How to build time-lock encryption*, Designs, Codes and Cryptography 2019 (Bitcoin reference-clock construction uses witness encryption for the corresponding chain relation).
