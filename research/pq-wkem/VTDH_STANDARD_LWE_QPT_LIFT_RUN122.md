# Run 122 — current VTDH formal proof gives a standard-LWE QPT lift for the Run-121 pad layer

## Checkpoint

Start state read from `syscoin/PVUGC#1`: branch `research/pq-wkem-validation-20260918`, head `4198b1815d3edc7be41ec1cb25c0c46fab24610e`, PR open/draft/unmerged, latest ordinary publication comment `5847380543`.

This run audits the **30 March 2026** revision of Branco–Choudhuri–Döttling–Jain–Malavolta–Srinivasan, *Black-Box Non-Interactive Zero Knowledge from Vector Trapdoor Hash*, ePrint 2024/1514, against Run 121's fixed-digest VTDH canonicalizer.

### New correction

Run 121 said the concrete LWE instantiation's key-pseudorandomness proof uses an additional binary/non-uniform-LWE transformation attributed to `[BLMR13]`. That is present in the **technical overview** (page 8), but it is not the dependency used by the **current formal Section 5 proof**.

Section 5 defines a gadget inverse `G^{-1}(A)` with `G G^{-1}(A)=A`. Lemma 8's formal `Hyb1 -> Hyb2` reduction receives an ordinary decisional-LWE challenge `(A,z)`, sets `W=G^{-1}(A)`, samples uniform `u'`, and sets

`v = z + u'W`.

If `z=sA+e`, then `A=GW` gives

`v=(sG+u')W+e`,

and `sG+u'` is uniform. If `z` is uniform, `v` is uniform. The preceding `Hyb0 -> Hyb1` step is likewise the ordinary replacement of polynomially many standard-LWE samples by uniform. Thus the formal proof does **not** need BLMR13 at this point. The page-8 sentence and the formal proof are inconsistent; for this audit the formal theorem/proof controls, without claiming author intent.

This materially upgrades Run 121's quantum status.

## QPT lift of the formal Section-5 hiding proof

The paper itself phrases the VTDH hiding game for PPT adversaries, so the following is a **derived theorem**, not an author-stated QPT theorem.

Assume decisional `LWE(q,n,sigma)` for the paper's Section-5 parameter/sample family is hard for the same class of QPT distinguishers under consideration. All honest algorithms remain classical PPT and all LWE samples/public views are classical.

Lemma 8's reduction is quantum-clean in shape: a classical reduction prepares one classical hybrid view, invokes the QPT distinguisher once, and returns its decision. It does not rewind, clone quantum state, program a random oracle, answer superposition oracle queries, or extract a witness. Therefore the same straight-line reduction contradicts **QPT-LWE** if a QPT adversary distinguishes the real public keys from the uniform alternate mode. With `k` encoding keys, a conservative ledger is at most two standard-LWE transitions per key, hence a polynomial loss such as `2k * Adv_LWE^QPT`.

Lemma 9 then proves the selected encoded bit statistically close to uniform under uniform hashing/encoding keys using conditional min-entropy plus the leftover-hash lemma, under its printed inequality

`ell <= (m - log(q) - 2lambda)/log(m)`

with even `q`. This is a distributional statistical-distance conclusion, so it holds against unbounded classical or quantum distinguishers regardless of the paper's PPT syntax.

## Consequence for the Run-121 fixed-digest pad

Run 121 publishes `p = r xor K^k`, where `r` is the encoded-bit vector of one setup-generated full opening for a fixed digest. Statistical binding already gave the same-key theorem: every full valid opening for that fixed digest recovers the same `K` by majority when `4t<k`.

For hiding, first switch the real public setup to the uniform alternate mode using the QPT lift of Lemma 8. Then replace the `k` coordinates of `r` by uniform one at a time using Lemma 9. The VTDH hiding game actually gives the adversary the stronger view of all other local openings; the Run-121 capsule reveals fewer. After all replacements, `p=U_k xor K^k` is exactly uniform and independent of `K`.

Hence, for polynomial `k`, a conservative advantage ledger is

`Adv_pad^QPT <= 2k * Adv_LWE^QPT + k * eps_stat(lambda)`,

where `eps_stat` is the per-coordinate statistical term from Lemma 9 (its displayed leftover-hash step is `2^-lambda`).

### Exact security classification

- **Honest model:** classical PPT setup/hash/encapsulation/decapsulation.
- **Adversary:** QPT on classical public outputs.
- **Hardness distribution:** standard decisional LWE with the exact Section-5 classical-sample parameter family, explicitly assumed QPT-hard.
- **Reduction model:** straight-line black-box; no rewinding, cloning, QROM, superposition-query simulation, or extraction.
- **Conclusion:** the **Run-121 VTDH pad/key-hiding layer** is QPT-secure conditional on standard QPT-LWE plus the paper's statistical parameter inequalities.
- **Not concluded:** generic-NP false-statement WE, fixed-digest source opening, or arbitrary-QPT true-statement FINAL-key recovery implying an ORIGINAL witness.

### Auxiliary-input boundary

The lift covers ordinary QPT adversaries, and nonuniform quantum advice only if QPT-LWE is assumed hard in the same advice model. Efficiently simulatable classical public transcript fields compose normally. It does **not** automatically cover an arbitrary quantum state correlated with the LWE secret/challenge that the reduction cannot generate; that would require a matching LWE-with-quantum-side-information assumption or a separate simulation theorem.

## Remaining bottleneck: simulation-aware fixed-digest source opening

The central witness restriction is unchanged. Setup itself can generate the fixed digest and one valid opening without knowing an ORIGINAL source witness, so no theorem of the form “every valid opening -> ORIGINAL witness” can be true.

The missing primitive must instead allow temporary setup simulation and erasure while ensuring that later genuine witnesses can open the **same digest**, and that unauthorized QPT FINAL-key recovery after setup implies either an ORIGINAL source witness or an independently justified standard-PQ break.

Generic simulation-extractable NIZK is not automatically enough: an adversary can in principle recover the key without outputting a fresh proof/opening. The reverse arrow required by the target is

`unauthorized QPT key recovery -> source-bearing object OR independent PQ break -> ORIGINAL witness`,

not merely `new proof -> witness`.

A related proof-interface constraint remains: because encapsulation itself sampled `K`, an extractor that sees only the adversary's final answer `K` learns no source-specific object. Any source proof must get leverage from a challenge value unknown to the reduction, a source-bearing representation/output, a quantum-safe multi-invocation theorem, or a direct independent hardness break. This is not a black-box impossibility theorem; it rules out the already-rejected value-only extraction pattern.

## Reproducible finite checker

`vtdh_standard_lwe_qpt_lift_run122_check.py` is deterministic and standard-library-only. Two executions were byte-identical. It checks tiny gadget inverses, the exact Lemma-8 embedding identity, uniformity under additive translation, exact Run-121 pad independence for uniform `r`, and representative Section-5.5 entropy inequalities. These checks validate algebra/bookkeeping only; they are not evidence of QPT-LWE hardness.

Final local SHA-256 before publication:

- checker: `17ffb313506f8a9105e58b6c8a34484584586286cff7dee3e8cdd783e7838442`
- captured output: `530dba26ed36e32a8f3cb688e69a0d1f627efbf2a4a5a27ef2528129e637f34f`

## Next handoff

Do not re-open the VTDH QPT-hiding question unless the paper/reduction changes. The highest-value next target is a **simulation-aware fixed-digest source-opening compiler** with an explicit QPT reverse-security arrow to the ORIGINAL NP witness or standard PQ break. Audit every candidate against arbitrary key recovery, not only proof forgery/extraction.

The complete practical generic-NP PQ witness-KEM stopping condition is **not met**.