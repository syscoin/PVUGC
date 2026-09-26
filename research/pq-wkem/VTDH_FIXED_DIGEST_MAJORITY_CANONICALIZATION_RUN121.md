# Run 121 — VTDH fixed-digest majority canonicalization: a real same-key layer, but source gating must be simulation-aware

## Status

Starting repository state was read from `syscoin/PVUGC#1` before research:

- branch: `research/pq-wkem-validation-20260918`
- head: `a0803edfa691f184e33ca92620471a81c17c611c`
- PR: open, draft, unmerged
- latest ordinary publication comment: `5843580758`, recording Runs 104–108 and 110–111.

The branch does not contain Runs 112–120; those remain historical local-only checkpoints from the conversation and are used here only as research context, not silently republished.

This run follows Run 120's rejection of the direct

`one-hot affine source compiler + centered noisy linear HPS/LWE`

composition.  Instead of asking noise magnitude to distinguish source-valid from ambient affine preimages, it audits the 30 March 2026 revision of Branco–Choudhuri–Döttling–Jain–Malavolta–Srinivasan, *Black-Box Non-Interactive Zero Knowledge from Vector Trapdoor Hash* (ePrint 2024/1514), and extracts a different primitive from its **statistical binding** property.

The new positive result is:

> A statistically binding VTDH already contains a robust, non-unique-proof **same-key canonicalization layer for one fixed digest**.  If all valid opening-bit vectors are within Hamming radius `t` of the digest's hidden decoded vector and `4t<k`, then a setup pad formed from any one honest opening vector lets **every** full valid opening vector recover the same setup-selected bit by majority.

The construction does **not** yet solve generic-NP source gating.  In fact, the audit sharpens that missing primitive: because setup can itself create one valid opening vector without the source witness, source extraction cannot simply say “every valid opening implies an ORIGINAL witness.”  The needed fixed-digest source-opening relation must be **simulation-aware**: setup may create/erase a simulated opening using temporary state, while later unauthorized opening/key recovery must still yield an ORIGINAL source witness or an independently justified QPT-hardness break.

No production code is changed.

---

## 1. Exact VTDH interface used

The current ePrint revision defines VTDH algorithms

- `Setup`,
- `Hash`,
- `Encode`,
- `Decode`, and
- `Verify`.

For `k` encoding positions, `Hash(hk,x)` returns one digest `h` and local openings `pi_i`.  `Encode(ek_i,pi_i)` gives a bit `e_i`; `Decode(td_i,h)` gives a bit `d_i`; `Verify(hk,h,i,pi_i)` checks the local opening.

The statistical-binding definition is unusually strong for our purpose.  For a universal constant `0<epsilon<1`, even an **unbounded** adversary has negligible probability of producing one digest and valid local openings at every index for which

`HW(e xor d) > t(lambda,k) := k^epsilon * poly(lambda)`.

The hiding definition is separate.  It switches to an alternate setup mode and states per-index pseudorandomness against **PPT adversaries**: the selected encoded bit remains pseudorandom even given the digest and all other local openings.

Two scope points matter:

1. statistical binding is information-theoretic;
2. the published computational hiding theorem is **classical/PPT as stated**, not automatically QPT.

The paper's LWE construction has polynomial modulus-to-noise ratio.  Its key-pseudorandomness proof uses ordinary LWE hybrids and, in one step, LWE with binary LWE matrices attributed to `[BLMR13]`; the paper still states the adversary as PPT.  This run does not silently promote that chain to a quantum theorem.

---

## 2. Fixed-digest majority wrapper

Let public VTDH parameters be

`PP = (hk, ek_1, ..., ek_k)`.

During setup, sample a random VTDH hash input `x_0` and compute

`(h, pi^0_1, ..., pi^0_k) <- Hash(hk,x_0)`.

Let

`r_i = Encode(ek_i, pi^0_i)`

and write `r=(r_1,...,r_k)`.

Choose the WKEM raw key bit

`K <- {0,1}`

and publish the bit pad

`p = r xor K^k`,

where `K^k` is the all-`K` vector of length `k`.

The public fixed-digest capsule is

`C = (PP, h, p)`.

Setup may erase `x_0` and `pi^0` after finalization.

A future party supplying a **full valid opening vector**

`pi=(pi_1,...,pi_k)`

for the **same fixed digest `h`** computes

`e_i = Encode(ek_i,pi_i)`

and returns

`K' = Majority(p xor e)`.

This is classical and polynomial-time.

---

## 3. Canonical same-key theorem

Let

`d(h)=(Decode(td_1,h),...,Decode(td_k,h))`.

Suppose statistical binding gives radius `t`, so every full valid opening vector for this fixed digest has encoding vector in the Hamming ball

`B_H(d,t)`.

The setup-generated `r` is also the encoding of a full valid opening vector, except with the negligible completeness/binding failure already present in the VTDH definition.  Therefore, on the good setup event,

`dist_H(r,d) <= t`

and for any future full valid opening vector `e`,

`dist_H(e,d) <= t`.

By the triangle inequality,

`dist_H(r,e) <= 2t`.

But

`p xor e = K^k xor r xor e`.

A vote differs from `K` exactly where `r` and `e` differ.  Hence at most `2t` votes are wrong.

### Theorem 1 — fixed-digest canonicalization

If

`4t < k`,

then every full valid opening vector for the fixed digest returns the **same** setup-selected key bit `K` by strict majority.

This is information-theoretic once the VTDH binding event holds.  It does not require uniqueness of proofs, uniqueness of hash preimages, a KDF inversion theorem, or centered-noise magnitude separation.

The threshold is natural: when `4t>=k`, two strings each lying within radius `t` of the same center can be separated by at least `k/2`, so universal strict-majority correctness can tie or fail.

Because the VTDH bound has

`t = k^epsilon * poly(lambda)`

with universal `epsilon<1`, choosing `k=lambda^a` with sufficiently large constant `a` makes `t/k` vanish and therefore permits `4t<k` asymptotically, subject to the construction's own parameter inequalities.

---

## 4. Multi-bit extension

The one-bit repetition vector is only the simplest exact statement.

More generally, let `Enc_code(K)` be a binary error-correcting codeword with minimum distance `Delta`.  Publish

`p = r xor Enc_code(K)`.

A future full valid opening obtains

`Enc_code(K) xor (r xor e)`

with at most `2t` corruptions.  Therefore unique decoding works whenever

`4t < Delta`.

As `t/k=o(1)`, an asymptotically good binary code could in principle carry a linear number of raw key bits per VTDH block.  This run does not select or benchmark a concrete code; the checker validates the repetition/majority special case exactly.

---

## 5. Conditional hiding from the VTDH hiding game

The pad layer itself introduces no new cryptographic assumption if the setup-generated `r` is jointly pseudorandom.

The VTDH definition gives **per-index** pseudorandomness in the alternate setup mode, even while revealing all *other* local openings.  For our capsule we reveal **no** local openings.  A standard coordinate hybrid therefore gives joint pseudorandomness of

`r=(r_1,...,r_k)`

for this weaker public view:

1. replace coordinate `1` by uniform using index-1 pseudorandomness;
2. continue through coordinate `k`;
3. ignore the extra other-opening information supplied to each reduction;
4. locally sample the coordinates already replaced by uniform.

If each coordinate hybrid costs at most `adv_i`, the total cost is at most

`sum_i adv_i`.

Mode indistinguishability then transports the result from the alternate setup to the real public setup parameters by ordinary efficient post-processing: sample `x_0`, compute `Hash`, compute the encoded vector, xor the chosen codeword, and publish the capsule.

After all coordinates are uniform,

`p = U_k xor K^k`

is exactly uniform and independent of `K`.

### QPT classification

The reduction *shape* above is quantum-clean **if** both VTDH mode indistinguishability and per-index pseudorandomness are available against QPT adversaries:

- one straight-line invocation of the adversary per hybrid;
- no rewinding;
- no cloning of auxiliary quantum state;
- no random-oracle programming;
- no extraction from a measurement transcript.

But the source paper quantifies pseudorandomness over **PPT** adversaries.  Its concrete LWE instantiation uses an additional binary/non-uniform LWE transformation in the key-pseudorandomness proof.  This run has not completed the separate theorem audit needed to claim that entire proof against arbitrary QPT adversaries.

Therefore:

`VTDH fixed-digest pad hiding against QPT = UNPROVED`.

The majority correctness/binding theorem itself is information-theoretic.

---

## 6. Why this does not inherit Run 120's noise-only failure

Run 120 showed that a centered noisy linear HPS accepts public source-invalid affine pseudowitnesses because they evaluate the same linear identity with only a constant-factor larger Gaussian residual.

The Run-121 wrapper does not decide validity from the magnitude of a centered real-valued residual.  It uses a **digital binding ball** around one hidden decoded bit vector.  Once a full opening passes the VTDH verification predicates, statistical binding says its encoded vector lies near the same canonical center.

Thus proof non-uniqueness is no longer, by itself, a same-key problem.

This is a genuine positive correction to the previous handoff:

> VTDH is not merely a NIZK ingredient.  Its statistical binding can be repurposed as a fixed-digest canonical-key reconciliation layer.

But the qualification “fixed digest” is decisive.

---

## 7. The paper's HBG/NIZK transform does not provide fixed-digest source opening

The paper's own VTDH -> hidden-bits-generator transform does the following **at proof generation time**:

`x <- random`

`(h,pi_1,...,pi_k) <- Hash(hk,x)`

`com := h`.

So each honest hidden-bits generation samples its own fresh hash input and its own commitment/digest.  The generic NIZK prover built on that HBG therefore does **not** take a digest fixed earlier by a witness-free WKEM setup and then teach an arbitrary NP witness how to open that same digest.

That difference kills the naïve direct composition:

- WKEM setup needs one fixed `h_0` because the pad is tied to its canonical opening-bit class;
- the future VTDH/HBG prover normally generates a new `h`;
- a new `h` has a new canonical bit class and therefore does not recover the setup key.

Publishing a separate pad for every possible future digest would simply move the missing witness-release problem into another exponentially large or cryptographic map.

---

## 8. Stronger source-gating correction: extraction cannot cover *every* valid opening

There is a second, important consequence.

Setup itself generated

`(h, pi^0_1,...,pi^0_k)`

without knowing an ORIGINAL source witness.

Therefore no generic theorem of the form

`every full valid opening vector for h -> ORIGINAL source witness`

can hold for this wrapper: applying that extractor to setup's own valid vector would solve the source search problem during witness-free setup.

This is the fixed-digest analogue of the setup-known-value warning from Run 112.

A viable source compiler must instead distinguish **simulated/setup-generated** openings from **knowledge-bearing** future openings at the proof level.  In other words, the missing primitive now looks like a simulation-aware fixed-digest opening system:

1. witness-free setup, using temporary erased simulation state `tau`, may create the fixed digest and one opening vector needed to form the pad;
2. after `tau` is erased, a genuine source witness can create another full valid opening vector for the same digest;
3. an unauthorized QPT process that recovers the final key or creates an additional useful opening must imply either an ORIGINAL source witness or a break of an independently justified QPT-hard assumption;
4. the extractor/reduction must not incorrectly extract from the setup simulator's own opening.

This resembles the role of simulation-extractability / dual-mode proof systems, but **no cited construction is being claimed here to instantiate it**.

---

## 9. Relation to WPRF / invariant-adaptor checkpoints

Run 111 asked for a common hidden invariant across non-unique completions.  Run 112 corrected the over-strong idea that the common value itself could have a value-only witness extractor.  Run 113 identified WPRF as the right functionality abstraction.

Run 121 gives a concrete partial answer to the **common-value** half:

`non-unique full openings`

`-> statistically bounded Hamming class`

`-> error-correcting canonicalization`

`-> one common setup key`.

The common value need not be literally identical at the raw `Encode` layer; an error-correcting wrapper can quotient the whole binding ball to one key.

What remains is the source gate and QPT security of the computational hiding layer.

---

## 10. Exact checker

`vtdh_fixed_digest_majority_run121_check.py` is deterministic and standard-library-only.

Three executions were byte-identical.  The finalized output records **494,480 assertions** and checks:

1. exhaustive fixed-center binding balls for multiple `(k,t)` with `4t<k`;
2. every pair of valid encoding vectors in those balls and both key bits;
3. every possible decoded center for independent small-`k` controls;
4. tightness examples when `4t>=k`, producing either ties or wrong majorities;
5. exact pad-distribution equality for uniform opening bits through `k=10`;
6. exact hybrid-bound arithmetic controls;
7. the fact that *any* vector in the accepted binding ball decapsulates, regardless of whether it came from a source witness.

These checks validate finite combinatorics and wrapper functionality.  They are not evidence for computational LWE hardness, QPT hiding, or a generic-NP fixed-digest source-opening compiler.

---

## 11. Assumption / dependency ledger

| Component | Honest model | Adversary model actually justified here | Assumption / distribution | Conclusion |
|---|---|---|---|---|
| VTDH statistical binding | classical | unbounded | source paper's VTDH construction/parameters | valid opening vectors lie in a sublinear Hamming ball except negligible setup failure |
| Majority canonicalization | classical | unbounded | none beyond binding event | every full valid fixed-digest opening gets same bit if `4t<k` |
| Pad hiding hybrid | classical | PPT **as published** | VTDH mode indistinguishability + per-index pseudorandomness | classical computational hiding of the codeword/key, conditional on the paper's games |
| QPT lift of pad hiding | classical | arbitrary QPT | would require QPT versions of the entire VTDH LWE proof chain | **UNPROVED** |
| Fixed-digest source opening | classical | arbitrary QPT target | no adequate construction supplied | **UNPROVED** |
| Unauthorized FINAL-key recovery -> ORIGINAL witness / QPT break | classical honest algorithms; QPT extractor permitted | arbitrary QPT | depends on missing source-opening compiler | **UNPROVED** |

---

## 12. Next handoff

Do **not** return to centered-noise norm filtering or direct public affine pseudowitnesss.

The next highest-value target is now:

> **simulation-aware fixed-digest source opening** over a statistically binding VTDH/HBG-style canonicalization layer.

Concretely, search for a construction where a setup trapdoor can generate exactly one simulated fixed-digest opening class and erase, while a genuine NP witness can later generate an opening to the **same** digest, and where additional opening/final-key recovery is QPT-extractable to the ORIGINAL source witness or an independently justified QPT-hardness break.

In parallel, audit the LWE VTDH proof's `[BLMR13]` binary/non-uniform LWE step for an explicit QPT-preserving reduction.  Until that is done, the computational hiding half is classical-only as published.

The practical generic-NP PQ WKEM stopping condition is **not met**.
