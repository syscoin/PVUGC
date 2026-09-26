# Run 117 — exact one-hot affine source compiler, and the same-secret failure of shifted multi-preimage matrices

## Status

Starting PR head: `a0803edfa691f184e33ca92620471a81c17c611c` on `research/pq-wkem-validation-20260918`; PR #1 was open, draft, and unmerged. This run continues Run 116 rather than republishing Runs 112–116.

Run 116 left two issues entangled: (1) construct a generic-NP affine short-preimage relation whose every sufficiently short solution extracts an ORIGINAL source witness, and (2) make the carrier compatible with standard QPT-hard LWE. This run separates them.

The first issue has a simple exact solution for 3SAT: a polynomial-size one-hot affine compiler with an l1 gap. The second issue remains the hard one. A natural attempt to use the Waters–Wee–Wu shifted multi-preimage matrices to obtain uniform-looking LWE carriers fails if the same LWE secret is reused across two correlated matrices: public differencing cancels the shared random matrix and exposes a noisy powers-of-two gadget encoding of the secret.

No production path is changed.

## 1. Exact 3SAT -> affine short-preimage compiler

Let `phi` be a 3CNF on variables `x_1,...,x_n` with `m` clauses. We build an integer matrix `M`, target `t`, and bound

`B = n + m`.

For every variable `x_i`, create a two-coordinate group `(v_{i,0},v_{i,1})` and impose

`v_{i,0}+v_{i,1}=1`.

For every clause `C_j`, create one coordinate `c_{j,a}` for each locally satisfying assignment `a in {0,1}^3` of that clause and impose

`sum_a c_{j,a}=1`.

For each clause position `p` referring to global variable `x_i`, impose the consistency equation

`sum_{a: a_p=1} c_{j,a} - v_{i,1}=0`.

All coefficients lie in `{-1,0,1}`. The number of columns is at most `2n+7m` for ordinary non-tautological clauses and remains polynomial with repeated literals. The number of rows is `n+4m`.

### Completeness

A satisfying assignment chooses one coordinate in every variable pair and the unique local 3-bit assignment induced in each clause group. The resulting vector `z` is Boolean, satisfies

`Mz=t`,

and has exactly one `1` per group, hence

`||z||_1=B`.

### Supplied-short-preimage extraction

Now let `z` be an **integer** solution of `Mz=t` with

`||z||_1 <= B`.

The group-sum equations have disjoint supports. For every group `G`,

`sum_{k in G} z_k = 1`,

so by the triangle inequality

`sum_{k in G} |z_k| >= 1`.

There are exactly `B` groups. Therefore `||z||_1 >= B`. Combining this with the assumed upper bound forces equality in every group. For an integer vector with coordinate sum `1` and l1 norm `1`, the negative mass is zero and the positive mass is exactly one, so the group is a standard basis vector: exactly one coordinate equals `1` and all others equal `0`.

Thus every variable group selects one Boolean value, every clause group selects one locally satisfying assignment, and the consistency equations force the selected local bits to equal the global variable bits. The extracted global assignment satisfies every clause.

Hence

`Mz=t and ||z||_1 <= B  =>  ORIGINAL satisfying assignment`.

This is deterministic polynomial-time supplied-representation extraction.

### Modular form

Interpret `z` by centered integer representatives modulo `q`. Since every row of `M` has coefficients of magnitude at most one and `t_r in {0,1}`,

`|(Mz-t)_r| <= B+1`.

If `q>2(B+1)` and `Mz=t mod q`, the residual is a multiple of `q` of magnitude strictly below `q/2`; therefore it is zero over the integers. The extractor above applies unchanged.

So the compiler gives the exact affine relation Run 115/116 wanted:

`M_phi z = t_phi (mod q), ||z||_1 <= n+m  =>  ORIGINAL 3SAT witness`.

The semantic short-preimage compiler was therefore not the fundamental missing piece. The remaining difficulty is embedding this highly structured `M_phi` into a standard-LWE-hard public carrier without destroying the short witness or creating public short pseudowitnesses.

## 2. Why ordinary left/right randomization still does not finish it

Run 116 already showed the basic conflict. Left multiplication preserves every witness but preserves the row space. Right multiplication can randomize a full-rank orbit, but maps any fixed nonzero short witness to a uniform nonzero vector and therefore destroys the l1 guarantee with overwhelming probability at cryptographic dimensions.

The one-hot compiler sharpens that conclusion: it gives an exact source-extraction threshold `B=n+m`, but its security carrier remains visibly structured.

## 3. Waters–Wee–Wu shifted multi-preimage sampler

Waters, Wee, and Wu, *New Techniques for Preimage Sampling: Improved NIZKs and More from LWE* (ePrint 2024/1401, EUROCRYPT 2025), construct correlated matrices with uniform individual marginals and a succinct public shifted-multi-preimage trapdoor.

Their construction expands a uniform CRS `[A|B]` into

`A_i = [A | B - u_i^T tensor G]`,

where `u_i` is the binary representation of the index and `G=I_n tensor g^T` is the powers-of-two gadget. The public sampler can, for arbitrary targets `t_i`, produce one common shift `c` and short `pi_i` satisfying

`A_i pi_i = t_i + c`.

The security notion is deliberately **somewhere**: SIS/LWE should remain hard for any *individual* `A_i` even given the other matrices and the public trapdoor; a programmable sampler can embed an arbitrary random matrix at one selected index. The theorem also gives transparent setup, local expansion, simulatable openings, and perfect somewhere programmability.

This is highly relevant to Run 116 because it solves an auxiliary-view challenge-embedding problem for one selected random marginal. It does **not** say that ordinary LWE with one common secret remains hard when simultaneous LWE samples under all of the correlated `A_i` are published.

## 4. Same-secret joint LWE is broken by matrix differencing

Consider the tempting composition

`b_i = A_i^T s + e_i`

using the **same** secret `s` for two different indices `i != j`. Partition off the W-W-W tail:

`A_i^tail = B - u_i^T tensor G`.

Then

`b_i^tail - b_j^tail`

is

`((u_j-u_i)^T tensor G)^T s + (e_i^tail-e_j^tail)`.

Because `u_i != u_j`, choose any bit position `r` where they differ. The corresponding public block of the difference is exactly

`+/- G^T s + eta`,

with

`||eta||_infinity <= ||e_i||_infinity + ||e_j||_infinity`.

For the standard powers-of-two gadget, Run 110 proved the separation lemma

`max_h |2^h delta|_q >= q/3`

for every nonzero `delta mod q`. Therefore `G^T s+eta` uniquely determines `s` whenever

`||eta||_infinity < q/6`.

With per-sample bound `||e_i||_infinity,||e_j||_infinity <= E`, it is enough that

`2E < q/6`, i.e. `E < q/12`.

Thus:

**Theorem (same-secret correlated-matrix leak).** For any two distinct W-W-W index labels, publishing bounded-error LWE vectors under `A_i` and `A_j` with the same secret reveals the entire secret by classical polynomial-time public differencing whenever `E<q/12`.

This attack does not use the public trapdoor and does not contradict the W-W-W theorem. Their theorem protects each selected marginal in its somewhere-programmable game; the attack exploits a joint same-secret sample distribution that their stated individual-marginal claim does not provide.

For narrow unbounded Gaussians the deterministic statement becomes a high-probability one conditioned on the difference noise staying in the `q/6` decoding radius; no blanket concrete probability is claimed here.

## 5. Consequence for combining the one-hot compiler with shifted multi-preimages

There is an attractive algebraic identity behind the failed composition. Suppose public shifted preimages satisfy

`A_j pi_j = tau_j + c`.

If a Boolean source witness selects exactly `B` items and its item targets satisfy

`sum_j z_j tau_j = T`,

then a same-secret projected hash would telescope to

`sum_j z_j b_j^T pi_j = s^T(T+B c) + noise`,

which is independent of the particular valid witness. This would give the desired all-witness common value.

But implementing all `b_j` with one common secret is exactly what the difference attack above destroys. Using independent secrets removes that attack but also removes the telescoping common-value identity unless an additional secret-sharing/correlation layer is supplied. Constructing that layer without recreating public quotient or pseudorepresentation attacks is again a nontrivial witness-release problem.

So W-W-W supplies a valuable challenge-embedding and public shifted-preimage component, but the direct same-secret bridge to the Run-115/116 noisy HPS is invalid.

## 6. QPT/security ledger

### One-hot affine compiler

Honest algorithms: classical deterministic polynomial time.

Adversary model: none needed for the extraction lemma; it is unconditional.

Conclusion: any **supplied** centered modular preimage with l1 norm at most `n+m` yields an ORIGINAL satisfying assignment when `q>2(n+m+1)`.

This does not constrain an arbitrary final-key recovery algorithm to output such a preimage.

### W-W-W sampler

The paper gives individual-marginal SIS/LWE somewhere hardness, transparent setup, and shifted sampling. Its paper-level security statements are not silently upgraded here to arbitrary-QPT theorems.

The same-secret attack is classical and unconditional under the stated bounded-error radius, so it refutes that naive composition against QPT attackers a fortiori.

### Standard-LWE wrapper from Run 116

The wrapper remains promising *if* its effective public carrier is an ordinary LWE distribution under independently justified QPT-hard parameters. This run does not produce such a carrier for `M_phi`.

## 7. Validation

`onehot_shifted_multipreimage_run117_check.py` is deterministic and standard-library-only. Three executions were byte-identical.

It checks:

- all sign patterns of a 3-variable clause plus repeated-variable satisfiable and unsatisfiable fixtures;
- 188,616 vectors in exact l1 balls;
- every short modular solution found in those fixtures unwraps and extracts a satisfying assignment;
- the group l1 equality -> one-hot lemma on small widths;
- 240 randomized W-W-W-tail difference attacks for `q in {31,61,127,257}`;
- exact recovery of the shared secret whenever `2E<q/6`;
- an independent-secret semantic control.

Total recorded assertions: 1,265. These finite checks validate algebra/functionality only; no computational security follows from them.

## 8. Next handoff

The next pass should not search for another semantic NP-to-short-vector compiler; this run supplies one. The real target is now:

1. a way to embed the structured one-hot affine relation into a public carrier whose **full joint output distribution** reduces straight-line to QPT-hard LWE/SIS;
2. while preserving the l1 source-extraction threshold;
3. without reusing a common secret across W-W-W correlated matrices, because public differencing exposes the gadget secret;
4. without replacing the problem by an assumed WE/WPRF-equivalent compiler.

Two concrete surviving directions are worth testing: an independent-secret encoding with a separately proven common-value sharing relation, or a single-marginal programmable construction where all NP structure is moved into a witness-dependent short preimage of one hard random carrier rather than spread over many correlated matrices.

The complete practical generic-NP PQ WKEM remains open.
