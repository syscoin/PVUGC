# Run 152 — CMV-form MinRank capsule gives all-witness release and a one-copy QPT source extractor; structured-instance hiding is the remaining bottleneck

**Status:** new construction/reduction checkpoint. This is **not** a completed PQ
witness-KEM and does **not** claim that Chatterjee--Mu--Vasudevan (CMV) security
extends to the statement-derived Hair--Sahai instances below.

## 1. Verified repository starting point

Connected GitHub reads at the start of this run verified `syscoin/PVUGC#1`:

- branch `research/pq-wkem-validation-20260918`;
- exact head `a81bac1eb92e57160c5b373d7fbef8032e127d04`;
- open, draft, unmerged;
- latest ordinary PR comment read: `5859816284`, which records the publication
  catch-up for Runs 129 and 131--134.

Exact current-head inputs used here:

- Run 79, `ANCHOR_SHIFT_MINRANK_RUN79.md`,
  blob `30084603c3b35c449be4e154f6d214533526d3c5`;
- Run 82, `FINITE_DIFFERENCE_LOWRANK_RUN82.md`,
  blob `6430557fd1596308db029d17b48549f9ed9490c8`;
- Run 102, `FULL_KEY_ONE_COPY_QPT_EXTRACTION_RUN102.md`,
  blob `5ec37cfcf47fcdc68d279af1dc1b6c90a7287c8d`;
- Run 129, `HAIR_SAHAI_PUBLIC_ANCHOR_QUOTIENT_BARRIER_RUN129.md`,
  blob `cb74329d418b365abd325270185673b29fb10560`;
- Run 131, `TWO_SIDED_UNIFORMIZATION_AND_ANCHOR_RESIDUAL_RUN131.md`,
  blob `910ae37f9f03f7b712674e46cc672e76cb2ffc06`;
- Run 134, `GAPMDP_GAP_ONLY_SYNDROME_SEPARATION_RUN134.md`,
  blob `16d356d1118caf8db5e6a55eb659b9f9656a041e`;
- Run 147, `BITWISE_LACONIC_EXTWE_NATIVE_ESCROW_RUN147.md`,
  blob `440a59de11556424cefe51aa5433d383c757ee7b`.

Conversation-local blocked Runs 148--151 are not republished, renamed, or used as a
publication workaround in this run. The construction below can be stated directly
from the already-published Run-79/129 source interface.

## 2. Primary-source ingredient: CMV PKE correctness is really low-rank-residual correctness

Primary source audited this run:

Rohit Chatterjee, Changrui Mu, Prashant Nalini Vasudevan,
*Public-Key Encryption from the MinRank Problem*, arXiv:2510.03752.

CMV define a `t`-block-wise matrix inner product over `F_2` and prove

`rank(<A,B>_t) <= min(rank(A) rank(B), t)`.

Their PKE public key has random matrices `A_1,...,A_k` and

`Y=A(s)+E`

for a low-rank residual `E`. To encrypt zero they choose low-rank `R` and output

`(<R,A_1>_t,...,<R,A_k>_t,<R,Y>_t)`.

Decryption forms

`M=C_(k+1)-sum_i s_i C_i=<R,E>_t`

and recognizes its low rank. Encryption of one is a uniform tuple.

The paper's **security** proof needs uniformly random MinRank generators and its
formal theorem is against polynomial-time algorithms. Neither fact is changed
below.

But the **correctness algebra** does not need a randomly generated public key:

> for any fixed public tuple `(A_1,...,A_k,Y)` and any coefficient vector `s`
> whose residual `E=Y-A(s)` has low rank, that `s` decrypts the structured
> ciphertext in exactly the same way.

This observation is the bridge to the public NP source.

## 3. Compile the Hair--Sahai affine witness slice into one fixed MinRank public key

Run 79 gives the binary source interface after its recorded scalar descent:

- public matrix space `S_x`;
- public nonzero anchor `ell`;
- every ORIGINAL valid witness supplies `B_w in S_x` with
  `rank(B_w)=1` and `ell(B_w)=1`;
- on a false source, every nonzero source matrix has rank at least `D`;
- a supplied sufficiently low-rank nonzero source matrix feeds the ORIGINAL
  witness extractor.

Run 129 shows that setup can compute, with no witness,

`K_x=S_x cap ker(ell)`

and a public representative

`U_x in S_x, ell(U_x)=1`.

Let `K_1,...,K_d` be a public basis of `K_x`.

Then the entire anchor-one slice is exactly

`U_x + span{K_1,...,K_d}`.

For every ORIGINAL witness there is a coefficient vector `s_w` such that

`B_w=U_x+sum_i (s_w)_i K_i`

over `F_2`.

Define the fixed MinRank-form public key

`PK_x=(K_1,...,K_d,U_x)`.

Its residual at witness coefficient `s_w` is

`E_w=U_x-sum_i (s_w)_i K_i
    =U_x+sum_i (s_w)_i K_i
    =B_w`,

so

`rank(E_w)=1`.

### Result 1 — all-witness same-bit correctness

Use the CMV blockwise ciphertext form on this fixed public key.

Every ORIGINAL witness may correspond to a **different** coefficient vector
`s_w`, but every one obtains a rank-one residual and therefore decrypts the same
structured bit.

This removes an important ambiguity in the MinRank route:

> the witness need not canonicalize to one coefficient vector. The ciphertext bit
> is canonical even when the valid MinRank secrets are not.

Setup knows only the public source basis and anchor. It does not know `s_w`.

This is already the exact WE-like *correctness* interface required by the bridge.

## 4. Kronecker lift and stronger correctness parameters

For a block parameter `t`, set

`A_i'=J_t tensor K_i`,
`Y'=J_t tensor U_x`,

where `J_t` is the all-one matrix and has rank one.

For a valid witness,

`Y'-sum_i (s_w)_i A_i'=J_t tensor B_w`

still has rank one.

For the exact Fourier analysis below, sample

`R=sum_(j=1)^r u_j v_j^T`

with independent uniform factors. Then `rank(R)<=r`.

The structured ciphertext is

`C_i=<R,A_i'>_t`,
`C_(d+1)=<R,Y'>_t`.

A valid witness computes

`M_w=C_(d+1)-sum_i (s_w)_i C_i
    =<R,J_t tensor B_w>_t`,

and therefore

`rank(M_w)<=r`.

The uniform-bit branch makes `M_w` a uniform `t x t` matrix.

So unlike the original CMV generated-key setting, where both the public residual
and the encryption randomizer have rank about `r` and correctness uses an
`r^2` threshold, the source residual here has rank exactly one.

A threshold just above `r` suffices for the structured branch. Standard finite-field
rank counting gives exponentially small uniform-side error once the rank-deficiency
gap `t-r` grows sufficiently; for example a coarse bound is proportional to
`2^(-(t-r)^2)`.

This larger allowable randomizer rank is potentially important for hiding.

## 5. Exact complete-output Fourier law

Let one ciphertext contain `d+1` matrices in `F_2^(t x t)`.

Index a character by

`Lambda=(Lambda_1,...,Lambda_(d+1))`.

For every block position `(p,q)`, define the source matrix

`N_Lambda^(p,q)
 = sum_(i=1)^d (Lambda_i)_(p,q) K_i
   + (Lambda_(d+1))_(p,q) U_x`.

Assemble those `t^2` source matrices into one block matrix `N_Lambda`.

Bilinearity gives

`sum_i <Lambda_i,C_i>_F = <R,N_Lambda>_F`.

For one uniform outer product `u v^T`,

`E[(-1)^(u^T N_Lambda v)] = 2^(-rank(N_Lambda))`.

For `r` independent outer products,

`boxed(
  P0_hat(Lambda)=2^(-r rank(N_Lambda))
)`.

This is an **exact** complete-public-output law.

Because `{K_1,...,K_d,U_x}` is a basis of `S_x`, `Lambda != 0` implies that
at least one block `N_Lambda^(p,q)` is a nonzero matrix in the actual source space.

Hence on a false source,

`Lambda != 0  =>  rank(N_Lambda)>=D`.

This recovers Run 79's gap transfer, but now the decoder is the standard
MinRank-residual decoder rather than the anchor-shift `+mu I_t` decoder.

## 6. False-statement hiding has one exact rank-spectrum criterion

Define

`T_false(r)
 = sum_(Lambda != 0) 2^(-2r rank(N_Lambda))`.

For the normalized character convention,

`chi^2(P0 || U)=T_false(r)`,

where `P0` is the structured ciphertext distribution and `U` is uniform.

Therefore

`boxed(
 TV(P0,U) <= (1/2) sqrt(T_false(r)).
)`.

If `T_false(r)` is negligible, false-statement hiding is information-theoretic,
hence secure against arbitrary QPT adversaries.

The minimum-rank-only bound

`T_false <= (2^L-1) 2^(-2rD)`,
`L=(d+1)t^2`,

is again far too crude for the known Hair--Sahai dimensions.

Run 82 is directly relevant: the actual false Hair--Sahai source can contain
exponentially many efficiently constructible anchor-sensitive matrices of rank only
`R+1` or `R+2`. Putting one such matrix in one block gives corresponding
low-rank `N_Lambda` characters. Thus no sparse-near-gap heuristic may be assumed.

This run does **not** prove `T_false` negligible.

## 7. New theorem — arbitrary-QPT bit prediction source-extracts from the same rank spectrum

The more useful advance is on the TRUE-instance extraction side.

Let the challenge bit `beta` be uniform.

- if `beta=0`, give the structured ciphertext `C<-P0`;
- if `beta=1`, give a uniform ciphertext `C<-U`.

Let an arbitrary non-uniform QPT circuit adversary, with arbitrary mixed quantum
auxiliary advice, output a bit `bhat`.

Define its signed response

`f(C)=E[(-1)^bhat | C] in [-1,1]`.

If its prediction probability is

`Pr[bhat=beta]=1/2+epsilon`,

then exactly

`E_(P0)[f]-E_U[f]=4 epsilon`.

Using normalized Fourier coefficients,

`4 epsilon
 = sum_(Lambda != 0)
   f_hat(Lambda) 2^(-r rank(N_Lambda)).`

Fix a source-extraction rank threshold `B`.

Define the source spectral masses

`T_<=B
 = sum_(0<rank(N_Lambda)<=B)
   2^(-2r rank(N_Lambda))`

and

`T_>B
 = sum_(rank(N_Lambda)>B)
   2^(-2r rank(N_Lambda))`.

Parseval and Cauchy--Schwarz bound the high-rank contribution by

`sqrt(T_>B)`.

Put

`delta=4 epsilon-sqrt(T_>B)`.

If `delta>0`, then the adversary's low-rank Fourier mass obeys

`boxed(
 M_<=B
 = sum_(0<rank(N_Lambda)<=B) |f_hat(Lambda)|^2
 >= delta^2 / T_<=B.
)`.

### One-copy arbitrary-QPT Fourier extraction

Run 102 already proved the needed circuit fact for an arbitrary mixed auxiliary
state.

Given the adversary's circuit description, use a reversible dilation, phase the
classical output-bit register, apply the circuit adjoint, Fourier transform a
uniform ciphertext register, and measure `Lambda`.

For every `Lambda`, the actual measurement probability is at least

`|f_hat(Lambda)|^2`.

It uses the same one copy of arbitrary mixed quantum advice throughout; there is no
advice cloning, re-preparation, measurement rewinding, random oracle, or QROM
programming.

Therefore, if

- `T_>B` is small enough that `delta` is inverse-polynomial, and
- `T_<=B` is polynomially bounded,

one execution/repetition of the direct circuit reduction obtains a nonzero
`Lambda` with

`rank(N_Lambda)<=B`

with non-negligible probability.

At least one block `N_Lambda^(p,q)` is nonzero. As a submatrix,

`rank(N_Lambda^(p,q)) <= rank(N_Lambda) <= B`.

That block is an **actual matrix in `S_x`**, not an ambient pseudorepresentation.

When `B` lies inside the Hair--Sahai supplied-low-rank extraction threshold, feed
that block directly to the source extractor and obtain an ORIGINAL NP witness.

Thus, under the explicit rank-spectrum conditions,

`boxed(
 arbitrary-QPT unauthorized bit prediction
 -> ORIGINAL source witness.
)`.

There is no new computational hardness assumption in this extraction theorem.

## 8. This closes a gap between Run 79 and Run 102

Run 79 already had:

- deterministic all-witness rank decoding;
- exact complete-output Fourier coefficients;
- false-source rank-gap inheritance.

But it did not transform an **arbitrary QPT decoder/predictor** into an ORIGINAL
witness.

Run 102 had exactly that one-copy arbitrary-QPT Fourier machinery, but for a
Hamming/syndrome source whose generic-NP compiler remained missing.

The fixed MinRank public-key view above lets the two interfaces meet:

`Hair--Sahai source witness`
` -> rank-one MinRank residual`
` -> CMV-form one-bit capsule`
` -> native-seed bit via Run 147`.

And in the reverse direction:

`QPT bit predictor`
` -> low-rank ciphertext Fourier character`
` -> actual low-rank source block`
` -> ORIGINAL witness`.

This is the cleanest source-to-release-to-extraction chain obtained so far.

## 9. Why CMV's published PKE theorem still does not finish false hiding

CMV prove semantic security when their public MinRank generators are sampled
**uniformly at random** and decision MinRank is hard on that random distribution.

Here `K_1,...,K_d,U_x` are deterministic functions of an NP statement and inherit
substantial Hair--Sahai structure.

CMV's average-case duality theorem does not say that the structured ciphertext
distribution is computationally indistinguishable from uniform.

The paper's MinRank conjecture and Theorem 4.1 are also formally stated against
(non-uniform) probabilistic polynomial-time algorithms, not arbitrary QPT
adversaries. The authors discuss known quantum algorithms only as cryptanalytic
evidence; that is not a QPT reduction theorem.

Therefore there are only two acceptable ways forward:

1. prove the explicit `T_false(r)` rank-spectrum sum negligible, giving
   information-theoretic/QPT hiding; or
2. give a new straight-line reduction from this **statement-derived fixed-instance
   distribution** to an independently justified QPT-hard standard assumption.

Calling it “MinRank” is not enough.

## 10. Relation to the exact Bitcoin target

Run 147 shows that one-bit laconic release is payload-complete.

If the one-bit capsule above receives the required QPT hiding/extraction theorem,
setup can encrypt the bits of a future native PQ signing seed, erase the seed/key
under the allowed one-honest N-of-N ceremony, and every ORIGINAL valid challenge
witness reconstructs the same seed.

Bitcoin then sees only an ordinary branch-bound native PQ signature plus the fixed
covenant/timelock conditions.

No source circuit, AuxPoW proof, VM transition, PCP round, or general proof
verifier appears on Bitcoin.

## 11. QPT / assumption ledger

### Honest algorithms
All setup, capsule generation, witness coefficient recovery, rank decoding, and
native-seed reconstruction are classical polynomial-time when dimensions are
polynomial.

### All-witness correctness
Algebraic and unconditional for the structured bit: every source rank-one witness
is a low-rank MinRank residual and decrypts the same bit.

### False-instance hiding
**UNPROVED in general.** It is information-theoretic if `T_false(r)` is negligible.
The CMV random-instance PKE theorem does not instantiate the statement-derived
source.

### True-instance unauthorized recovery
Conditional on the explicit low/high rank-spectrum bounds, the Run-102 one-copy
circuit reduction handles arbitrary non-uniform QPT adversaries with arbitrary
mixed quantum auxiliary advice and source-extracts an ORIGINAL witness.

### Computational assumptions
None are used in the extraction theorem. No CMV/MinRank assumption is silently
promoted to QPT security.

### Auxiliary state / quantum reduction
The direct Fourier sampler is non-black-box in the adversary-circuit description
and uses the circuit plus its adjoint. It uses one copy of the mixed advice and no
rewinding/QROM programming.

## 12. Deterministic validation

`cmv_minrank_laconic_qpt_source_bridge_run152_check.py` is standard-library-only.

It passed syntax validation and two byte-identical executions with
**540 assertions**.

The finite `F_2` fixture checks:

- two distinct valid rank-one MinRank secrets decrypt every structured ciphertext
  into rank at most one;
- the exact uniform-bit small-fixture rank-error probability;
- all **256** complete-output
  characters against the exact
  `2^(-r rank(N_Lambda))` law;
- all **255** nonzero false
  characters inherit source rank at least two;
- exact Parseval/chi-square identity;
- exact false tiny-fixture TV
  `45/64`;
- a source-bearing rank-one response character with structured correlation
  `1/2`
  and equal-prior prediction success
  `5/8`;
- small exact random-matrix rank-deficiency probabilities.

The checker is algebra/probability validation only. It does not simulate a QPT
adversary or establish cryptographic hardness.

## 13. Precise handoff

The central problem is now narrower than “construct generic WE”:

> **Prove hiding for the statement-derived CMV-form structured transcript, or
> prove its exact false-instance rank-spectrum sum negligible, while keeping the
> true-instance spectrum sufficiently concentrated for the one-copy source
> extractor.**

This is one concrete two-sided spectral problem on the actual Hair--Sahai source
space.

The next pass should therefore compute/bound

`sum_Lambda 2^(-2r rank(N_Lambda))`

for the actual weighted-table source compiler, using Run 82's explicit
finite-difference low-rank family as a mandatory lower-bound sanity check.

Do not return to BitVM, on-chain proof verification, a public linear quotient,
or a random-MinRank security theorem that does not cover the structured source.

The complete practical generic-NP public/offline PQ witness-KEM stopping condition
remains **UNMET**.
