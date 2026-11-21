# SP-NIDR: support-projected noisy ideal-dual release

**Run:** SPNIDR-2026-11-01-T09. Exact predecessor: NIDR-ECO at PR #1 head `7647173457b19cb1aebba3dd7397570aec4190f6`, research blob `6c13ad7efadeec31a6f876e3e86ffa40ae52f758`. This is a **restricted constructive efficiency and family-extension result, NOT a generic NP witness-KEM**. The executable `checker.js` is the same function executed in this run; the full independent 50,866-assertion standard-library Python checker and fuller derivation are preserved in a separate local archive.

## SOURCE and all-ORIGINAL-witness release

For the bound ORIGINAL statement `x` (relation identity, actual claim/UTXO, authorized branch, anchors/window, context, native checking key, capsule domain), compile Boolean gate constraints into polynomials `g_i(z)` in a multilinear quotient. The compiler is classical PPT, public, and **does not know the witness**. Let `S={1} ∪ union_i supp(g_i)`, and retain *only* those monomial columns. This gives public `A_x∈F_q^{r×M}` with `M=|S|`. A valid ORIGINAL witness `W` yields its own Boolean trace `z(W)` and monomial vector `v_S(W)∈{0,1}^M` satisfying `v_0=1, A_x v_S(W)=0`. Distinct valid traces need not be equal.

Let odd prime `q`, `g=(q−1)/2`, `s←U(F_q^r)`, `e←U([-B,B]^M)`, with independent fresh coins per ciphertext. Encrypt each bit `m` of three XOR-share lanes of the *same genuine precommitted native signing core* `K`:

`c=A_x^T s+e+gm e_0 (mod q)`.

Each related capsule re-shares `K` independently, with genuinely correlated native `vk`, ciphertext-bound signed manifests, allowed P-domain signing transcripts and scoped context. Public OFF-CHAIN `Lift(C,W)` first verifies ORIGINAL `R(x,W)=1` and evaluates `v_S(W)^T c=gm+v_S(W)^T e`. If `q>4BM+2`, nearest-center decoding recovers `m` for **every** valid ORIGINAL witness and every bounded honest error sample, then XOR reassembles exactly `K`. No canonical witness or common intermediate state is required. Bitcoin would only verify an ordinary native signature under a hypothetical PQ-native output; no NP circuit, proof/VM/PCP or dispute trace is run in consensus.

## Exact support-projection lemma (reusable for general gate systems)

In a dense carrier with monomial universe `U⊇S`, every removed column `j∈U\\S` is zero in `A_x`, and `j≠0`. Therefore its ciphertext coordinate is **exactly `c_j=e_j (mod q)`**, independent of the bit, native core, sampled lattice secret, other errors, auxiliary data and other capsules. Its opened error coin is the same independent `e_j`. Conditional on the public statement, all secret core/shares, and admissible classical opening policy, the dense transcript equals the sparse transcript augmented with independently sampled dummy errors; conversely the sparse transcript is its exact projection. Deleting these coordinates cannot weaken the applicable statistical hiding argument or QPT processing bound. It also improves completeness from `q>4B|U|+2` to `q>4B|S|+2`.

This distributional equivalence concerns source/ciphertext/opening coins, **not signed-byte interchangeability**: an honest Build or a challenger with a permitted signing oracle authenticates the new sparse manifest format and domain separately. Do not transfer old manifest signatures. Crucially this compression applies to generic polynomial constraints but establishes *no general security* for them.

## Independently instantiated full FALSE simulator for every simple signed 2-XOR graph

For a finite loopless simple undirected graph `G=(V,E)` with labels `b_uv∈{0,1}`, the ORIGINAL relation is `z_u XOR z_v=b_uv`, encoded by

`g_uv(z)=z_u+z_v−2z_u z_v−b_uv=0`.

The complete sparse basis is `S={1}∪{z_u}∪{z_u z_v : uv∈E}`, so `M=1+|V|+|E|`. A classical linear-time BFS either finds an ORIGINAL witness or an inconsistent simple cycle `C` with odd signed label sum `b_C=Σ_{e∈C}b_e`. In the FALSE case compute `δ_e=(q+1)/2` on that cycle and zero on other rows. Then `h=center_q(ge_0+A_x^Tδ)` has coefficient `−(b_C+1)/2` at the constant monomial, `+1` on cycle vertices, `−1` on cycle-edge monomials, and zero elsewhere. Hence

`H=||h||_1=(b_C+1)/2+2|C|≤(5|C|+1)/2`.

This holds for **every** falsely labeled signed XOR graph, including arbitrary extra chords, multiple contradictions and disconnected components; the original odd all-different parity cycle was just a special case. The FALSE simulator computes the entire source and `δ` from public `x`; it assumes **no SourceOpen oracle** or supplied representation. TRUE graph instances may have many distinct satisfying assignments, all lifting to the same `K`.

For each encrypted share bit publish simulated `c=A_x^T s+e`. On a permitted plaintext/coin opening as `m`, return `(m,s+mδ,e−mh)`, giving the **exact identity** `Enc_x(m;s+mδ,e−mh)=c`. The joint opened-coin statistical discrepancy is exactly `1−∏_j max(0,1−|h_j|/(2B+1))≤H/(2B+1)`. For `C_caps` related capsules, `k` private key bits, `T=3C_caps k` ciphertexts, the entire bounded classical interaction differs from honest by at most `T H/(2B+1)`. Open at most two of three XOR lanes per `(capsule,key-bit)`, adaptively with classical queries; each disclosed subset is independently uniform even given unknown `K`. A straight-line simulator gets the genuine `vk`, allowable P-domain signatures and authentication via an independently assumed native QPT-EUF-CMA challenger. No signing in the fresh target path. Arbitrary coherent QPT *postprocessing of the classical transcript* is covered by statistical-distance contractivity, but coherent quantum superposition opening/signing oracles are excluded. Independently simulatable auxiliary data and authentic ciphertext-bound context are included; arbitrary secret-correlated auxiliary inputs, maliciously retained protected coins and plaintext-share commitments are excluded.

Under precisely these restrictions, FALSE final key recovery or fresh native forgery has upper bound `Adv_native-QPT-EUF-CMA+T H/(2B+1)+Adv_auth`. **This is statistical FALSE security for a polynomial-time-decidable language**, not standard QPT-LWE security on a structured generic NP source, and **not a hard-TRUE witness-extraction theorem**.

## Size and reproducibility

With two capsules, 512 private bits, 3 lanes, `T=3072` and 32-byte q-ary residues, a simple 31-edge cycle shrinks from **48,857,088 bytes (497 features)** to **6,193,152 bytes (63 features)**, a **7.89× reduction**. A 101-cycle uses 203 instead of 5152 features (25.38×); a 1001-cycle uses 2003 instead of 501502 (250.38×). These exclude source, native key, manifest, signature and evidence. The exact executed standalone JS checker tests dense/sparse projection, independent zero columns, signed false-cycle shifts with arbitrary extra chords, coin equations and two distinct true ORIGINAL witnesses; `output.json` records its assertions. Extended independent Python tests passed 50,866 assertions twice identically (75 TRUE and 75 FALSE graphs, 750 true bit decryptions, 225 coin equations and four distinct valid gate-circuit witnesses). They remain local-only.

Illustrative `q=2^255−19, B=2^148` satisfy completeness for tested sizes. The worst 31-cycle has `H≤78`, giving `log₂(T H/(2B+1))<−131`. **At n=1001 this B gives only about 126 bits** in the worst case; increase B (e.g. to `2^151` with this finite q) for a 128-bit statistical bound. These numbers are *not* calibrated QPT native-signature hardness or realistic Bitcoin deployment costs.

## Still missing: the decisive original reduction

For arbitrary NP ORIGINAL `R`, establish a classical-PPT witness-free compiler and **full-joint, QPT-secure** source-dependent release/hybrid on **all FALSE statements**, with true correlated `vk`, context, auxiliary data, and related capsules. An unauthorized hard-TRUE final-key recovery or fresh native forgery must imply an **actual ORIGINAL witness or an independently justified PQ break**, without SourceOpen, attacker-volunteered representation, public projection of the key, or a secretly strong witness-release assumption. The old structural signed/fractional opener, public linear masks, low-degree closure, local switching and capsule-correlation barriers remain mandatory regressions. Malicious N-of-N honest erasure/pre-signing/abort/DA, authentic SYS/BTC AuxPoW/tag/window qualification, challenge inclusion and hypothetical native no-EC PQ Bitcoin support also remain unproved. No generic NP breakthrough or deployment is claimed.
