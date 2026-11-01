# NIDR-ECO: straight-line equivocal coins for adaptive openings

**Run:** NIDR-ECO-2026-11-01-T08 (bounded, offline). **Predecessor:** `research/pq-wkem/noisy_ideal_dual_20261101/RESEARCH.md` at exact PR #1 head `e2910dcf4a9f8d4977946737b2af6e27876e6fe0`, predecessor blob `bce3eb5a0c71e10c3e197adcafb8227435b4fac6`.

**Result classification:** A constructive source-dependent release / proof advance **only for the already independently instantiated parity-cycle source family** and, more generally, for explicitly supplied, polynomial-time computable bounded-shift certificates. It closes NIDR's previous *adaptive classical coin opening* exclusion under exact stated restrictions. It does **not** produce a generic NP witness-KEM, a standard structured-source QPT-LWE reduction, a hard-TRUE ORIGINAL extractor, malicious setup protection, or a Bitcoin-deployed PQ endpoint. Do not call this a complete solution.

## 1. Public source, native correlation, and explicit release

Let `x` name a Boolean ORIGINAL verifier with its full claim/outpoint, challenge path, anchors/window/context, intended public native verification key and domain. NIDR compiles its Boolean polynomial constraints to a public `A_x in F_q^(r×M)` in a degree-D multilinear quotient, with feature index 0 the constant monomial. It requires no witness to build `A_x`. Each valid ORIGINAL witness `W` gives an evaluation vector `v(W) in {0,1}^M` with `v_0=1`, `A_x v=0`, and `||v||_1 <= M`. Distinct witnesses and intermediate states are permitted. Only the explicitly tested parity-cycle family is independently instantiated here; embedding arbitrary SYS/BTC correctness constraints is NOT established by this test.

Let `q` be an odd prime, `g=(q-1)/2`, `E_B=[-B,B]` as centered integers, `s <- F_q^r` uniform, `e <- E_B^M` independent uniform. For each bit `m in {0,1}` of one of three independently sampled XOR shares of the actual native *private* signing core `K`, publish

`Enc_x(m;s,e) = A_x^T s + e + g m e_0 (mod q)`.

Each of `C` related capsules has **fresh, independent** three-share XOR sharing of the *same* precommitted `K`; each share bit ciphertext has independent `(s,e)`. Public native `vk` is genuine, not a synthetic key uncorrelated with the encrypted core. Authenticated allowed P-domain signature transcripts and ciphertext hashes/manifests are included in the public view. Do **not** publish plaintext-share commitments or expose coins for any protected third share.

Public off-chain `Lift(C,W)` first checks ORIGINAL `V_x(W)` (Bitcoin does not), derives `v(W)`, computes `t=v^T Enc_x(m)`, and decodes the bit nearest to `0` or `g` modulo `q`. The trace vector kills `A_x^T s` and leaves `gm+v^T e`, with `|v^T e| <= BM`. With `q > 4BM+2`, this deterministically recovers each share bit for **every valid ORIGINAL witness and every supported bounded-error sample**, then XORs shares to the same `K` in all related capsules. The native signing capability is that original canonical key, not a new per-witness key. Actual SLH/native Bitcoin verification remains conditional.

## 2. The exact equivocal-coins algorithm

For a FALSE source suppose a *classically efficiently computed* public vector `delta in F_q^r` and centered integer vector `h in Z^M` satisfy

`h = center_q(g e_0 + A_x^T delta)`; write `H=||h||_1`.

**SimCipher:** sample `s <- F_q^r` and `e <- E_B^M`; publish `c=A_x^T s+e (mod q)` as though the share bit were zero. Keep `(s,e)` local to the simulation.

**SimOpen(m):** when the same encrypted share bit must be opened as `m in {0,1}`, return plaintext `m` and coins

`(s_m,e_m) = (s+m delta (mod q), e-m h)`.

Then **exactly** (no error probability in this algebraic identity)

`Enc_x(m;s_m,e_m) = A_x^T s+e = c (mod q)`.

For `m=1`, `s_m` is perfectly uniform and the only discrepancy from honest encryption/opening is the noise law `E_B^M-h` versus `E_B^M`. The *exact joint (ciphertext, plaintext, coins)* total variation for fixed `m=1` is

`epsilon_1 = 1 - product_{j=0}^{M-1} max(0,1-|h_j|/(2B+1)) <= H/(2B+1)`.

For `m=0`, it is zero. Out-of-range shifted coins, which occur only in the `epsilon_1` discrepancy event, can be returned and recognized as inconsistent with the claimed uniform support; this is fully charged to the statistical bound, not silently ignored. There is no need to know any SOURCE opener, ORIGINAL witness, capsule plaintext, native signing secret, or LWE challenge secret to compute this simulator. It needs only the public false-source shift `delta` and the sampled zero-encryption coins.

## 3. Full restricted adaptive transcript with the genuine checking key

Define `T=3*C*k` independently encrypted share-bit ciphertexts for `k` native-private-core bits and `C` related capsules. A QPT adversary receives `(R,x,A,Capsules,vk,context,aux,related capsules)`, processes classical data in an arbitrary coherent quantum computation, and makes **classical, adaptive** requests revealing `m,s,e` for at most two of the three lanes **for each (capsule, private-key-bit)**. It can select a different protected lane for each bit/capsule based on prior opened bits, coins and observed ciphertexts. Coherent quantum queries to opening or signing oracles and auxiliary access to the third protected coins are out of scope. Plaintext-share commitments or cross-capsule reuse of actual share coins are excluded.

**Hybrid H0 (honest):** native Gen gives `(sk,vk)`, the `k` private core bits determine independently reshared triples `X_(c,b,0) XOR X_(c,b,1) XOR X_(c,b,2) = K_b`, honest `Enc(X)` is published, and allowed P-domain signatures come from the true signing key.

**Hybrid H1 (programmed but initially with latent real shares):** keep exactly the same native key and full latent share triples. For each share bit sample a *zero* encryption `c=Enc(0;s,e)` and define opening coins via `SimOpen(X)` above. Conditioned on the complete latent key/shares/allowed native signatures and on auxiliary data independent of encryption/share randomness, all `T` ciphertext+potential-opening laws differ from H0 by TV at most `T*H/(2B+1)`. The bound holds before any adversarial adaptive postprocessing, so classical adaptive opening strategies and arbitrary coherent QPT processing cannot increase it. Different `(c,b)` need not disclose the same unprotected lane.

**Hybrid H2 (straight-line simulator without sk):** receive *authentic* `vk` and a classical signing oracle for allowed P-domain messages from the native QPT-EUF-CMA challenge. Generate all zero ciphertexts of H1. **Defer** selection of share plaintext bits until an opening is requested. For each fixed `(capsule,bit)`, any ordered, adaptively selected subset of at most two XOR shares is a pair of *independent uniform bits, even conditioned on `K_b`*. Therefore sample a fresh consistent uniform bit upon each first opening and use `SimOpen(bit)` for its saved ciphertext coins. Repeat openings return the same bit/coins. Across capsules the samplings are independent. The exposed transcript is *exactly* the distribution of H1 under the allowed leakage policy, even though the simulator never knows `sk` or the encrypted core. Genuine `vk` and allowed P-domain signatures are issued via the native challenger, while ciphertext-only authenticated manifests can be assembled and signed in the permitted signing domain. The challenger has never signed the fresh target-domain challenge.

Consequently, for arbitrary nonuniform QPT adversaries with classical oracles and efficient, independently simulatable auxiliary data (including genuine `vk`, allowed P-domain signatures and hashes of public ciphertexts),

`Pr_real[fresh challenge-path native forgery or recovered signing-capable core] <= Adv_native-QPT-EUF-CMA + T*H/(2B+1) + Adv_external_auth`,

where a recovered core is converted to a fresh native signature using public Sign. This proof is straight-line: no rewinding, random-oracle extraction, assumed SourceOpen, or demand for an adversary-supplied representation. It is valid only for FALSE sources satisfying the *independently instantiated* small-shift condition. A true-instance witness legitimately recovers the key, and no unauthorized-hard-TRUE extraction theorem follows. A quantum advice state correlated to unrevealed share/encryption coins, secret-key-dependent auxiliary outputs not simulatable from `vk`/allowed signing oracle, or coherent opening queries are NOT covered. No uniform-A or structured-source QPT-LWE hardness claim is made; hiding for these FALSE instances is statistical.

## 4. Independent finite-family instantiation and concrete resources

Let `n>=3` be a parity cycle with ORIGINAL equations, for each edge `i` modulo `n`,

`z_i+z_(i+1)-2z_i*z_(i+1)-1 = 0`.

Use constant, `n` degree-1, and `n(n-1)/2` degree-2 monomial features: `M=1+n+n(n-1)/2`. `A` has the `n` explicit constraint rows (optional extra rows get zero coefficients in `delta`). For even `n`, two distinct alternating ORIGINAL witnesses exist. For odd `n`, no Boolean witness exists and setting *each* `delta_i=(q+1)/2` gives

`h_const=-(n+1)/2`, `h_vertex_i=+1`, `h_actual_edge=-1`, all other degree-2 coordinates zero, hence `H=(5n+1)/2`.

This works for odd n without requiring a finite-degree polynomial-calculus refutation. For `C=2`, `k=512`, `T=3072`, `B=2^145`, `q=2^255-19` (prime), n=3/5/7 each satisfy `q>4BM+2`, and the restricted full interactive opening transcript statistical error upper bounds are respectively `2^-131.415`, `2^-130.715`, `2^-130.245`. For the n=3 source, one 255-bit residue is stored in 32 bytes, so raw ciphertext payload across both capsules is `T*M*32 = 688,128` bytes plus source rows, manifests, and native signature overhead. This is **not** a generic NP parameter set or a 128-bit hardness calibration; source satisfiability is trivial, and the q-ary arithmetic uses large integers. The statistical claim only bounds the effect of encrypted shares, not native forgery hardness without the separately assumed native scheme.

## 5. Exact executed checker and limits

The standard-library Python `checker.py` was executed *twice* and produced byte-identical `output.json` with 79,361 assertions. It checks the exact source rows/shift at odd n=3/5/7, all-valid-two-witness release at even n=4/6, 512 real adaptive share-coin opening equations for two capsules, the uniform marginal for every two-share ordering and a bit-dependent adaptive next-lane strategy. It enumerates all `5^7=78,125` toy error vectors for n=3 at B=2 and checks exact overlap count 12,288, TV `65837/78125` and the interval coupling bound. These are finite algebra, not a QPT-security experiment; the only quantum claim follows from exact classical TV and CPTP contractivity.

**Unsolved original program:** build a polynomial-size generic-NP ORIGINAL compiler and full-public false security for *every* false x without a low-degree certificate or easy small shift; prove arbitrary unauthorized hard-TRUE final-key recovery or native forgery -> an **actual ORIGINAL witness or independently justified PQ break**. Must instantiate challenge source and full checking-key/aux/related-capsule correlations together, not merely prove marginal pad hiding; handle malicious N-of-N setup/abort, arbitrary auxiliary inputs, quantum-coherent oracle access where required, signer/graph/DA, authentic SYS/BTC headers/AuxPoW/tag windows and the hypothetical native PQ output. No new Bitcoin covenant/proof checking is assumed.
