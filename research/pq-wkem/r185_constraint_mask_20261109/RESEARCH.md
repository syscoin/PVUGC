# R185: Boolean-quotient source mask and full-public linear-key recovery

**STATUS:** One explicit hash/SHA-circuit-dependent candidate was constructed and adversarially tested. The proposed public polynomial release is **insecure**, and the nonlinear/commitment repairs did NOT instantiate a source-conditioned KEM. This is a restricted-class regression result, not a breakthrough in ORIGINAL bridge release or generic impossibility. No native endpoint/real BTC-SYS source implementation, QPT attack run, or production change.

## Source/continuity and actual execution

PR syscoin/PVUGC#1, open/draft, branch research/pq-wkem-validation-20260918, observed start `0d56b39cbe2f643c67082b9f1ddc8ac97a1d2fbb`. Read exact R184 intermediate graph-path note, R183 OR-combiner conditional QROM lemma, R182 activated-annex source binding, R181 source-slot warning, and recent PR conversation comments only. Intermediate checkpoint was committed on the actual branch at `29060193eb454c37c89878dd0da5e757543e9b39` and verified by readback (blob `38f76dc281cc669df63e340b8c8729e9a6140c4d`) before the local checker. No external research, independent agent, unsupported source issuer or other repo writes.

Local Python 3 standard-library `checker.py` was executed twice with byte-identical `captured.json` and `rerun.json`. Source SHA256 `81a0ebba3ea41958510c691c7fd2436692fe891417f64862a5de585d2154e6a6`; captured output SHA256 `e8a4b3de85f26c7181db224bac51484beea2369c73ed8429cf119230d9277cb6`. Exact executed files + hash manifest are in `EXECUTED_CHECKER.tar.xz`, compressed archive SHA256 `fa237dbaa61abf09a6baa3fed4f1bd806430f9c2eb77ba137feb6dc0a6397dbb`, Git blob `55634e24cb3d196b722010ebbe3957771dd7f625`. Separate local-only full derivation/checkpoint is retained in the working run archive. No ordinary PR progress comment is warranted.

## Concrete attempted pre-source Build/Open

Let `R_cancel(x_W,w)` authenticate the **actual** Bitcoin activation wtxid/annex, source anchors, work, claimed burn/UTXO and relevant AuxPoW tag/ancestry checks, with qualifying `R1 OR R2 OR R3` challenge semantics. One notary may activate, anyone may challenge, and N-of-N preauthorization constrains the spending graph separately. Source branch identity is not parent work certificate identity; two parent PoW certificates for the same child are not a fork. Bitcoin verifies ordinary native cancellation authorization only; large evidence is off-chain.

Over Boolean quotient `B_n=F_p[z_1,...,z_n]/(z_i^2-z_i)`, represent *all* actual SHA256/consensus verifier constraints `c_i(z)` and insist each ORIGINAL accepted full trace `w` satisfies `c_i(w)=0`. Propose public mask

    F(z) = K*1 + SUM_i c_i(z) * g_i(z),

where setup freezes one capability key `K` and samples independent random polynomials `g_i` in a published low-degree monomial span. Any valid ORIGINAL witness gives `F(w)=K`, for all source histories and all three challenge types, without requiring canonical witness equality. This is exact functional convergence. An honest off-chain Open could evaluate `F(w)` and unmask the native cancellation signature. **However:** outputting `F` in this form exposes K independently of R.

## Exact full-public linear-dual attack on this encoding

Let `V_D` be the Fp-vector space of Boolean monomials of degree at most `D` and `W_D = span{c_i(z)*m(z)}`, with allowed multipliers `m` chosen so products lie inside the publicly represented `V_D`. Honest setup produces `F=K*1+S` for some `S in W_D`.

If **any** ORIGINAL valid witness `w*` exists, its evaluation functional `ev_w*` annihilates `W_D` while `ev_w*(1)=1`. Therefore `1 is not in W_D`. The public coefficient matrix

    M = [ vec(1) | vec(c_1*m_1) | ... | vec(c_t*m_t) ]

and public `vec(F)` allow ordinary Gaussian elimination for `M*(alpha,beta)=vec(F)`. A solution exists by honest construction. If two solutions had different alpha, their difference would put a nonzero multiple of 1 in W_D, a contradiction. **Every solution has alpha=K.**

The adversary never produces a witness, a source certificate, a representation of an internal quantum state, or a proof of work. This classical direct key-recovery algorithm is polynomial in the number of explicitly published coefficients and generators. If D is constant, `dim(V_D)=SUM_{j=0}^D C(n,j)=O(n^D)`; even computationally hard TRUE original statements cannot protect this encoding. A classical attack also suffices against the requested arbitrary-QPT security.

This theorem is limited to **explicit polynomial coefficient disclosure / efficiently expandable bounded-degree ideal-mask encoding**. For large degree D, coefficient expansion may be exponential and a succinct nonlinearly obfuscated representation is outside the theorem. It does NOT exclude other hash-only nonblackbox constructions, obfuscated computation, high-degree compact representations, or all computational WE. It overlaps the earlier quotient/fixed-probe regression; do not report it as a new generic impossibility.

## Actual bounded synthetic checker

The executable toy uses eight Boolean wires, six quadratic-ish AND/XOR/OR trace constraints (including an OR acceptance bit), Fp=65537, degree cap 4, coefficient space dimension 163, and 54 allowed constraint-monomial columns. Its input is **not real SHA256 or AuxPoW**. It has six satisfying toy assignments. Across 24 independent random fixture keys/masks, public elimination recovered K in 24/24, while 144 witness openings returned the same K. Each fixture had an invalid assignment giving a different value. The checker enumerates toy assignments only to validate correctness; key recovery uses coefficient linear algebra, not witness search. Test counts are not crypto security estimates.

## Repairs attempted, not instantiated

1. Nonlinear SHA syndrome: `F(z)=K XOR H(SUM a_i*c_i(z))` has a common output on valid traces. If setup exposes an ordinary public evaluator containing K and the a_i as literals, a reader simply extracts them. Hash commitments `H(a_i)` may hide these coefficients but do not enable a public evaluator to derive `H(SUM a_i*c_i(w))` from source evidence; SHA is not an additive/homomorphic opening scheme. Assuming a magically sealed public evaluator is assuming the missing source compiler, not a repair.
2. Compact high-degree circuit: it may evade the **bounded-degree coefficient** argument, but to work it must be efficiently buildable *before* future activated source evidence exists, evaluable on **every** authentic relevant future BTC/SYS witness, and opaque to arbitrary public inspection/invalid probes. Neither a Merkle commitment nor a hash of hidden coefficients supplies this opening. R184 node-potential XOR telescoping also depends on uninstantiated source-gated hidden edge tokens, so concatenating them is not a repair.

## The exact missing interface remains

    Build_hash(R_cancel,x_slot,sigma_i) -> C_i   [classical PPT; before source]
    Open_hash(C_i,activated_source,w_ORIGINAL) = SAME sigma_i
        for EVERY qualifying ORIGINAL R1 OR R2 OR R3 witness.

Full public view includes relation, actual claim/UTXO and activated BTC annex/wtxid, BTC work/source windows, full PoB authorization/burn roots, AuxPoW coinbase/history tags, native VK/M and checking keys, N-of-N sibling capsules and malicious participants' retained coins, auxiliary QPT advice and selective openings. Arbitrary QPT accepted unauthorized final-key recovery or native signing must yield FULL ORIGINAL qualifying evidence or an independently justified QPT hash/native forgery break. Actual original source authentication must be inside the cryptographic release; an honest-only post-decryption verifier does not suffice. NO new native Bitcoin verifier, online release authority, independent hash puzzle, lattice/group wrapper, fabricated source tag or special signer is assumed.

**Next constructive task:** seek a genuinely nonlocal computational hash-circuit correlation with a polynomial classical public compiler and an ORIGINAL-evidence evaluator; test the full public simulator jointly. Do not further optimize this failed linear/quotient mask or treat source-authentication metadata as a secret-token issuer.