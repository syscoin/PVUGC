# Signed anchor-one ghosts: negative SOURCE compiler checkpoint (2026-10-27)

**No qualified positive WKEM advance.** This exact countercheck concerns only the previously attempted structured 3CNF-to-fixed-weight-kernel compiler. It does **not** attack the current unplanted uniform-random-`B` Gaussian transverse-LWE reference release.

## Exact degree-one identity

The SOURCE compiler represents each variable with one-hot bits `Y_{i,0},Y_{i,1}`, a global anchor `a`, and each three-literal clause `c` with seven local allowed truth-pattern indicators `T_{c,t}`. Its integer constraint matrix `M_F` has rows for:

`Y_{i,0}+Y_{i,1}=a`, `sum_{t allowed}T_{c,t}=a`, and `sum_{t allowed:t_j=1}T_{c,t}=Y_{var(c,j),1}`.

For a clause excluding a local truth pattern `f`, define `f^1`, `f^2`, `f^{12}` by flipping the first bit, second bit, and both first two bits, respectively. They are all allowed. The formal signed combination

`[f^1]+[f^2]-[f^{12}]`

has coefficient sum one and the same three bit marginals as the **excluded** pattern `f`. Thus for ANY 3CNF and ANY Boolean assignment `s`, form `z_s` with anchor one, normal variable one-hots, normal allowed clause one-hots, and this signed three-term combination for every violated clause. It satisfies exactly, over the integers,

`M_F z_s=0`, `anchor(z_s)=1`, `sum(z_s)=h=1+v+m`, `||z_s||_1=||z_s||_2^2=h+2 b(s)`.

Here `b(s)` is the number of clauses violated by `s`. Its coefficients belong to `{-1,0,1}`. If `s` violates a clause, `z_s` is NOT a legal binary ORIGINAL witness, yet is an available **public linear** opening direction.

## Actual attempted release and false-source key extraction

For the structured transplant `p_j=(g/h)*1*t_j+M_F^T u_j+e_j (mod q)`, public evaluation along `z_s` gives

`z_s^T p_j=g*t_j+z_s^T e_j (mod q)`.

This is **anchor one**, not the factor-two alias in the preceding diagnostic. It cancels the LWE secret for every `u_j`, on true and false statements. If `|e_i|<=beta`, `|z_s^T e_j|<g/2` is guaranteed whenever `(h+2b(s))*beta<g/2`; then cyclic nearest-radix decoding reveals each true digit without an ORIGINAL witness. For independent ideal discrete-Gaussian errors of parameter `sigma`, a standard Gaussian MGF bound gives error probability at most `2 exp(-g^2/[8 sigma^2(h+2b(s))])` per digit, plus the exact finite-sampler coupling loss if separately certified.

The unsatisfiable test instance `(x OR x OR x) AND (!x OR !x OR !x)` has `h=4`, `M_F` with 9 rows and 17 columns, no binary accepted witness and a signed anchor-one ghost with `||z||_1=||z||_2^2=6`. At `q=2^20, g=640, radix=1638`, all 1000 deterministic bounded-error diagnostic samples (`e_i` in `[-5,5]`) opened correctly. For ideal `sigma=16/5`, the exact one-column exponent is `2500/3`; the tail is less than `2^-1199`. The full pinned finite-dyadic sampler's coupling was not independently re-established in this run.

## Repair outcome and actual bounded tests

Anchor-one normalization, changing radix to eliminate factor-two leakage, any left-row mixing `L M_F`, and an offline Boolean/weight Open check do not suppress the public combination. Any **linear local integrity equation** agreeing with all seven allowed one-hot clause patterns also respects the excluded pattern's displayed signed degree-one identity. Global nonlinear enforcement would be needed, and no new polynomial-cost cryptographically binding release or full-public QPT simulator was established.

`publish_check.py` was executed twice, byte-identical result `published_output.json`: **3266 checks**, all eight forbidden patterns, exact signed marginals, integer matrix annihilation for both Boolean assignments on an UNSAT source, 1000 deterministic literal ciphertext openings, and exact ideal-Gaussian exponent. The extended local `check.py` was also executed twice, 3420 checks each, and is preserved in the local research archive but not required for this published reproducer. The run did not execute a quantum attack or prove an assumption about ordinary QPT-LWE.

## Current state and exact next obligation

The jointly published relation, capsule, *real* native checking key, context, auxiliary data and related capsules still need a classical PPT setup/opening algorithm and an independent coherent-QPT challenge simulator whose false-source and hard-true final-key security is **not** defeated by arbitrary public algebraic or quantum recovery. Every valid ORIGINAL witness must release the same precommitted capability without canonicalizing its intermediate states. The present source-dependent signed degree-one matrix is disqualified; the previously established uniform-`B` reference stays unaffected and does not yet encode ORIGINAL Bitcoin/Syscoin or generic NP.

Provenance: `syscoin/PVUGC` draft PR #1, branch `research/pq-wkem-validation-20260918`, actual read head `78c08f4dffe406c0c9c0baf392dc2aaef74650f7`, exact predecessor proof `research/pq-wkem/native_key_list_lwe_20261027/PROOF.md` blob `1403770e563eab3a725f3886a245d58a9924e9e6`, latest substantive ordinary comment `6445428331`. No external literature/web research, no production/workflow/merge/deployment action. Research record `ghost-anchor-one-20261027`, not a supplied scheduler UUID.
