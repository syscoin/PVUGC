# PNIDR: narrow certified-prime fields for the sparse NIDR-ECO release

Run ID: **PNIDR-2026-11-01-T10**. Chosen predecessor: SP-NIDR, `syscoin/PVUGC#1` branch `research/pq-wkem-validation-20260918` at exact SHA `bfd0796d08f9fc55d98bc62451e3f56b6fa45cf6`; SP-NIDR research/blob `research/pq-wkem/nidr_sparse_graph_20261101/RESEARCH.md`, `a32031b9b979bc4367db7bf53309e96a5327e9d4`. No external literature or other repository was consulted. This is a **meaningful measured size reduction for the previously proved RESTRICTED signed-XOR family**, not a generic-NP PQ witness-KEM or an ORIGINAL extraction theorem.

## Prior construction and precise change

The public ORIGINAL statement `x` contains an independently specified signed-XOR graph `G=(V,E)`, relation/claim/UTXO, branch, anchors, timing/window/context and intended native verification key and spending capability. SOURCE is compiled publicly from the graph, independently of a satisfying witness: for edge `(u,v)` with XOR label `b_uv`, form polynomial `f_uv=z_u+z_v-2 z_u z_v-b_uv`. Use only monomials `S={1} ∪ {z_v} ∪ {z_u z_v : uv∈E}`, with `M=1+|V|+|E|`. Let public coefficient matrix `A_x∈F_q^{|E|×M}`, constant coordinate `e_0`, and `g=(q−1)/2`. Each independently encrypted bit `m` has ciphertext

`c=A_x^T s+e+g m e_0 mod q`,  `s←U(F_q^{|E|})`,  `e←U([-B,B]^M)`.

Three XOR lanes share each bit of the SAME precommitted native signing core `K`. Each related capsule re-shares `K` independently. Public off-chain `Lift(C,W)` verifies the actual ORIGINAL signed-XOR witness and uses its own monomial vector `v_S(W)`, which satisfies `v_0=1` and `A_x v_S(W)=0`. It decodes `v^T c = g m + v^T e`, then XOR-assembles exactly `K`, with no canonical witness or common intermediate state. Native off-chain signing is a separate hypothetical no-EC Bitcoin PQ-native path; Bitcoin is not being asked to run the graph verifier.

SP-NIDR unnecessarily fixed `q=2^255−19` and serialized each residue as 32 bytes. **This iteration changes neither the encryption/opening algorithm nor any number of ciphertexts or permitted disclosures.** It chooses `B` and a certified prime `q` from solely public sizes and security budget, then serializes each residue in `ceil(bitlength(q)/8)` bytes. There is no added assumption of post-quantum LWE hardness: this restricted FALSE theorem is statistical. The native-signature QPT-EUF and authentication assumptions remain external, unchanged.

## Public, witness-free parameter derivation

Inputs are public `n=|V|`, `E=|E|`, `M=1+n+E`, number `C` of related capsules, native private-core bits `k`, `L=3` XOR lanes, target statistical budget `lambda`. Define `T=C*k*L` and **public upper bound** `Hmax=floor((5n+1)/2)` on the short-shift norm for any inconsistent simple cycle (because the cycle has at most `n` vertices). Choose

`B = 2^(lambda−1) * T * Hmax`, `q` any **odd certified prime** satisfying `q > 4 B M + 2`.

The choice of `B,q` depends only on `n,E,C,k,lambda`; it DOES NOT require deciding TRUE versus FALSE, knowing an ORIGINAL witness, finding a contradiction, knowing the native signing secret, or receiving an external SOURCE opening. The initial restricted verifier must enforce the publicly committed parameters consistently across the source, related capsules, and authenticated manifests. In the explicit fixtures the source graph is a simple n-cycle, so `M=1+2n`; arbitrary signed graphs use `M=1+n+E`.

For a certificate without probabilistic primality claims, the checker searches `q=k0*2^p+1` with odd `k0<2^p` and proves primality using Proth's criterion `a^((q−1)/2)≡−1 mod q`. The published `(p,k0,a)` values are fully reproducible, exact witnesses to primality. **The bounded Proth search is only an offline parameter finder, not a proof that it succeeds in polynomial time for every arbitrary n**; production-size public parameters could instead be preagreed/certified or generated with ordinary probabilistic prime sampling and polynomial-time primality verification.

## Exact completeness and statistical security accounting

For every valid ORIGINAL witness `W`, its monomial vector `v` has coordinates in `{0,1}`, `v_0=1`, `Av=0`, and `||v||_1≤M`. Hence `|v^T e|≤BM`. Since `q>4BM+2`, nearest-center bit decoding between `0` and `g=(q−1)/2` succeeds for every honest error sample, every valid witness and every independently shared capsule. The same `K` is recovered regardless of which valid ORIGINAL witness generated `v`. This is a deterministic correctness proof, not a hardness assumption.

For every FALSE signed-XOR graph, a classical polynomial-time BFS returns an inconsistent simple cycle with odd edge-label sum `b_C`. Put `delta_e=(q+1)/2` on those cycle rows and 0 elsewhere. For `h=center_q(g e_0 + A^T delta)`, exact integer coefficients are:

* constant: `−(b_C+1)/2`;
* each cycle vertex: `+1`;
* each cycle-edge monomial: `−1`;
* all other coordinates: `0`.

Thus `H=||h||_1=(b_C+1)/2 + 2|C| ≤ Hmax`, uniformly over public graph labels and extra edges. A simulator publishes `c=Enc_x(0;s,e)` with `s` uniform and `e` uniformly bounded. An adaptive *classical* request to open the ciphertext as bit `m` is answered using **actual opening coins** `(s+m delta, e−m h)`, and the ciphertext equation is exact. These opened-coin distributions differ from honest by

`TV ≤ 1−∏_j max(0,1−|h_j|/(2B+1)) ≤ H/(2B+1)`.

For `T=3 C k` independent ciphertexts, a straight-line adaptive hybrid gives `TV_full ≤ T Hmax/(2B+1) < 2^(−lambda)`. Open at most two of three lanes per `(capsule,key-bit)`, preserving a single undisclosed lane per bit; opened shares remain independently uniform even conditioned on the genuine native `vk`. All published ciphertexts and opened coins remain in the joint view. The simulator retains the real public relation, all context, a genuine native checking key from an external QPT-EUF challenger, signed/authenticated manifests produced using separately held authentication authority or permitted native signing queries, permitted signing transcripts, independently reshared related capsules and admissible independently simulatable auxiliary data. Fresh signing of the target challenge path is excluded. It makes no SOURCE-opening oracle query.

The resulting **restricted** bound for recovered native final key (converted into a fresh target-path signature) or an accepted fresh native forgery is

`Adv_native-QPT-EUF + Adv_authenticated-manifest + T Hmax/(2B+1)`.

The statistical step holds under arbitrary QPT internal computation and coherent QPT **processing of the complete classical view**, by trace-distance contractivity. It does NOT support quantum-superposition signing/opening queries, maliciously disclosed protected coins, plaintext-share commitments, arbitrary secret-correlated auxiliary data, dishonest setup, or hard-TRUE witness extraction. This is not a generic SOURCE-dependent QPT-LWE reduction. Smaller `q` does not weaken any *proved* bound in this deliberately restricted statistical family; it would require fresh cryptanalysis if future constructions add computational LWE assumptions.

## Measured size: identical security budget and leakage rules

All numbers count `T=3072` ciphertexts (2 related capsules × 512 secret bits × 3 lanes) and omit authentication, source, manifests, native signature and witness storage. In each case target `lambda=128` and the field is **provably prime** with the indicated Proth witnesses. Sizes are actual fixed-width field-residue payloads, not estimates of the complete protocol.

| Simple cycle | M | Old q-field bytes | New q bits / bytes | Old ciphertext bytes | New ciphertext bytes | Exact saving |
|---:|---:|---:|---:|---:|---:|---:|
| 31 | 63 | 32 | 155 / 20 | 6,193,152 | **3,870,720** | **37.5%** |
| 101 | 203 | 32 | 159 / 20 | 19,955,712 | **12,472,320** | **37.5%** |
| 1001 | 2003 | 32 | 164 / 21 | 196,902,912 | **129,217,536** | **34.375%** |

Certificate tuples `(p,k0,a)`: n=31 `(148,81,5)`; n=101 `(152,81,5)`; n=1001 `(158,43,3)`. Their exact `B,q` appear in `output.json`. Unlike multiplying bits into a shared plaintext symbol, this compression does **not** accidentally disclose additional share bits upon an encryption-coin opening: it preserves one independent ciphertext per share bit, per lane, per capsule.

## Reproducible evidence and boundary

`checker.py` uses only the Python standard library. It asserts the Proth primality congruence and parameter inequalities, source/correctness for two distinct ORIGINAL witnesses on TRUE cycles, same-capability bit decoding and fixed-width serialization, the exact independent FALSE shift and adaptive opening coins, and exact small-space total-variation formulas. It ran twice identically, `2,826` finite assertions per run. This is neither a simulated quantum attack nor empirical native Bitcoin PQ testing. `output.json` is the captured output, and `provenance.json` records SHA-256 digests and execution conditions.

**Unsolved**: This does not turn signed-XOR into generic NP. For arbitrary `R_original` we still lack a polynomial-size, witness-free SOURCE plus non-publicly-reversible release whose full-joint arbitrary-QPT false-instance security is justified and whose arbitrary unauthorized hard-TRUE final-key recovery/accepted native forgery **yields an actual ORIGINAL witness or independently justified PQ break**, without assuming a SOURCE opening or adversary-volunteered representation. No universal short-shift/refutation compiler is established. Malicious N-of-N erasure/preauthorization, abort and DA, authenticated SYS/BTC AuxPoW/tag/window qualification, enforceable challenge inclusion and hypothetical Bitcoin-native PQ signature support remain conditional. No production/merges/deployments are touched or claimed.
