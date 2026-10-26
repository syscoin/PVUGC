# Tagless vector-scalar SOURCE release: covered-false native composition (2026-10-26)

Research-only component, **NOT practical generic-NP post-quantum witness encryption, not a Bitcoin deployment, and not a hard-true witness-security proof**. Prior exact checked head `d47fb4cdf4e426ea00749a7e61f2b67850071df0`; Run 704 unit-certificate coupling Git blob `67e2ea70503c0b4cf9379b89b90d98a536e56bba`; Run 697 sparse operator Git blob `736d8d961f06cc0b26745c27a174d21dc486190b`. No outside web research. This variant deliberately removes the Run 696 spectral decoder and Run 704 optional secret-dependent native tag; it does **not** claim that the resulting scalar-only carrier supplies the bridge's hard-true economic security.

## Exact classical algorithms

Let `R_x(w)` be the ORIGINAL relation. The public `x` binds relation identity, claim/UTXO, branch, actual burn/authorization/output, anchors/window, the intended native verifying key and full context. A verified, source-sound compiler must map every valid ORIGINAL witness to its own `y=Encode(x,w)` on which all public residual polynomials `r_i(y)` vanish. That compiler is **not implemented for full SYS/BTC here**.

Work over an explicit finite field `F_q`. Specify explicit polynomial spaces `P_i`, and let `W_x=Σ_i r_i P_i` be a public linear space of formal polynomials. An honest N-of-N preauthorization ceremony conceptually samples a native PQ signing keypair `(sk,pk)←Native.KeyGen(1^λ)` and an **independent** uniform session key `z∈{0,1}^κ`. This research assumes secrecy/erasure; it does not implement the ceremony, malicious-abort defenses, or the conditional PQ-native Bitcoin endpoint. Encode the **entire exact signing secret** and session key reversibly as a vector `T∈F_q^d` (bytes can be embedded in `F_257`; the native key distribution need not be uniform and may correlate with `pk`).

For every coordinate `a≤d` and source residual `i`, sample independently uniform private `q_{i,a}∈P_i`. Publish **only** the complete aggregate polynomial coefficients:

```
F_a(y)=T_a+Σ_i r_i(y)q_{i,a}(y),  a=1,...,d.
Public=(x,pk,F,field,spaces,encoder,context,admissible-aux).
```

There is **no** spectral matrix, candidate eigenvalue/root, extra public native-secret hash tag `tau`, SourceOpen oracle, native-secret-to-session-key KDF, or on-chain NP verification. `Open(F,x,w)` checks ORIGINAL `R_x(w)=1` off chain, computes `y_w=Encode(x,w)`, evaluates every `F_a(y_w)`, reversibly deserializes the exact native `sk` and independent session key, then signs the claim/path-specific message with ordinary Native.Sign. Every valid ORIGINAL witness, possibly with distinct states, evaluates every residual to zero and receives exactly the **same precommitted secret and session key**. The on-chain challenge path, if the specified native signature endpoint ever exists, would only verify its usual native signature and fixed graph conditions.

## Whole-public covered-false theorem and exact simulator

The **actual chosen** spaces must admit the independent, formal polynomial identity `1=Σ_i r_i(y)p_i(y)` with `p_i∈P_i` for the particular false ORIGINAL statement. Then for ANY vectors `T,T'`, writing `Δ=T'-T`, translate every hidden mask as `q'_{i,a}=q_{i,a}-Δ_a p_i`. Uniform independent mask coefficients remain uniform, while `T'_a+Σr_i q'_{i,a}=T_a+Σr_i q_{i,a}` coefficient-for-coefficient for **all** inputs, including malformed inputs. This is a bijection of the honest private random tape, not a marginal-pad or local-probe proof.

Conditionally on `x,pk`, independently generated native pre-signatures and auxiliary material that does not reveal/correlate with private mask coins, the **complete public polynomial transcript** is therefore distributed independently of `T`. The simulator samples the genuine residual spaces and masks and inserts dummy `T*=0`; it does not know a SOURCE opening or even the unit certificate. Exact equality of classical transcript distributions survives arbitrary coherent QPT processing of public coefficients and evaluation circuits, with no rewinding or QROM step. Fully arbitrary secret-correlated quantum advice must already be provided by a matching native-security challenge; ordinary QPT EUF-CMA does not promise a simulator such advice.

With independent masks, any number of related **covered false** capsules sharing `sk,z` compose by conditioning on the same secret and taking products. False/true mixed capsules sharing a secret, disclosure of challenge masks, malicious setup retention, correlated private coins, and unconstrained selective opening are **not** covered. The public native `pk` is key-correlated; the theorem says the capsule adds nothing conditional on that `pk`, not that `pk` itself reveals nothing.

## Straight-line reduction to ordinary native QPT EUF-CMA: no augmented tag assumption

Suppose the native signature scheme is QPT EUF-CMA secure against QPT adversaries making classical signing-oracle queries. Consider an adversary creating a valid new signature on the designated claim/path message that was **never** a legitimately pre-signed or oracle-queried message. A standard-native EUF-CMA reduction, given only challenge `pk` and a signing oracle, builds the exact false-covered release transcript using dummy `T=0`, obtains any legitimate preauthorized signatures from its oracle, invokes the adversary once, and forwards its fresh signature as an EUF-CMA forgery. The simulation is **exact** under the unit identity and independence assumptions. If the adversary returns the native `sk`, the reduction signs a fresh unqueried message with that key and forges. The capsule contributes **zero** extra probability over the standard native EUF-CMA game. This replaces Run 704's *augmented* `(pk,tau)` assumption by changing the construction so no tag is published; it does not assert QPT security of an undeployed signature or extend EUF-CMA to forgeries on previously signed messages. Preauthorized replay/bypass and transaction-graph security remain separate. Public quantum-coherent evaluation is okay; a quantum signing oracle would require the corresponding stronger native-security game.

Because `z` is independently uniform and no key-dependent session tag is published, the same exact coupling gives **statistical session-key IND on covered false instances** against QPT distinguishers. No hash-derived session-key/QROM composition is necessary. Auxiliary data derived from `z` would need separate treatment.

## Instantiated nontrivial false fixture and complete algebraic checks

Take `r1=1-u`, `r2=u(1-v)`, `r3=v`, and `P1=P2=span{1}`, `P3=span{1,u}`. Every Boolean assignment violates at least one residual and **formally** `1=r1+r2+u*r3`. For each protected field coordinate with independently uniform `a,b,c,d`:

```
F(u,v) = (T+a) + (-a+b)u + c v + (-b+d)uv.
```

The transformation from four hidden masks to four **entire published polynomial coefficients** is invertible, so the full law is uniform for every `T`. The published JS checker exhausts all `5^4=625` mask tuples for every secret in `F_5`, all `3^4=81` tuples for every secret in `F_3`, and independently validates formal identities across five fields. For two independently protected capabilities, the extended local-only Python checker exhausts the whole two-capability `F_2` joint law. As a true two-witness check, choose `r1=(1-u)(1-v)`, `r2=u(1-v)`; both `(u,v)=(0,1),(1,1)` recover the exact same protected vector despite different original assignments. These are mathematical fixtures, **not** a SYS/BTC verifier or QPT signature test.

## Exact boundaries and next equation

This scalar-only carrier **provably reveals the complete `T` publicly** whenever `1∉W_x`. An efficiently computed public linear functional `ℓ` can satisfy `ℓ(W_x)=0`, `ℓ(1)=1`; hence `ℓ(F_a)=T_a` for every coordinate. **Every true** instance has `1∉W_x` (evaluate a hypothetical unit identity at any witness), and insufficient-degree **false** instances can also fail coverage. Thus this is **not** a viable witness-cost-based authorization for hard-true PoW/light-client claims, and is directly insecure on uncovered false sources. It meets only the stated bounded-certificate *false-only* security definition. Dropping true-instance extraction from standard WE does not repair this economic-security mismatch.

A polynomial-time algorithm returning polynomial-size **explicit** spaces covering *every* false 3CNF would give a polynomial-time SAT decider through public linear span membership; no such generic construction is claimed. A concise scalar aggregate reduces per-monomial overhead relative to a spectral matrix, but neither the potentially exponential public polynomial coefficient count nor 128-bit QPT parameters are solved. One native-scheme forgery theorem conditional on ordinary QPT EUF-CMA **does not** establish general PQ WKEM.

The exact next release obligation is a polynomial-resource computational carrier with a simulator for **the joint native checking key, original relation, public coefficient/evaluation data, context, auxiliary inputs and related capsules** that does not know the challenge signing secret, and that retains witness-cost security on hard true instances where the bridge demands it. It must not assume a source-opening oracle or an attacker-volunteered representation. The bridge's one-honest-party N-of-N setup, abort/erasure, pre-funding availability, observer inclusion/timing, full AuxPoW/burn consistency, finite source evidence, and conditional PQ-native Bitcoin transaction graph are still open.

## Execution and provenance

The committed self-contained `check_exact.js` is an actual independent executed checker: **70,514 assertions, twice with byte-identical output**, including exact full-coefficient distributions and bijective mask translations. `validation.json` is captured from that executable. A longer Python standard-library checker passed **11,367 assertions twice**, and a full local report/checker/archive is separately available to the user; it is not represented as GitHub-published. Toy algebra tests are not cryptographic security evidence. All changes are research-only under this existing PR branch; no external literature/web research, production code, workflows or deployment changes.
