# Run 367 — coherent public-sampler density at a source-sensitive release frontier

Starting exact draft PR head: `e64820d82318765ec36360caf11370c4d8c03f82`. Run 366 note: blob `b1b184d81d1be3bd2b675e275dfa99acaeb839b4`; Run 259 binding note: blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`.

## Theorem (precisely conditional)

Let a classical PPT setup publish the complete public capsule P_x, native checking key pk_x, relation/UTXO/branch/window/context and intended challenge-message binding. Assume a separately callable public classical PPT release frontier Release(P_x,z;coins), plus a public classical PPT Check(P_x,pk_x,challenge,candidate;coins') which accepts exactly when its candidate gives a usable **new pre-release challenge authorization**. Let S_x(u) be any publicly efficient sampler, with all randomized coins explicitly included in a uniform seed u of length d. Let T_x(u)=Check(Release(P_x,S_x(u))) and p_x=Pr_u[T_x(u)=1].

All public classical computations have reversible coherent implementations. A QPT adversary implements a phase oracle for T_x, uncomputes its work registers, and amplitude-amplifies the sampler. For known p, after t Grover iterations the EXACT marked-state probability is

`sin^2((2t+1) arcsin(sqrt(p_x)))`.

For p>0, public amplification gives an accepted authorization with O(1/sqrt(p_x)) coherent Release/Check evaluations (standard unknown-p search is also possible). The adversary need not reveal an ORIGINAL witness or an accepted Run-259 representation. Neither an NP verifier nor a VM transition is evaluated on Bitcoin. If Release is not independently callable on arbitrary sampler-produced raw states, this theorem does NOT apply.

If the raw-input space is all d-bit strings and M distinct strings successfully release/sign under the *actual correlated public pk_x*, then p=M/2^d. The search-only 128-bit oracle-query benchmark therefore requires approximately d-log2(M)>=256. This is a **necessary benchmark against this specific attack, not sufficient concrete PQ security**; oracle gate costs, hardware, memory and other attacks remain separate. Do not count original witnesses unless their accepted state encodings are distinct.

The checking predicate recognizes usable native authorizations, NOT source validity. Ambient non-ORIGINAL successful states (as in the Run-362 style source-language enlargement) increase M without breaking Run 259's conditional supplied-representation theorem. Legitimate public-signature relays (Run 361) are excluded: success here means fresh pre-release control.

## Attack taxonomy and scope

The attack uses public chosen-input evaluation, the public checking-key correlation, and genuine quantum coherent amplitude amplification. It needs no local seam, gauge synchronization, statistical gate fingerprint, Simon period, or cycle. Related capsules may offer a larger maximal p; no multi-capsule direct-sum theorem is claimed. Malicious setup/retained coins, cross-UTXO/branch replay, and distinct native sighash encodings require independent proofs. A hidden/authenticated uncallable boundary is outside this falsifier.

## Literature and proof status

Brassard–Høyer–Mosca–Tapp, arXiv:quant-ph/0005055, supplies the amplitude amplification result. Actual Sections 6.1–6.3 of Gheorghiu–Gupte–Havlíček–Liu, arXiv:2609.40289v2 (PDF dated 2026-10-06), were inspected: Assumption 6.1 is quantum split-circuit pseudorandomness, Assumption 6.3 is quantum RIO including correlated public-view seam experiments, and Assumption 6.5 is a separate stability requirement; Theorem 6.4 and Corollary 6.6 are conditional, not concrete PQ source-extractable release. The full Canetti–Chamon–Mucciolo–Ruckenstein ePrint 2024/006 primary PDF was unavailable (HTTP 403); no full audit is claimed.

An exact standard-library finite checker passed syntax validation and two byte-identical executions. Its compact published version checks 232 exact Grover/closed-form identities; a more extensive local version checks 4,136 assertions. These numerical identities do not prove QPT hardness or an implemented witness-KEM.

**Unproved:** all-public-output false-instance QPT hiding; unauthorized true-instance final-key or new challenge signature -> accepted Run-259 representation -> ORIGINAL witness/QPT break; malicious N-of-N ceremony/abort/erasure, multiple capsules, P2MR-like native SLH endpoint/graph, concrete 128-bit resources. Practical PQ WKEM UNSOLVED; no production changes.
