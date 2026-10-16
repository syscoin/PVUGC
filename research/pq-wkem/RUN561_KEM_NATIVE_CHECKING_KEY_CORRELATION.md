# Run 561 — conditional QPT-native signing-key correlation firewall (minimal release interface)

Date: 2026-10-16. Research-only checkpoint on draft syscoin/PVUGC#1. Exact starting PR head `80e9b844d9d1320af5b866eeb5628892ac13f9ef`. No production, graph, or native Bitcoin change.

## Finding: the right public-verification-key security game

A valid SLH-DSA-style signing secret `sk` is not pseudorandom *given its public verifying key* `pk`: testing a candidate secret against `pk` distinguishes it from an independent guess. But this observation **does not** invalidate a standard chosen-message witness-encryption (WE) security reduction. For any false ORIGINAL statement `x`, suppose `W.Enc(x,m)` is QPT IND secure for arbitrarily chosen equal-length plaintexts. The minimal hypothetical release capsule may be simply `(pk, C=W.Enc(x,sk))`. The WE-IND reduction internally generates `(sk,pk)`, chooses messages `sk` versus `0^L`, and publishes `pk`. In the zero-message hybrid a QPT EUF-CMA reduction receives external challenge `pk` and publicly computes `W.Enc(x,0^L)`. Therefore, for a *fresh* pre-release challenge-path signature:

`Pr[forge on false x] <= Adv_WE-IND(false x) + Adv_Sig-EUF-CMA`.

This is a **straight-line QPT reduction** (with classical honest setup/encryption); it needs no false assertion that `sk` looks random given `pk`. It neither constructs WE nor proves security for TRUE instances.

## A KEM-only release interface, if a concrete minimal mixer ever exists

If the protected frontier can only encapsulate its own uniform secret instead of encrypting chosen messages, let honest classical-PPT `Encap(x)` return `(C,K)`, where `K` is uniform `L` bits and can be recovered off chain by **every valid ORIGINAL witness** using `Decap(x,C,w)`. Generate a fresh independent signing pair `(sk,pk)` of serialized secret width `L`; publish `T=sk XOR K`, `C`, `pk` and all exactly bound `x=(relation identity, claim/UTXO, branch, anchors/window, graph/sighash context)`. An honest watcher recovers the SAME `K` from any valid witness, computes the SAME `sk=T XOR K`, checks the derived `pk`, and signs the intended branch only. Bitcoin would only verify a conditional native signature plus its fixed graph constraints.

**False-instance KEM-key-pseudorandomness game.** For `x notin L_R`, an arbitrary nonuniform QPT adversary must not distinguish `(C,K)` from `(C,U_L)` when `(C,K)<-Encap(x)` and `U_L` is independent uniform. Public algorithms are available for coherent quantum evaluation; public pp, auxiliary context, checking keys and honest setup transcripts are part of the simulator's view. Quantum advice cannot contain erased secret state or otherwise violate the assumed honest setup. This is a **requirement**, not a proven assumption.

**Theorem: correlated-pk false-instance fresh-signature bound.** A QPT KEM game adversary obtains challenge `(C,V)` for `V=K` or `V=U_L`, generates `(sk,pk)` and gives a targeted forger `(pk,T=sk XOR V,C)`. In the random-key hybrid, `T` is statistically uniform and independent of `(sk,pk,C)`; an EUF-CMA forger with only public challenge `pk` can itself sample `T`, run public `Encap(x)` to get a `C` and emulate all permitted signature queries. Hence

`Adv_false_fresh_sign <= Adv_KEM_false_key_PR + Adv_Sig_QPT_EUF-CMA`.

Both reductions are **straight-line**, with no rewinding, no QROM programming and no quantum-state copying. Recovery of the complete signing secret also yields a fresh signature, so it is covered under the stated signature-security game. Neither result asserts pseudorandomness of `sk` given `pk`.

**WE equivalence boundary.** A general-NP uniform-key KEM with this strong false-instance key pseudorandomness can encrypt arbitrary same-length messages using public `m XOR K` alongside `C`; therefore it already implies ordinary witness encryption. Renaming it a local mixer would be circular. If only one-way secrecy of `K` is available, the XOR-signing-key security proof above is **not justified**, because partial leakage of `K` leaks `sk`. The fundamental relation-dependent cryptography is still missing.

## Specific attacks and composition scope

(1) Seam cancellation: public `T` is uniformly distributed given `pk`, but combining it with any independently recovered `K` reveals `sk`; the joint security relies entirely on the claimed KEM-key game. (2) Frame/gauge: no frame network exists in this wrapper. (3) Fingerprints: `T` alone leaks no information about `sk`; `(T,C)` is computationally protected only conditionally. (4) Multi-view: reuse of a pad is fatal—given `sk_1,T_1,T_2` with shared `K`, compute `K=sk_1 XOR T_1`, then `sk_2=T_2 XOR K`, even if x2 is FALSE. Sharing one `sk` across independently challenged UTXOs is also fatal after any legitimate unlock. (5) Chosen public input: the KEM theorem has to include arbitrary coherent computation of public `Encap/Decap`, not just honest watcher inputs. (6) Retained setup coins, known full `K` or `sk`, biased K and forged pk: **outside this honest setup theorem** and fatal without a genuine N-of-N one-honest, erasure/abort ceremony. (7) Cross-UTXO/branch replay: unique independently generated keys/capsules and exact sighash/path binding are mandatory. (8) Checking-key correlation: handled explicitly by EUF-CMA hybrid, not by secret-key pseudorandomness. (9) Coherent quantum attacks: reductions are QPT-compatible conditional on QPT KEM-key PR and signature EUF; no new quantum hardness is proved.

## Run 259 and the remaining gap

Run 259 `GLOBAL_FINGERPRINT_SOURCE_BINDING_RUN259.md`, exact source blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`, proves a downstream implication *accepted complete representation -> ORIGINAL witness* (statistical global folding or conditional SIS). **Neither of the false-statement native-key hybrids proves that a naked accepted signature for TRUE x produces an accepted representation.** This crucial pre-release `forgery/recovery -> complete z -> ORIGINAL` arrow remains UNPROVED. Standard WE/KEM hiding for false instances is not a knowledge-extraction theorem for true ones. Plain public checking also cannot replace it.

N-of-N ceremony/secret erasure/abort, multiple true/false capsules, malicious setup, public evaluation of a concrete mixer, 128-bit concrete resources, Bitcoin preauthorized challenge/timeout graph and native-PQ deployment are all UNPROVED. A hypothetical no-EC-key-path P2MR-like output does not install native SLH verification, CAT or NP verification. No BitVM proof execution is introduced. The stronger keyless retained-coins builder game is not satisfied.

## Executed finite checks and resource note

The separately committed exact JavaScript checker exhaustively checks uniform OTP masking against public key predicates for toy 2–8-bit keyspaces, two distinct valid witness inputs recovering the same signed secret in a functionality-only fixture, key/pad reuse exposure and public key checking correlations. Its output is recorded alongside source and provenance. **These tests do not instantiate a KEM, WE, signature scheme or QPT attack.** An independent larger Python checker and extended proof are preserved locally.

For FIPS 205 SLH-DSA serialized secrets `L=4n`: 64/96/128 bytes for n=16/24/32; a KEM-only XOR wrapper adds exactly `L` public bytes but no on-chain evidence-dependent computation. Native signing remains hypothetical for Bitcoin; signature sizes/network assumptions are not certified here. Primary parameter reference: https://csrc.nist.gov/pubs/fips/205/final (2024-08-13).

**Decision:** the public checking-key correlation is a solvable *composition* issue; it is not the central relation-dependent mixer. Do not treat a uniformly hiding general-NP KEM as narrower than WE, and do not infer true-instance source extraction from EUF-CMA or Run 259 alone. Stopping condition unmet.
