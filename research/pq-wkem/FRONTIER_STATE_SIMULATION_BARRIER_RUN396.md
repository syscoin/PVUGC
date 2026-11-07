# Run 396 — Witness-free simulation of a randomized local release frontier

**Date:** 2026-10-09 UTC. **Scientific status:** a scoped *negative* theorem, not a WKEM implementation or a new assumption. **Source:** live `syscoin/PVUGC#1` head `bba5c4bb4e37144a390b40f0b58a7ff633d7a1f1`, branch `research/pq-wkem-validation-20260918`, open/draft. Read back the exact Run 259 source-binding proof (blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`), Run 393 ideal extractor (blob `7ee3cc73f1115a2788a4d54021ca808f865405dd`), Run 394 generic-NP QROM WE implication (blob `7afc59866028fef93728d6c3da766d7c9deafdc6`), and CLZ applicability (blob `c19d9d9cd515140e3ce62eac960cd548c0add622`). The most recent substantive ordinary PR comment was 6067040320. Run 395 is not the actual PR head.

## Question and model

Can a *small*, independently callable protected release region accept an already-publicly-verified, witness-derived state if the state is randomized so thoroughly by local reversible mixing that its complete distribution is efficiently samplable *without the witness*?

Fix a **true** and precisely context-bound `x` (relation/claim/UTXO/branch/anchors), honest classical PPT setup producing full public view `V=(x,P_x,vk_x,aux)` and a signing capability `K_x`, and a valid ORIGINAL witness `w` independent of secret signing-key generation. A public classical PPT source algorithm `E_V(w;r)` returns a *complete* frontier input `s`, including every label, tag, proof and metadata actually supplied to the protected region. Let a separately callable classical PPT release algorithm `L(P_x,s)` return a candidate credential. The public native algorithm `Authorize(V,s)` tests whether this credential produces a valid ordinary signature for the intended branch message; release may use fresh coins (included in both distributions). Attackers are arbitrary QPT with all published keys, arbitrary allowed auxiliary classical/quantum registers, related capsules and coherent access to public code. This attack requires only classical independent chosen-input evaluation.

The interface condition **independently callable** is indispensable. This result does not extract internal states from a white-box obfuscated *whole* program, does not posit that separated source computations can be bypassed in a protected implementation, and does not assume RIO reveals gate tables or inverses. `P_x` is only the public release component and is *not* assumed to contain a working secure obfuscation.

## Theorem — witness-free simulator barrier

Let `D_real` be the joint distribution of `(V,aux,E_V(w;r))`, including *all* signing-verification-key and auxiliary-state correlations, and let `D_sim` be `(V,aux,Q(V,aux))`, where `Q` is a classical PPT sampler not given `w`, `K_x`, or hidden setup coins. Suppose:

1. **Honest correctness:** `Pr_{D_real}[Authorize(V,s)=1] >= 1-epsilon`.
2. **Sampler closeness:** the classical joint total variation distance is `Delta(D_real,D_sim)<=eta`. With auxiliary quantum advice, replace this by the complete joint cq-state trace distance (and require `Q` to use only its allowed input). Alternatively assume the exact QPT indistinguishability advantage against the specific public `Authorize` distinguisher is at most `eta`.
3. The claimed source-enforcing release accepts arbitrary `s` at its public input boundary. No unseen credential or authenticated source-binding material lies outside the modeled `s`.

Then a **classical PPT attacker without an ORIGINAL witness**, who samples `s<-Q(V,aux)` and calls the release/signing algorithms, obtains native authorization with probability at least

`Pr[unauthorized native authorization] >= 1 - epsilon - eta`.

**Proof.** `Authorize` is a public PPT event on the complete correlated distributions. Statistical distance bounds its success-probability gap; likewise, computational QPT indistinguishability bounds the gap because the public authorization circuit is itself a QPT distinguisher. Honest correctness supplies the first probability. No extraction, random oracle, rewinding, LWE/SIS assumption, or secret-key inversion is involved. The attack is classical, so it also works for the arbitrary-QPT adversary game. `eta` MUST measure the **joint** view and complete frontier input, not individual marginal distributions. This is an elementary statistical/computational simulation lemma, not a claimed novel mathematical technique.

### Exact full-domain permutation corollary

Suppose for any fixed valid `w` and fixed honest public/setup view `V`, the source frontier state is

`E_V(w;r) = pi_{V,w}(r)`, with `r` uniform on `{0,1}^b` and `pi_{V,w}` a bijection.

`pi` may be a randomly composed reversible circuit, a per-witness shift/permutation, or even a hidden permutation. Conditioned on `(V,w)`, `E` is **exactly uniform**. Thus `Q` simply samples a uniform `b`-bit state: `eta=0`. If the release function succeeds with probability at least `1-epsilon` on any valid witness's randomized frontier states, then it succeeds with **the same probability** for a witness-free random state. Even a *secret* full-domain permutation does not preserve source admissibility at an independently callable frontier.

This is not a generic no-go for local mixing or iO: RIO aims to mix *circuit representations*, not necessarily to make every accepting witness's complete input to a separable release function uniformly samplable. Correlated source certificates/proofs or a source-checking circuit behind the protected boundary can defeat the simulator premise; their security remains to be proved. It also does not attack a frontier that can only be evaluated as part of a sealed whole source-to-release program.

## Joint-correlation negative control

It would be invalid to infer the theorem from *separate marginal uniformity*. For uniform `u` and fixed key `K`, let two shares be `(u,u XOR K)`. Both individual shares are uniformly distributed. Their joint distribution is supported on only `2^b` of `2^(2b)` pairs. Compared to independent uniform shares, total variation is exactly `1-2^-b`, and the XOR decoder succeeds with probability `1` on honest correlated pairs but only `2^-b` on independent pairs. Therefore the theorem cannot be used unless `Q` simulates **all of** `(P,vk,aux,s)` jointly. This check is especially important for neighboring gate masks, frame seams, multi-capsule correlations and public checking keys.

The theorem is also distinct from Run 388's quantum searchable accepting-state density bound: Run 396 gives a **direct classical, polynomial-time authorization attack without searching at all**, whenever a witness-free efficient sampler of the complete accepting-state distribution is available. It does not imply such a sampler exists for a sound protected release program.

## Run 259 interface and attack taxonomy

A successful random `s` need not contain any accepted **complete** `z` satisfying `rho_x(z)=0` (or accepted SIS global fingerprint). The attack therefore escapes Run 259 without contradicting it. A repair must cryptographically ensure that the **entire accepted release input** is a complete source-bound representation (or permit an independently justified reduction from arbitrary native authorization to one); publicly calling a source verifier and then passing an unprotected `accept=1` flag to an independently callable release does not suffice.

(1) **Local seam/cancellation:** an unprotected independently callable cut is the attacked seam; no gate-inverse leak is required. (2) **Global gauge/synchronization:** not needed; full-domain permutations are covered even when secret. (3) **Fingerprint:** joint-correlation counterexample shows why uniform marginals are inadequate. (4) **Multiple capsules:** theorem requires Q to sample complete *joint* view; not shown for related capsules. (5) **Chosen-input/public evaluation:** direct one-sample attack, no trace dispute. (6) **Malicious setup/retained coins:** attack already works with honest setup; malicious security remains unproved. (7) **Cross-UTXO/branch replay:** not assumed; bind context and independent credentials. (8) **Public checking key:** explicitly in `V` and used by `Authorize`, not ignored. (9) **Quantum coherence:** this falsifier is already classical; no separate coherent attack on surviving architectures or QROM extraction is claimed.

## Exact finite validation and provenance

The exact deterministic `frontier_state_simulation_run396_check.js` uses every one of the `8!=40320` reversible three-bit permutations, three distinct valid witness labels and eight randomizer states each. It checks 967,680 complete honest state evaluations: the honest success rate and the witness-free uniform sampler success rate are **both 7/8**. It separately verifies two-share marginal uniformity and exact `TV=7/8` versus independent random shares (which authorize with probability `1/8`). The 242,074 JavaScript assertions pass; repeated executions are byte-identical. A separate extended Python checker (242,082 assertions) also passed but is preserved locally only. These are finite tests of the theorem's hypotheses and negative control, not cryptographic security experiments; the symbolic signing capability is deliberately insecure and the test does not instantiate RIO, SLH-DSA, SIS or a WKEM.

Literature context: Canetti–Chamon–Mucciolo–Ruckenstein, *Towards General-Purpose Program Obfuscation via Local Mixing*, TCC 2024 / ePrint 2024/006, https://eprint.iacr.org/2024/006 (explicitly conditional RIO to iO under split-circuit pseudorandomness). A 2026 quantum extension of local-mixing ideas, arXiv:2609.40289, https://arxiv.org/abs/2609.40289, is a literature lead only; full quantum proof and exact assumptions were not audited in this pass. This theorem is **not** attributed to either paper.

## Core handoff

A viable construction needs a *not publicly simulatable, cryptographically source-bound* complete release input or a sealed full-program boundary; it must not merely make valid witness-state marginals look random. This is a **necessary negative criterion**, not a substitute for a construction or permission to assume source-gated release. The main missing arrow remains `arbitrary unauthorized signing -> accepted complete Run-259 representation -> ORIGINAL witness or independently justified QPT break`, together with full-public false-instance QPT hiding, N-of-N malicious/abort/erasure, all-witness common capability for a secure implementation, joint capsules, 128-bit concrete resources and the conditional Bitcoin native-PQ endpoint. All unproved. Research-only; no production changes and no automation stopping condition met.
