# Run 558 — LWE compute-and-compare target-entropy interface

Date: 2026-10-16. Draft PR research only, starting SHA `bd643632156f5d15aab2536f9b04cbf460bb7a4b`. One bounded follow-up to Runs 552–557. No code outside `research/pq-wkem/` is changed.

## Focused primary-paper audit

Wichs and Zirdelis, *Obfuscating Compute-and-Compare Programs under LWE*, FOCS 2017, https://ieee-focs.org/FOCS-2017-Papers/3464a600.pdf , pp.600–602, 605, 607–608. A multi-bit compute-and-compare program `MBCC[f,Y,K](w)` outputs K only if f(w)=Y. This is an attractive *narrow* obfuscation interface. However the distributional VBB theorem requires target Y to have sufficient pseudoentropy, or with extra assumptions be computationally unpredictable, **given the plain description of f and auxiliary information**. Theorem 1 in the proceedings addresses high pseudoentropy and branching programs; general-circuit/unpredictable-target extensions require separate hypotheses. The published 2017 proof was not audited for arbitrary QPT attackers.

## Theorem A — exact accept-bit entropy/completeness tradeoff

Let R(x,w) be ANY public Boolean ORIGINAL verifier, and let a public deterministic `Phi_a:{0,1}->{0,1}^k` include any public hash, salt, KDF or local-mixing postprocessing. Define `f(w)=Phi_a(R(x,w))`.

* For all-valid-witness common-key correctness set `Y=Phi_a(1)`. Then classical PPT `Predict(f,a)=Phi_a(1)` wins with probability 1. The target has **zero conditional min-entropy and is computationally predictable**, so the cited compute-and-compare security theorem cannot be invoked. Obfuscating the final code cannot retroactively make the target unpredictable **given the unobfuscated f**, which is what the theorem requires.
* If Y instead is independent uniform in k bits, for any nonempty valid-witness set the event that **every valid witness** triggers release is `[Y=Phi_a(1)]`, probability exactly `2^-k`. For general independent target distribution Q, this is `Q(Phi_a(1))`.
* If `Phi_a(0)=Phi_a(1)`, a false statement releases even on invalid inputs. If those labels differ, the functional test is correct but programmed Y remains predictable.

This is a syntactic, information-theoretic **failure of one proposed theorem application**. It is **not** an attack on Wichs–Zirdelis's actual scheme, nor a general impossibility theorem for WKEM. It is not another attempt to hash different witnesses into a globally common representation: the tested construction maps only the public SOURCE-ACCEPTANCE BIT into a comparison target.

## Theorem B — a genuine restricted semantic island

Let G be injective, f public, setup pick hidden Y and publish P=G(Y). Define the entirely different public relation `R_*((G,f,P),w)=[G(f(w))=P]`. Then by injectivity:

`R_*(x,w)=1 <=> f(w)=Y <=> MBCC[f,Y,K](w)=K.`

This gives **every** valid w the identical K, even if multiple w have different intermediate states. False instances reject. A toy G(y)=y^3 mod257 and f(w)=floor(w/2), w=0..255, has 128 true instances (exactly two witnesses each) and 129 false instances. This G is **publicly invertible and NOT secure**. The exact validation checks each source/release truth value.

A conditional asymptotic version might use a QPT-hard one-way permutation G, Y uniform, f(w)=0||u for w=(u,d). Then half the generated statements are true with two witnesses, and half are false. If G is QPT one-way for uniform Y, conditioning Y to a specified first bit can lose at most a factor two in inversion probability. **This only addresses conditional target unpredictability given P**. It does not establish QPT security of the CC obfuscator with P, K's public native checking key, malicious setup, quantum coherent queries or related capsules. The WZ unpredictable-target result itself needs added hypotheses (RO/ELF); the basic LWE theorem is not automatically a practical 128-bit PQ construction.

Moreover this `R_*` is an artificial one-way-puzzle relation, **not** authenticated SYS/BTC fork/greater-cumulative-work evidence. Setup knows Y, and intended true instances already have a witness at setup. No safe, source-faithful adapter from the desired Syscoin ORIGINAL relation to this island is given. No public-key-only keyless builder or one-honest-party N-of-N generation protocol is established.

## Attack family and QPT ledger

Seam/gauge attacks on transparent masks are irrelevant to this narrower MBCC interface; no inversion of locally randomized gates is claimed. The **public accept target itself** is an exact fingerprint, surviving any one- or multi-capsule public auxiliary view. Adaptive evaluation is not needed to predict Y. Tiny `Phi` collisions cause direct false-release in the toy cases; no extrapolation to cryptographic hashes. Maliciously biased Y/retained coins would void target unpredictability. Cross-UTXO/branch replay requires context-binding not built here. Include `vk(K)`, other capsules, context, and all allowed auxiliary data in target-unpredictability and native forgery games. A classical PPT predictor is already a QPT adversary; for the independent hidden-target island, genuinely coherent QPT security remains **UNPROVED**.

Run 259 supplies ORIGINAL source extraction only for a supplied complete accepted representation meeting its exact residual-map and (where used) SIS conditions. A native signature alone is not such a representation. No recovery/forgery-to-ORIGINAL arrow, full-public false-instance QPT hiding, arbitrary-QPT distributional MBCC proof, N-of-N/abort or practical resource analysis is supplied. Conditional P2MR/SLH endpoint unchanged.

## Reproduction and handoff

The **exact executed** JS checker and captured JSON in this commit report 234,474 assertions, 10,920 public adapters, 135,408 independent targets and the 128/129 restricted true/false toy census. These tests verify elementary finite algebra, NOT cryptographic assumptions.

**Handoff:** Either exhibit an independently secure, publicly source-faithful f with a comparison target unpredictable even given f and full auxiliary data, or reject CC obfuscation as a shortcut. Programming Y into a public SOURCE-acceptance postprocessor, including public salt/hash, fails this exact condition. No complete WE-like PQ witness-KEM exists from this checkpoint.
