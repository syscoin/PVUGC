# Run 456 — Public checking keys expose short ancestor-seed entropy

Date: 2026-10-12 UTC. Research only. Live starting syscoin/PVUGC#1 head: 634d2ff059f857396695e9af6ab0ce3ce8378a98, branch research/pq-wkem-validation-20260918, open/draft/unmerged. Production unchanged.

## Precise candidate and threat model

Honest classical PPT setup samples a uniformly random h-bit master S, derives a native leaf signing secret sk_c=Derive(S,c) using a PUBLIC classical PPT derivation algorithm, and publishes the context-specific native vk_c=NativePK(sk_c). The complete canonical context c contains relation, claim/UTXO, branch, anchors/window and sighash binding. Setup parties erase S in the original honest-erasure N-of-N model. A local-mixing capsule may protect sk_c perfectly; the attack does not evaluate the release capsule or need an accepting frontier state. Auxiliary public data includes every vk, other capsules, their checksums, and ordinary transaction messages. Arbitrary quantum advice independent of the secret S is allowed. Correlated advice about S must be included in the actual conditional entropy model and is not covered by this uniform-secret theorem.

## Public-key checking theorem

Define A_c(s)=[NativePK(Derive(s,c))=vk_c] for s in {0,1}^h. This is an efficient publicly checkable predicate with M>=1 solutions because the honest S is a solution. A quantum attacker implements the known classical Derive and NativePK circuits reversibly, then uses standard multi-solution search (including unknown M) to find a solution s* in O(sqrt(2^h/M)) coherent predicate evaluations, up to polynomial gate overhead. It computes sk*=Derive(s*,c) and signs the intended native challenge branch. Correctness of NativeSign for any sk* yielding vk_c gives an accepted signature. Public-key collisions increase M and cannot defeat the attack.

In particular, h=O(log(lambda)) gives a polynomial-time QPT attack. For an illustrative h=128 root the generic quantum upper cost is about 2^64 public-key tests; h=192 gives 2^96; h=256 gives 2^128. These are abstract quantum query exponents, NOT realistic end-to-end gate/space estimates. If the advertised threat target is at least 2^128 such tests, h>=256 is necessary to exclude this particular generic attack for a uniform master-seed construction. A 256-bit leaf signing seed produced deterministically from a 128-bit master still has only 2^128 candidate ancestors.

This is distinct from Run 451: there the ancestor was disclosed by an authorized sibling release; here it remains secret and is searched using PUBLIC vk. It is distinct from Run 454/455: no terminal accepting state, no chosen release call, no source verifier bypass, no public reversible mixer inverse. Run 259 cannot extract an ORIGINAL representation from the resulting native signature.

## Independent multi-target variant

For T distinct independent uniformly generated h-bit native seed candidates under one public native key-generation map, A(s)=[exists i: NativePK(Derive(s))=vk_i] marks at least T distinct seeds when their published vks are distinct. Search uses O(sqrt(2^h/T)) idealized coherent predicate queries. Computing membership against T checking keys costs resources (straightforward O(T) comparisons and table storage); do not treat a giant target set as free qRAM or claim a practical 128-bit cost without an explicit gate/memory accounting. This separate variant does not equate independent leaf keys with T descendants of the SAME master.

## Local-mixing attack taxonomy

(8) The public checking key is the decisive offline candidate oracle; (9) the adversary evaluates it coherently; (4) independent multi-target capsules accelerate a related attack; (5) evaluation is fully local and chosen-input; (6) malicious seed bias would worsen the bound, but honest uniform setup already suffices; (7) complete context, branch, UTXO and message binding prevent replay but not key testing. (1) seams, (2) gauge and (3) gate-class fingerprints are not involved. This is not an attack on an actual RIO/CCMR/CLZ implementation or on the standardized SLH-DSA key generation algorithm.

## Checks and exact scope

Published compact JavaScript checker uses a deliberately invertible 32-bit toy public-key map solely to validate marked-set sizes, multiple targets, and exact coherent Grover amplitudes. Its 32-bit permutation is NOT a cryptographic scheme; source and captured output are committed. An independent local Python checker used SHA-256 child derivation and real Ed25519 (NON-PQ) signatures on h=4..10 root spaces, verified seven exhaustive ancestor recoveries, branch/message rejection, five statevector fixtures and five target-set fixtures; 158 assertions, two byte-identical runs. The local checker and extended proof are not claimed to establish real QPT security.

Honest classical setup/algorithms and arbitrary QPT attack are explicit. QPT coherent access is obtained by reversible simulation of public classical code, NOT by assuming coherent queries to an online service. No use of QROM programming, classical rewinding, secret extraction from obfuscated code or post-unlock constraints. Query bounds concern classical deterministic secret expansion from S; independently generated secret leaf randomness outside S invalidates the h-bit bound.

## Cumulative obligations and handoff

An actual local-mixing WE-like release compiler remains UNCONSTRUCTED. Still unproved: all-witness SAME-leaf capability correctness, full-public-output false-instance QPT hiding, unauthorized true-instance recovery/native forgery -> ORIGINAL representation or independent QPT break, Run 259's complete-representation source binding at the actual release interface, malicious setup/erasure/abort, arbitrary auxiliary advice/capsule composition, concrete 128-bit gates/memory, and conditional nondeployed native SLH/P2MR endpoint. Do not impose the stronger retained-coin public Build model on the original N-of-N baseline. The next constructive pass should use a fixed and sufficiently large independently protected per-claim secret input to any local mixer, and audit how public vk correlates with every key derived from common ancestors; doing so alone does NOT supply WE security.

Literature: Boyer–Brassard–Høyer–Tapp, *Tight Bounds on Quantum Searching*, https://arxiv.org/abs/quant-ph/9605034 (search with unknown numbers of marked inputs). NIST FIPS 205 public record https://csrc.nist.gov/pubs/fips/205/final . CCMR https://eprint.iacr.org/2024/006 and live CLZ_APPLICABILITY_20261008.md remain architectural background; no full new cryptographic proof audit this run.