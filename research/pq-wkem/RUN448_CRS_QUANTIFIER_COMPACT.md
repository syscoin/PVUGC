# Run 448 — Per-context CRS quantifier gap and quantum grinding

Verified starting head: `0320998abf12ceb1fb58647f08f4ed8a460dd735` on draft/unmerged PR #1, `research/pq-wkem-validation-20260918`. Latest substantive comment: `6067040320`. Exact dependencies Run 447 blob `b745265044224d03d101d15331d7064c4cbab41a` and Run 259 blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`. Prior Simon attacks are ALREADY published in Runs 366 and 415; the separately examined XOR-shift candidate is rejected as duplication, not claimed as a new result.

## Context-dependent reference randomness: classical theorem

Bind complete original statement x=(relation, claim/UTXO, branch, anchors/window, context) with injective encoding, and in an IDEAL random oracle derive rho_x=RO("WKEM-CRS" || Encode(x)). Let Bad_x(rho) mean there exists ANY accepting proof for an ORIGINAL-false x; assume for every fixed false x, Pr_uniform rho[Bad_x(rho)]<=delta. A classical adaptive adversary (even unbounded) that reads at most Q distinct fresh false-statement oracle entries and nominates at most one further new false x encounters a bad entry with probability <=min(1,(Q+1)delta). Proof: lazy sampling makes each fresh rho_x uniform independent conditional on its classical query transcript; union bound. This does NOT cover quantum-superposition queries, maliciously controlled RO, correlated hidden advice, or unlimited aborted setup retries. It repairs only Run 447's trivial shared-rho one-shot selection, not witness encryption.

## Global existential counterexample (information theoretic)

Let all x=(0,z), z in {0,1}^lambda, be ORIGINAL-false. Define rho_z=RO("CRS"||(0,z)) in {0,1}^lambda, and V(rho_z,(0,z),pi)=[rho_z=z AND pi=0^lambda]. For every FIXED z, bad probability is exactly 2^-lambda. Yet with independent RO entries across all 2^lambda statements:

Pr[exists some FALSE z with accepted proof] = 1-(1-2^-lambda)^(2^lambda) -> 1-e^-1 ~=0.63212.

Thus a SINGLE global function G(K,z,pi) that releases K on acceptance is NOT extensionally equal to bottom on all z with constant probability, even though each separately fixed-x circuit is bottom on a 1-2^-lambda fraction of setups. Standard exact-function iO does not permit a universal global replacement based only on the pointwise bound. This is not a concrete key-recovery attack: finding that bad context computationally remains a separate question.

## Coherent quantum context grinding

For an efficiently checkable mark [prefix_lambda RO(x)=0], public deterministic RO evaluation supports reversible coherent phase marking. With near 2^-lambda density and sufficiently many contexts, Grover succeeds in Theta(2^(lambda/2)) oracle calls, whereas independent classical trials require Theta(2^lambda). For the isolated ideal mark-search criterion, 128-bit generic coherent work therefore calls for about lambda=256, NOT merely 128. This is NOT a polynomial-time QPT break for asymptotic lambda, nor a sufficient security estimate for full WKEM. A post-commit genuinely fresh honest CRS without freely searchable claim contexts has a different exposure.

## Boundaries and dependencies

This is a scoped SETUP-INTERFACE result, not a local-mixing release primitive, iO construction, WE, or practical standard-model PQ scheme. QPT security of an arbitrary capsule with correlated native vk, auxiliary quantum information, retained N-of-N setup coins, multiple capsules and actual QROM oracle access is UNPROVED. Run 259 only binds an accepted complete z to ORIGINAL (or conditional SIS break); an arbitrary native signature still need not expose any such z. No ORIGINAL all-witness SAME-K release is constructed. Context/branch/UTXO replay and malicious last-mover seed selection remain open. Numerical checks are finite algebra and ideal Grover amplitude arithmetic only; no quantum machine or concrete hash security test.

Attack taxonomy: cross-claim reused randomness (4); adaptive public input/oracle (5); retained seed, setup grinding and abort (6); cross-context replay (7); correlated pk left open (8); genuine coherent search (9). No claim about local seams, global frame gauge or concrete CCMR/RIO failure. Full CCMR/CLZ primary-paper proofs were not audited here. The native Bitcoin PQ endpoint remains conditional only. **Stopping condition UNMET; production unchanged.**
