# Run 584 — 3-local in-place Toffoli release frontier

**2026-10-17.** Draft syscoin/PVUGC#1, research/pq-wkem-validation-20260918, starting SHA 8dc12eb56c23eee0bc8b03ff248afca2a9d79454. Exact prerequisites: Run 582 blob 196fb9181982758790067c647f7b3eb7de592a27; Run 259 source binding blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2. Run 583 is local-only and is not silently treated as published.

## Exact public construction
For n >= 4, use n classical bits z_0,...,z_(n-1). Apply reversible Toffoli G_2 with controls (0,1), target 2; then for every j from 3 to n-2 apply Toffoli G_j with controls (j-1,j+1), target j. Let U_n be their composition. Publish Q_n(z)=1 XOR output_bit_(n-2)(U_n(z)). This is an in-place, zero-ancilla, exactly n-3 gate, 3-wire local reversible circuit.

## Theorem and proof
The Boolean algebraic normal form of Q_n has degree EXACTLY n-2, but EXACTLY 2^(n-1) inputs are accepted. Hence independent uniformly random public probes find acceptance in expected two trials, even for n=256 (253 Toffoli gates and degree 254).

Proof: F_2=z_2 XOR z_0 z_1 is degree two with unique top monomial z_0 z_1. For j>=3, the updated target is F_j=z_j XOR F_(j-1) z_(j+1), because wire j+1 is untouched at that time. Inductively the unique degree-j monomial is z_0 z_1 times the product of z_t for 4<=t<=j+1. Thus deg(Q_n)=n-2. Every Toffoli is a bijection, so U_n maps the uniform input distribution to itself; an output bit is zero on exactly half the states. Each 3-wire gate, when n>=4, is an EVEN permutation on the full n-wire state because it is repeated on 2^(n-3) untouched-wire assignments. This explicitly avoids the odd in-place transposition synthesis issue of the earlier Run 583 illustration.

## Security scope
If every Q_n-accepted state can be publicly finalized into an accepted branch signing credential, without any independent complete ORIGINAL-source check, a classical PPT attacker succeeds in an expected two probes. The same counterexample defeats arbitrary-QPT accepted-credential hiding under that precise acceptance-only interface; no quantum algorithm or assumption is required. This does NOT break a construction whose complete credential-producing finalizer additionally authenticates an ORIGINAL representation or imposes independently justified secret protection. Run 259 gives only accepted complete representation -> ORIGINAL witness; it does not give credential/forgery -> representation.

Attack taxonomy: visible local gate seams and explicit public chosen-input evaluation; even in-place gauge/permutation, not a hidden odd swap; density fingerprint 1/2 persists at high algebraic degree; no multi-capsule attack, seed leakage, replay or checking-key correlation is needed. Malicious N-of-N setup, true-instance extraction, quantum auxiliary inputs and a protected finalizer remain UNPROVED.

## Executed evidence and references
The exact JS checker in this commit was executed twice with byte-identical stdout: 8,284 finite assertions for n=4..12, covering reversibility, permutation parity, ANF degree/top coefficient and acceptance count. An independent extended Python local checker passed 9,652 assertions. These prove no cryptographic security.

Parity/ancilla context: Boykett, Kari, Salo, arXiv:1602.04967. CCMR local mixing, TCC 2024 / ePrint 2024/006, is background, not broken. No concrete QPT release construction, all-witness SAME key, malicious setup, arbitrary native-signature-to-ORIGINAL proof, 128-bit parameterization or Bitcoin settlement graph is provided. WKEM stopping condition UNMET.
