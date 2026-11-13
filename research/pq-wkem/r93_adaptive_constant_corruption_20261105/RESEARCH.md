# R93: Adaptive constant-budget opening for R92 threshold LWE-leaf release

Run: R93-ADAPTIVE-THRESHOLD-OPENINGS-20261105 (offline, 2026-11-05).
Repository: syscoin/PVUGC, PR #1, research/pq-wkem-validation-20260918.
Verified initial open/draft/unmerged head: 0601f55e668ce0b8f595a530aff9c032e4e48f3e.
Exact predecessor R92 RESEARCH.md blob 43d1b2f81a01098e295fa2112a943c8d214abf44 and R91 RESEARCH.md blob a880bb46f1bdb83eb4f8e69f3d357d43ec2c4133. Latest previous ordinary PR comment 6665172665. No external internet/literature research.

## Constructive delta and scope

R92 proved a joint-public-output hard-TRUE theorem only for a fixed, pre-selected unauthorized set of disclosed LWE leaf witnesses. Here is an explicit straight-line reduction for a stronger **post-ciphertext adaptively selected corruption set**, provided the maximum number t of corruptions is an absolute constant smaller than k, the threshold. The challenger guesses the FINAL disclosed set U before constructing the complete capsule, simulates genuine QPT-INDCPA leaf ciphertext challenges for all leaves outside U, and aborts only if the adversary later requests an opening outside its guess. Partitioning by the final set avoids any classical rewinding. The loss is polynomial O(n^t) for fixed t, and can be exponential when t grows with n. No new witness-encryption, obfuscation, noncommitting-encryption, random-oracle extraction or SourceOpen assumption is introduced.

A proof correction is necessary: R91/R92's stated 2^(-kappa) terminal for exact seed recovery is NOT justified by the ordinary PRG hybrid, whose challenge does not reveal its underlying seed. The correct tested straight-line distinguisher compares the generator output of the candidate seed with the challenge output. Its uniform-challenge residual is at most 2^(kappa-L), with L the full output length of an independently QPT-secure PRG G:{0,1}^kappa -> {0,1}^L. A separate stronger lemma would be needed to claim a tighter 2^(-kappa) residual. The native target-signature theorem instead uses independently assumed native QPT-EUF-CMA.

This is a restricted proof advance; it is NOT the generic arbitrary-NP recovery-to-ORIGINAL-witness reduction.

## Exact original relation, honest algorithms and parameters

Retain R92's explicit actual source. Parameters: independent prime q>6, n distinct leaf public keys with n<=255, threshold 1<=k<=n, fixed corruption limit 0<=t<k, root length kappa divisible by eight, L>=kappa+1, packed message width ell, leaf matrix dimensions m by d, bounded error distribution chi supported on [-beta,beta], septenary encryption randomness r in {-3,...,3}^m, fresh for every packed group. Require the strict correctness margin 3*m*beta<q/4-1. Honest TRUE leaf public keys are sampled independently by A_i uniform Z_q^(mxd), S_i uniform Z_q^(dxell), E_i from chi^(mxell), B_i=A_i*S_i+E_i modulo q. A leaf ORIGINAL witness is ANY S,E satisfying that ACTUAL A_i,B_i equation and the error bound; it need not be the sampled pair. The full ORIGINAL restricted statement is at least k distinct publicly named leaves with actual valid short-error pairs, with relation identity, claim/UTXO, challenge branch, authenticated anchor/window/context, immutable graph, intended native verification key and exact target message all explicitly bound. This is not a generic SYS/BTC fork-authentication compiler.

Build is classical PPT and does NOT know or need any ORIGINAL witness. Sample T uniform in {0,1}^kappa. For every byte b, choose independent uniform degree-(k-1) polynomial p_b over GF(256) with p_b(0)=T_b. Leaf i receives share t_i from p_b(alpha_i), alpha_i=i nonzero and distinct. Independently encrypt each share in g=ceil(kappa/ell) packed Regev groups using the ACTUAL independently sampled leaf public key and fresh r. Honest N-of-N preauthorization, treated as a separately unproved ceremony/graph premise, supplies one native signature sigma on the exact bound challenge M before funding. Derive disjoint P||Bcheck=G(T), publish Dsig=sigma XOR P, public checking value CK=F(Bcheck,Dsig,actual ciphertext bytes,context,independent related capsules), and Aux=H(Bcheck,Dsig,CK,actual ciphertext bytes,context,independent related capsules). F,H are deterministic classical PPT, acyclic, and have no hidden dependence on T, native secret, challenge randomness or unknown LWE secret. Include preflight only if it can be generated with a genuine challenger ciphertext. Public raw hash of T or any other additional seed-correlated record is EXCLUDED: ordinary PRG security alone would not justify its inclusion. Native sigma/T must be protected or erased in the baseline; all-builder-secrets-retained keyless Build is not established.

Off-chain Open checks ACTUAL public-key secret/error witnesses, decrypts any k distinct valid shares, interpolates the same T over GF(256), verifies all checking and auxiliary correlations, unmasks sigma and requires ordinary native verification on EXACT M. Every valid ORIGINAL threshold witness, including disjoint leaf sets and different valid secret/error representations, reconstructs the SAME precommitted T and sigma. No canonical witness, identical inner state or witness leakage is required for functionality. Large ORIGINAL evidence stays off chain. Bitcoin does not run the verifier, proofs, PCP, VM, or BitVM disputes; the hypothetical native SLH-like signature and no-EC-keypath P2MR-like endpoint remain conditional.

## Exact QPT adaptive-corruption game

Give arbitrary nonuniform QPT A the entire classical public transcript (relation, statement, leaf public keys, capsule ciphertexts, native vk, Dsig, CK, Aux, claim/UTXO, graph, context, anchors/window, independently simulatable preflight, and allowed independently keyed/rooted related capsules) with arbitrary quantum advice INDEPENDENT OF honest setup randomness. After observing all ciphertexts, A can make at most t sequential CLASSICAL Corrupt(i) calls for distinct indices, each revealing the actual honest sampled secret/error key S_i,E_i and its decrypted source share. A can process the entire view and responses coherently internally, and chooses each next index as a function of the preceding quantum/classical interaction. Once corrupted, indices remain in the final set U. A wins by outputting the exact T or a valid native signature on the one target M. Since t<k, its disclosed U does not itself authorize release. No adversary-provided internal representation is requested.

Excluded: adversary already possesses unknown valid secret pairs outside its corruption budget, malicious source key generation, correlated source-secret quantum advice, quantum-superposition corruption-oracle calls, adversarial ciphertext decryption queries, related capsules exposing target source keys or reusing target root, target native signing-oracle query or pre-signature disclosure, selective opening of independent setup coins other than named leaf secret pairs. Classical adaptive corruption is a meaningful improvement over R92's pre-fixed U, but does NOT imply unconstrained adaptive selective-opening security.

## Lemma 1: fixed-final-U coupling with actual QPT-INDCPA challengers

The events E_U = {final disclosed set exactly U, success} partition success, where U ranges over I_t={U subset [n] : |U|<=t}. There are M_t=sum_{j=0}^t binomial(n,j) possibilities. For each fixed U construct Game_U, which encrypts real Shamir shares for i in U and ZERO shares for i outside U. It answers corruption only for i in U, and aborts with zero reward if any outside U is requested. Such a query can never lead to E_U in the real experiment either.

To change a target (i,g) for i outside U, the straight-line simulator samples T, all share-polynomials, native sigma and all unrelated keys itself, obtains one GENUINE chosen-message ordinary-QPT-INDCPA encryption challenge under a true independently sampled leaf public key, and inserts that ciphertext for real share or zero. It need not know that challenge leaf's S_i,E_i or r_{i,g}. It can service every possible corruption consistent with E_U, because those indices are in the known-key set U. Regenerate public CK, Aux, all allowed preflight, and every dependent record from the ACTUAL challenger ciphertext bytes, rather than simulating marginal ciphertexts without their correlations. Any nonuniform QPT A, including one retaining quantum state between successive classical corruption calls, yields a straight-line QPT distinguisher. No rewinding, source-opening oracle, or presumed internal representation is used.

For single-group chosen-message advantage eps_PKE under the EXACT independent TRUE leaf distribution:

|Pr_Real(E_U)-Pr_GameU(E_U)| <= (n-|U|)*g*eps_PKE.

Here eps_PKE must follow independently from ordinary decisional QPT LWE and the septenary extractor, with all parameters/exact sampling accounted for; it is not a new common-release assumption. If full-leaf multi-message INDCPA is independently established with advantage eps_full, substitute (n-|U|)*eps_full.

## Lemma 2: complete source/share independence of root in Game_U

For each fixed U with |U|<k, the GF(256) Vandermonde map from the independent k-1 polynomial coefficients to shares_U has full row rank |U| at distinct nonzero alpha_i. Thus shares_U is UNIFORM and independent of T as a JOINT vector, even conditioned on true public leaf keys. All real source ciphertexts under U use only shares_U and independent encryption randomness; all ciphertexts outside U now encrypt zeros. All actual U secret/error keys, contexts and independently keyed unrelated capsules are also independent of T. The only remaining dependence on T anywhere in this entire public view is through the single PRG output Y=G(T), by the explicit F,H restriction.

A PRG challenger does not disclose T. The simulator nonetheless samples the entire joint opened-share vector directly as independent uniform bytes, samples keys for U, encrypts shares_U normally, encrypts zeros outside U, and uses Y as its P||Bcheck, recomputing Dsig, CK and Aux. This is IDENTICAL to Game_U's complete classical public distribution when Y=G(uniform T), and simulatable with no hidden challenge seed/coins. If Y is uniform L bits, Dsig is uniform independently of native sigma.

## Lemma 3: correct PRG terminal for exact seed recovery and native signature

For exact T, the PRG reduction tests whether G(A_output)==Y, additionally requiring final set U. In the real PRG branch, success by outputting actual T always passes this test; the test may accept extra wrong seeds, which is harmless for an UPPER bound. With independent uniform Y, even a computationally unbounded algorithm can output a matching preimage only if Y belongs to Im(G); that occurs with probability <=2^kappa/2^L. Therefore

Pr_GameU(E_U for exact T) <= eps_PRG + 2^(kappa-L).

This repairs the previously unjustified test-of-unknown-seed derivation. To budget only this term at <=2^(-lambda) over all U, require L-kappa>=lambda+ceil(log2 M_t). The previously published 2^(-kappa) claim is not asserted here.

For a valid target native signature, uniformly replace Y. Because P is uniform, Dsig=sigma XOR P is indistinguishable from a truly independent uniform mask without knowing sigma. A native QPT-EUF-CMA challenger supplies vk; the reduction never asks it to sign target M, constructs independent Dsig, Bcheck, CK, Aux and all allowed related records, and passes A's accepted native signature on M as a real independent native forgery. Hence

Pr_GameU(E_U for native target signature) <= eps_PRG + eps_native_EUF.

Both reductions include the entire public joint view, not only a seed/pad marginal. They use classical PPT honest setup and arbitrary QPT distinguishers, classical adaptive corruptions and independent quantum advice; no proof from a classical rewind, random-oracle extraction or quantum-unsafe assumption is smuggled in.

## Resulting bounded adaptive theorem

Summing the mutually exclusive E_U events over all U in I_t:

Pr_Real[exact T] <= g * sum_U(n-|U|)*eps_PKE + M_t*(eps_PRG+2^(kappa-L)).

Pr_Real[accepted native target signature] <= g * sum_U(n-|U|)*eps_PKE + M_t*(eps_PRG+eps_native_EUF).

Coarse upper bound M_t*(n*g*eps_PKE + eps_PRG + terminal); cap all probability claims at one. This is polynomial-loss for CONSTANT t, NOT for arbitrary k-1 corruption where t scales. n=16 gives M_2=137, M_3=697, M_7=26333. Since g groups can be large, no concrete QPT-128 security is claimed from these symbolic bounds. Related capsules must be counted under independent roots/keys, with no source-key or target-signature leakage. FALSE security remains R91's HONESTLY SAMPLED, pre-fixed TRUE/FALSE leaf distribution; nothing here establishes arbitrary adversarial fixed-FALSE or adaptively exposed uniform-FALSE keys, since such keys do not have known actual short-error secrets.

## Exact checker, output and provenance

The committed checker.py is the EXACT Python source executed in the local container in this run, and captured-output.json is its EXACT stdout. It passed 954,290 finite assertions. It exhausts a GF(5) 3-of-4 toy Shamir sharing system with <=2 classical adaptive key openings, in which the second index depends on the first decrypted share and complete public ciphertext. It enumerates all 78,125 (root, coefficient, pad) tapes, 11 possible final corruption sets, 15,625 complete observed transcripts, exact root-independence histograms, and matches the final-U events in real vs pre-guessed all-outside-U-zero hybrids. It separately checks the size-of-image inequality on a tiny insecure 5-to-10-bit deterministic generator. The test encryption is an idealized toy one-time-pad mod 5; its toy generator is NOT LWE, and no QPT hardness is experimentally verified. Formal claims are the independently derived mathematical hybrids above; checking finite instances does not establish the untested cryptographic premises.

## Exact outstanding ORIGINAL reduction and endpoint obligations

Still missing: a classical PPT generic source Comp(R_original,x) with actual x-dependent, honestly simulatable ordinary QPT-LWE challenge and entire public CK/Aux/related view together, such that every valid ORIGINAL arbitrary-NP witness releases one same precommitted T and ANY unauthorized QPT final-key recovery or accepted already-pre-signed native forgery yields an ACTUAL ORIGINAL witness or an independent justified PQ break, with no SourceOpen and no adversary-supplied representation. R93 does not solve generic NP or SYS/BTC authenticated fork validity. Malicious one-honest N-of-N setup, graph bypass exclusions, abort and pre-funding data availability, censored challenge inclusion, arbitrary/adaptive false instances, all-builder-secrets-retained keyless Build, concrete 128-bit QPT resource estimates and conditional Bitcoin PQ-native endpoint remain unresolved. This is research-only. Do not disable the existing automation.
