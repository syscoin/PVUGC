# Run 506 — Reversible two-generator late-witness loader and exact public-view symmetry

2026-10-14 UTC. syscoin/PVUGC#1; branch research/pq-wkem-validation-20260918; starting SHA 4482087d574ef63170b9c420e55ea744199936ae. **This is a bounded ideal-model source-input interface theorem, NOT a practical PQ WKEM, WE, iO/RIO instantiation, or release authorization.**

## Exact unary-orbit limitation

From an initial protected semantic plaintext (K,0^n), suppose the only plaintext-changing public operation is sequential iteration of **one fixed deterministic unary F**. Ciphertext rerandomization without changing plaintext is allowed. The number of distinct semantic states reachable with at most T evaluations is at most T+1. To permit an arbitrary later n-bit ORIGINAL witness (2^n possibilities), one needs T >= 2^n - 1. A cycle over all n-bit witness strings achieves this bound. This is not a bound on schemes with an additional public input-write operation, public controlled functions, fast powers, ciphertext merging, or an already encoded late witness. It does not refute Canetti–Luo–Zhang's full scheme; it sharpens the narrow “fixed unary iteration alone” applicability issue.

## Two reusable seed-preserving reversible generators

Let plaintext D={0,1}^h × {0,1}^n consist of a protected native seed K and a witness register w. Define R(K,w)=(K,rot_right_1(w)) and X(K,w)=(K,w xor 1). For target bits w_j (j=0,...,n−1), start from (K,0^n); in iteration j apply X iff w_j=1, followed by R. A flip inserted at j undergoes n−j rotations, landing at final bit j. Thus the final state is (K,w) in exactly n+HW(w) <= 2n reversible calls, preserving K and allowing distinct witness states. It is a constructive **semantic loader**; public availability of protected executions of R and X remains a cryptographic implementation question.

## Positive information-theoretic theorem for the COMPLETE loader-only public view

Choose a **uniform random permutation P on the entire D**, independent of K, its checking key and all auxiliary inputs. Publish both complete conjugated action tables A_R=P R P^(-1), A_X=P X P^(-1) and public anchor a=P(K,0^n). For any K,K', let delta=K xor K' and T_delta(k,w)=(k xor delta,w). T_delta commutes with R and X. Replace P by P'=P o T_delta. Then A_R and A_X remain **pointwise identical**, while P'(K',0^n)=P(K,0^n). This bijection on the uniform permutation space proves that the **joint** distribution of (A_R,A_X,a) is exactly identical for every hidden K. Arbitrary public chosen-input compositions, coherent quantum evaluation and quantum postprocessing of this view cannot distinguish K. A correlated external VK(K) can itself reveal information, but the loader view adds none provided P is freshly sampled independently. Independent fresh P per capsule preserves that limited nonleakage for correlated keys.

The proof concerns the complete loader-only view, not any decoder, release capsule or adversary advice correlated with the hidden P.

**Infeasibility of naive instantiation:** P is a uniform permutation on 2^(h+n) elements. Sampling/storing it and the explicit action tables requires exponential work/space, so this is **not classical PPT setup** and gives no practical 128-bit parameters. Publishing a succinct P and P^(-1) immediately reveals K by computing P^(-1)(a). Publishing only compact A_R,A_X without P^(-1) introduces a new obfuscation/joint-program security obligation; the ideal symmetry theorem does NOT justify it.

## Falsification: orbit reachability is not ORIGINAL authentication

Any outsider can apply the public R/X conjugated actions to a and generate a_w=P(K,w) for **every** chosen w in <=2n calls without knowing K or satisfying R_source(x,w)=1. Hence any proposed release guard that treats mere reachability from a as an admitted ORIGINAL source representation accepts invalid states, even when x is ORIGINAL-false. Requiring an actual source check is necessary. A publicly supplied Boolean “valid” flag is not an authenticated source check. Run 259 begins with an accepted COMPLETE z satisfying the global residual (or the stated SIS collision), not with an arbitrary reachable encoded state. **This theorem does not give an attacker K or a native signature from the loader-only view.**

## Nine attack families (precise scope)

(1) seam and (2) gauge: correlated paths exist; seed-translation symmetry protects the absolute K label in the ideal loader view, not a secret-dependent final gate. (3) fingerprints: cycle/orbit structure can be learned, not the absolute K label. (4) multi-view: reuse of the same P reveals equality of K from anchor equality; fresh frames required. (5) chosen inputs: every w is constructible; reachability fails as admission. (6) malicious setup: P=identity exposes K in a. (7) claim/branch replay: context binding is not provided. (8) public checking key: no *additional* information in loader view under stated independence, not a native-key pseudorandomness theorem. (9) quantum: exact full-view distributional equality survives coherent processing; no QPT claim for a succinct mixer/release.

## Reproduction / dependency / open work

The EXACT committed JS checker was executed twice byte-identically and returned 208461 PASS assertions. It enumerated 40,344 full-permutation couplings (all S_4 and S_8), 2,046 late witness words and 2,046 unary cycle points, 80 larger frame samples and 560 ORIGINAL-false but orbit-reachable toy states. The independent local Python checker passed 374,520 assertions, repeat-byte equality and strict syntax checks. These are toy finite algebra tests only.

Exact current-head dependencies: Run 259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2; Run 504 blob 34789abfe1dd007be319b1781cfa48cc1d4deb40; CLZ applicability blob c19d9d9cd515140e3ce62eac960cd548c0add622. CLZ's CRYPTO 2026 paper (*How to Encrypt with Random Reversible Circuits*, pp.539–580, DOI 10.1007/978-3-032-35367-2_18) advertises unbounded public iterations of one length-preserving g; this research is not a full proof audit or refutation of its controlled homomorphism/FE/CCA security.

**Handoff:** input insertion can be O(n) with two public reversible actions, but they only generate candidate states, never certify the ORIGINAL source. Seek a compact controlled evaluator with sound final admission and a cryptographically protected 256-bit common-seed decoder; attack public P^(-1), seam/gauge leakage, malformed setup, unrelated capsules, and native authorization bypass. Full-public false-instance QPT hiding; arbitrary true-instance signing-to-ORIGINAL extraction; practical classical PPT setup; claim graph; and concrete resources remain UNPROVED. Production untouched; PR must stay draft/unmerged; stopping condition not met.
