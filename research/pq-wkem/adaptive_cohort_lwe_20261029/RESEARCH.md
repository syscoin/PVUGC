# Adaptive-cohort, one-LWE-hybrid release theorem for the signed-ternary SOURCE (research only)

## Exact predecessor, purpose, and status

Offline continuation on syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918, starting head 122ceaaee4257410d8b1436558848d115ada1819 (open/draft/unmerged). Selected original file signed_ternary_triple_lwe_20261029/RESEARCH.md, exact Git blob 4197776ae7618e94d6cc56452f97540aa15f7ed1, and the original contributor model distributed_prime_lwe_source_20261029/RESEARCH.md, blob 5339c8fdde647c2f217593f57e0444730a4bf5. Latest substantive ordinary PR comment inspected: 6505607709. No external literature/web research or full PR diff.

**Actual constructive change:** Replace the fixed-in-advance corrupted N−1 cohort in the surviving LWE SOURCE theorem by an adaptively selected set of up to N−1 distinct contributors, chosen after the full public transcript and from earlier complete opening replies. At least ONE contributor must remain uncorrupted across the ENTIRE related-capsule collection. The proof uses a survivor-event decomposition (not quantum rewinding), one global decisional LWE hybrid, one bounded complete-ciphertext statistical replacement per possible survivor, and an independently justified native QPT EUF-CMA reduction. This removes the earlier unnecessary second LWE term. It is NOT an arbitrary-NP witness-KEM, a malicious-secure ceremony or a 128-bit security calibration.

## Honest classical PPT distribution and SAME-capability release

Let q be an odd prime and n,m,N,J,L polynomial in security lambda. Sample uniform A in F_q^(n×m), uniform s in F_q^n, bounded efficiently sampled e in chi^m with |e_j| <= B, b=A^T s+e, and publish H=[A;b^T]. A valid restricted SOURCE preimage is any (s',e') with b=A^T s'+e' mod q and |e'_j|<=B. Honest SOURCE generation is a TRUE-LWE sample. This does NOT compile a general ORIGINAL relation into LWE.

Independently run genuine native KeyGen to obtain complete serialized signing secret sk and native checking key pk, bound to SOURCE H, relation identity, claim/UTXO, branch, anchors/window/context and intended challenge path. The whole *usable native secret* is divided into L=ceil(secret-bits/3) base-8 digits a_l (final zero padding checked). An honest-erasure dealer samples N−1 independent uniform q-ary shares for each digit and sets the last to a_l minus their sum mod q. It privately authenticates and distributes these to N contributors, then erases the original sk and all full-share/coin lists. Honest setup and eventual erasure are essential; no dealerless malicious secure KeyGen is claimed.

For each of J independently randomized capsules and each digit, contributor i samples r_(j,i,l) uniformly from signed constant-weight support

    T={r in {-1,0,+1}^m: number of nonzero entries exactly w},
    |T|=binom(m,w)*2^w.

Sampling can use exact uniform combinatorial unranking with bounded rejection and pre-funding abort, as in the predecessor. It emits full authenticated ciphertext

    u_(j,i,l) = A*r_(j,i,l),
    v_(j,i,l) = b^T*r_(j,i,l) + g*z_(i,l)     (mod q),
    g=floor(q/8).

A keyless assembler sums all N contributor ciphertexts, without seeing the complete sk. For ANY accepted restricted SOURCE witness (s',e') the public off-chain Release residual is

    d = v-s'^T u = g*a_l + e'^T sum_i r_(j,i,l)  (mod q),
    |e'^T sum_i r_(j,i,l)| <= N*w*B.

All eight circular digit centers are separated by at least g; if g>2NwB, nearest-center decoding returns exactly a_l for EVERY witness and every honest coin sample. Thus all witnesses and related same-scope capsules recover one precommitted native sk, checked against genuine pk; native signing happens off-chain. Large evidence remains off chain and Bitcoin does not verify the original NP relation. Native SLH-like signatures on a no-EC P2MR-like output remain an unverified endpoint assumption.

## Full joint public/QPT/adaptive corruption game

A nonuniform arbitrary QPT adversary sees the classical full relation/statement/source H, genuine pk, context/claim/branch/anchors, every participant's public ciphertext, aggregates, authenticators, all J related same-scope capsules and auxiliary data generated from public inputs, independent authenticator randomness and permitted revealed shares. It may make arbitrary classical native nonchallenge signing queries. It may *adaptively* call Corrupt(i) for new contributor identities, cumulatively at most N−1 across all related capsules, learning that contributor's q-ary share for EVERY digit, ALL its encryption coins for all capsules and any independent authentication secrets; all revealed openings must reproduce the published data. It can choose the next identity based on pk, full public data, previous openings and its coherent QPT computations. There is no SourceOpen oracle, source witness leak, protected contributor exposure, native sk/dealer-retention leakage, malformed public share-to-pk proof, superposition corruption/signing interface or unknown secret-correlated quantum advice.

The attacker wins by outputting a usable complete native secret or an accepted fresh native signature on the intended unqueried challenge path. If it outputs a usable native secret, a challenger can use that secret to sign a fresh intended message; the event yields a native EUF-CMA forgery. Public source-binding records, authentication and permitted auxiliary records must be efficiently simulatable from H, pk, context, corrupt openings and independent keys; arbitrary auxiliary dependent on hidden s,e,sk or the protected contributor is NOT covered.

The same native key can be shared by J capsules ONLY as aliases of the same claim/path authorization scope. Across different authorization scopes it must be different; otherwise one valid release authorizes all. The N−1 corruption budget is **global across related capsules**, NOT N−1 per capsule with a changing union. If a sequence of corruptions reveals all N parties' q-ary shares over different capsules, summing the shares directly reveals sk without NP witness: this is a real failure.

## Precise non-rewinding reduction, including full checking-key correlations

Let Win be native-key recovery or fresh native forgery, and for h=1..N let Win_h = Win AND h was never corrupted. Because at most N−1 distinct parties can be corrupted, Win implies OR_h Win_h. Consequently Pr[Win] <= sum_h Pr[Win_h] in *each* game; the events need not be disjoint, and the adversary never volunteers a survivor index.

G0 (real) to G1 (uniform SOURCE): Replace only H=(A,A^T s+e) by independently uniform (n+1)×m H. An ordinary decisional-QPT-LWE challenger supplies H; the distinguisher can itself run genuine native KeyGen, produce all q-ary shares, all contributions and authenticators, and answer ANY adaptive corrupt-share/whole-coin queries, without knowing s,e. The entire interactive public transcript is a classical efficient transformation of H and independent randomness. Quantum data processing and QPT decisional LWE therefore give

    |Pr_G0[Win]-Pr_G1[Win]| <= Adv_QPT-DecLWE(q,n,m,chi).

**There is no second reverse LWE hybrid.** The final native-EUF simulator can sample H uniformly itself. This strengthens the predecessor's formerly stated two-LWE-term bound.

Fix h. G1 to G2(h) (zero protected contributions): Under uniform H, independently replace only h's J*L encrypted q-ary shares by encryptions of zero using independently sampled r in T. Stop/abort the h-specific experiment on Corrupt(h), where Win_h has already become false. For every distinct r,r' in T, r-r' has a nonzero coordinate mod q (q odd prime), so uniform H maps r to H*r as a two-universal hash family. An exact complete-output second-moment argument and Cauchy-Schwarz give

    delta_T = (1/2)*sqrt((q^(n+1)-1)/(binom(m,w)*2^w)).

A last-coordinate shift g*z_h preserves distance to uniform, so the mean statistical distance between Enc_H(z_h) and Enc_H(0) is <=2*delta_T, for every fixed hidden z_h independent of H. For J*L fresh independent protected r with the SAME H, a sequential product hybrid costs <=2*J*L*delta_T. The real pk, other N−1 shares, full corrupt coins, authenticators, public context and related capsules remain jointly present. Conditioning on these independent setup coins and source-independent native secrets is legitimate; adaptively selected disclosures are applied afterwards as quantum channels, so they cannot increase the initial trace distance. No classical rewinding or random-oracle extractor is used.

G2(h) to native EUF-CMA, directly: Obtain genuine pk and a classical signing oracle from the native EUF-CMA challenger but not sk. Choose uniform H. For every digit, independently sample N−1 q-ary shares for contributors i≠h, and honestly encrypt them with retained coins. Publish an encryption of zero for h; all aggregate/authenticator/related-capsule outputs are computed exactly from these public contributions. For ANY fixed native digit a, every selection of N−1 coordinates from a uniform additive N-of-N sharing is itself uniform on F_q^(N−1), independent of a and of pk. Therefore the entire G2(h) distribution (including adaptive replies to Corrupt(i) for i≠h) is EXACTLY simulated without sk. A successful usable sk or fresh signature gives a native EUF-CMA forgery. This is the indispensable checking-key correlation: native pk is real, not replaced with a synthetic fingerprint, and no unknown protected share is needed by the simulator.

For each h,

    Pr_G1[Win_h] <= 2*J*L*delta_T + Adv_QPT-native-EUF-CMA.

Take the survivor union once in G1, and combine it with the ONE global LWE hybrid:

    Pr_G0[Win] <= Adv_QPT-DecLWE
                  + N * (2*J*L*delta_T + Adv_QPT-native-EUF-CMA).

All assumptions are independent ordinary nonuniform-QPT decisional LWE and native EUF-CMA with classical interfaces. N is a genuine proof-loss factor; a claim of unchanged concrete QPT security would be incorrect. The proof covers arbitrary coherent QPT computation on classical transcripts and adaptive classical disclosures but not quantum oracle-superposition openings, secret-correlated quantum auxiliary input or malicious N-of-N dealer/output-authentication.

## Bounded executed check and illustrative resources

The exact committed standalone JavaScript checker was executed as its actual V8 function body and passed 5,336 assertions. Its captured OUTPUT.json records 2 related capsules, a full 256-bit mock secret, 41 complete adaptive corruption paths, 2,064 contributor-opening consistency checks, exact enumeration of 9 q=3 additive-sharing marginals and 6,561 uniform toy H matrices over F_3 with 24 signed-ternary coin vectors. Mean complete-output TV was 0.21717556605529426 against delta=0.28867513459481287; mean shift TV 0.25727785398567293 against 2*delta. The independently executed extended LOCAL-only Node checker passed 27,405 assertions in TWO byte-identical executions, with 11,352 adaptive opening checks and full two-witness, two-capsule whole-key reconstruction. Neither code implements quantum cryptanalysis or a real native SLH signature; toy randomness is seeded.

For unvalidated example q=16777213, n=256, m=6800, B=128, N=4, J=2, w=2000 and 256 mock key bits, L=86, log2|T|=7936.51366975, log2(delta_T)=-885.256868, and log2(2*N*J*L*delta_T)=-874.830603. This bounds ONLY the statistical hybrid term, not QPT-LWE hardness, native EUF-CMA, actual signing-key serialization/size, performance, setup security or overall 128-bit PQ security.

## The original unproved reduction (mandatory handoff)

This is honest-TRUE-LWE SOURCE conditional security, not a witness-free classical-PPT arbitrary-ORIGINAL-NP compiler. The crucial still-missing algorithm is jointly instantiated Comp(R_original,x,claim,branch,anchors,context,pk), source/capsule public setup and Release(W_original,...) that give every valid ORIGINAL W the SAME precommitted usable native sk. The complete real joint view must hide sk for EVERY fixed FALSE x, and arbitrary unauthorized hard-TRUE final sk recovery/native forgery must reduce without an adversary-supplied representation to ACTUAL ORIGINAL W or an independently justified QPT break. An oracle that supplies SOURCE preimages is not an independent solution. The earlier factor-local signed public pseudo-decoder and pivot-SL2 qualified false-source recovery paths remain live counterexamples.

One honest N-of-N preauthorizer excluding bypass edges, malicious setup and erasure/abort/funding/presignature/DA/observation graph security, actual SYS/BTC header/AuxPoW/tag/height/interval/cross-height linkage and fork qualification, and hypothetical native PQ-only Bitcoin output/signature support remain unresolved. No deployment, generic WKEM completion, independent agent or scheduled-stop claim.
