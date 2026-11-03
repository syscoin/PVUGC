# R39 — LWE-REGEV-JOINT-SOURCE: hard-TRUE *surrogate* source with a full joint QPT simulator

**Status 2026-11-03; offline only.** Continuation of R38 at initial PR head 944d713343101b87f8b95b660712b283f6d86e39. This note is an independent standard-assumption LWE setup/open/joint-challenge *component* for a restricted **search-LWE-secret relation**, **NOT** a generic ORIGINAL NP/SYS-BTC witness-KEM. In particular it does **not** solve recovery-to-ORIGINAL-fork-witness and is not a repair of R35's polynomial masking by a scalar LWE wrapper.

## Fully instantiated classical source and public view

Use odd prime q, n,m, secret s uniform in Z_q^n, A uniform in Z_q^(n×m), e sampled from a specified chi supported on [-B,B]^m, and b=A^T s+e (mod q). Source public key pk=(A,b). The surrogate NP relation R_LWE(pk,(s',e')) verifies b=A^T s'+e' mod q and ||e'||_infty≤B. It is **not** a relation about a BTC fork, Syscoin AuxPoW, authentic tags, burn or authorization. Require mB<(q-1)/4 and Delta=(q-1)/2. Honest KeyGen and Build are classical PPT. Build takes pk and does not need s or any SourceOpen oracle.

Separately generate native signing (sk_N,vk_N), compute an immutable challenge m*=M(pk,vk_N, claim/UTXO, branch, authenticated anchors/window/context), and pre-sign sigma*=Sign(sk_N,m*) before irreversible funding. Privately choose a k-bit uniform K. Form D=sigma* XOR G(K,domain,context), where G is a QPT-secure pseudorandom expansion to the exact signature length, with public domain separation and no disclosed K. For each bit K_j and every separate scope or same-key related capsule a, choose **fresh independent** r_{j,a} uniform in {0,1}^m, publish (u,v)=(Ar, b^T r+Delta K_j) mod q. T=k×scopes total classical Regev bit ciphertexts. Publish the complete statement, pk, vk_N, m*, D, all ciphertexts, context, and CK=H(domain||encode(all PUBLIC preceding values)), plus arbitrary efficiently publicly samplable/derived aux and related data. Neither CK nor auxiliary data may independently reveal K, sigma*, s, e, sk_N or target private openings; arbitrary such secret-correlated checking keys are NOT covered. All related ciphertexts in this theorem use the same K and fresh random r. No target selective opening.

**Every** valid R_LWE witness (s',e'), even if distinct from s, computes v-s'^T u=e'^T r+Delta K_j (mod q). Since |e'^T r|≤mB<Delta/2, nearest-0/Delta decoding recovers K_j for **every** bit and scope deterministically. Each valid witness thus recovers the SAME precommitted K and sigma*, then checks native Verify(vk_N,m*,sigma*) off chain. No intermediate states need coincide. This is surrogate ORIGINAL-witness correctness, **not** completeness for genuine SYS/BTC original evidence.

## Exact QPT joint simulation, no SourceOpen

For random public uniform S=(A,b), define universal h_S(r)=(Ar,b^T r) from binary r. For any r≠r', r-r' has some coefficient ±1, so (A(r-r'), b^T(r-r')) is uniform in Z_q^(n+1) across S. The strong leftover-hash lemma yields

  delta = TV((S,h_S(r)),(S,U in Z_q^(n+1))) ≤ 1/2 sqrt(q^(n+1)/2^m).

For T independently randomized ciphertexts sharing S, **joint** TV ≤ T delta by telescoping hybrids, including all ciphertext correlations through S. This is a random-S average, NOT a per-key guarantee. QPT coherent processing of the classical full view cannot amplify TV. The exact small-field checker confirms average conditional TV=16120/59049 at q=3,n=1,m=4, below 3/8, while an exceptional seed has TV 8/9.

Assume QPT decisional-LWE hardness for the **exact** (n,m,q,chi) distribution (A,A^T s+e), not generic unnamed LWE hardness. Let V_K be the honest complete view with all T encryptions of bits of K and D=sigma* XOR G(K). Let V_0 use encryptions of zero bits in all T slots while keeping the SAME K, sigma*, vk_N, D, contexts, checking key and public auxiliary output sampler. For an arbitrary QPT distinguisher, move pk from LWE to uniform, use joint leftover hashing to erase the T messages, and move uniform back to LWE with zero messages. The two LWE distinguishing hybrids and two statistical hybrids establish

  |Pr[A(V_K)=1]-Pr[A(V_0)=1]| ≤ 2 Adv_QPT-DLWE + 2T delta.

This is a **straight-line full-public-output reduction**. Each LWE distinguisher receives a candidate pk, locally generates native sk_N and sigma* AFTER deriving m*=M(pk,vk_N,...), chooses K and D, and publicly computes CK, context/aux/related capsules from the complete view. Thus it jointly simulates vk-dependent sighash and D correlations with all source openings without knowing s or a hidden LWE challenge secret. It does NOT attempt an opening oracle.

In V_0, all Regev ciphertexts are independent of K. An independently justified QPT PRG distinguisher replaces G(K) with a uniform signature-length pad, constructing a native signature itself to simulate D. The resulting D is uniformly independent of sigma* even conditional on native vk_N. An independent straight-line QPT native EUF-CMA adversary is supplied vk_N, generates honest pk and encrypted-zero capsules, a uniform D, CK and all public data, makes **zero** signing queries, invokes A once and submits any accepted native signature on m*(pk,vk_N,ctx). Therefore:

  Pr_real[A produces ANY accepted native signature on intended fixed m*]
  ≤ Adv_QPT-EUF(Sig) + 2 Adv_QPT-DLWE + 2T delta + Adv_QPT-PRG(G).

This bounds recovery of the prescribed sigma* as well. QPT adversaries can process all classical capsules coherently, hold nonuniform advice independent of hidden setup secrets, and receive simulatable public quantum auxiliary inputs. No classical rewinding, random-oracle extraction or representation offered by A. It does NOT address adversaries endowed with target K/sigma/s private-state advice, malicious ceremony data or non-simulatable secret checking keys. Native Lamport used in toy tests is NOT Bitcoin-native; SLH-like verifier and no-EC-key-path are conditional.

A sufficient, *statistical only*, parameter constraint for 2T delta≤2^-lambda is m≥(n+1)log2(q)+2(lambda+log2 T), alongside mB<Delta/2. Actual QPT-DLWE security for chosen chi and parameters and QPT-PRG security must be assessed independently. There is no 128-bit production-security estimate.

## Boundary: why this is NOT generic ORIGINAL NP

For adversarial FALSE pk, take A=0,b=(B+1,0,...), B+1<Delta/2. R_LWE has no witness, yet v=(B+1)r_0+Delta K_j gives disjoint output bands and leaks K_j perfectly. Thus arbitrary-FALSE full-public-output security is NOT proved. The theorem covers honestly LWE-generated *hard-TRUE surrogate pk only*. Anyone knowing s can open without authentic BTC/SYS evidence. Adding an unrelated ORIGINAL verifier as an extra AND condition does not stop the Regev decryptor from bypassing it. No generic compiler x->pk with all valid ORIGINAL witnesses as decoders AND no alternate bypass is constructed. The one-honest N-of-N preauthorization/erasure, aborts, target selective openings, authentic SOURCE proof, full DA, Bitcoin endpoint and practical size all remain open.

The symbolic DEM reduces bit-PKE cost from 8|sigma*|×scopes to k×scopes at the price of an independent QPT PRG assumption. This is not a measured practical parameter result.

## Exact reproducibility and handoff

Beside this note, CHECKER.js is the actual V8-executed checker (function source preserved without rewriting) and OUTPUT.json is its captured repeated-identical result. Independently executed local-only Python checker passed 7700 assertions twice, enumerated 6561 q=3 public hash seeds and all 16 r, verified 1024 bit decodings for two valid but distinct witnesses, and checked the FALSE disclosure. The published JS checker uses a deliberately insecure arithmetic toy signature/PRG; it is not a cryptographic hardness test. The extended offline archive includes the longer equation derivation and independent Python source. No external literature or unrelated websites consulted.

**Next exact requirement:** For actual original generic-NP relation R_x(w), build pk(x) and public opening data using x alone such that every legitimate (possibly distinct) w decodes the SAME signature capability; NO easy surrogate secret s may bypass R_x; the entire (x,pk,C,D,vk,m*,CK,aux,related) view must admit an independently based QPT simulator without hidden challenge secrets, and any unauthorized recovery/native acceptance must yield the ACTUAL ORIGINAL witness or a justified independent PQ break. The present theorem supplies only a restricted source+simulator example.