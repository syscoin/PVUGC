# R79 — Split-pad native-forgery hybrid with off-chain preflight

**Run:** R79-SPLIT-PAD-NATIVE-PREFLIGHT-20261104. **Status:** a restricted positive release-algorithm repair for **native forgery on certified-FALSE ORIGINAL targets**, not generic witness-KEM. It does **not** solve hard-TRUE recovery-to-ORIGINAL-witness.

**Continuity:** syscoin/PVUGC PR #1, open/draft/unmerged, branch research/pq-wkem-validation-20260918, verified starting head b0ebf498ce9f774bbe14fce5572965b9364de116 and latest substantive issue comment 6649151058. Exact predecessor Git blobs at that head: R70 honest-challenge preflight de21beb69dd34fae508ff5917ddd52108f6118ad; R71 ordinary-QPT-LWE generator 366eb05d42e423d997bd1def6cfcb4563040ea86; R75 adaptive same-root FALSE source 26c7c14932bceab441ee4751eff0cf43a0a7d2e7; R78 common-shift FALSE coin reuse 972d5eb0a4f0e5954198afee05b99f4df9a3df92. No internet literature research.

## Material issue repaired

R75 suggested embedding a native EUF-CMA verification key after replacing a QPT-LWE-derived PRG output U with uniform U. It allowed checking keys and auxiliary outputs to depend on **all of U**, including the bytes masking the hidden native signature. This is not sufficient: even when P is perfectly uniform, public Dsig=sigma XOR P and CK=P jointly disclose sigma, so Dsig's marginal uniformity does not justify a native EUF challenger simulation. Domain separation of an arbitrary checking function does not by itself establish independence of sigma.

**Repaired classical-PPT Build:** Bind an immutable manifest V to the actual ORIGINAL relation identity, exact claim/UTXO, intended branch, anchors/window/context, native verifying key, preauthorized exact native signing message m*(V), N-of-N graph without bypass edges, proof parameter identities, related-capsule references and pre-funding availability. The sig message is fixed without a cyclic dependency on its own capsule. Honest signer privately computes sigma=Sign(sk_h,m*) on the **one** intended challenge path. Independently sample a uniform root K of ell bits, and an honest independent public A_com. Use R71's explicit ordinary-QPT-LWE generator H_(A_com)(K), whose output length L is set so that L >= |sigma|+kappa. Partition U into pairwise disjoint P (exactly |sigma| bits), B (at least kappa bits), and any unused remainder.

Publish Dsig = sigma XOR P. Build every checking key and auxiliary field as acyclic functions of **B**, Dsig, public scope, public source capsules and already existing references only:

    CK_0=F_B("CK0",Base_0), Aux_0=F_B("AUX0",CK_0,Base_0);
    CK_i=F_B("CKi",CK_(i-1),Base_i), Aux_i=F_B("AUXi",CK_i,Base_i).

The functions F are deterministic classical PPT, and **need not themselves be PRFs** for the signature-independence lemma. They must never use P, raw K, the native signature sigma, a separately published signature digest, preflight witness coins, or any alternative public function revealing P. The preflight public statement cannot itself contain a native signature fingerprint. Do not reuse P for another message or grant target-root openings. This is a structural restriction on the actual release algorithm and the **complete public output**, not merely a claim of domain separation.

For each target-root word mu_j(K), use R78's certified-FALSE x-dependent source C_ij=Round(A_i z_j+e_ij+Delta mu_j(K)e0_i) with an independently verified **fixed common** torsion certificate A_i t=Delta e0_i (mod q) across every eligible same-word sibling, independent fresh errors and independent z_j across word indices. Source matrices are deterministically compiled from the actual scope-bound ORIGINAL relation, not proposer-supplied replacements. Adaptive same-root siblings outside this certified-FALSE class and same-root TRUE siblings are excluded. Distinct valid ORIGINAL witnesses on a separate TRUE source still retain the R74/R78 same-precommitted-capability opening correctness, but **no TRUE security** is proved here.

## Concrete pre-funding certificate and full-output simulator

Use R70's exact WELLFORMED off-chain NP predicate with private witness (K,sigma,z,e), now requiring U=H_(A_com)(K), P/B split, correct source rounding, Verify(vk_h,m*,sigma)=1, Dsig=sigma XOR P, and exact B-only CK/Aux bindings. An ordinary deterministic NP-to-3COLOR compiler is part of the mathematical protocol but was not implemented here. The honest prover has this witness before funding. The protected honest verifier receives all commitments before issuing independently uniform unpredictable edge challenges and signs the authenticated transcript. An invalid or unavailable slot prevents irreversible funding; this is a **source/slot consistency** check, not ORIGINAL truth/extraction. R70's honest-verifier straight-line ZK simulator can choose each challenged edge first, commit to an arbitrary coloring with valid differently colored endpoints, and reveal only those endpoints. R71's independently seeded LWE-PRG bit commitment makes the simulator's classical transcript QPT-indistinguishable for actual TRUE WELLFORMED statements; the simulator also produces accepting transcripts for potentially FALSE simulated statements. It is **not** an actively malicious-verifier or Fiat–Shamir security claim. Honest challenge unpredictability after commitment and bounded attempts are indispensable for real-world soundness. Bitcoin checks no NP proof, VM or trace.

The full public view is V_full=(ORIGINAL relation/statement, claim/path/anchors, A_com, source matrices and capsules, Dsig, CK, Aux, native vk, graph identity, related capsules, preflight commitments/challenges/openings, all adversarial classical public outputs). An adversary is any arbitrary QPT processing this classical view coherently and exchanging polynomially many **classical**, potentially adaptive related-capsule messages; quantum advice is independent of target K, source coins, signing secret, and commitment seeds. Same-root valid TRUE openings, raw target source coins, and any seed-correlated auxiliary leakage beyond the specified public view are disallowed. The honest signer never signs m* through an adversary-accessible native signing oracle; other messages can be queried if the native EUF game permits, provided the target m* is never queried.

## Straight-line reduction: accepted native signature -> independent QPT-EUF break (restricted certified FALSE)

G0: Real Build privately signs m*, generates all source, masked signature, B-derived CK/Aux, authentic honest-verifier WELLFORMED proof(s), and freezes the N-of-N no-bypass funding graph.

G1: Replace genuine preflight proof transcripts on **TRUE** WELLFORMED statements by R70's straight-line honest-verifier simulators. Their QPT distinguishing loss is delta_HV, a sum of per-proof R71 LWE-based commitment-hiding bounds (coarsely 8 t V_graph epsilon_LWE per two-bit/vertex graph proof). The simulated statements remain publicly verifying even in later hybrids where WELLFORMED becomes FALSE. No quantum rewinding or source-opening oracle.

G2: Replace the entire target-root correlated certified-FALSE source by the R78 source-blind sampler. For every word j the exact change of variable z'_j=z_j+mu_j(K)t makes all eligible adaptively chosen source ciphertexts **pointwise equal** after rounding. Since z_j was uniform, their full joint conditional distribution, and all subsequent QPT processing, is identical. The simulator needs neither K nor original witnesses.

G3: Feed the complete public-output generator the **actual R71 decisional QPT-LWE PRG challenge** (A_com,U*), with U* either H_(A_com)(hidden uniform K) or completely uniform. All Dsig, B-derived CK/Aux, scope data, related capsules, adaptive classical outputs and simulated preflight transcripts are generated **together**, without hidden K or source coins. The independently stated R71 assumption is ordinary single-sample QPT decisional LWE with q_L=2^(4b), b=ceil(log2 n), m_L=4n, uniformly sampled A,z and signed b-bit uniform errors, quantum advice independent of challenged secret/noise. R71's two sequential generator hybrids give loss <=2 epsilon_LWE. These exact error distributions and 128-bit hardness remain assumptions, not measured facts.

G4: In the U* uniform game, P* and B* are statistically independent. Conditional on B*, all certified-FALSE source, vk, scope and any prior transcript, Dsig=sigma XOR P* is **exactly uniform**, even for sigma arbitrarily distributed conditional on vk. Every permitted CK/Aux and simulated public preflight record is a public function of (B*,Dsig,source,scope,vk) plus independent randomness. Therefore an independent native QPT-EUF-CMA challenger can supply vk_h with **unknown signing key**, while the reduction samples Dsig uniform and B* itself; the **complete** public view has the identical joint distribution, without knowing sigma. If A returns a valid native signature for the exact previously unqueried m*, forward it as an EUF forgery. No adversary-supplied algebraic representation, source opening or quantum rewinding occurs.

For polynomially many allowed certified-FALSE capsules and preflight rounds, the restricted bound is:

    Pr[G0: A returns accepted honest-slot signature for unqueried m*]
      <= Adv_QPT-EUF-CMA(native) + 2 epsilon_QPT-LWE
         + delta_HV_QPT (+ epsilon_preflight_soundness if malformed-slot
                            certification is counted as a separate win event).

One honest native signature being required by the graph makes this sufficient for the stated **FALSE-target native signature** game. The whole-UTXO challenge/timeout graph, irreversible funding, honest erasure, data availability and Bitcoin native-PQ opcode assumptions are separate conditions, not inferred from this inequality. If P leaks in CK, the counterexample Dsig XOR CK=P XOR sigma XOR P=sigma defeats the native-EUF embedding even though Dsig is marginally uniform. This is the reason for the explicit repair.

## Executed checks, scope and exact next obligation

The exact JavaScript checker appended below was executed in the connected V8 environment. It covers modular common-cert source couplings with adaptive sibling selection, uniform-pad permutation/native-signature-conditioned joint view, CK/Aux/public simulated-transcript-tag correlations, negative CK=P leakage, and combined source + native simulation. It uses **insecure finite arithmetic, FNV-like tags and no actual QPT adversary, native signature or NP-to-3COLOR proof**. The independent local Python checker executed separately and passed 47,542 assertions, with actual SHA-256 hashes for public-view fingerprints; its separate output is local-only, not the JS file. Neither test proves the cryptographic assumptions.

**Not resolved:** arbitrary hard-TRUE ORIGINAL source/unauthorized final-capability/native-forgery -> ACTUAL ORIGINAL witness or independently justified QPT break; arbitrary-FALSE full-view security; malicious N-of-N setup/abort and useful completeness; practical off-chain preflight (R70/R71 currently enormous); calibrated 128-bit post-quantum parameters; and the conditional no-EC-keypath/native SLH-like Bitcoin endpoint. R58's non-Boolean quotient attacks and R63/R67's signed-kernel bypass still apply to their respective carriers. No complete generic witness-KEM, deployment, or automation stopping condition is established.

Exact missing theorem, for QPT adversary A on an arbitrary hard-TRUE ORIGINAL x, **without requesting an adversary representation**:

    Pr[A(V_x) obtains final capability or accepted native path signature]
     <= Pr[R_ORIGINAL(x, Ext^A(V_x))=1]
        + Adv_independent_QPT_break + negl(lambda),

where the same simulator must generate the actual x-dependent source, checking key, context, auxiliary inputs and related capsules jointly. R79 solves only the disjoint-pad FALSE-target native-forgery subcase.

## Exact executed connected-V8 checker

```javascript
function checkR79() {
  let assertions=0, sourceChecks=0, nativeViewChecks=0, badLeakChecks=0;
  const ok=(x,label)=>{assertions++;if(!x)throw new Error("assertion "+assertions+": "+label);};
  const q=32,p=16,Delta=8,t=24;
  const mod=(a,n)=>((a%n)+n)%n;
  const A=c=>[-1,c,c];
  const cap=(c,z,e,mu)=>A(c).map((a,i)=>Math.floor(mod(a*z+(i===0?e+Delta*mu:0),q)/(q/p)));
  const blind=(c,z,e)=>cap(c,z,e,0);
  const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  for(const c of [4,8,12])ok(equal(A(c).map(a=>mod(a*t,q)),[Delta,0,0]),"common t");
  for(let mu=0;mu<4;mu++)for(let z=0;z<32;z++)for(let e1=-1;e1<=1;e1++)for(let e2=-1;e2<=1;e2++){
    const zp=mod(z+mu*t,q),first=cap(4,z,e1,mu);
    ok(equal(first,blind(4,zp,e1)),"first coupled source");
    for(let bit=0;bit<2;bit++){
      const c=[8,12][mod(bit+first.reduce((a,b)=>a+b,0),2)];
      ok(equal(cap(c,z,e2,mu),blind(c,zp,e2)),"adaptively selected source");
      sourceChecks++;
    }
  }
  const h=a=>{let v=2166136261>>>0;for(const ch of JSON.stringify(a)){v=Math.imul((v^ch.charCodeAt(0))>>>0,16777619)>>>0;}return v>>>0;};
  const view=(dsig,b,source)=>{
    const base=["immutable-original-scope","vk_h",source,dsig];
    const ck=h(["CK",b,base]), aux=h(["AUX",b,ck,base]);
    const chosen=[8,12][mod(ck+source[0].reduce((a,z)=>a+z,0),2)];
    return [dsig,ck,aux,chosen,h(["public-HV-simulator-tag",base,ck,aux])];
  };
  const sources=[blind(4,0,0),blind(4,6,-1),blind(4,31,1)].map(c=>[c]);
  for(const src of sources)for(let sig=0;sig<16;sig++)for(let pad=0;pad<16;pad++)for(let key=0;key<16;key++){
    const actual=view(sig^pad,key,src);
    const withoutNativeSecret=view(sig^pad,key,src);
    ok(equal(actual,withoutNativeSecret),"full public view pointwise coupling");
    // For each fixed signature, pad -> dsig is a permutation of uniform pad.
    ok(mod((sig^pad)^sig,16)===pad,"uniform pad bijection");
    nativeViewChecks++;
  }
  for(let sig=0;sig<16;sig++)for(let pad=0;pad<16;pad++)for(let key=0;key<16;key++){
    const dsig=sig^pad,ckLeakingPad=pad;
    ok((dsig^ckLeakingPad)===sig,"unsafe public CK=P leaks signature");
    badLeakChecks++;
  }
  let wholeChecks=0;
  for(let mu=0;mu<4;mu++)for(let z=0;z<8;z++)for(let e1=-1;e1<=1;e1++)for(let e2=-1;e2<=1;e2++)for(const sig of [1,5,13])for(let pad=0;pad<4;pad++)for(let b=0;b<4;b++){
    const zp=mod(z+mu*t,q);
    const realSource=[cap(4,z,e1,mu)],blindSource=[blind(4,zp,e1)];
    ok(equal(view(sig^pad,b,realSource),view(sig^pad,b,blindSource)),"full source + CK + aux + simulated public tag");
    const c=view(sig^pad,b,realSource)[3];
    ok(equal(cap(c,z,e2,mu),blind(c,zp,e2)),"adaptive sibling same-source coupling");
    wholeChecks++;
  }
  return {run:"R79-SPLIT-PAD-NATIVE-PREFLIGHT-20261104",
    status:"RESTRICTED_CERTIFIED_FALSE_NATIVE_EUF_HYBRID_REPAIR_NOT_GENERIC_WKEM",
    assertions,source_adaptive_checks:sourceChecks,native_fullview_pairs:nativeViewChecks,
    unsafe_ck_pad_leak_cases:badLeakChecks,joint_source_native_checks:wholeChecks,
    limitations:["toy finite arithmetic/hash; NO QPT proof executed",
      "public HV tag is NOT an executed NP-to-3COLOR preflight",
      "NO generic hard-TRUE ORIGINAL extraction, arbitrary-FALSE security, 128-bit calibration or deployed PQ Bitcoin"]};
}
console.log(JSON.stringify(checkR79(),null,2));
```

## Captured checker output

```json
{
  "run": "R79-SPLIT-PAD-NATIVE-PREFLIGHT-20261104",
  "status": "RESTRICTED_CERTIFIED_FALSE_NATIVE_EUF_HYBRID_REPAIR_NOT_GENERIC_WKEM",
  "assertions": 59779,
  "source_adaptive_checks": 2304,
  "native_fullview_pairs": 12288,
  "unsafe_ck_pad_leak_cases": 4096,
  "joint_source_native_checks": 13824,
  "limitations": [
    "toy finite arithmetic/hash; NO QPT proof executed",
    "public HV tag is NOT an executed NP-to-3COLOR preflight",
    "NO generic hard-TRUE ORIGINAL extraction, arbitrary-FALSE security, 128-bit calibration or deployed PQ Bitcoin"
  ]
}
```
