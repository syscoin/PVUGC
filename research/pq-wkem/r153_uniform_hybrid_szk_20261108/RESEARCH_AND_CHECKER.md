# R153 — Polynomial statistical uniform-source release for generic NP implies NP ⊆ SZK

**STATUS: MAJOR CONDITIONAL COMPLEXITY-THEORETIC BARRIER, NOT A SECURE CONSTRUCTION.** The implication proved here is that a classical polynomial-time arbitrary-ORIGINAL-NP compiler with all-witness correctness and **statistical** false-instance hiding in its uniformly sampled source must put NP in Statistical Zero Knowledge (SZK). This is not a proof that NP is outside SZK, not an LWE attack, and not an impossibility of computational witness encryption. It substantially changes the proof target: optimizing Fourier damping until *every* false statement has negligible full-source statistical leakage is an unexpectedly strong goal, not a missing bound that ordinary QPT-LWE alone supplies.

Continuity (read-only before research): syscoin/PVUGC PR #1, draft/open/unmerged on branch research/pq-wkem-validation-20260918; verified starting SHA 9d8765c34149eb4de293e46ca958577afab00785; latest R152 note exact Git blob 2b7618ef2cd3fda9440f1ffcde61adf8ed78f1d8, and latest ordinary PR comment 6698876958. R152 explicitly rejects itself as an R149-equivalent affine carrier, while identifying its *uniform-g spectral false-hiding target*. R153 addresses this target for arbitrary nonlinear attempted repairs, not just that affine example. No web/external literature search or unrelated repository access.

## Formal theorem — actual sampling distributions, all public correlations

Fix an NP-complete ORIGINAL relation R(x,w), e.g. original 3SAT, with classical-PPT verifier. Suppose classical PPT algorithms S_b(1^λ,x), b∈{0,1}, generate an honest public SOURCE view C_b, with complete statement-bound public setup, relevant checking/source keys, context and auxiliary/related-capsule outputs whose sampling is explicitly polynomial-time **without any satisfying witness**. They are defined for every x. Allow randomized classical-PPT Open(C,w). For polynomial-length x,w uniformly over sufficiently large λ assume:

(A) ALL ORIGINAL true witnesses are correct in the SOURCE experiment: if R(x,w)=1, Pr[Open(S_b(x),w)=b] ≥1−ε(λ) for b=0,1, for ε≤1/12. Distinct witnesses may use different internal states but must recover the SAME precommitted b within each capsule.

(B) FULL SOURCE statistical false hiding: for every R-false x, TV(S_0(x),S_1(x)) ≤δ(λ), δ≤1/12.

Then **NP⊆SZK**.

Proof. The classical sampler-circuit descriptions for S_0(x),S_1(x) are computable uniformly in poly(|x|,λ) time with the honest setup sampled internally. If x is true choose any valid w (existentially; the reduction does not need to find w). The event D_w(C)=1[Open(C,w)=0] has probability at least 1−ε under S_0 and at most ε under S_1 (integrate any opening coins), so TV(S_0,S_1)≥1−2ε≥5/6. If x is false the assumed TV≤1/12. Hence x↦(circuits S_0(x),S_1(x)) is a uniform polynomial many-one reduction from 3SAT to the Statistical Difference promise problem with thresholds 5/6 and 1/12. The standard Statistical Difference characterization of SZK gives 3SAT∈SZK and hence NP⊆SZK. No witness extraction or hardness assumption is used in this implication. A negligible-error version makes the promise gap overwhelming.

The conclusion holds already when SOURCE marginal outputs suffice to run Open. Requiring TV closeness of the native-VK/masked-signature *entire* public view is strictly stronger; native verification correlations may themselves make unbounded statistical hiding impossible. No claim is made that unbounded parties are unable to invert a public native VK. What matters is that an efficiently sampled, source-decodable view is simultaneously statistically false-hiding and correct for every true witness.

## Ordinary QPT-LWE does NOT evade this implication by claiming uniform-g incompleteness

Consider a *different* LWE-embedded sampler with g real = A^T s+e versus uniform g, an exact straight-line full-joint simulator creating ALL public output fields from (A,g), known coins, and allowed independent setup, including correlated CK/J/Aux and related capsules. If real-g source correctness holds with 1−ε for every polynomial-length true pair (x,w), then under ordinary nonuniform decisional QPT-LWE, uniform-g correctness holds with 1−ε−negl as well. Otherwise hardwire a failing (x,w,b) into nonuniform advice and distinguish real from uniform ordinary LWE using the classical test 1[Open(C,w)=b]. The full-joint simulator must work on *actual* challenge bytes and not assume a SourceOpen oracle or target secret. Its public related outputs must preserve shared-g correlations. This is a straight-line distinguisher, not quantum rewinding, and is uniform over bounded-size x,w families under the nonuniform LWE assumption.

For R152 specifically, the identity p−v^T B=Δb+η−v^Te cancels g exactly, so the uniform-g correctness premise is already unconditional for actual supported v. Thus combining (i) the proposed source-side **statistical** false hiding for ALL false original instances with (ii) a generic every-valid-ORIGINAL-witness compiler and (iii) the actual classical samplers entails NP⊆SZK. Standard ordinary QPT-LWE only supports the real-to-uniform hybrid; it does **not** supply a second, computationally secure SOURCE hiding argument, nor the arbitrary hard-TRUE key-recovery→ORIGINAL-witness reduction.

## What the theorem rules out and what it leaves open

This is a sharp *conditional complexity consequence*, not an unconditional no-go theorem: NP⊄SZK is unproved. An efficient **computationally** false-hiding uniform-g source can have statistical distance near one and still be difficult for QPT adversaries to distinguish without a witness, so such a source is not ruled out. But that computational claim needs an INDEPENDENT quantum-hardness basis (not a renamed WE/iO/WPRF or the already-used ordinary-LWE hybrid). Other proof architectures could avoid the statistical step. Hard-TRUE extraction and native forgery remain strictly harder, independent obligations.

The intended original x includes original relation identity, actual claim/UTXO, challenge path, branch, anchors/window, native VK/capability and context. Large witness evidence remains off chain; the hypothetical no-EC-key-path/SLH-like native endpoint is not deployed. N-of-N preauthorization, one honest signer excluding bypass and protecting/erasing secrets, pre-funding DA, watcher/ChainLock separation, SYS/BTC source semantics and censor/reorg assumptions remain unfinished and are not altered by this mathematical theorem.

## Executed finite checker — sanity evidence, NOT the proof

A second, independent offline Python standard-library checker executed 1,191 assertions, re-executed with byte-identical output. This V8 checker was also executed before Git-object creation and its exact source and captured output are below. They independently enumerate all 11×3³=297 tapes per key with uniform g∈F_11, e1,e2,η∈{−1,0,1}, q=11, Δ=5. TRUE T=(1,1),b=1 admits distinct v=(1,0),(0,1), both perfectly correct, and TV(K0,K1)=1. Easy FALSE T=(0,0),b=1 has TV=0. Short-witness FALSE T=(1,1),b=5 has TV=11/27; it is an example of residual leakage, not evidence of generic security. Neither checker measures LWE hardness or runs a QPT adversary.

## Next exact foundation obligation

Construct a genuine classical-PPT **nonlinear** arbitrary-ORIGINAL-NP SOURCE with computational false-instance QPT hiding even when uniform-g alternatives are *statistically far*, instantiate its real setup/opening algorithm and the entire checking/auxiliary/multiple-capsule joint simulator together, make every valid ORIGINAL witness recover the identical bound native capability, and prove arbitrary unauthorized final-key recovery or accepted native forgery → an ACTUAL ORIGINAL witness or an independently justified QPT break without demanding any internal representation from the adversary. If another strategy bypasses uniform-g statistical leakage entirely, state and prove that change. No restricted credential optimization until those requirements are met.

## Exact V8 checker source

\`\`\`javascript
// Exact checker executed in this GitHub-connected V8 run.
(function checker() {
  "use strict";
  const q=11, Delta=5, E=[-1,0,1], total=11*27;
  let checks=0;
  function check(v,msg){checks++;if(!v)throw Error("check #"+checks+" "+msg)}
  function histogram(T,b,bit){
    const hist=new Map();
    for(let g=0;g<q;g++) for(const e1 of E) for(const e2 of E) for(const eta of E){
      const B1=((T[0]*g+e1)%q+q)%q;
      const B2=((T[1]*g+e2)%q+q)%q;
      const p=((b*g+Delta*bit+eta)%q+q)%q;
      const key=[B1,B2,p].join(",");
      hist.set(key,(hist.get(key)||0)+1);
    }
    return hist;
  }
  function sumAbs(a,b){
    const keys=new Set([...a.keys(),...b.keys()]);
    let n=0;for(const key of keys)n+=Math.abs((a.get(key)||0)-(b.get(key)||0));
    return n;
  }
  const cases=[
    ["two_witness_true",[1,1],1,1,1],
    ["unreachable_false",[0,0],1,0,1],
    ["short_representations_false",[1,1],5,11,27]
  ];
  const results=[];
  for(const [name,T,b,n,d] of cases){
    const c0=histogram(T,b,0),c1=histogram(T,b,1);
    const num=sumAbs(c0,c1);
    check(num*d===2*total*n,"exact source TV "+name);
    results.push({case:name,total_tapes_per_key:total,tv:`${n}/${d}`,support_K0:c0.size,support_K1:c1.size});
  }
  function decode(y){
    y=((y%q)+q)%q;
    const d0=Math.min(y,q-y), d1=Math.min((y-Delta+q)%q,(Delta-y+q)%q);
    return d0<d1?0:1;
  }
  for(let bit=0;bit<2;bit++) for(let g=0;g<q;g++) for(const e1 of E) for(const e2 of E) for(const eta of E){
    const B1=((g+e1)%q+q)%q, B2=((g+e2)%q+q)%q, p=((g+Delta*bit+eta)%q+q)%q;
    check(decode(p-B1)===bit,"first witness");
    check(decode(p-B2)===bit,"second witness");
  }
  return {experiment:"R153 independent finite uniform-source sanity checker",checks,q,Delta,error_support:E,results,note:"No QPT/LWE hardness test; NP⊆SZK implication is a mathematical theorem."};
})();
\`\`\`

## Captured checker output

\`\`\`json
{
  "experiment": "R153 independent finite uniform-source sanity checker",
  "checks": 1191,
  "q": 11,
  "Delta": 5,
  "error_support": [
    -1,
    0,
    1
  ],
  "results": [
    {
      "case": "two_witness_true",
      "total_tapes_per_key": 297,
      "tv": "1/1",
      "support_K0": 209,
      "support_K1": 209
    },
    {
      "case": "unreachable_false",
      "total_tapes_per_key": 297,
      "tv": "0/1",
      "support_K0": 99,
      "support_K1": 99
    },
    {
      "case": "short_representations_false",
      "total_tapes_per_key": 297,
      "tv": "11/27",
      "support_K0": 275,
      "support_K1": 275
    }
  ],
  "note": "No QPT/LWE hardness test; NP⊆SZK implication is a mathematical theorem."
}
\`\`\`
