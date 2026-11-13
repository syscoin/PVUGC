# R82 — hard-TRUE source: exact source-coin simulator obstruction and required joint-challenge replacement

Run: R82-TRUE-SOURCE-COSET-OBSTRUCTION-20261105.
Status: NO POSITIVE WKEM ADVANCE. A bounded mathematics/repair iteration only. Not a generic NP no-go and not a PQ proof.

## Current exact continuity
The live syscoin/PVUGC PR #1 was open/draft/unmerged at 473250523fe5a3f38628538a538f53b9d4142c57, branch research/pq-wkem-validation-20260918. Latest substantive top-level issue comment: 6651845446 (R81). Exact relevant R81 proof blob 7854382541a0ab5bd6ee4462dc71bc4484775393 and R80 source blob 5756f4326425c4098f6e662f64c3c471ea1581b4 were read, plus the latest PR metadata and recent comments. No whole PR diff/historical sweep, web research, external literature, or independent agents. The run did not modify production/main/workflows.

## Explicit candidate and what was tested
Candidate: extend R77/R78's *exact* source-coin translation (including arbitrary nonlinear permutations of the honest source coins), rather than assume a new witness-release primitive. Honest classical-PPT Build knows the root K and publishes, for every encoded word mu of K, the rounded source

    C_mu = Round_{q to p}(A_x z + e + Delta*mu*e0),

where z is uniform, e has independent bounded noise, and A_x/e0 compile the actual ORIGINAL relation. Every valid ORIGINAL witness w yields a normalized public moment row r_w with r_w^T A_x=0 mod q and r_w^T e0=1 mod q; the declared decoder should recover mu reliably. The bound statement/context/claim, native verification key, source, signature-mask Dsig, checking keys, auxiliary fields and other capsules remain the full public view, not merely C.

### Theorem 1: the R77 exact shift certificate cannot hold for TRUE ORIGINAL instances
If a valid ORIGINAL witness row exists and Delta is nonzero modulo q, there is no t for which A_x t=Delta*e0 modulo q. Multiplication by r_w^T gives 0 = Delta*1 modulo q, a contradiction. This holds over composite moduli (no division/inversion). Therefore R77's certified-FALSE exact translation method is *inherently inapplicable* to any such TRUE instance, not a missing choice of t. It says nothing about computationally secure nonlinear source algorithms.

### Theorem 2: no exact seed-only/permutation blind simulator with all-witness decoding
Let L_mu denote the public source distribution for word mu. Fix ANY valid ORIGINAL witness w and its honest decoder D_w. For distinct mu and nu, assume

    Pr_{C <- L_mu}[D_w(C)=mu] >= 1 - eps_mu,
    Pr_{C <- L_nu}[D_w(C)=nu] >= 1 - eps_nu.

The event D_w(C)=mu then distinguishes L_mu from L_nu with statistical advantage at least 1-eps_mu-eps_nu. Hence

    TV(L_mu,L_nu) >= 1 - eps_mu - eps_nu.

In particular, if decoding is exact, L_mu and L_nu have disjoint support. No reparameterization, affine or nonlinear, of independent source random coins can make these *exactly equal* without destroying completeness. Any full public transcript including C has at least this TV distance to a distinguisher that ALREADY KNOWS a valid witness. This is an information-theoretic lemma, not a claim that a witnessless QPT adversary can FIND a hard witness or distinguish distributions. A computationally hidden hard-TRUE source, if constructible, is not ruled out.

### Concrete test and failed repair
Take q=32, p=8, spacing=4, Delta=8, A_x=(-4,4,4,4)^T and e0=(1,0,0,0)^T; centered nearest-cell rounding; independent errors per coordinate in {-1,0,1}. The TRUE ORIGINAL relation a+b+c=1 has THREE distinct valid witness rows (1,1,0,0), (1,0,1,0), (1,0,0,1). They each recover exactly the same encoded 2*mu mod 8 and thus all encoded words with the same root. The code exhaustively enumerates 32 values of z, 3^4 error vectors and all four encoded mu. Every pair of source supports is disjoint (TV=1), and no certificate t exists.

Attempted repair: enlarge first-coordinate error to UNIFORM modulo 32. Now the full source distribution is exactly independent of mu (TV=0), but each original exact-word decoder is correct only 1/8 of the time. More generally, if all four source-word distributions are identical, any decoder's average probability to distinguish four equally likely words is at most 1/4. This repairs hiding by destroying release correctness, not a candidate advance.

### Interpretation and next *construction* requirement
R77/R78's TRUE-extension via exact source translation is closed by a mathematical contradiction, not a parameter choice. R81's valid EUF signing-oracle simulation for unqueried native messages is unaffected; it samples K itself and never tries to embed a hidden LWE seed. R79/R80's certified-FALSE pad hybrids also remain separate.

For hard TRUE, a candidate must supply a NEW, classical-PPT statement-dependent source/challenge embedding rather than a source-coin reparameterization. A genuine ordinary-QPT-LWE simulator receives (A_com,U*) with U* a real LWE-derived generator value or uniform and WITHOUT its hidden seed K; it must construct jointly (C_x, Dsig, CK, Aux, context, related capsules, checking keys, any simulated off-chain WELLFORMED preflight) with a real-branch distribution indistinguishable from the honest (H_A(K), C_x(K)) distribution. This construction must preserve Open(x,w,C_x(K))=K for EVERY genuine ORIGINAL witness, and ultimately prove arbitrary QPT recovery of the pre-signed same-message capability implies an actual ORIGINAL witness or an independently justified QPT break. No SourceOpen oracle, adversary-volunteered representation, or classical rewind can be assumed. The required joint-challenge sampler and extraction are NOT constructed here.

Model: honest setup/evaluation classical PPT; adversaries arbitrary QPT with allowed independent quantum advice and classical adaptive related-capsule/selective-opening queries. The algebraic theorems hold independently of computational adversaries, but do not prove false-instance security, target TRUE security, QPT LWE, QPT native signatures, malicious N-of-N setup/abort, practical resources or native Bitcoin PQ functionality. If an adversary holds a valid ORIGINAL witness in auxiliary input, disclosure is authorized and cannot be treated as an unauthorized key-hiding experiment.

This is an exact unresolved handoff, not a completion claim; leave the existing research automation enabled.

## Exact executed JS checker
The source below is the JavaScript function actually invoked in the connected V8 environment in this publication action. Its printed JSON return value is captured beneath it. This only checks finite toy identities and failures, not QPT cryptography.

```javascript
function checkR82(){
  const Q=32,P=8,g=4,Delta=8;
  const A=[-4,4,4,4], e0=[1,0,0,0],
        W=[[1,1,0,0],[1,0,1,0],[1,0,0,1]];
  let checks=0;
  const check=(v,s)=>{checks++;if(!v)throw Error("assertion "+checks+": "+s)};
  const mod=(x,n)=>((x%n)+n)%n;
  const dot=(a,b,n)=>mod(a.reduce((s,v,i)=>s+v*b[i],0),n);
  const rnd=x=>Math.floor(mod(x+2,Q)/g);
  const capsule=(mu,z,e)=>A.map((a,i)=>rnd(a*z+Delta*mu*e0[i]+e[i]));
  const key=v=>v.join(",");
  for(const w of W){
    check(dot(w,A,Q)===0,"witness annihilates original source");
    check(dot(w,e0,Q)===1,"witness normalization");
  }
  const shifts=[];
  for(let t=0;t<Q;t++)if(A.every((a,i)=>mod(a*t-Delta*e0[i],Q)===0))shifts.push(t);
  check(shifts.length===0,"no additive true-source certificate");
  const hist=[];
  for(let mu=0;mu<4;mu++){
    let h=new Map();
    for(let z=0;z<Q;z++)for(let a=-1;a<=1;a++)for(let b=-1;b<=1;b++)for(let c=-1;c<=1;c++)for(let d=-1;d<=1;d++){
      const C=capsule(mu,z,[a,b,c,d]);
      const k=key(C); h.set(k,(h.get(k)||0)+1);
      for(const w of W)check(dot(w,C,P)===2*mu,"every ORIGINAL witness same decoded word");
    }
    check([...h.values()].reduce((s,v)=>s+v,0)===Q*81,"complete distribution sampled");
    hist.push(h);
  }
  for(let i=0;i<4;i++)for(let j=i+1;j<4;j++)
    check([...hist[i].keys()].every(k=>!hist[j].has(k)),"disjoint distinct-word law");
  const wide=[];
  for(let mu=0;mu<4;mu++){
    let h=new Map(),good=[0,0,0];
    for(let z=0;z<Q;z++)for(let e=0;e<Q;e++){
      const C=capsule(mu,z,[e,0,0,0]);let k=key(C);
      h.set(k,(h.get(k)||0)+1);
      W.forEach((w,i)=>{if(dot(w,C,P)===2*mu)good[i]++;});
    }
    check(good.every(n=>n===Q*Q/P),"wide-noise exact decoding probability 1/8");
    wide.push(h);
  }
  const mapEq=(x,y)=>x.size===y.size&&[...x].every(([k,v])=>y.get(k)===v);
  for(let i=0;i<4;i++)for(let j=i+1;j<4;j++)
    check(mapEq(wide[i],wide[j]),"wide-noise public source independent of word");
  return {
    run:"R82-TRUE-SOURCE-COSET-OBSTRUCTION-20261105",
    result:"NO_POSITIVE_WKEM_ADVANCE",
    assertions:checks,
    source_params:{q:Q,p:P,g,Delta,A,e0},
    original_witness_rows:W,
    exact_shift_certificates:shifts,
    word_values:4,
    exhaustive_bounded_noise_source_samples_per_word:Q*81,
    source_support_sizes:hist.map(h=>h.size),
    pairwise_total_variation_bounded_noise:1,
    pairwise_total_variation_wide_noise:0,
    exact_word_decoding_success_wide_noise:"1/8",
    limitations:["finite toy math, not QPT","not generic NP no-go","does not instantiate hard-TRUE LWE-source challenger"]
  };
}
```

## Captured checker output

```json
{
  "run": "R82-TRUE-SOURCE-COSET-OBSTRUCTION-20261105",
  "result": "NO_POSITIVE_WKEM_ADVANCE",
  "assertions": 31131,
  "source_params": {
    "q": 32,
    "p": 8,
    "g": 4,
    "Delta": 8,
    "A": [
      -4,
      4,
      4,
      4
    ],
    "e0": [
      1,
      0,
      0,
      0
    ]
  },
  "original_witness_rows": [
    [
      1,
      1,
      0,
      0
    ],
    [
      1,
      0,
      1,
      0
    ],
    [
      1,
      0,
      0,
      1
    ]
  ],
  "exact_shift_certificates": [],
  "word_values": 4,
  "exhaustive_bounded_noise_source_samples_per_word": 2592,
  "source_support_sizes": [
    8,
    8,
    8,
    8
  ],
  "pairwise_total_variation_bounded_noise": 1,
  "pairwise_total_variation_wide_noise": 0,
  "exact_word_decoding_success_wide_noise": "1/8",
  "limitations": [
    "finite toy math, not QPT",
    "not generic NP no-go",
    "does not instantiate hard-TRUE LWE-source challenger"
  ]
}
```
