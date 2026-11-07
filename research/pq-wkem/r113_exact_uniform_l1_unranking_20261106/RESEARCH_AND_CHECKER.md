# R113 — Exact uniform bounded-L1 LWE encryption coins, without rejection

**Run:** R113-EXACT-L1-COMBINATORIAL-UNRANK-20261106; **PR:** syscoin/PVUGC#1; **initial expected head:** `f9f3bd6ed90d0747e3a8c10b8330bf047e6e4a7a`; **branch:** `research/pq-wkem-validation-20260918`. Exact predecessor R110's source/coin-law note has Git blob `938c767403b2c0f7d4852853ec6618178a7db73f`, and R112's rejection note blob `ce01402ff529cbd2c4dda2b8ed41f2390f356aa6`. Both were read at exact prior head before this iteration. No outside literature/web research was used.

**Status: positive efficiency of a surviving RESTRICTED LWE-credential release, not generic NP witness encryption.** R111/R112's attempted arbitrary-ORIGINAL-3CNF dual-Regev compiler remains broken by classical public near-keys for fixed-FALSE statements. R113 does not repair it or claim quantum hardness.

## Exact replaced distribution and full-public relation

Keep R110's actual restricted relation, public uniform shared `A∈Z_q^(m×d)`, independently sampled honest bounded-error source credentials `B_(i,j)=A*S_(i,j)+E_(i,j)`, adversarially chosen corrupted source keys, all contexts/claims/branches/anchors/window/graph/native verification keys, immutable N-of-N pre-signed native challenge signatures, XOR-CNF clause-share release, checking-key/Aux and related-capsule correlations. Every valid restricted credential witness must reconstruct the same precommitted native signature. Existing conditional QPT IND-CPA, QPT-EUF-CMA, classical adaptive corruption and one-honest N-of-N restrictions remain; actual arbitrary-NP-to-source soundness is NOT supplied.

The encryption coins in **every** R110 honest scalar/vector-LWE ciphertext group must be exactly
`r ← Uniform(D_(m,L))`,
`D_(m,L)={r∈{-3,-2,-1,0,1,2,3}^m: ∑|r_i|≤L}`,
with `m=2000,L=2729,q=65521,d=256,ell=64,error bound 3`.
Ciphertext groups retain `u=A^T r; v=B^T r+16380·mu (mod q)`. Every **accepted** bounded-error representation yields `||E'^T r||∞ ≤3L=8187<8190`, the exact two-bit decoding radius. The release/opening/manifest algorithms and ALL published fields are otherwise byte-law-identical to R110.

## Constructive algorithm and unconditional proof

Let `P(z)=1+2z+2z²+2z³` and `c_n(k)=[z^k]P(z)^n`, so `c_0(0)=1` and
`c_n(k)=c_(n−1)(k)+2c_(n−1)(k−1)+2c_(n−1)(k−2)+2c_(n−1)(k−3)`, with impossible indices zero. Compute exact arbitrary-precision INTEGER coefficients truncated only above L; never use floating-weight approximations. Store just the coefficient rows corresponding to the recursively balanced binary block lengths of m=2000: `0,1,2,3,4,7,8,15,16,31,32,62,63,125,250,500,1000,2000` (18 rows). One streaming O(mL) polynomial-time preprocessing pass suffices. The coefficient count is `N=∑_(k=0)^L c_m(k)`, and independently reproduces R110's `log2 N=5445.079378072014`.

For each new ciphertext group, draw a SINGLE exact uniform integer `rank∈{0,...,N−1}` using a classical cryptographic unbiased `randbelow(N)`. Separate integer ranks by total norm k, descending, in blocks of sizes `c_m(k)`. At a balanced split `n=a+b` and weight k, separate ranks into left-weight h blocks of size **exactly** `c_a(h)c_b(k−h)`; inside a block let `rank'=rank_left*c_b(k−h)+rank_right` by integer quotient/remainder. Recurse. The length-one leaf has exactly one norm-0 vector (0) and two norm-t vectors (−t,+t), t=1,2,3. Concatenate left/right results. Cache rank split cumulative sums by `(block_length,weight)` within this parameter-closed sampler.

**Proof, not an assumption:** By induction on n, every split is a disjoint partition of all alphabet strings of total norm k. Counts are exact coefficient counts, and integer quotient/remainder identifies a unique pair of child ranks. Leaves are bijective. Hence rank ↔ one supported vector is bijective globally. Every full supported r has EXACT probability 1/N under a uniform rank, identical (not computationally close) to R110's conditional-tilt/rejection law. All full-public outputs and their correlations—including original restricted statement, capsule, native VK, context, CK/Aux, related capsules, source-generator QPT state, and permitted selective-opening records—therefore have the SAME joint distribution as in R110. The original reduction hypotheses and hybrid losses are neither strengthened nor weakened. Arbitrary quantum coherent postprocessing cannot distinguish distributions that are exactly equal. Theorems conditional on R110's separately unproven QPT-LWE parameters and native-signature assumptions remain conditional.

Complexity is classical PPT: O(mL) polynomial-bit integer arithmetic for the shared one-time table, O(L log m) integer entries for stored balanced levels, and per-sample O(m+L log m) split-option arithmetic on polynomial-bit integers. `randbelow(N)` itself uses unbiased bitstring rejection with expected <2 rank proposals; there is no rejection of complete 2000-coordinate vectors. The algorithm is not constant-time; production side-channel hardening is outstanding.

## Reproducibility and measured efficiency

The exact separately executed Python 3 checker (stdlib only, archived locally) exhausted **every** rank and independently enumerated each entire toy support for six `(m,L)` pairs: `(2,2,13),(3,3,63),(4,4,313),(5,5,1583),(6,4,1277),(7,5,6987)`: 10,236 unique ranks, each exactly once. The full 2000-coordinate check reconstructed R110's exact support count and sampled 150 vectors, verifying support and worst-case decryption-error bound. It compared against an **INTEGER-EXACT** implementation of R110's original `t=13/18` proposal weights `[5832,4212,4212,3042,3042,2197,2197]`, rejection at `||r||₁>2729` and exact rational accept `(13/18)^(2729−||r||₁)`. Under seeded CPython on one local machine, 150 accepted groups gave 3.468181 ms per unranked vector versus 19.023283 ms for the exact integer-tilt baseline: **5.485089× sampling-only speedup**, 29.84 old complete-vector proposals per accepted group versus one rank draw for new. Shared table precompute took 3.927367 seconds, with 2,306,027 bytes raw BigInt coefficient payload (not the total Python heap); at observed times the setup cost amortizes after approximately 253 groups. This is NOT a benchmark of end-to-end LWE matrix multiplication, deployment latency, CSPRNG speed or actual optimized native implementations. The local deterministic test RNG is NOT cryptographically secure: real coin generation MUST use a cryptographic unbiased `randbelow` (for example Python `secrets.SystemRandom().randrange`).

The independent, below-published JavaScript checker is the **exact source actually executed in the connected authorized research runtime**. It independently exhausts 5 toy vector supports/rank spaces, and verifies the exact m=2000 coefficient count, seven large unrankings and correctness margin. JSON below is its captured result, not fabricated.

## Exact remaining research obligation

No equation of the form `Open(Comp(R_ORIGINAL,x),w)=same_precommitted_native_capability` for every arbitrary valid ORIGINAL-NP witness is established here. There is no generic full-public challenge simulator, no arbitrary unauthorized hard-TRUE recovery/native forgery → ORIGINAL witness or independently justified QPT break, and no generic fixed-FALSE security. R111/R112's affine/near-key bypass remains a regression test. A future generic source needs genuinely nonlinear statement binding without off-domain/key-recovery leakage and must simultaneously permit ordinary-QPT-LWE challenge simulation of all setup/opening/public CK/Aux/related correlations, with no hidden SourceOpen oracle or supplied-representation requirement.

N-of-N one-honest preauthorization/erasure/abort/data availability and authenticated SYS/BTC AuxPoW/header/tag/ancestor/window/reorg/censorship source, concrete PQ calibration, and hypothetical no-EC-key-path native PQ Bitcoin output also remain open. Bitcoin must not verify the original NP predicate, SNARG, VM or PCP trace; no online committee or extra opcode is introduced. Existing research automation must remain enabled.

## Actual executed independent JS checker

```javascript
function runCheck(){
  let checks=0;
  const ok=(v,msg)=>{checks++;if(!v)throw Error("R113 checker FAIL: "+msg+" #"+checks)};
  function build(m,L){
    const sizes=new Set([0]);
    function need(n){if(sizes.has(n))return;sizes.add(n);if(n>1){need(Math.floor(n/2));need(n-Math.floor(n/2))}}
    need(m);
    let last=[1n];const tab=new Map([[0,last]]);
    for(let n=1;n<=m;n++){
      const curr=[];
      for(let k=0;k<=Math.min(3*n,L);k++){
        let v=k<last.length?last[k]:0n;
        for(let a=1;a<=3;a++)if(k-a>=0&&k-a<last.length)v+=2n*last[k-a];
        curr.push(v);
      }
      last=curr;
      if(sizes.has(n))tab.set(n,curr);
    }
    const total=tab.get(m).reduce((a,b)=>a+b,0n);
    const cache=new Map();
    function choices(n,k){
      const key=n+":"+k;
      if(cache.has(key))return cache.get(key);
      const l=Math.floor(n/2),r=n-l,ca=tab.get(l),cb=tab.get(r);
      let c=0n;const lo=Math.max(0,k-3*r),hi=Math.min(3*l,k),prefix=[];
      for(let a=lo;a<=hi;a++){c+=ca[a]*cb[k-a];prefix.push(c)}
      ok(c===tab.get(n)[k],"split normalization");
      const val={lo,prefix};cache.set(key,val);return val;
    }
    function unrank(rank){
      ok(rank>=0n&&rank<total,"rank inside support");
      let k=Math.min(L,3*m);
      while(rank>=tab.get(m)[k]){rank-=tab.get(m)[k];k--}
      function rec(n,w,t){
        if(n===1){ok(w<=3&&t<(w===0?1n:2n),"leaf");return [w===0?0:t===0n?-w:w]}
        const l=Math.floor(n/2),r=n-l,{lo,prefix}=choices(n,w);
        let i=0;while(prefix[i]<=t)i++;
        t-=i?prefix[i-1]:0n;
        const a=lo+i, q=tab.get(r)[w-a];
        const left=rec(l,a,t/q),right=rec(r,w-a,t%q);
        return left.concat(right);
      }
      return rec(m,k,rank);
    }
    return {total,unrank,coeffRows:tab.size,coefficientBitLength:total.toString(2).length};
  }
  const toy=[];
  for(const [m,L,expected] of [[2,2,13],[3,3,63],[4,4,313],[5,5,1583],[6,4,1277]]){
    const s=build(m,L);ok(s.total===BigInt(expected),"exact count "+m);
    const actual=new Set();
    const recur=(arr)=>{if(arr.length===m){if(arr.reduce((t,x)=>t+Math.abs(x),0)<=L)actual.add(arr.join(","));return}for(let x=-3;x<=3;x++)recur([...arr,x])};
    recur([]);ok(actual.size===expected,"independent alphabet enumeration");
    const images=new Set();
    for(let rank=0n;rank<s.total;rank++){
      const v=s.unrank(rank),key=v.join(",");
      ok(actual.has(key)&&!images.has(key),"bijection "+m+":"+rank);
      images.add(key);
    }
    ok(images.size===actual.size,"complete support "+m);
    toy.push({m,L,rank_count:images.size});
  }
  const s=build(2000,2729);
  ok(s.coefficientBitLength===5446,"R110 support bit length");
  const ranks=[0n,1n,s.total/7n,s.total/3n,s.total/2n,s.total-2n,s.total-1n];
  const norms=[];
  for(const rank of ranks){
    const v=s.unrank(rank),norm=v.reduce((t,x)=>t+Math.abs(x),0);
    ok(v.length===2000&&norm<=2729&&Math.max(...v.map(x=>Math.abs(x)))<=3,"large norm support");
    ok(3*norm<=8187&&8187<8190,"every accepted LWE key exact opening bound");
    norms.push(norm);
  }
  return {run:"R113-EXACT-L1-COMBINATORIAL-UNRANK-20261106",
    status:"PASS; SAME R110 COIN LAW, RESTRICTED SOURCE ONLY",
    assertions:checks, toy, large:{m:2000,L:2729,support_bit_length:s.coefficientBitLength,
      count_rows:s.coeffRows,exact_rank_tests:ranks.length,norms},
    crypto_hardness_measured:false, original_NP_reduction_solved:false};
}
console.log(JSON.stringify(runCheck(),null,2));
```

## Captured JS checker stdout

```json
{
  "run": "R113-EXACT-L1-COMBINATORIAL-UNRANK-20261106",
  "status": "PASS; SAME R110 COIN LAW, RESTRICTED SOURCE ONLY",
  "assertions": 37943,
  "toy": [
    {
      "m": 2,
      "L": 2,
      "rank_count": 13
    },
    {
      "m": 3,
      "L": 3,
      "rank_count": 63
    },
    {
      "m": 4,
      "L": 4,
      "rank_count": 313
    },
    {
      "m": 5,
      "L": 5,
      "rank_count": 1583
    },
    {
      "m": 6,
      "L": 4,
      "rank_count": 1277
    }
  ],
  "large": {
    "m": 2000,
    "L": 2729,
    "support_bit_length": 5446,
    "count_rows": 18,
    "exact_rank_tests": 7,
    "norms": [
      2729,
      2729,
      2729,
      2728,
      2727,
      1,
      0
    ]
  },
  "crypto_hardness_measured": false,
  "original_NP_reduction_solved": false
}
```
