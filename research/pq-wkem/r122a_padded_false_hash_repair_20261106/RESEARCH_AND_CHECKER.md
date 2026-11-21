# R122A — Noise-projective ORIGINAL source with public privacy amplification (REJECTED)

**Conclusion: NO secure arbitrary-ORIGINAL-witness advance.** This is one bounded foundational release-repair attempt continuing the exact R121 rejected global noisy-projective source, not a packing or efficiency iteration. It is distinct from the earlier historical Run 122 ordinary-QPT-LWE lift note. R121's raw fixed-FALSE integer projection recovers single hidden bits on every noise tape with E=1 and its original q. We tried increasing the allowed noise relative to the center separation and hashing many independently encoded bits to yield a common signature pad. The new repair **fails for a polynomially generated family of FALSE ORIGINAL statements, with a classical PPT attack recovering the entire pad with overwhelming probability**.

**Exact continuity at analysis start:** syscoin/PVUGC PR #1, branch `research/pq-wkem-validation-20260918`, SHA `2d46d4988ae6a50e6a071f69f347a62dbb492de4` (open/draft/unmerged). Read ordinary comment `6697800505` and exact R121 research blob `ccfae837d239bc21ba639065cf1b9e5ea9b99847`. No whole PR diff or external research.

## Candidate explicit release and same-capability correctness

For ORIGINAL 3CNF x, use R121's polynomial-sized integer incidence constraints `A_x z=b_x`, where every honest satisfying w yields a *different permitted* one-hot z_w as necessary with `||z_w||_1=n+m=W`. Choose prime q >= 4EW+5; centers `h0=0`, `h1=floor(q/2)`; sample independent pad bits `B_i uniform {0,1}`. For each i, choose alpha_i uniformly conditioned on `b_x^T alpha_i=h_{B_i} (mod q)` (classical PPT, a coefficient of b_x is 1) and independent coordinate noise e_i uniform on `[-E,E]^(2n+3m)`. Publish `p_i=A_x^T alpha_i+e_i (mod q)`, common native VK, public seeded universal extractor description and seed r, and `D_sigma=sigma XOR Ext_r(B_1,...,B_L)`. The fixed native sigma is preauthorized and domain-bound to ORIGINAL relation identity, claim/UTXO, branch, actual anchors/window/context, graph, intended native challenge path, VK and capability. CK/J/Aux/context and sibling capsules remain in the full public distribution.

A witness w computes `<p_i,z_w>=h_{B_i}+<e_i,z_w> mod q`. Because `|<e_i,z_w>|<=EW` and shortest cyclic center distance is at least `2EW+2`, nearest-center decoding gives B_i **deterministically on every permitted encryption tape**. Thus every valid ORIGINAL witness can recover the same frozen sigma, without a canonical witness or shared state. This is functional correctness for this candidate, not security.

## Exact padded FALSE family and full-public classical attack

Let x_t be the AND of t disjoint pairs `(X_j OR X_j OR X_j) AND (!X_j OR !X_j OR !X_j)`; it is FALSE for all t. One block has R121's public rows

```
A = [[1,1,0,0,0,0,0,0],
     [0,0,1,1,1,0,0,0],
     [0,0,0,0,0,1,1,1],
     [0,3,0,1,2,0,0,0],
     [3,0,0,0,0,0,1,2]]
b = [1,1,1,3,3]
z_bad = [0,1,1,0,0,0,-1,2]
```

The attacker constructs block diagonal A_t and the explicit concatenated z_bad,t. Direct integer arithmetic gives `A_t z_bad,t=b_t`, `W=3t`, `||z_bad,t||_1=5t`, and `||z_bad,t||_2^2=7t`. The attacker never asks an off-chain witness verifier to accept this longer invalid representation. For every published pad source bit,

```
v_i = <p_i,z_bad,t> = h_{B_i} + N_i (mod q),
N_i = <e_i,z_bad,t>.
```

Because the noise coordinates are centered, independent and bounded by E, Hoeffding gives

```
Pr[ |N_i| >= E W ] <= 2 exp(- (EW)^2 / (2 E^2 ||z_bad,t||_2^2))
                        = 2 exp(-9t/14).
```

When `|N_i|<EW`, nearest-center decoding is necessarily correct since q>=4EW+5. Recovering **every** one of L arbitrary source bits therefore succeeds with probability at least `1-2L exp(-9t/14)`. This requires no independence among output bits for the union bound; the stated noise distribution is enough. For any polynomial L(t), the attack recovers all source bits with overwhelming probability. Once B is known, the public extractor seed r and `D_sigma` immediately reveal the precommitted native sigma. For t=512, the explicit union upper bound even for L<=2^20 is below `2^-453.85`. This is an **ATTACK FAILURE** bound, not a security estimate. It defeats false-instance security without breaking LWE, recovering any valid ORIGINAL witness, or requesting an internal representation.

The larger-noise plus public-universal-hash repair specifically fails because the false attack projection has noise standard deviation O(E sqrt(t)) while the deterministic accepted-witness threshold is Omega(E t). Padding with independent contradictory live variables overwhelms the chance of a false projection exceeding the threshold. This observation is a limitation **only** of the independent bounded-noise linear-projective family; it is not a generic impossibility proof for witness encryption or arbitrary correlated nonlinear sources.

## Full-public QPT scope and precise unfinished equation

Full public `(R_original,x,A_x,b_x,all p_i,r,D_sigma,VK,CK,J,Aux,context,graph,related capsules)` and all admissible auxiliary inputs/side information are visible. The attack is classical and uses a subset of public bytes, so arbitrary QPT quantum advice, coherent joint attacks and additional public correlations cannot prevent this failure. The candidate supplies *no* QPT-LWE full-public simulator and *no* arbitrary hard-TRUE recovery/native-forgery -> ORIGINAL-witness extractor; its FALSE branch fails independently.

Still indispensable: a classical-PPT `Comp(R_ORIGINAL,x)` with real statement-dependent source opening and joint-public QPT simulator, satisfying `Open(Comp(R_ORIGINAL,x),w)=SAME precommitted sigma` for **every** ORIGINAL witness, but for which arbitrary early QPT sigma recovery or accepted native forgery implies an actual ORIGINAL witness or an independently justified QPT break, not adversary-supplied representations. No new WE/iO/WPRF assumption, heuristic LWE label, fixed-probe success or inner-SNARG equivalence substitutes for this reduction. Malicious N-of-N setup/abort and graph composition, data availability, source authenticated SYS/BTC semantics, numerical PQ calibration and hypothetical Bitcoin native endpoints remain separately open.

## Executed independent checker and captured output

The **exact function below was executed** in a GitHub-connected V8 tool runtime *before publication*. It verifies block source equations, an analogous satisfiable instance, explicit affine-setup/public-projection samples, full integer convolution over supported error sums for t=1,2,4,8,16,32,64,128, both secret bit values, deterministic honest decoding bound and the t=512 asymptotic union certificate. It is reproducibility evidence, not quantum hardness evidence. An independent locally executed Python standard-library checker passed 10,352 assertions and captured the same family probabilities; it is local-only, not claimed to be in GitHub. No efficiency optimization occurred.

```javascript
function runR122A(){
 let assertions=0;const ok=(x,m)=>{assertions++;if(!x)throw Error("assertion "+assertions+" "+m);};
 const A=[[1,1,0,0,0,0,0,0],[0,0,1,1,1,0,0,0],[0,0,0,0,0,1,1,1],[0,3,0,1,2,0,0,0],[3,0,0,0,0,0,1,2]];
 const b=[1,1,1,3,3], bad=[0,1,1,0,0,0,-1,2], sat=[0,1,1,0,0,1,0,0];
 const Asat=[...A.slice(0,4),[0,3,0,0,0,0,1,2]];
 const dot=(x,y)=>x.reduce((s,v,i)=>s+v*y[i],0);
 for(let j=0;j<5;j++){ok(dot(A[j],bad)===b[j],"false affine");ok(dot(Asat[j],sat)===b[j],"true analogue");}
 ok(bad.reduce((s,v)=>s+Math.abs(v),0)===5,"bad L1");ok(dot(bad,bad)===7,"bad L2^2");ok(sat.reduce((s,v)=>s+Math.abs(v),0)===3,"good L1");
 const mod=(v,q)=>((v%q)+q)%q;
 const prime=q=>{if(q<2)return false;for(let i=2;i*i<=q;i++)if(q%i===0)return false;return true;};
 const nextPrime=q=>{while(!prime(q))q++;return q;};
 const nearest=(v,bit,q)=>{let d=(a,b)=>Math.min(mod(a-b,q),mod(b-a,q));return d(v,bit?Math.floor(q/2):0)<d(v,bit?0:Math.floor(q/2));};
 let rows=[];
 for(const t of [1,2,4,8,16,32,64,128]){
   const W=3*t,q=nextPrime(4*W+5);ok(q>=4*W+5,"correctness margin");
   let c=new Map([[0,1n]]);
   for(let j=0;j<t;j++)for(const w of [1,1,1,2]){
     const v=new Map();
     for(const [s,k] of c)for(const e of [-1,0,1])v.set(s+e*w,(v.get(s+e*w)||0n)+k);
     c=v;
   }
   let denom=3n**BigInt(4*t),sum=0n,fail=[0n,0n];
   for(const [s,k] of c){
     sum+=k;
     for(const bit of [0,1])if(!nearest(mod((bit?Math.floor(q/2):0)+s,q),bit,q))fail[bit]+=k;
   }
   ok(sum===denom,"exact count");
   ok(fail[0]===fail[1],"symmetric conditional errors");
   const p=Number(fail[0])/Number(denom), bound=2*Math.exp(-9*t/14);
   ok(p<=Math.min(1,bound)+1e-14,"Hoeffding bound");
   for(const bit of [0,1])for(let e=-W;e<=W;e++)ok(nearest(mod((bit?Math.floor(q/2):0)+e,q),bit,q),"valid short decoder");
   if(t<=16)for(const bit of [0,1]){
     let a=Array.from({length:5*t},(_,i)=>mod(i*53+11*t+bit*37,q));
     a[0]=mod((bit?Math.floor(q/2):0)-a.slice(1).reduce((s,v,j)=>s+v*b[(j+1)%5],0),q);
     ok(mod(a.reduce((s,v,j)=>s+v*b[j%5],0),q)===(bit?Math.floor(q/2):0),"affine setup conditioning");
     let P=[],evec=[],Z=[];
     for(let j=0;j<t;j++)for(let k=0;k<8;k++){
       const e=mod(17*k+13*j+t,3)-1; evec.push(e);Z.push(bad[k]);
       P.push(mod(A.reduce((s,row,r)=>s+row[k]*a[5*j+r],0)+e,q));
     }
     ok(mod(dot(P,Z),q)===mod((bit?Math.floor(q/2):0)+dot(evec,Z),q),"full published projection");
   }
   rows.push({t,W,q,wrong_probability:p,wrong_numerator:String(fail[0]),denominator:String(denom),hoeffding_bound:Math.min(1,bound)});
 }
 const t=512,log2delta=1-(9*t/14)/Math.LN2;
 ok(log2delta+20< -400,"poly pad break");
 return {run:"R122A-PADDED-FALSE-EXTRACTOR-REPAIR-20261106",assertions,rows,analytic:{t,per_bit_log2_bound:log2delta,all_bits_log2_bound_L_le_2pow20:log2delta+20},result:"REJECTED: classical polynomial-time false-instance recovery; no generic-NP WKEM advance"};
}
console.log(JSON.stringify(runR122A(),null,2));

```

### Captured exact V8 result

```json
{
  "run": "R122A-PADDED-FALSE-EXTRACTOR-REPAIR-20261106",
  "assertions": 3142,
  "rows": [
    {
      "t": 1,
      "W": 3,
      "q": 17,
      "wrong_probability": 0.06172839506172839,
      "wrong_numerator": "5",
      "denominator": "81",
      "hoeffding_bound": 1
    },
    {
      "t": 2,
      "W": 6,
      "q": 29,
      "wrong_probability": 0.018594726413656455,
      "wrong_numerator": "122",
      "denominator": "6561",
      "hoeffding_bound": 0.5529060932591287
    },
    {
      "t": 4,
      "W": 12,
      "q": 53,
      "wrong_probability": 0.0017464744875689835,
      "wrong_numerator": "75180",
      "denominator": "43046721",
      "hoeffding_bound": 0.15285257398153615
    },
    {
      "t": 8,
      "W": 24,
      "q": 101,
      "wrong_probability": 0.00001822353388007257,
      "wrong_numerator": "33768576192",
      "denominator": "1853020188851841",
      "hoeffding_bound": 0.011681954686390493
    },
    {
      "t": 16,
      "W": 48,
      "q": 197,
      "wrong_probability": 2.5214025014664733e-9,
      "wrong_numerator": "8657698973730496650120",
      "denominator": "3433683820292512484657849089281",
      "hoeffding_bound": 0.0000682340326474404
    },
    {
      "t": 32,
      "W": 96,
      "q": 389,
      "wrong_probability": 6.418832124387198e-17,
      "wrong_numerator": "756792155200429124225291436047764681615104984",
      "denominator": "11790184577738583171520872861412518665678211592275841109096961",
      "hoeffding_bound": 2.327941605665981e-9
    },
    {
      "t": 64,
      "W": 192,
      "q": 773,
      "wrong_probability": 5.688722830281132e-32,
      "wrong_numerator": "7907805566399107880626207024354637267444869356477700830537210155595238204433422653969970936",
      "denominator": "139008452377144732764939786789661303114218850808529137991604824430036072629766435941001769154109609521811665540548899435521",
      "hoeffding_bound": 2.7096560596953532e-18
    },
    {
      "t": 128,
      "W": 384,
      "q": 1543,
      "wrong_probability": 3.8285602143937994e-62,
      "wrong_numerator": "739806083767144369070171360105979403970642714773948427870747754843775682242773188716327106916899320270223508303756694956036175522211994141487929353496225092303884072203235229662189752",
      "denominator": "19323349832288915105454068722019581055401465761603328550184537628902466746415537000017939429786029354390082329294586119505153509101332940884098040478728639542560550133727399482778062322407372338121043399668242276591791504658985882995272436541441",
      "hoeffding_bound": 3.671117980921874e-36
    }
  ],
  "analytic": {
    "t": 512,
    "per_bit_log2_bound": -473.85276774402456,
    "all_bits_log2_bound_L_le_2pow20": -453.85276774402456
  },
  "result": "REJECTED: classical polynomial-time false-instance recovery; no generic-NP WKEM advance"
}
```

**Status:** REJECTED; no positive security-foundation advance. The automation's optimization gate remains closed, with no modification to production code, Bitcoin, another repository, or PR merge/review state.
