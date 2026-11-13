# R98 — Universal near-key bypass defeats scaled 3CNF-to-LWE compiler

**Run:** R98-CLAUSE-GAP-AMP-NEAR-KEY-20261105. **Status:** NO positive secure witness-KEM advance; one bounded attempted repair and an exact negative theorem. **Source:** syscoin/PVUGC#1 open/draft/unmerged, branch \`research/pq-wkem-validation-20260918\`, starting commit \`97b14f3f5e25ba0ae54d78892c9c350cb03d951e\`. Prior exact R97 note blob \`f9e256417aa487db90fc89de2840b6b1f36b357d\`, prior R89 compiler blob \`4e42a958ccd6a9ae0c26886d5a73ba69856065f5\`, latest ordinary comment \`6671586657\`. No external internet research.

## Exact candidate

Continue the broken R89 witness-blind 3CNF bounded-distance compiler and R97's missing honest-LWE simulator. Let F have n Boolean variables and c 3-literal clauses; d=n+c, m=2n+2c, prime q, centered source-key error bound β=1. Keep each variable's two identical unit rows with targets 0,1; keep each clause slack's unit row with target 1; scale each clause row and its public target by a large γ. For clause j with h_j negative literal occurrences and truth count L_j(w) in {0,1,2,3}, the residual of source vector s=(w,t) is

    e_clause_j = 3 γ (1 - L_j(w) + t_j) (mod q).

Every satisfying ORIGINAL w gives t_j=L_j(w)-1∈{0,1,2}, clause residual exactly zero, remaining errors ≤1. Build still samples one precommitted seed T without a witness and encrypts each T-bit with Regev's published algebra:

    r <- {-3,-2,-1,0,1,2,3}^m;
    u=A^T r mod q; v=b^T r + Δ*Tbit mod q; Δ=floor(q/2).

With any accepted bounded-error source s, v-<s,u>=<b-As,r>+Δ*Tbit. Attempted repair: amplified clause rows make some v-only ciphertext guesses fail while keeping all genuine witnesses correct. This attempt *does not* make source distribution honestly ordinary LWE and *does not* make the decoder source-key aware.

## Exact theorem — public invalid near-key decrypts **all** capsules

Fix **any** 3CNF formula (even unsatisfiable) and **any publicly chosen Boolean assignment** w*, e.g. all zero. Calculate each clause's truth count and set public t*_j=L_j(w*)-1, even when a clause is false and t*_j=-1 (mod q). Set s*=(w*,t*). Then **regardless of γ** every amplified clause residual e_clause(s*) is exactly 0. Each duplicated-variable pair has one residual ±1 and the other 0; each slack residual is 1-t*=2-L_j(w*)∈{-1,0,1,2}. Consequently

    ||b-As*||_1 <= n+2c,   ||b-As*||∞ <= 2,
    |<b-As*,r>| <= 3(n+2c).

Under the legitimate Regev decoding margin 3(n+2c)<q/4-1, anyone can decrypt every T-bit from v-<s*,u>, **without** an accepted source key, ORIGINAL witness, challenge source secret or SourceOpen oracle. On a FALSE clause, its slack residual 2 exceeds β=1, so s* is **invalid** even though the unguarded arithmetic always decrypts.

A public CheckSource(s*) call rejecting it is irrelevant: an adversary simply computes the public affine correction and rounds; no honest Open call or representation is provided. As T is the common precommitted root, public recovery unblinds the preauthorized native signature via PRG(T), and allows exact recomputation of CK/Aux and all related-capsule correlations. This is an unconditional classical PPT break (hence QPT). It breaks FALSE-instance hiding and unauthorized hard-TRUE recovery for **this** compiler family; valid-source representation → ORIGINAL extraction does not help. It does NOT prove a generic impossibility for nonlinear sources, plain-LWE witness encryption or arbitrary NP.

## Exact fixed FALSE and TRUE experiments

Choose q=257, γ=25, β=1, n=1, m=6, F=(x∨x∨x)∧(¬x∨¬x∨¬x). This original statement is FALSE. Duplicated unit rows force x∈{0,1} mod q and slack unit rows force t∈{0,1,2}; every nonzero clause discrepancy δ∈{-3,-2,-1,1,2} gives |center(75δ mod 257)|>1. Thus **no source key** over the full modular field passes the stated β=1 source verification. But public s*=(0,-1,2) has e*=(0,1,2,0,-1,0), ∥e*∥₁=4. For ALL 7^6=117,649 septenary randomness vectors and both bits, s* decrypts every bit correctly (235,298/235,298), while the older v-only decoder fails in 124,334/235,298 trials. A satisfiable control with a repeated-positive clause opens correctly for all 7^4 coins and both bits (4,802/4,802). The exact JavaScript checker below also tests 2,000 clause/assignment identities and public affine-shift bypass.

This conclusively rules out **row-scaling-only amplification** of R89, including the apparent v-only leakage repair. A gamma choice with modular aliasing (e.g. 43) also spoils even accepted source soundness; γ=25 avoids those aliases but not the near-key bypass.

## Security, composition, and exact next obligation

The complete adversarial public view includes R_original and x, capsule, claim/UTXO, branch and native verification key/path, anchors and window/context, the already signed message and masked signature, checking key, auxiliary data, audit/DA statements and related capsules. Because T is public under this attack, *any acyclic* public checking/auxiliary functions based on T are recomputable. Neither independent nonuniform quantum advice nor coherent processing is needed; the classical adversary already wins. Actual honest ordinary-QPT-LWE INDCPA does not apply to structured A,b. Marginal LWE pads, scalar wrappers, affine shifts or hash-based checking do not authenticate a source secret before **public** decryption. QPT-PRG/native QPT-EUF-CMA become irrelevant once T is recovered. Selective openings, multiple related capsules, builder erasure and the earlier N-of-N audit cannot cure this source failure.

A necessary (not sufficient) requirement for any repaired public decoder using s as a purported source is that *no efficiently computable INVALID near-key*, including s*(w), recovers the seed with nonnegligible probability. In addition, the indispensable positive obligation is a **classical-PPT** generic-ORIGINAL NP compiler that jointly simulates its *genuine statement-dependent* ordinary-LWE challenge and the **full public output** without knowledge of the challenge secret or SourceOpen. It must support every valid ORIGINAL witness (distinct states allowed) recovering the SAME precommitted capability, and provide a reduction from arbitrary QPT unauthorized key recovery or already-accepted native forgery to **an actual ORIGINAL witness** or an independently justified QPT break, even when the adversary offers no internal representation. Arbitrary fixed-FALSE full-public security, malformed/malicious setup, N-of-N abort/DA/censorship, post-funding/related-key exposures, concrete 128-bit parameters and the conditional Bitcoin no-EC-key-path/PQ-native signature endpoint remain unresolved. No Bitcoin NP verifier, VM, general proof or BitVM trace dispute is assumed. SYS/BTC AuxPoW, tag, fork, ancestor/window and timely-watch assumptions remain as previously scoped. Do not disable the existing research automation.

## Exact executed reproducible V8 checker

The following function was executed in this run in V8; its exact function source, stdout and independent **local-only** Python 364,169-assertion checker are distinct artifacts. The V8 test is a finite algebraic demonstration with insecure q=257, a toy hash/XOR native signature mask, **not a QPT security test**.
```javascript
function runR98() {

  const q=257, g=25, beta=1, delta=128, rho=3, N=1, C=2, m=6, d=3;
  const A=[[1,0,0],[1,0,0],[0,1,0],[9*g,-3*g,0],[0,0,1],[-9*g,0,-3*g]];
  const b=[0,1,1,3*g,1,-6*g];
  const fake=[0,-1,2], expectedError=[0,1,2,0,-1,0];
  let checks=0;
  const counts={falseBoundedKeys:0,falseCoins:0,falseBitDecryptions:0,vOnlyFailures:0,trueBitDecryptions:0,universalClauseCases:0,affineShiftDecryptions:0,wholeSeedRecoveries:0};
  function ok(v,msg){checks++;if(!v)throw Error("assert "+checks+": "+msg)}
  function mod(z){return (z%q+q)%q}
  function ctr(z){return mod(z+128)-128}
  function dot(x,y){return x.reduce((a,t,i)=>a+t*y[i],0)}
  function uval(rows,r){return rows[0].map((_,k)=>mod(rows.reduce((sum,row,i)=>sum+row[k]*r[i],0)))}
  function bitDec(z){return +(Math.abs(ctr(z-delta))<Math.abs(ctr(z)))}
  const err=b.map((x,i)=>ctr(x-dot(A[i],fake)));
  ok(JSON.stringify(err)===JSON.stringify(expectedError),"fake residual exactly [0,1,2,0,-1,0]");
  ok(err.some(x=>Math.abs(x)>beta),"public fake fails source check");
  ok(rho*err.reduce((a,z)=>a+Math.abs(z),0)<q/4-1,"fake residual bound");
  let vars=[],slacks=[];
  for(let z=0;z<q;z++){
    if(Math.abs(ctr(-z))<=1 && Math.abs(ctr(1-z))<=1)vars.push(z);
    if(Math.abs(ctr(1-z))<=1)slacks.push(z);
  }
  ok(JSON.stringify(vars)==="[0,1]","full-field Boolean gadget intersection");
  ok(JSON.stringify(slacks)==="[0,1,2]","full-field slack gadget intersection");
  for(let k=-3;k<=2;k++)if(k!==0)ok(Math.abs(ctr(3*g*k))>1,"no modular clause wrap alias");
  for(let x of vars)for(let t0 of slacks)for(let t1 of slacks){
    let s=[x,t0,t1];
    let good=b.every((z,i)=>Math.abs(ctr(z-dot(A[i],s)))<=1);
    ok(!good,"UNSAT instance has no accepted source key");
    if(good)counts.falseBoundedKeys++;
  }
  for(let index=0;index<7**6;index++){
    let x=index,r=[];
    for(let j=0;j<m;j++){r.push((x%7)-3);x=Math.floor(x/7)}
    let u=uval(A,r);
    let eNoise=dot(err,r);
    ok(Math.abs(eNoise)<q/4-1,"fake error under threshold");
    counts.falseCoins++;
    for(let bit=0;bit<=1;bit++){
      let v=mod(dot(b,r)+delta*bit);
      ok(bitDec(ctr(v-dot(fake,u)))===bit,"public invalid key decrypts");
      counts.falseBitDecryptions++;
      if(bitDec(ctr(v))!==bit)counts.vOnlyFailures++;
    }
  }
  ok(counts.vOnlyFailures>0,"amplified clause blocks v-only in some cases");
  // A satisfiable unit source uses the same amplified clause rule.
  const AT=[[1,0],[1,0],[0,1],[9*g,-3*g]],bT=[0,1,1,3*g],sT=[1,2];
  const errT=bT.map((x,i)=>ctr(x-dot(AT[i],sT)));
  ok(JSON.stringify(errT)==="[-1,0,-1,0]","true source error");
  for(let index=0;index<7**4;index++){
    let x=index,r=[];
    for(let j=0;j<4;j++){r.push((x%7)-3);x=Math.floor(x/7)}
    let u=uval(AT,r);
    for(let bit=0;bit<=1;bit++){
      let v=mod(dot(bT,r)+delta*bit);
      ok(bitDec(ctr(v-dot(sT,u)))===bit,"all valid TRUE openings");
      counts.trueBitDecryptions++;
    }
  }
  // Clause lemma holds for all ordered 3-literal clauses, n<=3, all w.
  for(let nv=1;nv<=3;nv++){
    const lits=[];
    for(let i=1;i<=nv;i++){lits.push(-i,i)}
    for(let a of lits)for(let bLit of lits)for(let cLit of lits){
      const clause=[a,bLit,cLit];
      for(let mask=0;mask<(1<<nv);mask++){
        const w=Array.from({length:nv},(_,i)=>(mask>>i)&1);
        const L=clause.reduce((v,lit)=>v+((w[Math.abs(lit)-1]===(lit>0?1:0))?1:0),0);
        const t=L-1;const h=clause.reduce((v,lit)=>v+(lit<0?1:0),0);
        const row=Array(nv+1).fill(0);row[nv]=-3*g;
        for(let lit of clause)row[Math.abs(lit)-1]+=3*g*(lit>0?1:-1);
        ok(ctr(3*g*(1-h)-dot(row,[...w,t]))===0,"all clause residuals zero for public extension");
        ok(Math.abs(ctr(1-t))<=2,"all slack residuals at most 2");
        counts.universalClauseCases++;
      }
    }
  }
  // A public affine shift cannot help if its shift can be reconstructed.
  let shift=[11,37,79],b2=b.map((x,i)=>mod(x+dot(A[i],shift)));
  for(let index=0;index<7**6;index+=101){
    let x=index,r=[];
    for(let j=0;j<m;j++){r.push((x%7)-3);x=Math.floor(x/7)}
    let u=uval(A,r);
    for(let bit=0;bit<=1;bit++){
      let v=mod(dot(b2,r)+delta*bit);
      ok(bitDec(ctr(v-dot(fake.map((a,i)=>a+shift[i]),u)))===bit,"affine-shift fake decryption");
      counts.affineShiftDecryptions++;
    }
  }
  // Toy whole-output capability: reproducible bit stream recovered with fake key.
  const seed=[1,0,1,1,0,0,1,0],recovered=[];
  for(let k=0;k<seed.length;k++){
    let x=k,r=[];
    for(let j=0;j<m;j++){r.push((x%7)-3);x=Math.floor(x/7)}
    const u=uval(A,r),v=mod(dot(b,r)+delta*seed[k]);
    recovered.push(bitDec(ctr(v-dot(fake,u))));
  }
  ok(JSON.stringify(recovered)===JSON.stringify(seed),"full source root recovered");
  const H=(arr,salt)=>arr.reduce((v,z)=>(Math.imul(v^z,16777619)+1013904223)>>>0,salt>>>0);
  const sig=H([2,4,6,8],23),pad=H(seed,17),D=(sig^pad)>>>0;
  const CK=H([pad,D,...seed],41),Aux=H([CK,D,...seed],73);
  const recoveredSig=(D^H(recovered,17))>>>0;
  ok(recoveredSig===sig && CK===H([H(recovered,17),D,...recovered],41)
      && Aux===H([CK,D,...recovered],73),"full masked native output plus CK/Aux recomputed");
  counts.wholeSeedRecoveries++;
  return {run:"R98-CLAUSE-GAP-AMP-NEAR-KEY-20261105",
    status:"NO_POSITIVE_WKEM_ADVANCE",q,gamma:g,beta,rho,m,d,
    errorOfPublicInvalidKey:err,checks,counts,
    conclusion:"All 3CNF false/true instances under this linear clause-amplified decoder admit a public near-key; fails full-public security; not a QPT experiment."};
}

console.log(JSON.stringify(runR98(),null,2));
```

## Captured exact V8 output

```json
{
  "run": "R98-CLAUSE-GAP-AMP-NEAR-KEY-20261105",
  "status": "NO_POSITIVE_WKEM_ADVANCE",
  "q": 257,
  "gamma": 25,
  "beta": 1,
  "rho": 3,
  "m": 6,
  "d": 3,
  "errorOfPublicInvalidKey": [
    0,
    1,
    2,
    0,
    -1,
    0
  ],
  "checks": 364111,
  "counts": {
    "falseBoundedKeys": 0,
    "falseCoins": 117649,
    "falseBitDecryptions": 235298,
    "vOnlyFailures": 124334,
    "trueBitDecryptions": 4802,
    "universalClauseCases": 2000,
    "affineShiftDecryptions": 2330,
    "wholeSeedRecoveries": 1
  },
  "conclusion": "All 3CNF false/true instances under this linear clause-amplified decoder admit a public near-key; fails full-public security; not a QPT experiment."
}
```

**Executed actions/provenance:** connected GitHub PR metadata, latest ordinary comments and exact-version R97/R89 file reads; bounded local Python and V8 checks. Any publication receipt is recorded independently after verifying the generated Git commit and fetched file. No claims of a secure construction or background work.
