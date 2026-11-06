# R112 — Tight-margin dual-Regev ORIGINAL source repair: REJECTED

**Run:** R112-TIGHT-MARGIN-JOINT-NEAR-KEY-20261106. **Starting verified PR #1 head:** cabd468988c98260b04b46f2fd3b3f58d6119e87, open/draft/unmerged on research/pq-wkem-validation-20260918. Exact predecessor: research/pq-wkem/r111_dual_regev_original_3cnf_20261106/RESEARCH_AND_CHECKER.md, Git blob e651dfdafd14f5b68c60e36e62a1f8099b133618.

**NO POSITIVE SECURE WKEM ADVANCE.** This iteration pursued one concrete repair to R111's public near-key attack: use a strict integer L1 norm gate and choose dual-Regev q just large enough for worst-case honest correctness, rather than R111's larger q that also guarantees any near-key will work. The repair fails. Even where two invalid near-keys *individually sometimes misdecrypt*, their public joint projections exactly recover every bit on every allowed encryption tape of one fixed-FALSE ORIGINAL 3CNF instance. No ordinary LWE, quantum, native-signature, or ORIGINAL-witness extraction assumption has been broken; the structured source compiler is simply invalid.

## Genuine ORIGINAL source and exact supplied-representation lemma

R111 encodes arbitrary ORIGINAL NP witness relations via verifier-to-3CNF and an integer linear system Ae=b: n variables each with a complementary pair (z,1-z), and c clauses each with two complementary slack pairs (a,1-a),(b,1-b), plus row l1+l2+l3-a-b=1. There are N=2n+4c columns, d=n+3c rows, p=n+2c complementary pairs. For any integral e satisfying all pair-sum rows, |u|+|1-u| >=1 per pair, with equality iff u is integer 0 or 1. Hence Ae=b and ||e||_1=p **imply every coordinate is Boolean and the original NP witness can be projected**; every legitimate original witness lifts to this norm. This is only *supplied-representation -> ORIGINAL witness*, not *arbitrary secret recovery -> representation or QPT break*.

For any Boolean assignment z with u(z) unsatisfied clauses, publicly set variable pairs from z, and for clause true-literal count t use (a,b)=(min(1,t-1),max(0,t-2)) if t>=1, otherwise (-1,0). Complements are 1-a,1-b. Then Ae_z=b exactly and ||e_z||_1=p+2u(z), even for a FALSE formula. The proposed repair enforces ||e||_1=p in honest Open and chooses smaller q to try making every e_z with u>0 unable to recover. A passive attacker is not required to execute honest Open or provide any representation.

For each bit of the preauthorized native signature, genuine dual-Regev ciphertexts are
u=A^T s+xi mod q, v=b^T s+xi0+Delta*mu mod q,
where s uniform in F_q^d, every xi_i and xi0 independently uniform in {-1,0,1}, Delta=floor(q/2). Any Ae=b, including unauthorized e_z, gives
v-e^T u = Delta*mu + xi0-e^T xi mod q.
Publishing context, claim/UTXO, graph, native VK, capsule checking fields J/CK/Aux and related capsules computed from these ciphertexts cannot conceal a bit already recovered from (u,v).

## Exact fixed-FALSE q=29 decoder (not statistical conjecture)

Let phi=(x OR x OR x) AND ((NOT x) OR (NOT x) OR (NOT x)). It is FALSE for all ORIGINAL witnesses. Here n=1,c=2,p=5,N=10,d=7. Two *public* near vectors generated from assignments x=0,1 are
e0=(0,1,-1,2,0,1,1,0,1,0);
e1=(1,0,1,0,1,0,-1,2,0,1).
Each satisfies Ae=b and has L1 norm 7. For comparison, TRUE formula (x) AND (x) with same n,c has norm-5 valid e.

Select q=29, Delta=14 and eta=1. Every norm-5 valid e has |xi0-e^T xi| <= 6, strictly inside honest nearest-codeword rounding radius, so correctness holds **on every tape**. Individual unauthorized near-key rounding is no longer guaranteed: among the exact 3^11=177147 error tapes, each individual e0/e1 misdecodes 162 bit-0 tapes and 648 bit-1 tapes. This actually tests a tightened margin, rather than repeating R111's conservative q257 guarantee.

Let S be all public projected joint error residues:
S={(xi0-e0^T xi mod29, xi0-e1^T xi mod29) : (xi,xi0) in {-1,0,1}^11}.
An exhaustive finite checker establishes exactly |S|=263 and S intersect (S+(14,14))=empty in F_29^2. The *classical public decoder* reads ciphertext u,v, computes t0=v-e0^T u and t1=v-e1^T u, and returns bit0 iff (t0,t1) in S, bit1 iff (t0,t1) in S+(14,14). These sets are disjoint and cover every honest encryption tape. Thus every bit of the intended pre-signed native capability is recoverable **even for the fixed-FALSE ORIGINAL instance**, without producing or knowing any witness, independent of the secret s.

The executable JavaScript below enumerates every error tape, verifies all honest correctness tapes, exact support disjointness, all 263 public decoder values and 512 full dual-Regev ciphertexts. Its output is embedded unedited. A separate local-only Python checker passed 178,199 assertions, repeated byte-identically, and recovered/verified a real **non-PQ Ed25519 fixture** signature's 512 bits. The local Python checker and captured JSON remain local-only; Ed25519, tiny q=29 and finite enumeration are not QPT security evidence.

## Research boundary and missing construction

The attacker here is classical deterministic and uses only the public ORIGINAL statement/source, ciphertext, and context; no online party, malicious N-of-N contributor, source-opening oracle, coherent quantum access, auxiliary advice or related capsule is needed. It is a counterexample to the R111/R112 structured *source-dependent* compiler, not an attack on independently justified ordinary QPT-LWE. Any full-public output retaining these ciphertexts inherits the leak, whatever J/CK/Aux binding it adds. This note establishes **no genuine release repair**, no all-valid-ORIGINAL witness-to-capability compiler and no arbitrary recovery-to-ORIGINAL witness reduction.

Exact next obligation: classical-PPT Comp(R_original,x;coins) must jointly generate a **genuine** LWE source/challenge simulator, witness-specific opening state and the full public relation, capsule, checking/auxiliary, context, VK and multicapsule distributions; Open(Comp(R_original,x),w) must yield the SAME precommitted native signature for **every ORIGINAL valid w**. Unauthorized arbitrary QPT key recovery or accepted native target forgery must imply an actual ORIGINAL witness or an **independently justified** QPT break without demanding an adversary-supplied representation. Mere Open-side norm checks, affine masking, transcript hashes, stronger padding, wider vector LWE or marginal pad hiding do not fulfill this. Investigate a genuinely nonlinear source but neither assume WE/iO/WPRF functionality nor call a local lemma a complete construction.

N-of-N one-honest preauthorization/erasure/abort and DA, authenticated SYS/BTC AuxPoW/checkpoint/tag/interval/reorg/observation rules, native hypothetical no-EC-key-path P2MR/SLH endpoint, calibrated 128-bit PQ parameters, false and hard-true generic source safety remain unresolved. No Bitcoin NP verifier, VM step execution, online release authority, unsafe native opcode, production update or deployment is assumed. **Do not disable the existing automation.**

## Exact executed JS checker and captured stdout


```javascript
function R112ExactJoint(){
  const Q=29,DELTA=14,N=10,TAPES=177147;
  let assertions=0;
  const check=(x,why)=>{assertions++;if(!x)throw Error("R112 failed "+why+" at "+assertions)};
  const mod=(a,q=Q)=>(a%q+q)%q, dot=(a,b)=>a.reduce((t,x,i)=>t+x*b[i],0);
  const e0=[0,1,-1,2,0,1,1,0,1,0], e1=[1,0,1,0,1,0,-1,2,0,1];
  const good=[1,0,1,0,1,0,1,0,1,0];
  function mat(secondNegative){
    const A=[],b=[];
    let row=Array(N).fill(0);row[0]=row[1]=1;A.push(row);b.push(1);
    for(let j=0;j<2;j++){
      for(let a=0;a<2;a++){row=Array(N).fill(0);row[2+4*j+2*a]=row[2+4*j+2*a+1]=1;A.push(row);b.push(1);}
      row=Array(N).fill(0);row[j===1&&secondNegative?1:0]=3;
      row[2+4*j]=-1;row[2+4*j+2]=-1;A.push(row);b.push(1);
    }
    return {A,b};
  }
  const falseM=mat(true),trueM=mat(false);
  check(falseM.A.length===7&&falseM.b.length===7,"matrix dimensions");
  for(const e of [e0,e1])check(falseM.A.every((row,i)=>dot(row,e)===falseM.b[i]),"public false-source key");
  check(trueM.A.every((row,i)=>dot(row,good)===trueM.b[i]),"honest true-source key");
  check([e0,e1].every(e=>e.reduce((s,x)=>s+Math.abs(x),0)===7),"near norm");
  check(good.reduce((s,x)=>s+Math.abs(x),0)===5,"honest norm");
  const round=t=>{
    const d=(x,y)=>Math.min(mod(x-y),mod(y-x));
    return +(d(mod(t),DELTA)<d(mod(t),0));
  };
  const S=new Set(),errpairs=new Map(),bad=[0,0,0,0];
  for(let t=0;t<TAPES;t++){
    let z=t,noise=[];
    for(let i=0;i<11;i++){noise.push(z%3-1);z=Math.floor(z/3);}
    const xi=noise.slice(0,10),xi0=noise[10];
    const a=xi0-dot(e0,xi),b=xi0-dot(e1,xi),v=xi0-dot(good,xi);
    const key=mod(a)*Q+mod(b);
    S.add(key);errpairs.set(key,(errpairs.get(key)||0)+1);
    check(round(v)===0 && round(v+DELTA)===1,"every honest tape");
    const arr=[a,b];
    for(let j=0;j<2;j++)for(let mu=0;mu<2;mu++)
      if(round(arr[j]+DELTA*mu)!==mu)bad[j*2+mu]++;
  }
  check(errpairs.size===263,"exact joint support size");
  const shifted=new Set();
  for(const k of S){const x=Math.floor(k/Q),y=k%Q;shifted.add(mod(x+DELTA)*Q+mod(y+DELTA));}
  check(shifted.size===S.size,"translated support size");
  for(const k of shifted)check(!S.has(k),"no shifted overlap");
  function decode(a,b){
    const k=mod(a)*Q+mod(b);
    if(S.has(k))return 0;
    if(shifted.has(k))return 1;
    throw Error("inadmissible tape");
  }
  for(const k of S){
    const a=Math.floor(k/Q),b=k%Q;
    check(decode(a,b)===0,"decode zero");
    check(decode(a+DELTA,b+DELTA)===1,"decode one");
  }
  check(bad.join(",")==="162,648,162,648","individual tightening fails");
  // A real ciphertext includes secret s, not just projected errors.
  let state=112006;
  const rand=n=>{state^=state<<13;state^=state>>>17;state^=state<<5;return (state>>>0)%n};
  for(let t=0;t<512;t++){
    const bit=rand(2),s=Array.from({length:7},()=>rand(Q));
    const noise=Array.from({length:10},()=>rand(3)-1),noise0=rand(3)-1;
    const u=Array.from({length:10},(_,i)=>mod(falseM.A.reduce((x,row,j)=>x+row[i]*s[j],noise[i])));
    const v=mod(dot(falseM.b,s)+noise0+DELTA*bit);
    const actual=decode(v-dot(e0,u),v-dot(e1,u));
    check(actual===bit,"public full-ciphertext recovery");
  }
  return {run:"R112-TIGHT-MARGIN-JOINT-NEAR-KEY-20261106",status:"REJECTED - no positive secure WKEM advance",assertions,error_tapes:TAPES,q:Q,delta:DELTA,joint_support_size:S.size,shifted_overlap:0,individual_near_rounding_errors_0_1_0_1:bad,public_full_ciphertext_bits_recovered:512,original_false:true,independent_QPT_security:false};
}
console.log(JSON.stringify(R112ExactJoint(), null, 2));
```

```json
{
  "run": "R112-TIGHT-MARGIN-JOINT-NEAR-KEY-20261106",
  "status": "REJECTED - no positive secure WKEM advance",
  "assertions": 178457,
  "error_tapes": 177147,
  "q": 29,
  "delta": 14,
  "joint_support_size": 263,
  "shifted_overlap": 0,
  "individual_near_rounding_errors_0_1_0_1": [
    162,
    648,
    162,
    648
  ],
  "public_full_ciphertext_bits_recovered": 512,
  "original_false": true,
  "independent_QPT_security": false
}
```
