# R137 — Complement-pair ORIGINAL-3CNF compiler and dual-LWE native-bit release (REJECTED)

**Result:** No positive secure generic witness-KEM advance. One bounded offline ORIGINAL-dependent candidate and a repaired representation-soundness lemma, followed by an explicit FALSE-instance unauthorized recovery counterexample. No external literature, web search, optimization, independent agent, native-signature implementation, or deployment.

## Explicit ORIGINAL-dependent Build and source/opening data

For an arbitrary ORIGINAL 3CNF statement x with n Boolean variables and m 3-literal clauses, define B=n+2m integer bit positions: one position for each input variable and two slack positions p_j,q_j per clause. For every position i introduce an **integer complement pair** (z_{i,0},z_{i,1}) satisfying z_{i,0}+z_{i,1}=1. For every clause j require sum of its three literal values (positive literal z_{i,0}, negative z_{i,1}) minus p_j minus q_j equals 1. Collect these public linear equations H_x z=b_x in Z^(B+m) with 2B integer unknowns.

Define *qualified supplied representation* as H_x z=b_x over the integers and ||z||_1<=B. Exact proof: for any integer a, |a|+|1-a|=1 iff a is 0 or 1, otherwise at least 3. All complement pair contributions are at least 1; hence ||z||_1<=B makes every pair Boolean. The clause equations then force at least one true literal. Conversely, any satisfying ORIGINAL witness w defines all input bits, and clause slack p_j+q_j=(number of satisfied literals)-1 in {0,1,2}, producing an exact qualified representation with ||z||_1=B. Distinct witnesses have distinct z and satisfy the same representation predicate. FALSE instances have no qualified representation. This is a classical-PPT representation lemma, NOT an arbitrary key-recovery theorem; it is not new generic cryptographic soundness.

Attempted *actual release* uses a dual-LWE-style phase: publish A=H_x mod q, u=b_x mod q, sample s uniformly in Z_q^(B+m), e uniformly in {-1,0,1}^(2B), e0 uniformly in {-1,0,1), precommit capability bit K, and publish c=A^T s+e and c0=u^T s+DELTA*K+e0 mod q. A public full-view includes x, relation identity, claim/UTXO, graph/branch, anchors, context, native verification key, checking-key hashes of actual displayed bytes, all auxiliary fields and related capsules. The off-chain Open(x,w) converts a valid ORIGINAL witness into its qualified z, then decodes c0-z^T c, which equals DELTA*K+e0-z^T e mod q. ALL valid ORIGINAL witnesses get the SAME K when the noise margin holds. No SourceOpen oracle is assumed.

## Rejection: the correct representation bound is not cryptographically enforced

Consider x=(v OR v OR v) AND (NOT v OR NOT v OR NOT v), an unconditionally FALSE ORIGINAL 3CNF. Here B=5. The **publicly computable invalid representation** (v,p1,q1,p2,q2)=(0,-1,0,1,1), expanded into complement pairs, is z*=(0,1,-1,2,0,1,1,0,1,0). It satisfies H_x z*=b_x exactly, but has ||z*||_1=7 rather than <=5, and does not describe a valid ORIGINAL witness. The formal supplied-representation checker rejects it correctly.

Nevertheless **the LWE phase accepts the same invalid z***. For q=257 and DELTA=128, every specified noise tape satisfies |e0-z*^T e|<=8. The adversary calculates the public phase c0-z*^T c without volunteering z* to an authority or running the checker. This recovers K with probability one, even when x is FALSE. Public invertible row mixing does not help: replacing (A,u) by (UA,Uu) preserves Az*=u and the phase identity. Recomputing CK/Aux from real ciphertexts and adding sibling capsules does not help. This is a direct classical PPT full-public attack on the stated candidate, not an attack on ordinary uniform-matrix QPT-LWE; A is statement dependent and no challenge simulator for its distribution has been established.

Thus complement-pair integer encoding really repairs **representation -> ORIGINAL soundness** at exact l1 bound, but ordinary dual-LWE plaintext extraction ignores that bound and is unsafe. Neither representation soundness nor a correctness proof is evidence of arbitrary recovery -> ORIGINAL extraction. This is consistent with prior R121/R122A longer-preimage barriers, not a claimed breakthrough.

## Precise QPT and distribution limitations

Honest proposed algorithms are classical polynomial time; a simple classical recovery adversary qualifies as QPT, including against coherent attackers. q=257, bounded noise and the binary capability are counterexample parameters, NOT a 128-bit security claim. No quantum hardness is assumed for A=H_x, and this note cannot claim an ordinary QPT-LWE hybrid. Signature-bit K is a small model for the precommitted native signature release; actual native QPT-EUF-CMA and malicious N-of-N graph/abort security remain independent unproved requirements. Multi-capsule and selective opening only enlarge the public view and do not repair the target FALSE bypass. The exact leakage occurs before any public native verification key is used.

The next actual task is not a new bound check: instantiate a polynomial-time ORIGINAL-dependent **cryptographically enforced** source release plus an LWE challenge simulator for its jointly correlated public A,u,c,c0,J,CK,Aux,VK,context and sibling capsules, and prove arbitrary QPT key recovery/native forgery -> ORIGINAL witness or an independent QPT break WITHOUT asking for the internal short vector. This candidate is rejected; no efficiency work is justified.

## Exact executed JavaScript checker

```javascript
function runR137(){
 const Q=257,DELTA=128; let seed=1371107>>>0,checks=0,tries=0,unauthorized=0;
 const rand=(n)=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n;};
 const ck=(p,msg)=>{checks++;if(!p)throw Error("R137 "+checks+": "+msg);};
 function construct(clauses){
   const B=1+2*clauses.length,dim=2*B,H=[],b=[];
   for(let i=0;i<B;i++){const r=Array(dim).fill(0);r[2*i]=r[2*i+1]=1;H.push(r);b.push(1);}
   for(let j=0;j<clauses.length;j++){
     const r=Array(dim).fill(0);
     for(const lit of clauses[j])r[lit===1?1:0]++;
     r[2*(1+2*j)]--;r[2*(2+2*j)]--;
     H.push(r);b.push(1);
   }
   return {H,b,B,dim};
 }
 const dot=(a,b)=>a.reduce((v,z,i)=>v+z*b[i],0);
 const apply=(H,z)=>H.map(row=>dot(row,z));
 const pair=(bits)=>bits.flatMap(x=>[x,1-x]);
 const t=construct([[0,0,0]]);
 const f=construct([[0,0,0],[1,1,1]]);
 const zt=pair([1,1,1]),zf=pair([0,-1,0,1,1]);
 ck(dot(zt,zt)===3 && zt.reduce((v,z)=>v+Math.abs(z),0)===3,"true short");
 ck(zf.reduce((v,z)=>v+Math.abs(z),0)===7 && f.B===5,"false longer");
 ck(JSON.stringify(apply(t.H,zt))===JSON.stringify(t.b),"true syndrome");
 ck(JSON.stringify(apply(f.H,zf))===JSON.stringify(f.b),"false invalid syndrome");
 for(let a=-50;a<=50;a++){let n=Math.abs(a)+Math.abs(1-a);ck(n>=1&&(n===1)===(a===0||a===1),"pair gap");}
 for(let bits=0;bits<32;bits++){
   let z=pair(Array.from({length:5},(_,i)=>(bits>>>i)&1));
   ck(JSON.stringify(apply(f.H,z))!==JSON.stringify(f.b),"no false Boolean certificate");
 }
 const center=x=>{let v=((x%Q)+Q)%Q;return v<=Q/2?v:v-Q;};
 function decode(src,z,K){
   let s=src.H.map(()=>rand(Q)), e=z.map(()=>rand(3)-1), e0=rand(3)-1;
   const c=z.map((_,j)=>(src.H.reduce((v,r,i)=>v+r[j]*s[i],0)+e[j])%Q);
   const c0=(dot(src.b,s)+DELTA*K+e0)%Q;
   const phase=((c0-dot(z,c))%Q+Q)%Q;
   const noise=center(phase-DELTA*K);
   const dk=Math.abs(center(phase))<=Math.abs(center(phase-DELTA))?0:1;
   ck(Math.abs(noise)<=1+z.reduce((v,w)=>v+Math.abs(w),0),"residual");
   ck(dk===K,"bit recovered");
   return dk;
 }
 for(let i=0;i<512;i++){
   let k=rand(2);ck(decode(f,zf,k)===k,"unauthorized false");unauthorized++;
   ck(decode(t,zt,k)===k,"authorized true");tries++;
 }
 for(let j=0;j<4;j++)for(let k=0;k<2;k++)ck(decode(f,zf,k)===k,"sibling capsule");
 return {run:"R137-DUAL-LWE-COMPLEMENT-PAIR",status:"REJECTED",q:Q,assertions:checks,correct_true_trials:tries,unauthorized_false_decodes:unauthorized,short_bound_false:f.B,false_invalid_l1:7,related_capsules:4};
}
console.log(JSON.stringify(runR137(),null,2));
```

Captured output from one actual execution of runR137 (above); the code is deterministic:

```json
{
  "run": "R137-DUAL-LWE-COMPLEMENT-PAIR",
  "status": "REJECTED",
  "q": 257,
  "assertions": 3233,
  "correct_true_trials": 512,
  "unauthorized_false_decodes": 512,
  "short_bound_false": 5,
  "false_invalid_l1": 7,
  "related_capsules": 4
}
```

A separate **LOCAL-ONLY** stdlib Python checker ran twice with identical captured JSON: 2,208 assertions, 512 FALSE recoveries, four sibling capsules. Local source SHA-256: `1f63b1222f5fda5a603401debf318453f303c9b671fa12241ac8c0e3ccea21f5`; local captured JSON SHA-256: `12ada9b87adefde2d48b0bc2727bebcd1078114c399f8a7487e6b4c431022b4c`. The Python code is not claimed to be GitHub-published.