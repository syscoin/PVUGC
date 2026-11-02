# MINK-BOOLEAN-QUOTIENT-SOURCE — R21 (2026-11-02)

**Research only; NOT a secure generic PQ WKEM.** Exact predecessor: R19 Boolean-ideal source, R20 certified-FALSE joint-public simulator. This is an actually instantiated square-free release and a stronger degree-one FALSE certificate (R19 needed degree two for the same parity-cycle FALSE source); it does **not** close the unauthorized hard-TRUE recovery-to-ORIGINAL-witness reduction.

## Exact prior and provenance
Verified starting PR head: deb501de17a5d4fc7d1a7597cd493152fb2b210b; syscoin/PVUGC PR #1 open, draft, unmerged, branch research/pq-wkem-validation-20260918. R19 research Git blob c5288b50604f735f940429b0cfd6df8346e87b6b; R20 blob c268d165df30a2cf5fb7ff494ffa855981a2ebc3; latest substantive ordinary comment 6585411049. Only authorized GitHub continuity reads; no web/external literature research.

## Concrete source and correctness
Canonical x includes ORIGINAL NP relation/verifier identity, claim/UTXO, branch, anchors/window, intended verification key/capability, and challenge context. A standard witness-preserving NP-to-3CNF compiler gives phi on n Boolean variables and c clauses. Work in finite Boolean algebra A_n=F_q[z_1,...,z_n]/(z_i^2-z_i). Its square-free basis z_S uses subsets S, with product z_S*z_T=z_(S union T). For each clause j, g_j is the product of literal-failure factors, so g_j(w)=1 exactly if Boolean w violates clause j. Fix integer d>=0. Let D=min(n,d+3); rows are S subsets with |S|<=D; columns are the coefficient vectors of g_j*z_T, reduced in A_n, for each clause j and T subset with |T|<=d. Matrix B has M=sum_{k<=D} binom(n,k) rows and L=c*sum_{k<=min(n,d)} binom(n,k) columns. Booleanity columns are unnecessary because z_i^2=z_i is enforced algebraically, not assumed.

Classical Build generates native signing tape K and its genuine correlated vk (conditional on a separately QPT-EUF-CMA-secure native scheme). For each bit mu and independently randomized capsule, sample r uniformly in F_q^L and e independently with entries bounded by eta; publish C=B*r+Delta*mu*e0+e modulo q and manifest bound to x/vk/claim/branch/anchors/related capsules. Builder needs no ORIGINAL witness but knows K, which requires erasure/protection in the separate ceremony model; keyless Build NOT claimed. Given any valid ORIGINAL witness w and its Boolean extension a, Lift evaluates lambda_a[S]=prod_{i in S}a_i and computes lambda_a^T*C. Since lambda_a^T B=0 and lambda_a^T e0=1 for **EVERY** valid original witness, output is Delta*mu+lambda_a^T e; all witnesses obtain the SAME precommitted K, without identical intermediate states. Worst-case centered error <=M*eta, so deterministic circular decoding works if M*eta<min(Delta,q-Delta)/2. Check vk and sign ONLY the intended native challenge path off chain. Build/Lift are classical PPT for fixed d; not for d growing with n.

## Stronger certificate theorem (unconditional)
If an R19 degree-d refutation was 1=sum_j Q_j*g_j+sum_i T_i*(z_i^2-z_i), reduce it modulo the Boolean ideal. Every Booleanity term vanishes and Q(Q_j) has square-free degree <=d. Hence the new B has an exactly checkable t satisfying B*t=e0. **Every R19 publicly certified FALSE source remains certified at the same degree; the guaranteed restricted perfect hiding class cannot shrink.**

For such a certificate, the R20 challenger uses genuine correlated vk and the same explicit public-only checking-key/context/auxiliary generator G (plus allowed classical signing-oracle access). It samples C0=B*r0+e without knowing K. The bijective mask shift r0=r+Delta*mu*t proves the entire restricted public view (R,x,C,vk,checking key,context,public G auxiliary,related independently randomized capsules) is exactly identical to honest Build, even under coherent QPT post-processing. This covers classical adaptive fresh unopened capsule/signature queries and advice independent of protected private tape beyond that permitted public/oracle interface. Target same-key openings, secret-correlated auxiliary, coherent opening-oracle queries and the real malicious graph-proof checking keys are NOT simulated. Any fresh signature or usable signing key against protected certified FALSE scope gives a straight-line native QPT-EUF-CMA forgery (up to S target-scope guessing loss), conditional on actual native signature security.

**New concrete FALSE improvement:** for the six-clause 3-variable parity-cycle FALSE from R19, at degree **d=1** the square-free quotient has exact identity
1=(1-2*z2)*(g0-g1)+g2+g3+g4+g5.
Its eight nonzero certificate coefficients were explicitly verified over F_65537. R19 required d=2 and 56 rows / 90 mask columns to certify this same FALSE; R21 uses d=1 with **8 rows / 24 columns**. This is exact stronger certified-FALSE coverage at lower cost, not a generic FALSE result.

## Universal FALSE refutation at EXPONENTIAL cost
For any unsatisfiable Boolean CNF, assignment indicators delta_a=product_i(z_i if a_i=1 else 1-z_i) sum to 1. Choose for each a a clause j(a) it violates. If the clause has k_j distinct literal-failure conditions, delta_a=g_(j(a))*product_{i outside clause}(z_i if a_i=1 else 1-z_i). Partition and group by j: a **constructive unit refutation** has multiplier degree <=max_j(n-k_j). For proper clauses of 3 distinct variables, d<=n-3. But M=2^n and L approaches c*2^n: this proves all-FALSE confidentiality only with exponential public material and algorithmic work, NOT a practical classical-PPT generic NP compiler. Verified 33 explicit partition certificates offline (30 synthetic complete FALSE covers for n=3,4,5).

## Efficiency (number of rows is the ciphertext-field-symbol count PER key bit PER capsule)
R19 to R21:
- n=4,c=9,d=1: rows 70->16, columns 65->45 (4.375x capsule shrink).
- n=3,c=6,d=2: rows 56->8, columns 90->42 (7.0x).
- n=12,c=50,d=2: rows 6188->1586, columns 5642->3950 (3.902x).
- n=12,c=50,d=3: rows 18564->2510, columns 28210->14950 (7.396x).
At illustrative q=65537 (17 bits per coefficient), 256 capability bits, n=4,c=9,d=1, the field-packed capsule falls from 38,080 to 8,704 bytes, excluding public matrix, vk/signature, framing and manifests. Parameters are not 128-bit QPT certified.

## Material remaining risks and exact next equation
The q=65537, Delta=32768, eta=1 toy setup checks algebra only. R19's FALSE nine-clause source at d=0 is **still classically broken** after quotient reduction: public functional [constant]-[z0*z2] has l1 norm two, annihilates B and recovers 1024/1024 encrypted FALSE bits in extended Python tests. Thus adversarial universal FALSE security is false for that instance. Hard TRUE is not protected by a known QPT theorem either: B is source-structured, not an independently random ordinary LWE matrix; public elimination finds some y with y^T B=0,y^T e0=1 for TRUE, and only its potential large noise amplification prevents immediate decoding. Any proof from unauthorized key recovery or native forgery must handle arbitrary algorithms not volunteering y and yield an actual ORIGINAL witness or independent QPT break. This is **unproved**.

No unknown-one-honest N-of-N malicious ceremony/abort, keyless Build, secret-correlated checking keys/auxiliary, same-scope selective opening, genuine native PQ signature implementation, concrete QPT parameters, or Bitcoin endpoint is established. Next obligation is classical-PPT generic-NP Build/Lift together with a source-dependent QPT simulator of the FULL joint public output secure for every adversarial FALSE x, and a hard-TRUE arbitrary recovered-key/native-forgery reduction to ORIGINAL witness or independent post-quantum break. The current restricted result does not satisfy that.

## Exact actually executed Node checker and captured output
This checker was executed twice, byte-identical, 444 assertions each. A separately executed offline standard-library Python checker ran 10,680 assertions twice with identical output, including 1024 FALSE decodings, 33 unit certificates and full-capsule couplings. Neither implements actual PQ signing or tests QPT hardness. The complete extended research, standalone Python checker, captured outputs and SHA-256 provenance are preserved in the local offline archive. Node checker SHA-256: 4fa8c6d6f98e7d4958ab43056bfc496da92cff12684fa43530af03df16c73379. Exact captured Node JSON SHA-256: 64b39457d71b89998c34a3ac02e4a721eb03a8d3a267f732693d41824fe28069.

~~~javascript
'use strict';
function checkR21(){
 const q=65537,Delta=32768;let count=0,seed=2026110221;
 const ok=(v,m)=>{count++;if(!v)throw Error(m)};
 const mod=x=>((x%q)+q)%q;
 const rnd=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed};
 const mons=(n,d)=>Array.from({length:1<<n},(_,i)=>i).filter(x=>pop(x)<=d).sort((a,b)=>pop(a)-pop(b)||a-b);
 function pop(x){let c=0;while(x){c+=x&1;x>>>=1}return c}
 function mul(a,b){let c=new Map();for(const [u,x] of a)for(const [v,y] of b)c.set(u|v,mod((c.get(u|v)||0)+x*y));return c}
 function source(n,clauses,d){
   const basis=mons(n,d+3),shifts=mons(n,d),cols=[];
   const ix=new Map(basis.map((s,i)=>[s,i]));
   for(const clause of clauses){let g=new Map([[0,1]]);
     for(const [i,pos] of clause)g=mul(g,pos?new Map([[0,1],[1<<i,q-1]]):new Map([[1<<i,1]]));
     for(const t of shifts){let v=Array(basis.length).fill(0);
       for(const [a,b] of g)v[ix.get(a|t)]=mod(v[ix.get(a|t)]+b);
       cols.push(v)}
   }
   return {n,clauses,d,basis,shifts,cols};
 }
 function product(s,r){let v=Array(s.basis.length).fill(0);s.cols.forEach((c,j)=>c.forEach((x,i)=>v[i]=mod(v[i]+r[j]*x)));return v}
 function assignments(n){return Array.from({length:1<<n},(_,a)=>a)}
 function sat(clauses,a){return clauses.every(cl=>cl.some(([i,p])=>Boolean((a>>i)&1)===p))}
 function certByPartition(s){let t=Array(s.cols.length).fill(0);
   for(const a of assignments(s.n)){
     const j=s.clauses.findIndex(c=>!c.some(([i,p])=>Boolean((a>>i)&1)===p));ok(j>=0,'FALSE instance');
     const fixed=new Set(s.clauses[j].map(([i])=>i));let p=new Map([[0,1]]);
     for(let i=0;i<s.n;i++)if(!fixed.has(i))p=mul(p,(a>>i)&1?new Map([[1<<i,1]]):new Map([[0,1],[1<<i,q-1]]));
     for(const [m,c] of p){let k=s.shifts.indexOf(m);ok(k>=0,'degree bound');t[j*s.shifts.length+k]=mod(t[j*s.shifts.length+k]+c)}
   }
   ok(product(s,t).every((a,i)=>a===(i===0?1:0)),'whole coefficient refutation');return t;
 }
 const parity=[[[0,false],[1,true],[1,true]],[[0,true],[1,false],[1,false]],[[1,false],[2,true],[2,true]],[[1,true],[2,false],[2,false]],[[0,true],[2,true],[2,true]],[[0,false],[2,false],[2,false]]];
 const P=source(3,parity,1),pt=certByPartition(P);
 ok(P.basis.length===8&&P.cols.length===24,'parity smaller source');
 const explicit=Array(P.cols.length).fill(0),s=P.shifts.length;
 for(const [j,t,c] of [[0,0,1],[0,4,-2],[1,0,-1],[1,4,2],[2,0,1],[3,0,1],[4,0,1],[5,0,1]])explicit[j*s+P.shifts.indexOf(t)]=mod(c);
 ok(product(P,explicit).every((v,i)=>v===(i===0?1:0)),'explicit eight-term parity identity');
 for(let capsule=0;capsule<3;capsule++)for(let bit=0;bit<32;bit++){
   let mu=rnd()&1,r=P.cols.map(()=>rnd()%q),e=P.basis.map(()=>rnd()%3-1);
   let C=product(P,r).map((v,i)=>mod(v+e[i]+(i===0?Delta*mu:0)));
   let r0=r.map((x,j)=>mod(x+Delta*mu*pt[j]));
   ok(C.every((v,i)=>v===mod(product(P,r0)[i]+e[i])),'joint exact shift of masks');
 }
 const T=source(3,[[[0,true],[1,true],[2,true]],[[0,false],[1,true],[2,true]],[[0,true],[1,false],[2,true]]],1);
 const good=assignments(3).filter(a=>sat(T.clauses,a));ok(good.length===5,'distinct valid ORIGINAL witnesses');
 for(let mu=0;mu<=1;mu++)for(let rep=0;rep<32;rep++){
   let r=T.cols.map(()=>rnd()%q),e=T.basis.map(()=>rnd()%3-1),C=product(T,r).map((x,i)=>mod(x+e[i]+(i===0?Delta*mu:0)));
   for(const a of good){let l=T.basis.map(m=>((m&a)===m)?1:0);
     const v=mod(l.reduce((z,b,i)=>z+b*C[i],0)),noise=l.reduce((z,b,i)=>z+b*e[i],0);
     ok(mod(v-Delta*mu-noise)===0&&Math.abs(noise)<=T.basis.length,'all ORIGINAL witnesses decode same precommitted bit')}
 }
 const ratios=[];
 function choose(n,k){let x=1;for(let i=1;i<=k;i++)x=x*(n-i+1)/i;return Math.round(x)}
 for(const [n,c,d] of [[4,9,1],[3,6,2],[12,50,2],[12,50,3]]){
   const oldM=choose(n+d+3,d+3),newM=Array.from({length:Math.min(n,d+3)+1},(_,i)=>choose(n,i)).reduce((a,b)=>a+b,0);
   const oldL=(c+n)*choose(n+d,d),newL=c*Array.from({length:Math.min(n,d)+1},(_,i)=>choose(n,i)).reduce((a,b)=>a+b,0);
   ok(newM<=oldM&&newL<=oldL,'honest resource shrink');ratios.push([n,c,d,oldM,newM,oldL,newL]);
 }
 return {run:'MINK-BOOLEAN-QUOTIENT-SOURCE-R21',passed:true,assertions:count,parity_degree_1:true,parity_rows:8,parity_columns:24,partition_nonzero:pt.filter(x=>x).length,related_capsules:3,valid_original_witnesses:5,resources:ratios,limitations:'No universal FALSE or hard-TRUE/QPT security theorem'};
}
console.log(JSON.stringify(checkR21(),null,2));

~~~

~~~json
{
  "run": "MINK-BOOLEAN-QUOTIENT-SOURCE-R21",
  "passed": true,
  "assertions": 444,
  "parity_degree_1": true,
  "parity_rows": 8,
  "parity_columns": 24,
  "partition_nonzero": 8,
  "related_capsules": 3,
  "valid_original_witnesses": 5,
  "resources": [
    [
      4,
      9,
      1,
      70,
      16,
      65,
      45
    ],
    [
      3,
      6,
      2,
      56,
      8,
      90,
      42
    ],
    [
      12,
      50,
      2,
      6188,
      1586,
      5642,
      3950
    ],
    [
      12,
      50,
      3,
      18564,
      2510,
      28210,
      14950
    ]
  ],
  "limitations": "No universal FALSE or hard-TRUE/QPT security theorem"
}
~~~
