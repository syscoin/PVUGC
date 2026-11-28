# R111 — A genuine ORIGINAL 3CNF → dual-Regev source, but a universal FALSE-instance near-key (REJECTED)

**Research run:** R111-DUAL-REGEV-3CNF-PUBLIC-SOURCE-20261106. Previous exact R110 starting head `5ad30c84e283707f38a9942a79ff67e44be463ec`, branch `research/pq-wkem-validation-20260918`; its substantive note is blob `938c767403b2c0f7d4852853ec6618178a7db73f`. This one-candidate offline research execution establishes **NO positive secure witness-KEM advance**; do not merge this prototype into the restricted R110 path or promote it as quantum secure.

## An explicitly instantiated (but broken) source-dependent release

Given arbitrary ORIGINAL NP predicate R(x,w), convert its verifier to 3CNF phi_x with n binary witness-and-circuit variables and c clauses, preserving the property that every original valid w extends to satisfying z and every satisfying z projects to an ORIGINAL w. Build a public integer matrix A of d=n+3c rows and N=2n+4c columns and target b. Encode each Boolean variable using a pair (z_i,zbar_i) with row z_i+zbar_i=1. Introduce two slack-bit pairs (a_j,abar_j),(b_j,bbar_j) per clause, with pair rows equal to 1, and the clause row l1+l2+l3−a_j−b_j=1 for its three actual signed literal coordinates. Reduce mod q (choose q large enough that bounded-coordinate equations cannot accidentally wrap).

Every satisfying original witness w lifts to z and a `{0,1}^N` vector e_z: each clause with t_j∈{1,2,3} true literals has a_j=min(1,t_j−1), b_j=t_j−1−a_j and their complements. Therefore A e_z=b *exactly* and ||e_z||_1=n+2c. Conversely, any supplied e∈{−1,0,1}^N solving these exact equations must consist of (0,1)/(1,0) pairs and projects to a genuine ORIGINAL witness. This is an exact **supplied-short-representation → ORIGINAL witness** lemma. It is not a proof for an arbitrary adversary who outputs a final capability without revealing e.

Attempt to release a frozen preauthorized native signature σ on an unambiguously bound challenge message (relation identity, claim/UTXO, branch, anchors/window, graph, intended VK) via dual-Regev. For each of its bits μ choose s←Uniform(F_q^d), noise ξ←Uniform({−η,...,η}^N), ξ0 similarly; publish u=Aᵀs+ξ, v=bᵀs+ξ0+Δμ (mod q), Δ near q/2. An honest witness uses e_z to obtain v−e_zᵀu=Δμ+ξ0−e_zᵀξ, rounded to μ. If η(N+1)<q/4, **every valid ORIGINAL witness recovers the SAME precommitted native signature on every encryption tape**. The exact public relation/statement, source matrix, capsules, contexts, native VK, acyclic manifest J, CK/Aux and related capsules can all be computed from ciphertext bytes; no SourceOpen oracle is assumed. Native signature setup/erasure and N-of-N funding safety remain separately conditional.

## Classical public break of every FALSE instance

For ANY arbitrary assignment z, even an invalid one, set variable pairs to (z_i,1−z_i). For clause true-literal count t_j∈{0,1,2,3}, set the *non-Boolean* slack pairs to (a_j,abar_j)=(t_j−1,2−t_j) and (b_j,bbar_j)=(0,1). This public deterministic e* satisfies **A e*=b exactly regardless of phi_x satisfiability**. Its coordinates belong to {−1,0,1,2} and ||e*||_1≤n+4c≤N. Hence, under the same conservative correctness parameter η(N+1)<q/4, any adversary computes e* from public x and decrypts ALL ciphertext bits with zero error on every encryption tape, including a **fixed-FALSE** relation with no original witness at all. Even an actual native signature recovered in this way verifies under the intended native VK/path; public hashes, CK/Aux and post-recovery honest representation checks cannot undo its disclosure. This is a deterministic **classical PPT break**, so it also breaks arbitrary-QPT security. It never asks the adversary to volunteer e*, nor does it violate an ordinary native EUF-CMA assumption.

For any invertible U, the public row-mixed source A'=UA,b'=Ub has A'e*=b'. Therefore row/basis randomization cannot repair this attack. Tighter noise margins, ciphertext padding, more LWE columns, a scalar-key LWE wrapper, conventional MACs or malicious-source audits are NOT proved remedies. The structured (A(x),b(x)) is not the uniform public matrix/source law from ordinary decisional QPT-LWE; the required *joint* challenge simulator for relation/source, CK/Aux, context and related capsules has not been constructed. Thus a marginal LWE-hiding hybrid or the supplied-representation lemma provides neither fixed-FALSE nor arbitrary hard-TRUE key security.

## Exactly executed finite evidence

The embedded JavaScript is its **exact executed checker source**, with verbatim captured output. It builds three explicit ORIGINAL 3CNF instances: a FALSE two-clause contradiction, a TRUE one-witness instance and a TRUE two-distinct-witness instance; enumerates assignments and verifies the exact integer matrix equations, checks every binary satisfying representation, runs direct toy q=257 dual-Regev bit encryptions/decryptions before/after nontrivial invertible row transformations, and confirms both valid-witness SAME-capability reconstruction and public invalid near-key bypass, including FALSE. No cryptographic hardness is inferred. A separate **local-only** Python checker also executed and reproduced byte-identically with 65 assertions and actual Ed25519 (NON-PQ) signatures: its source, captured output, complete derivation and SHA-256 provenance are provided in the separate downloadable local R111 archive and were not uploaded here.

## Preserved obligation

**No positive advance** under the project's stated standard. Do not treat this prototype as a successor to R110. Next candidate must instantiate the ORIGINAL-dependent source, its genuine ordinary-QPT-LWE challenge simulator and **all** public checking/auxiliary correlations together, and prove that arbitrary unauthorized hard-TRUE final-key recovery / accepted native forgery yields an actual ORIGINAL witness OR an independently justified QPT break. Merely rejecting e* in honest Open is insufficient: attacker privately decrypts. Keep R89 near-keys, local switching, Boolean quotient off-domain, public hash collapse, arbitrary chosen-malicious keys, correlated multiple capsules/selective openings and N-of-N one-honest secrecy/abort/data availability as tests. Generic false-instance security, honest classical PPT setup with malicious graph composition, real PQ parameters, SYS/BTC authenticated fork/tag/interval evidence and the conditional no-EC-key-path PQ native endpoint remain unproved. Do not disable the research automation.

### Executed JavaScript checker (copy and run in a JS runtime)

```javascript
const R111ExactChecker = function R111ExactChecker(){
 const Q=257,D=128;let nassert=0,validOpen=0,falseOpen=0;
 const ok=x=>{nassert++;if(!x)throw Error("assert "+nassert);};
 const mod=x=>(x%Q+Q)%Q;
 let seed=177;const rnd=n=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return(seed>>>0)%n;};
 const lit=(z,[i,p])=>p?z[i]:1-z[i];
 function mat(n,clauses){
  let d=n+3*clauses.length,m=2*n+4*clauses.length,A=Array.from({length:d},()=>Array(m).fill(0)),b=Array(d).fill(0);
  for(let i=0;i<n;i++){A[i][2*i]=A[i][2*i+1]=1;b[i]=1;}
  clauses.forEach((cl,j)=>{let a=2*n+4*j,k=n+3*j;A[k][a]=A[k][a+1]=1;A[k+1][a+2]=A[k+1][a+3]=1;b[k]=b[k+1]=b[k+2]=1;for(const [i,p] of cl)A[k+2][2*i+(p?0:1)]++;A[k+2][a]--;A[k+2][a+2]--;});
  return {A,b,m,d};
 }
 function encZ(z,clauses,canonical){
  let e=[];for(const x of z)e.push(x,1-x);
  for(const cl of clauses){let t=cl.reduce((s,l)=>s+lit(z,l),0);let a=canonical?Math.min(1,t-1):t-1,b=canonical?t-1-a:0;e.push(a,1-a,b,1-b);}
  return e;
 }
 const mv=(A,e)=>A.map(row=>row.reduce((s,v,i)=>s+v*e[i],0));
 function encrypt(A,b,bit){let s=Array.from({length:A.length},()=>rnd(Q)),noise=Array.from({length:A[0].length},()=>rnd(3)-1),e0=rnd(3)-1;return {u:noise.map((v,i)=>mod(v+A.reduce((sum,row,j)=>sum+row[i]*s[j],0))),v:mod(e0+b.reduce((sum,x,j)=>sum+x*s[j],0)+D*bit)};}
 const decrypt=(ct,e)=>{let t=mod(ct.v-ct.u.reduce((s,v,i)=>s+v*e[i],0));return +(Math.min(mod(t-D),mod(D-t))<Math.min(t,Q-t));};
 let defs=[
  {name:"two-true",n:2,clauses:[[[0,true],[1,true],[1,true]],[[0,false],[1,true],[1,true]]],expected:2},
  {name:"fixed-false",n:1,clauses:[[[0,true],[0,true],[0,true]],[[0,false],[0,false],[0,false]]],expected:0},
  {name:"one-true",n:1,clauses:[[[0,true],[0,true],[0,true]]],expected:1}
 ];
 for(const c of defs){
  let {A,b,m,d}=mat(c.n,c.clauses);ok(Q>4*(m+1));
  let as=Array.from({length:1<<c.n},(_,a)=>Array.from({length:c.n},(_,i)=>(a>>i)&1));
  let good=as.filter(z=>c.clauses.every(cl=>cl.some(l=>lit(z,l))));ok(good.length===c.expected);
  for(const z of as){
   const near=encZ(z,c.clauses,false);ok(mv(A,near).every((v,i)=>v===b[i]));ok(near.reduce((s,v)=>s+Math.abs(v),0)<=m);
   if(good.some(w=>w.every((v,i)=>v===z[i]))){const e=encZ(z,c.clauses,true);ok(e.every(x=>x===0||x===1));ok(mv(A,e).every((v,i)=>v===b[i]));}
   else ok(near.some(x=>x<0||x>1));
  }
  for(let mix=0;mix<2;mix++){
   let AA=A.map(row=>row.slice()),bb=b.slice();
   if(mix)for(let j=1;j<d;j++){AA[j]=AA[j].map((v,i)=>mod(v+(j+1)*AA[0][i]));bb[j]=mod(bb[j]+(j+1)*bb[0]);}
   let attack=encZ(Array(c.n).fill(0),c.clauses,false);
   ok(mv(AA,attack).every((v,i)=>mod(v)===bb[i]));
   for(let t=0;t<64;t++){
    const bit=rnd(2),cipher=encrypt(AA,bb,bit);
    for(const z of good){ok(decrypt(cipher,encZ(z,c.clauses,true))===bit);validOpen++;}
    ok(decrypt(cipher,attack)===bit);falseOpen++;
   }
  }
 }
 return{result:"PASS, CANDIDATE REJECTED",assertions:nassert,validOriginalDecryptions:validOpen,publicInvalidNearKeyDecryptions:falseOpen,originalCases:3,parameters:{q:Q,delta:D,eta:1},quantumSecurity:false};
};
console.log(JSON.stringify(R111ExactChecker(),null,2));

```

### Captured checker output

```json
{
  "result": "PASS, CANDIDATE REJECTED",
  "assertions": 807,
  "validOriginalDecryptions": 384,
  "publicInvalidNearKeyDecryptions": 384,
  "originalCases": 3,
  "parameters": {
    "q": 257,
    "delta": 128,
    "eta": 1
  },
  "quantumSecurity": false
}
```
