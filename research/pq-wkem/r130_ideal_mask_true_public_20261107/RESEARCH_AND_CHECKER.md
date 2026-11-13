# R130 — ORIGINAL-dependent low-degree ideal-mask release: key publicly extractable on every TRUE instance (REJECTED)

**Classification:** No positive ORIGINAL-witness security advance; a bounded algebraic design check, not a completed witness-KEM or novel impossibility of WE. No ordinary top-level PR comment or user-facing negative update warranted.

**Provenance:** syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918; current head preflight is f2f9e5d90d1af86ecfd12a364e8ca435c21615b2. The latest substantive PR comment 6698876958 and exact R129 source at Git blob d096677faa0411839aa7ccb8aaa3bf8bec7c47bf were read. No unrelated website or outside literature.

## Explicit ORIGINAL NP candidate
Compile arbitrary 3CNF ORIGINAL x (n Boolean variables) to degree ≤3 constraint polynomials over F_q: for each clause C_j, let c_j(z)=product over literals ℓ in C_j of (1-ℓ(z)); add z_i²-z_i Boolean constraints. They all evaluate to zero at every satisfying Boolean witness. Let c_0 be the coefficient vector of the constant polynomial 1 in the explicit monomial basis V_{n,3}, dimension binomial(n+3,3)=O(n³). Builder chooses the precommitted capability K∈F_q and independent uniform r_j∈F_q. It publishes
    v = K*c_0 + sum_j r_j*c_j.
Open(x,v,w) evaluates that polynomial at supplied ORIGINAL w. Every valid ORIGINAL witness recovers exactly SAME K. Builder need not know w and all algorithms are classical PPT. This satisfies only a correctness desideratum, not security.

## Exact full-public linear recovery
If x has any satisfying w, c_0 cannot belong to span(c_j), since evaluation at w sends c_0→1 and c_j→0. Therefore there ALWAYS exists a public linear functional λ∈V* with λ(c_0)=1, λ(c_j)=0. Gaussian elimination over the openly represented O(n³) coefficient vectors finds λ in polynomial time WITHOUT an ORIGINAL witness. Hence λ(v)=K on every setup tape for every TRUE original instance, no matter how difficult finding w might be. In some FALSE instances λ exists too and reveals K. This is an unconditional classical key-recovery algorithm, stronger than merely 'not proved QPT secure'. It also defeats invertible public basis changes; the extraction functional changes contragrediently.

If 1 lies in the span of the constraints (e.g. the immediately contradictory (x) AND (not x)), uniform r can hide K information-theoretically because K*c_0 is absorbed in the random span. That is only a FALSE special case, not generic security. Full public relations, coefficients, CK/J/Aux and arbitrary related copies cannot repair TRUE recovery that needs no oracle or advice.

## Concrete attempted LWE repair and exact missing bridge
Encrypt v coefficientwise using independent ordinary scalar/dual LWE-PKE ciphertexts under a public key instead of revealing plaintext v. Homomorphic linear combination by a valid witness yields an *encryption* of K, not K. Giving Open the ordinary PKE decryption key would release K for arbitrary witnesses or allow direct ciphertext decryption. Deriving a decryption key from ANY valid ORIGINAL w and no public invalid key is the actual missing source compiler. No explicit witness-to-decryption generation algorithm or simulator is furnished here; therefore the proposed LWE-wrapped source is not a solution, and an IND-CPA marginal hybrid would be irrelevant. The required joint view includes relation/statement, capsule, checking key, context, Aux and related capsules and permitted selective openings. Unauthorized hard-TRUE key recovery/native forgery ⇒ ORIGINAL witness or independently justified QPT break is NOT established.

This excludes one transparent, low-degree masking route. It does NOT establish a generic impossibility of encrypted or obfuscated sources, a security theorem for any surviving construction, a parameter estimate, or any operational Bitcoin endpoint.

## Exact reproducible finite check (actually executed V8)
~~~javascript
function r130Checker(){
 const q=17,mod=x=>(x%q+q)%q;
 const solve=(vectors)=>{
   let n=vectors[0].length,rows=vectors.map((v,i)=>v.map(mod).concat(i===vectors.length-1?1:0));
   let r=0,piv=[];
   for(let j=0;j<n;j++){
     let k=r;while(k<rows.length&&rows[k][j]===0)k++;
     if(k===rows.length)continue;
     [rows[r],rows[k]]=[rows[k],rows[r]];
     const inv=(()=>{for(let x=1;x<q;x++)if(mod(rows[r][j]*x)===1)return x;throw Error("inverse");})();
     rows[r]=rows[r].map(v=>mod(v*inv));
     for(let t=0;t<rows.length;t++)if(t!==r&&rows[t][j]){
       let x=rows[t][j];rows[t]=rows[t].map((v,k)=>mod(v-x*rows[r][k]));
     }
     piv.push(j);r++;
   }
   if(rows.some(row=>row.slice(0,n).every(v=>v===0)&&row[n]!==0))return null;
   let out=Array(n).fill(0);for(let i=0;i<piv.length;i++)out[piv[i]]=rows[i][n];
   for(let i=0;i<vectors.length;i++){
     let v=mod(vectors[i].reduce((a,x,j)=>a+x*out[j],0));
     if(v!==(i===vectors.length-1?1:0))throw Error("bad projection");
   }
   return out;
 };
 const T=[
   {name:"TRUE XOR clauses",witnesses:[[1,0],[0,1]],c0:[1,0,0,0,0,0],cs:[[1,-1,-1,0,1,0],[0,0,0,0,1,0],[0,-1,0,1,0,0],[0,0,-1,0,0,1]]},
   {name:"FALSE direct contradiction",witnesses:[],c0:[1,0,0],cs:[[1,-1,0],[0,1,0],[0,-1,1]]},
   {name:"FALSE three-clause chain",witnesses:[],c0:[1,0,0,0,0,0],cs:[[1,-1,0,0,0,0],[0,1,0,0,-1,0],[0,0,1,0,0,0],[0,-1,0,1,0,0],[0,0,-1,0,0,1]]}
 ];
 let checks=0;const details=[];
 for(const t of T){
   let l=solve([...t.cs,t.c0]),recover=0;
   for(let key=0;key<q;key++)for(let seed=0;seed<29;seed++){
     let coeff=t.c0.map((c,j)=>mod(key*c+t.cs.reduce((a,row,i)=>a+row[j]*mod(seed*11+i*7+key*3),0)));
     if(l){let k=mod(l.reduce((a,v,j)=>a+v*coeff[j],0));if(k!==key)throw Error("key disclosure");recover++;}
     for(const w of t.witnesses){
       const mon=[1,w[0],w[1],w[0]*w[0],w[0]*w[1],w[1]*w[1]];
       const k=mod(mon.reduce((a,v,j)=>a+v*coeff[j],0));
       if(k!==key)throw Error("correctness");checks++;
     }
     checks++;
   }
   details.push({case:t.name,has_public_linear_extractor:!!l,extractor:l,tested_masked_capsules:q*29,public_recoveries:recover});
 }
 if(!details[0].has_public_linear_extractor||details[1].has_public_linear_extractor||!details[2].has_public_linear_extractor)throw Error("case check");
 return {run:"R130-IDEAL-MASK-TRUE-LEAKAGE-20261107",status:"REJECTED: public transparent coefficients reveal capability on all TRUE instances; LWE ciphertext wrapper lacks ORIGINAL-witness decryption",checks,details};
}
console.log(JSON.stringify(r130Checker(),null,2));
~~~

## Captured result (same execution, before Git-object creation)
~~~json
{
  "run": "R130-IDEAL-MASK-TRUE-LEAKAGE-20261107",
  "status": "REJECTED: public transparent coefficients reveal capability on all TRUE instances; LWE ciphertext wrapper lacks ORIGINAL-witness decryption",
  "checks": 2465,
  "details": [
    {
      "case": "TRUE XOR clauses",
      "has_public_linear_extractor": true,
      "extractor": [
        1,
        1,
        0,
        1,
        0,
        0
      ],
      "tested_masked_capsules": 493,
      "public_recoveries": 493
    },
    {
      "case": "FALSE direct contradiction",
      "has_public_linear_extractor": false,
      "extractor": null,
      "tested_masked_capsules": 493,
      "public_recoveries": 0
    },
    {
      "case": "FALSE three-clause chain",
      "has_public_linear_extractor": true,
      "extractor": [
        1,
        1,
        0,
        1,
        1,
        0
      ],
      "tested_masked_capsules": 493,
      "public_recoveries": 493
    }
  ]
}
~~~

The V8 checker explicitly solves public modular linear systems for a TRUE two-witness XOR-style relation, a FALSE direct contradiction with no such linear extractor, and a FALSE three-clause chain that DOES have one. It checks all K∈F17 over 29 varied setup masks per example. A separately executed offline CPython standard-library checker of dynamically generated 3CNF and Boolean polynomial vectors also passed and yielded the same qualitative conclusions; it is LOCAL-ONLY at /mnt/data/R130_ORIGINAL_IDEAL_LWE_GATE_20261107/checker.py with captured.json and RESEARCH.md, not claimed to be committed.

## Handoff
Do not spend further cycles optimizing transparent coefficient masks or encrypting them without an independently instantiated ORIGINAL-witness decryption bridge. A substantive successor must give Build and Open for a nonlinearly protected source, all valid ORIGINAL witnesses→SAME precommitted capability, genuine joint-public QPT challenge simulation, fixed-FALSE security, and arbitrary hard-TRUE native capability recovery→ORIGINAL witness or independent QPT break. Malicious N-of-N ceremony/abort, DA, graph composition and conditional Bitcoin PQ endpoint remain separate obligations. This is a REJECTED research record, not a public progress announcement.
