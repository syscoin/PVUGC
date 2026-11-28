# R127 — Minimum-modulus and gap-amplification attempt for R126 one-hot modular SOURCE
**Result:** Rejected ORIGINAL-dependent repair; no constructive security advance, no QPT break, no user-facing progress comment under quiet-reporting instruction.
**Continuity:** syscoin/PVUGC#1 draft/open/unmerged; branch research/pq-wkem-validation-20260918; exact starting SHA 544abaa025246d09f59f5732ec8af1d5d1f937be; previous R126 original file blob 40b8ccfa61918c33c6145adb8de5fa950b3b37af. Read-only PR metadata, most recent substantive comments since 2026-11-06T21:00Z, and exact R126/R125 files were inspected. This new work does not assert that R126 or R125 is secure.
## Proposed repair and real setup distribution
R126 showed a public low-complexity non-Boolean integer affine representation decrypts every bit for large q. This iteration tested the most direct non-padding repair: reduce q to essentially the **minimum modulus supporting deterministic every-witness decryption**, and use repeated unsatisfiable gadgets to force a constant fraction of violated clauses. A genuine strong-gap PCP transformation would only increase the number of violated clauses; this experiment checks whether the resulting variance gap can separate true openings from public false representations.
Given ORIGINAL 3CNF x with n variables and m clauses, P=n+2m, define R126's publicly computable integer A in Z^((P+m) x 2P) and delta in Z^(P+m). All P bit-pairs must sum to one; each clause enforces its three literal-indicator coordinates plus slack coordinates s1 + 2s2 = 4. A valid ORIGINAL assignment supplies z in {0,1}^(2P), Az=delta and ||z||_2^2=||z||_1=P.
Honest classical-PPT SOURCE bit Build samples B uniform {0,1}, r uniform Z_q^(P+m), independent e uniformly from {-1,0,1}^(2P), and e0 uniformly {-1,0,1}. It publishes U=A^T r+e mod q and V=delta^T r+e0+B floor(q/2) mod q, plus the statement/relation and any checking/public outputs derived from this actual ciphertext. For any valid w, Open computes z_w and nearest-center-decodes V-z_w^T U using centers 0 and floor(q/2). With any odd q>4(P+1)+1, every valid ORIGINAL witness recovers the identical B for **all supported error tapes**, since |e0-z_w^T e|<=P+1 and floor(q/2)/2>P+1. Build is classical polynomial-time; the example chooses an odd prime q just above 4(P+1)+1. This proves restricted correctness only, not false hiding.
## Rigorous public FALSE attack despite minimum q and maximal violated-clause proportion
For ANY public assignment a, construct the public integer z_bad by using true 0/1 variable pairs and clause slack first-bits (s1,s2) equal to (0,2),(1,1),(0,1),(1,0) when k=0,1,2,3 clause literals are satisfied; each slack pair's second coordinate is 1 minus its first. For u unsatisfied clauses, algebra gives
  Az_bad=delta, ||z_bad||_1=P+2u, ||z_bad||_2^2=P+4u<=P+4m<=3P.
In particular even when the ORIGINAL formula is FALSE this z_bad is public and constructible in classical PPT time, without any witness. Its residual cancels r identically:
  V-z_bad^T U = B floor(q/2) + Y (mod q),  Y=e0-z_bad^T e.
The independent centered bounded errors imply Hoeffding's inequality
  Pr[|Y|>=a] <= 2 exp(-a^2/(2(1+||z_bad||_2^2))) <= 2 exp(-a^2/(2(3P+1))).
For q>4(P+1)+1, |Y|<P+1 implies correct nearest-center decoding. Consequently for every FALSE x and any assignment a,
  Pr[publicly opening B incorrectly] <= 2 exp(-(P+1)^2/(2(3P+1))) = exp(-Omega(P)).
Thus reducing the modulus all the way to the **true deterministic correctness boundary** does NOT remove the classical public false opener: for P growing with the security parameter it succeeds with overwhelming probability. For any polynomial L related capsules/independent bits, the probability all L public openings succeed is >= 1 - 2L exp(-(P+1)^2/(2(3P+1))) by union bound, without assuming errors independent between capsules.
The explicit fixed-FALSE family has n=t and 2t clauses: for each independent variable x_i include (x_i OR x_i OR x_i) AND (NOT x_i OR NOT x_i OR NOT x_i). Every assignment violates exactly t of the 2t clauses, P=5t, ||z_bad||_2^2=9t and ||z_bad||_1=7t. Even forcing the maximal one-of-two contradiction rate does not help the repair. The result uses only the public (x,A,delta,U,V) marginal; full J/CK/Aux/context, related capsules and QPT coherent processing cannot restore hiding. This is NOT a generic impossibility theorem for witness encryption, and does not cover nonlinear/secret correlated-noise constructions, cryptographic encodings of bitness, or a source whose full-public simulator is genuinely reducible to QPT-LWE. Random-looking ciphertext distribution alone is not a simulator.
## Checker and captured output
The exact JS checker below was executed in the connector V8 isolate. It builds actual R126 affine matrices for each t, verifies Az_bad=delta and true modulus margins, then calculates the complete finite distribution of Y by exact BigInt discrete convolution over every possible independent error tape (factoring out zero coefficients), both message bits and ties. It compares exact error probabilities against the stated Hoeffding bound. This is exhaustive combinatorial arithmetic for the selected finite instances, not a QPT experiment or proof of security. No independent checker was invoked.
```javascript
function r127Checker(){
  let checks=0;
  function ck(c,s){checks++;if(!c)throw Error("R127 "+checks+" "+s)}
  function isPrime(n){if(n<2)return false;for(let d=2;d*d<=n;d++)if(n%d===0)return false;return true}
  const rows=[];
  for(const t of [1,2,4,8,16,32]){
    const n=t,m=2*t,P=n+2*m,N=2*P,z=[];
    // Fixed-FALSE: for every x_i include (x_i v x_i v x_i) and (!x_i v !x_i v !x_i).
    for(let i=0;i<t;i++)z.push(1,0);
    for(let i=0;i<t;i++)z.push(1,0,0,1,0,1,2,-1);
    ck(z.length===N,"representation length");
    const mat=Array.from({length:P+m},()=>Array(N).fill(0));
    for(let j=0;j<P;j++){mat[j][2*j]=1;mat[j][2*j+1]=1}
    for(let i=0;i<t;i++){
      const cpos=P+2*i,cneg=cpos+1,first=2*(t+4*i);
      mat[cpos][2*i]+=3;mat[cpos][first]+=1;mat[cpos][first+2]+=2;
      mat[cneg][2*i+1]+=3;mat[cneg][first+4]+=1;mat[cneg][first+6]+=2;
    }
    const A_z=mat.map(row=>row.reduce((a,v,j)=>a+v*z[j],0));
    ck(A_z.every((x,i)=>x===(i<P?1:4)),"exact false affine representation");
    const l1=z.reduce((a,x)=>a+Math.abs(x),0),l2=z.reduce((a,x)=>a+x*x,0);
    ck(l1===7*t&&l2===9*t&&l2<=3*P,"false norm certificates");
    const threshold=4*(P+1)+3;
    let q=threshold;while(!isPrime(q))q++;
    const delta=Math.floor(q/2);
    ck(q>4*(P+1)+1&&delta/2>P+1,"supported true all-tape correctness");
    // Exact distribution of Y=e0-z.e for independently uniform {-1,0,1}.
    // Zero z coordinates factor out identically from numerator and denominator.
    const coeff=[1,...z.filter(v=>v!==0)];
    let dist=new Map([[0,1n]]);
    for(const c of coeff){
      const next=new Map();
      for(const [y,count] of dist)for(const e of [-1,0,1]){
        const val=y+c*e; next.set(val,(next.get(val)||0n)+count);
      }
      dist=next;
    }
    const den=3n**BigInt(coeff.length);
    ck(Array.from(dist.values()).reduce((a,b)=>a+b,0n)===den,"exact probability normalization");
    const cyc=(a,b)=>{const v=Math.abs(a-b);return Math.min(v,q-v)};
    const mod=a=>(a%q+q)%q;
    const nums=[];
    for(const B of [0,1]){
      let num=0n;
      for(const [err,count] of dist){
        const r=mod(B*delta+err);
        const d0=cyc(r,0),d1=cyc(r,delta);
        // Count ties against the true bit, giving conservative exact error.
        if((B===0&&d1<=d0)||(B===1&&d0<=d1))num+=count;
      }
      nums.push(num);ck(num>=0n&&num<=den,"failure fraction valid");
    }
    ck(nums[0]===nums[1],"symmetric exact decoding errors");
    const p=Number(nums[0])/Number(den);
    const hoeff=2*Math.exp(-((P+1)**2)/(2*(1+l2)));
    ck(p<=hoeff,"Hoeffding bound dominates exact error");
    rows.push({t,P,q,Delta:delta,public_false_l2_sq:l2,public_false_l1:l1,success_error_probability:p,exact_error_numerator:nums[0].toString(),exact_denominator:den.toString(),hoeffding_bound:hoeff});
  }
  return {run:"R127-MINIMUM-MODULUS-GAP-SOURCE-20261107",assertions:checks,rows,verdict:"rejected repair; no secure ORIGINAL WKEM"};
}
console.log(JSON.stringify(r127Checker(),null,2));
```
Captured exact execution JSON:
```json
{
  "run": "R127-MINIMUM-MODULUS-GAP-SOURCE-20261107",
  "assertions": 54,
  "rows": [
    {
      "t": 1,
      "P": 5,
      "q": 29,
      "Delta": 14,
      "public_false_l2_sq": 9,
      "public_false_l1": 7,
      "success_error_probability": 0.003657978966620942,
      "exact_error_numerator": "8",
      "exact_denominator": "2187",
      "hoeffding_bound": 0.33059777644317306
    },
    {
      "t": 2,
      "P": 10,
      "q": 47,
      "Delta": 23,
      "public_false_l2_sq": 18,
      "public_false_l1": 14,
      "success_error_probability": 0.0004729280076872754,
      "exact_error_numerator": "754",
      "exact_denominator": "1594323",
      "hoeffding_bound": 0.0828218514708116
    },
    {
      "t": 4,
      "P": 20,
      "q": 89,
      "Delta": 44,
      "public_false_l2_sq": 36,
      "public_false_l1": 28,
      "success_error_probability": 0.0000017588741113605821,
      "exact_error_numerator": "1490274",
      "exact_denominator": "847288609443",
      "hoeffding_bound": 0.005162613792023207
    },
    {
      "t": 8,
      "P": 40,
      "q": 167,
      "Delta": 83,
      "public_false_l2_sq": 72,
      "public_false_l1": 56,
      "success_error_probability": 1.18690729178634e-10,
      "exact_error_numerator": "28402611878340",
      "exact_denominator": "239299329230617529590083",
      "hoeffding_bound": 0.00001998454267296828
    },
    {
      "t": 16,
      "P": 80,
      "q": 331,
      "Delta": 165,
      "public_false_l2_sq": 144,
      "public_false_l1": 112,
      "success_error_probability": 8.214282657214592e-20,
      "exact_error_numerator": "1567946900173042411661294940",
      "exact_denominator": "19088056323407827075424486287615602692670648963",
      "hoeffding_bound": 2.9887647634916805e-10
    },
    {
      "t": 32,
      "P": 160,
      "q": 647,
      "Delta": 323,
      "public_false_l2_sq": 288,
      "public_false_l1": 224,
      "success_error_probability": 2.0369132276529177e-36,
      "exact_error_numerator": "247385755551405727534379490329879218084860514126428479996",
      "exact_denominator": "121451298068529844233553416568714964256622520646270917226600348303197298080156462274524325123",
      "hoeffding_bound": 6.678065028501719e-20
    }
  ],
  "verdict": "rejected repair; no secure ORIGINAL WKEM"
}
```
## Exact handoff (still missing)
Do not repeat simple modulus tuning, PCP gap amplification without multiplicative separation, repetition/hash of already leaked bits, public affine basis changes, or relying on an official norm-check Open interface. A viable successor must **instantiate** an ORIGINAL-dependent *nonlinear* source whose true-witness computation of a SAME precommitted capability cannot be reproduced using publicly computable invalid affine solutions or low-degree closure, and must supply a joint full-public QPT challenge simulator for its statement, checking key, source-dependent LWE data, auxiliary inputs, related capsules and selective openings. It must prove arbitrary unauthorized signature recovery/native forgery -> ORIGINAL witness or independently justified PQ break without asking an adversary for z. This candidate supplies none of those obligations. Malicious N-of-N ceremony/abort, graph/DA/SYS-BTC source, QPT parameter calibration and hypothetical native Bitcoin PQ endpoint remain unresolved.
