# R157 — Boolean-ideal noise phase: restricted FALSE hiding, unresolved generic ORIGINAL release

**STATUS: NOT a constructive secure generic-WKEM advance; routine diagnostic, no top-level PR progress comment.** This bounded offline iteration deliberately does **not** optimize parameters. The result is a restricted algebraic test of a new noisy coefficient source, not a QPT security proof. Previous R156 onehot linear source is rejected and not revived.

Continuity: syscoin/PVUGC PR #1, open/draft/unmerged, branch research/pq-wkem-validation-20260918, observed prewrite head `247e10fd4acf5367110a2d3460807354f46273f6`. Latest substantive ordinary PR comment 6718361572 (R153). Exact R156 research note blob 8bc6b6ffc26d5b0386cfcff15d70d004a5edae97 and checker blob 0907013834851f55de83407e6823fd421a512c0e were inspected. R155 exact note fe6369d3de7f6c38c2223f76da7a6f5bdc7f70df was also read. No external literature or web search.

## Candidate construction, actual distribution, and limitation

Use a Boolean quotient algebra ᴹ_n=F_q[X_1,...,X_n]/(X_i^2-X_i) with the canonical basis of square-free monomials, dimension D=2^n. For an ORIGINAL relation encoded by polynomial constraints g_j(X)=0, take a *public* coefficient matrix F_x whose columns are the coefficient vectors of m_S(X)g_j(X) for square-free monomials m_S of degree <=d. Let v denote the constant polynomial 1. Every valid Boolean ORIGINAL witness w annihilates every column of F_x.

For a single uniform K in {0,1}, sample **classically** r uniform from F_q^M and independent bounded integer errors e_i uniform [-eta,eta]. Publish actual source coefficient vector

    C_K = F_x r + e + Delta*K*v (mod q).

The full statement x includes original verifier identity, claim/UTXO, branch, anchors/window, context, native VK, and capsule ID, although the experiment does not instantiate native signatures or graph composition. An off-chain valid witness evaluates the public polynomial C at its Boolean values:

    Eval_w(C_K)=Delta*K+sum_{S subseteq supp(w)}e_S (mod q).

Thus all distinct valid witnesses recover the SAME K with deterministic correctness if Delta > 2 eta D and q > 2(Delta+eta D), by nearest-phase decoding. For a native signature, use independent source bits to mask a frozen, claim/path-bound signature; **this wrapping is not analyzed here**.

If v belongs to im(F_x), uniform r makes C_0 and C_1 *identically distributed*, even jointly with e, for this capsule source alone. The public coefficient matrix is **not uniformly random LWE**; no ordinary QPT-LWE challenge simulation is known. For true instances v cannot belong to im(F_x), because evaluation at a valid witness annihilates F_x and evaluates v to 1. Consequently, the public linear algebra already reveals the shift's *direction* and a dual linear functional; whether bounded e hides K against arbitrary QPT and related capsules is completely unproved. Do not assume false-source full-public security from source-only equality when checking keys, auxiliary data, setup correlations, openings, or sibling capsules are secret-dependent.

## Exact degree-two certificate for odd XOR rings

For n Boolean variables on a ring, let g_i=X_i+X_(i+1)-2X_iX_(i+1) (i<n), so each enforces equality. Let g_n=X_n+X_1-2X_nX_1-1, enforcing inequality. This is an ORIGINAL-FALSE 2-XOR instance, since the equalities imply X_n=X_1.

Working in the Boolean quotient, the identities are

    (1-2X_i)*g_i = X_(i+1)-X_i
    g_n = -1+(X_1-X_n)*(1-2X_n).

Telescoping gives the exact public degree-two multiplier certificate

    1 = -g_n - sum_{i=1}^{n-1}(1-2X_i)(1-2X_n)g_i.

Therefore v is in the degree-two mask span F_x for every n, and this restricted FALSE ring has *exactly identical* source C_0/C_1 distributions, with no LWE assumption. At multiplier degrees 0 and 1, v is not in this span. On the satisfiable all-equality ring, v is outside the ideal for every d, proven by evaluating at valid assignments (all zeros or all ones).

This is a **restricted and explicitly visible** situation, not generic ORIGINAL-NP FALSE hiding. If a polynomial-dimensional public F_x had v in its span for every FALSE NP statement and outside for every TRUE statement, the polynomial-time test `v in im(F_x)` would decide NP. In this class of public-linear source constructions, that would require NP=P. More general computationally hidden nonlinear sources are not ruled out. The honest success identity does not imply arbitrary key-recovery-to-ORIGINAL-witness extraction; an adversary must never be required to present an internal vector.

## What was tested and exactly what remains

The exact JavaScript function below was executed in the connected V8 research runtime, giving `110` successful algebraic assertions. It checks the polynomial certificate coefficientwise (not only on sampled Boolean points), every source column's annihilation at both TRUE assignments, and modular Gaussian span membership for n=3..7 and all multiplier degrees 0..n. A separate offline Python 3 standard-library checker was executed earlier in this run with 70 algebraic assertions and the same degree-two threshold (local-only). These checks are finite algebra, not QPT attacks or parameter calibration.

The next candidate must make the ORIGINAL-NP-dependent public source **computationally** secure instead of relying on a polynomial-dimensional public-linear ideal membership test. It must instantiate actual LWE setup/openings AND a full-joint challenge simulator including J/CK/Aux/context, related capsules, quantum advice, and selective openings; allow every valid ORIGINAL witness the identical frozen capability; and reduce *arbitrary* unauthorized recovery/native forgery to ORIGINAL witness extraction or an independent justified QPT break. No SourceOpen oracle, canonical/common witness, uninstantiated iO, or secret-dependent published checking field may be silently assumed. Malicious N-of-N/abort/erasure, DA/presignatures, SYS/BTC source and conditional native PQ endpoint remain unresolved. No bitcoin verifier changes, optimization, deployment or production edit.

## Exact executed checker (JavaScript)

```javascript
const result=(function checkR157(){
  "use strict";
  const p=101, ns=[3,4,5,6,7];let asserts=0,records=[];
  const ck=(x,label)=>{asserts++;if(!x)throw Error(`assert ${asserts} ${label}`)};
  const popcount=x=>{let n=0;while(x){n+=x&1;x>>>=1}return n};
  const mod=x=>(x%p+p)%p;
  function generators(n,odd){
    let gs=[];
    for(let i=0;i<n;i++){
      let j=(i+1)%n, a=Array(1<<n).fill(0);
      a[0]=odd&&i===n-1?p-1:0;
      a[1<<i]=mod(a[1<<i]+1);a[1<<j]=mod(a[1<<j]+1);
      a[(1<<i)|(1<<j)]=mod(a[(1<<i)|(1<<j)]-2);gs.push(a);
    }
    return gs;
  }
  function mul(a,b,n){
    let o=Array(1<<n).fill(0);
    for(let i=0;i<a.length;i++)if(a[i])for(let j=0;j<b.length;j++)if(b[j])o[i|j]=mod(o[i|j]+a[i]*b[j]);
    return o;
  }
  function span(vectors){
    let B=new Map();
    for(const v of vectors){
      let a=v.slice();
      for(const i of [...B.keys()].sort((a,b)=>a-b)){
        if(a[i]){let c=a[i],b=B.get(i);for(let j=0;j<a.length;j++)a[j]=mod(a[j]-c*b[j]);}
      }
      let pivot=a.findIndex(x=>x!==0);
      if(pivot>=0){
        let inv=1;while(mod(inv*a[pivot])!==1)inv++;
        B.set(pivot,a.map(x=>mod(x*inv)));
      }
    }
    return B;
  }
  function contains(v,B){
    let a=v.slice();
    for(const i of [...B.keys()].sort((a,b)=>a-b)){
      if(a[i]){let c=a[i],b=B.get(i);for(let j=0;j<a.length;j++)a[j]=mod(a[j]-c*b[j]);}
    }
    return !a.some(Boolean);
  }
  function masked(n,d,odd){
    let gs=generators(n,odd),v=[];
    for(const g of gs){
      for(let m=0;m<(1<<n);m++)if(popcount(m)<=d){
        let o=Array(1<<n).fill(0);
        for(let j=0;j<g.length;j++)if(g[j])o[j|m]=mod(o[j|m]+g[j]);
        v.push(o);
      }
    }
    return v;
  }
  function val(v,w){
    let z=0;
    for(let m=0;m<v.length;m++)if((m&w)===m)z=mod(z+v[m]);
    return z;
  }
  for(const n of ns){
    let constvec=[1,...Array((1<<n)-1).fill(0)];
    const f=generators(n,true);
    const fac=n0=>{let z=Array(1<<n).fill(0);z[0]=1;z[1<<n0]=p-2;return z};
    let cert=f[n-1].map(x=>mod(-x));
    for(let i=0;i<n-1;i++){
      let term=mul(mul(fac(i),fac(n-1),n),f[i],n);
      cert=cert.map((x,j)=>mod(x-term[j]));
    }
    ck(cert.every((x,j)=>x===constvec[j]),"degree2 exact ideal certificate");
    for(const odd of [false,true]){
      let seen=false;
      for(let d=0;d<=n;d++){
        let V=masked(n,d,odd),B=span(V),containsOne=contains(constvec,B);
        if(containsOne&&!seen){ck(odd&&d===2,"first degree2 false span");seen=true;}
        if(!odd){
          ck(!containsOne,"true has no constant in source span");
          ck(V.every(v=>val(v,0)===0&&val(v,(1<<n)-1)===0),"all true witness evaluation");
        }else{
          ck(containsOne===(d>=2),"false threshold degree2");
        }
        records.push({n,unsatisfiable:odd,degree:d,columns:V.length,rank:B.size,constant_in_span:containsOne});
      }
      ck(odd?seen:!seen,"universal case invariant");
    }
  }
  return {run:"R157",field:p,assertions:asserts,records,conclusion:"For odd parity rings constant v enters the local ideal mask span at multiplier degree two; for satisfiable zero-parity rings it never enters. Restricted statistical FALSE hiding does not give generic NP or hard TRUE security."};
})();
console.log(JSON.stringify(result,null,2));
```

## Captured checker output

```json
{
  "run": "R157",
  "field": 101,
  "assertions": 110,
  "records": [
    {
      "n": 3,
      "unsatisfiable": false,
      "degree": 0,
      "columns": 3,
      "rank": 3,
      "constant_in_span": false
    },
    {
      "n": 3,
      "unsatisfiable": false,
      "degree": 1,
      "columns": 12,
      "rank": 6,
      "constant_in_span": false
    },
    {
      "n": 3,
      "unsatisfiable": false,
      "degree": 2,
      "columns": 21,
      "rank": 6,
      "constant_in_span": false
    },
    {
      "n": 3,
      "unsatisfiable": false,
      "degree": 3,
      "columns": 24,
      "rank": 6,
      "constant_in_span": false
    },
    {
      "n": 3,
      "unsatisfiable": true,
      "degree": 0,
      "columns": 3,
      "rank": 3,
      "constant_in_span": false
    },
    {
      "n": 3,
      "unsatisfiable": true,
      "degree": 1,
      "columns": 12,
      "rank": 7,
      "constant_in_span": false
    },
    {
      "n": 3,
      "unsatisfiable": true,
      "degree": 2,
      "columns": 21,
      "rank": 8,
      "constant_in_span": true
    },
    {
      "n": 3,
      "unsatisfiable": true,
      "degree": 3,
      "columns": 24,
      "rank": 8,
      "constant_in_span": true
    },
    {
      "n": 4,
      "unsatisfiable": false,
      "degree": 0,
      "columns": 4,
      "rank": 4,
      "constant_in_span": false
    },
    {
      "n": 4,
      "unsatisfiable": false,
      "degree": 1,
      "columns": 20,
      "rank": 11,
      "constant_in_span": false
    },
    {
      "n": 4,
      "unsatisfiable": false,
      "degree": 2,
      "columns": 44,
      "rank": 14,
      "constant_in_span": false
    },
    {
      "n": 4,
      "unsatisfiable": false,
      "degree": 3,
      "columns": 60,
      "rank": 14,
      "constant_in_span": false
    },
    {
      "n": 4,
      "unsatisfiable": false,
      "degree": 4,
      "columns": 64,
      "rank": 14,
      "constant_in_span": false
    },
    {
      "n": 4,
      "unsatisfiable": true,
      "degree": 0,
      "columns": 4,
      "rank": 4,
      "constant_in_span": false
    },
    {
      "n": 4,
      "unsatisfiable": true,
      "degree": 1,
      "columns": 20,
      "rank": 12,
      "constant_in_span": false
    },
    {
      "n": 4,
      "unsatisfiable": true,
      "degree": 2,
      "columns": 44,
      "rank": 16,
      "constant_in_span": true
    },
    {
      "n": 4,
      "unsatisfiable": true,
      "degree": 3,
      "columns": 60,
      "rank": 16,
      "constant_in_span": true
    },
    {
      "n": 4,
      "unsatisfiable": true,
      "degree": 4,
      "columns": 64,
      "rank": 16,
      "constant_in_span": true
    },
    {
      "n": 5,
      "unsatisfiable": false,
      "degree": 0,
      "columns": 5,
      "rank": 5,
      "constant_in_span": false
    },
    {
      "n": 5,
      "unsatisfiable": false,
      "degree": 1,
      "columns": 30,
      "rank": 19,
      "constant_in_span": false
    },
    {
      "n": 5,
      "unsatisfiable": false,
      "degree": 2,
      "columns": 80,
      "rank": 29,
      "constant_in_span": false
    },
    {
      "n": 5,
      "unsatisfiable": false,
      "degree": 3,
      "columns": 130,
      "rank": 30,
      "constant_in_span": false
    },
    {
      "n": 5,
      "unsatisfiable": false,
      "degree": 4,
      "columns": 155,
      "rank": 30,
      "constant_in_span": false
    },
    {
      "n": 5,
      "unsatisfiable": false,
      "degree": 5,
      "columns": 160,
      "rank": 30,
      "constant_in_span": false
    },
    {
      "n": 5,
      "unsatisfiable": true,
      "degree": 0,
      "columns": 5,
      "rank": 5,
      "constant_in_span": false
    },
    {
      "n": 5,
      "unsatisfiable": true,
      "degree": 1,
      "columns": 30,
      "rank": 20,
      "constant_in_span": false
    },
    {
      "n": 5,
      "unsatisfiable": true,
      "degree": 2,
      "columns": 80,
      "rank": 31,
      "constant_in_span": true
    },
    {
      "n": 5,
      "unsatisfiable": true,
      "degree": 3,
      "columns": 130,
      "rank": 32,
      "constant_in_span": true
    },
    {
      "n": 5,
      "unsatisfiable": true,
      "degree": 4,
      "columns": 155,
      "rank": 32,
      "constant_in_span": true
    },
    {
      "n": 5,
      "unsatisfiable": true,
      "degree": 5,
      "columns": 160,
      "rank": 32,
      "constant_in_span": true
    },
    {
      "n": 6,
      "unsatisfiable": false,
      "degree": 0,
      "columns": 6,
      "rank": 6,
      "constant_in_span": false
    },
    {
      "n": 6,
      "unsatisfiable": false,
      "degree": 1,
      "columns": 42,
      "rank": 29,
      "constant_in_span": false
    },
    {
      "n": 6,
      "unsatisfiable": false,
      "degree": 2,
      "columns": 132,
      "rank": 53,
      "constant_in_span": false
    },
    {
      "n": 6,
      "unsatisfiable": false,
      "degree": 3,
      "columns": 252,
      "rank": 61,
      "constant_in_span": false
    },
    {
      "n": 6,
      "unsatisfiable": false,
      "degree": 4,
      "columns": 342,
      "rank": 62,
      "constant_in_span": false
    },
    {
      "n": 6,
      "unsatisfiable": false,
      "degree": 5,
      "columns": 378,
      "rank": 62,
      "constant_in_span": false
    },
    {
      "n": 6,
      "unsatisfiable": false,
      "degree": 6,
      "columns": 384,
      "rank": 62,
      "constant_in_span": false
    },
    {
      "n": 6,
      "unsatisfiable": true,
      "degree": 0,
      "columns": 6,
      "rank": 6,
      "constant_in_span": false
    },
    {
      "n": 6,
      "unsatisfiable": true,
      "degree": 1,
      "columns": 42,
      "rank": 30,
      "constant_in_span": false
    },
    {
      "n": 6,
      "unsatisfiable": true,
      "degree": 2,
      "columns": 132,
      "rank": 55,
      "constant_in_span": true
    },
    {
      "n": 6,
      "unsatisfiable": true,
      "degree": 3,
      "columns": 252,
      "rank": 63,
      "constant_in_span": true
    },
    {
      "n": 6,
      "unsatisfiable": true,
      "degree": 4,
      "columns": 342,
      "rank": 64,
      "constant_in_span": true
    },
    {
      "n": 6,
      "unsatisfiable": true,
      "degree": 5,
      "columns": 378,
      "rank": 64,
      "constant_in_span": true
    },
    {
      "n": 6,
      "unsatisfiable": true,
      "degree": 6,
      "columns": 384,
      "rank": 64,
      "constant_in_span": true
    },
    {
      "n": 7,
      "unsatisfiable": false,
      "degree": 0,
      "columns": 7,
      "rank": 7,
      "constant_in_span": false
    },
    {
      "n": 7,
      "unsatisfiable": false,
      "degree": 1,
      "columns": 56,
      "rank": 41,
      "constant_in_span": false
    },
    {
      "n": 7,
      "unsatisfiable": false,
      "degree": 2,
      "columns": 203,
      "rank": 90,
      "constant_in_span": false
    },
    {
      "n": 7,
      "unsatisfiable": false,
      "degree": 3,
      "columns": 448,
      "rank": 118,
      "constant_in_span": false
    },
    {
      "n": 7,
      "unsatisfiable": false,
      "degree": 4,
      "columns": 693,
      "rank": 125,
      "constant_in_span": false
    },
    {
      "n": 7,
      "unsatisfiable": false,
      "degree": 5,
      "columns": 840,
      "rank": 126,
      "constant_in_span": false
    },
    {
      "n": 7,
      "unsatisfiable": false,
      "degree": 6,
      "columns": 889,
      "rank": 126,
      "constant_in_span": false
    },
    {
      "n": 7,
      "unsatisfiable": false,
      "degree": 7,
      "columns": 896,
      "rank": 126,
      "constant_in_span": false
    },
    {
      "n": 7,
      "unsatisfiable": true,
      "degree": 0,
      "columns": 7,
      "rank": 7,
      "constant_in_span": false
    },
    {
      "n": 7,
      "unsatisfiable": true,
      "degree": 1,
      "columns": 56,
      "rank": 42,
      "constant_in_span": false
    },
    {
      "n": 7,
      "unsatisfiable": true,
      "degree": 2,
      "columns": 203,
      "rank": 92,
      "constant_in_span": true
    },
    {
      "n": 7,
      "unsatisfiable": true,
      "degree": 3,
      "columns": 448,
      "rank": 120,
      "constant_in_span": true
    },
    {
      "n": 7,
      "unsatisfiable": true,
      "degree": 4,
      "columns": 693,
      "rank": 127,
      "constant_in_span": true
    },
    {
      "n": 7,
      "unsatisfiable": true,
      "degree": 5,
      "columns": 840,
      "rank": 128,
      "constant_in_span": true
    },
    {
      "n": 7,
      "unsatisfiable": true,
      "degree": 6,
      "columns": 889,
      "rank": 128,
      "constant_in_span": true
    },
    {
      "n": 7,
      "unsatisfiable": true,
      "degree": 7,
      "columns": 896,
      "rank": 128,
      "constant_in_span": true
    }
  ],
  "conclusion": "For odd parity rings constant v enters the local ideal mask span at multiplier degree two; for satisfiable zero-parity rings it never enters. Restricted statistical FALSE hiding does not give generic NP or hard TRUE security."
}
```
