# MINK-BOOLEAN-IDEAL-SOURCE-20261102-R19

**Research-only. Not a secure generic post-quantum witness-KEM.** The new construction satisfies every-valid-ORIGINAL-witness SAME-capability correctness and proves an exact quantum-safe false-instance hiding theorem on a *degree-refutable* subclass. An explicit FALSE nine-clause instance at multiplier degree zero permits deterministic unauthorized key recovery via a public short dual, so the generic requirements are still unsolved.

## Provenance and continuation
- Source: syscoin/PVUGC PR #1, open/draft/unmerged, branch `research/pq-wkem-validation-20260918`; checked starting head `b41cbcf4611d5e001c0b4eedd3853a4010cd18ef`.
- Latest substantive ordinary comment 6582949233. Read exactly versioned R18 RESEARCH.md blob 6b8f9f4446df3b0def5903308b8dbb3bab31f423 and R17 RESEARCH.md blob 5c2c6e144e00d6b14ad0f33ac24aab521c191951. No entire PR diff, unrelated website or external literature.
- R18's generic 3CNF integer-syndrome source was fatally broken by an efficiently computed signed `As=b` solution. This iteration tests globally nonlinear Boolean-clause equations rather than another public basis change.

## Concrete Build/Lift and distributions
Include the ORIGINAL relation identity, claim/UTXO, branch, source/Bitcoin anchors and observation window, intended verification key, authorization path and domain-separated context in the canonical statement `x`. A polynomial-time compiler maps its ORIGINAL NP verifier to a 3CNF `phi`, with valid ORIGINAL witness extension and a sound reverse map.

Let `phi` have `n` variables and `c` clauses, prime field `F_q`, and public multiplier degree `d`. For each clause with literal polynomials `ell_jk(z)` set `g_j(z)=prod_{k=1}^3(1-ell_jk(z))`. Define Booleanity polynomials `h_i(z)=z_i^2-z_i`. Every valid extended ORIGINAL Boolean witness `w` simultaneously zeros all these polynomials. Form the coefficient basis of all monomials of degree <= `D=d+3`, size `M=binom(n+D,D)`, and the multiplier monomials of degree <= `d`, size `H=binom(n+d,d)`. Define public `M x (c+n)H` matrix `B_phi,d` whose columns are coefficient vectors of `g_j*t` and `h_i*t` for every multiplier monomial t. Let `e0` be the vector for the constant polynomial 1.

**Build (classical PPT for polynomial M,H):** sample the intended native signing tape K and genuinely derived native verification key vk (native PQ scheme and Bitcoin output are presently **conditional**, not implemented), encode each tape digit `mu` as a bit, sample independent `r <- uniform(F_q^((c+n)H))`, `e <- uniform([-eta,eta]^M)`; publish `C_mu = B*r + Delta*mu*e0 + e (mod q)`. Manifest binds x, vk, public parameters, capsule/claim/branch and all related-capsule identities. Builder does not require the ORIGINAL witness. Large evidence stays off chain.

**Lift:** verify ORIGINAL evidence and extend to Boolean assignment w. Construct `lambda_w=(monomial(w))` in the coefficient basis. Decode each `lambda_w^T C_mu` to the nearest circular center 0 or Delta, recover identical K, reconstruct/verify native vk and sign only the intended native challenge path.

**Proved every-witness correctness:** `lambda_w^T B=0` and `lambda_w^T e0=1` for *every* valid ORIGINAL witness, even when distinct witnesses have distinct states. Hence `lambda_w^T C_mu=Delta*mu+lambda_w^T e (mod q)`, with absolute error at most M*eta. It decodes correctly if `M*eta < min(Delta,q-Delta)/2`. This is an unconditional algebraic theorem, **not** a hard-TRUE key-hiding proof. Example q=65537, Delta=32768, eta=1, M<=56 is only an unassessed test setting, not 128-bit PQ security.

## NEW exact false-instance full-public ciphertext theorem (restricted and independent)
Call an adversarial FALSE formula degree-d refutable if the constant polynomial lies in the span of the above public masking columns: there is an efficiently checkable t with `B*t=e0`. Equivalently `1=sum_j Q_j*g_j+sum_i T_i*h_i` with multipliers degree <=d over F_q.

For every protected bit mu, the exact change of variables `r'=r+Delta*mu*t` is a bijection on the *uniform* coefficient-mask coins, and
`B*r+Delta*mu*e0+e = B*r'+e`.
Therefore ciphertexts are **statistically IDENTICAL for all K**, with no lattice hardness assumption, even for polynomially many related *unopened* capsules sharing K, provided each uses independent r and e. This holds jointly with genuine native vk, contextual checking keys, manifests and even a correlated QPT auxiliary register depending on x,K,vk, so long as that public/quantum auxiliary information is independent of the fresh r/e coins and is otherwise generated exactly. The equality is of the entire joint classical/quantum state, not a marginal ciphertext game. Thus arbitrary coherent QPT processing of this particular false view gains nothing from the capsules over the prior vk/auxiliary view. If the *remaining* metadata/auxiliary is simulatable from genuine vk, context and allowed classical native signing-oracle queries, recovered usable private tape or a fresh accepted native signature reduces straight-line to an independently QPT-EUF-CMA-secure native-signature forgery. This last clause is conditional on an actual QPT-EUF-CMA native scheme, not an invented SOURCE release assumption.

No promise about auxiliary leakage of r/e, arbitrary adaptive challenge-capsule opening, coherent opening-oracle queries, or same-K opened related capsules is made. Releasing opening randomness may disclose K. A checking key that itself reveals K cannot be hidden by this ciphertext theorem; native EUF security is independently required.

## Explicit deterministic adversarial-FALSE break
Take the following FALSE 3CNF on four variables, all 16 assignments unsatisfying:
`(!z3|z1|!z2)&(z0|z3|z2)&(z2|z0|!z3)&(z3|!z2|!z1)&(z1|!z0|z3)&(!z1|z2|!z0)&(!z2|!z3|!z1)&(z1|!z2|z3)&(z2|!z3|!z0)`.
At degree d=0 the publicly computed functional `L(P)=[constant]P - [z0*z2]P` annihilates every `g_j` and `h_i`, while `L(1)=1`. Therefore from the public ciphertext alone `L(C_mu)=Delta*mu+e_constant-e_(z0*z2)`, and error is **always** <=2eta. At the example parameters, **every** FALSE ciphertext reveals mu without a witness. The exact executed checker confirmed 1024/1024 such recoveries. This violates universal FALSE confidentiality and therefore disqualifies the candidate as a generic WKEM.

**Bounded repair and remaining barrier:** At degree d=1, the same nine-clause FALSE gains a publicly checkable unit refutation and hence the exact hiding theorem; degree d=2 also works. But the distinct FALSE six-clause parity cycle `z0=z1, z1=z2, z0!=z2` has no certificate at d=0 or d=1 (one appears at d=2). Lack of a degree-d certificate is NOT by itself a successful key-recovery attack. A certificate-only Build admission policy cannot be a generic-NP compiler: for TRUE statements `lambda_w^T B=0, lambda_w^T e0=1` makes such a certificate impossible, so the rule would reject all legitimate TRUE instances. The size M grows combinatorially with d.

**Not established:** B is the explicit highly structured polynomial-ideal matrix, not a uniform ordinary-QPT-LWE public key; Run 122's ordinary LWE pad hybrid does not apply automatically. Arbitrary hard-TRUE key recovery need not return a short linear representation; no honest-public-view QPT challenge simulator for source-dependent checking keys, proofs, auxiliary inputs, adapted related capsules or selected openings has been instantiated. No recovery-to-ORIGINAL-witness theorem, fully malicious unknown-one-honest N-of-N setup/abort proof, keyless builder, concrete 128-bit PQ parameters, operational DA/observation or native Bitcoin PQ endpoint has been established. Do not deploy or fund using this source.

## Executed reproducible checker
The following **self-contained checker function** was executed twice in the connected JavaScript execution runtime with byte-identical results; it requires only standard JavaScript and the appended Node entrypoint. It checks multi-witness correctness, the exact false-capsule random-coin coupling, nine-clause FALSE unauthorized recovery, and the degree repair/certification gap. It is a finite algebra check **not** a QPT test.

```javascript
const checker = function checker(){
  const q=65537,delta=32768,eta=1;let assertions=0,seed=2026110219;
  const ck=(b,m)=>{assertions++;if(!b)throw Error("assertion: "+m)};
  const mod=x=>((x%q)+q)%q;
  const rnd=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed};
  const randint=n=>rnd()%n;
  const monoms=(n,D)=>{
    let a=[];const go=(p)=>{if(p.length===n){if(p.reduce((u,v)=>u+v,0)<=D)a.push(p);return}for(let v=0;v<=D;v++)go([...p,v])};go([]);
    return a.sort((x,y)=>x.reduce((a,b)=>a+b,0)-y.reduce((a,b)=>a+b,0)||x.findIndex((v,i)=>v!==y[i])===-1?0:0);
  };
  // Total-degree then lexicographic sorting; constant monomial is always first.
  const sorted=(n,D)=>{let a=monoms(n,D);a.sort((x,y)=>{let d=x.reduce((u,v)=>u+v,0)-y.reduce((u,v)=>u+v,0);if(d)return d;for(let i=0;i<n;i++){if(x[i]!==y[i])return x[i]-y[i]}return 0});return a};
  const polyMul=(a,b)=>{let out=new Map();for(let [u,x] of a)for(let [v,y] of b){let k=u.map((p,i)=>p+v[i]).join(",");out.set(k,(out.get(k)||0)+x*y)}return new Map([...out].filter(([k,v])=>v!==0).map(([k,v])=>[k.split(",").map(Number),v]))};
  // Map key identity of arrays is inconvenient; canonical-key multiplication instead.
  const mul=(a,b)=>{let out={};for(let [k,x] of Object.entries(a))for(let [l,y] of Object.entries(b)){let u=k.split(",").map(Number),v=l.split(",").map(Number);let s=u.map((p,i)=>p+v[i]).join(",");out[s]=(out[s]||0)+x*y}return Object.fromEntries(Object.entries(out).filter(([k,v])=>v))};
  const source=(n,clauses,d)=>{
    let basis=sorted(n,d+3),shifts=sorted(n,d),ix=new Map(basis.map((e,i)=>[e.join(","),i])),zero=Array(n).fill(0);
    let gs=clauses.map(cl=>{
      let p={[zero.join(",")]:1};
      for(let [v,pos] of cl){let ex=zero.map((_,i)=>Number(i===v)),f=pos?{[zero.join(",")]:1,[ex.join(",")]:-1}:{[ex.join(",")]:1};p=mul(p,f)}
      return p;
    });
    for(let i=0;i<n;i++){let e=zero.map((_,j)=>Number(i===j)),e2=e.map(v=>v*2);gs.push({[e2.join(",")]:1,[e.join(",")]:-1})}
    let cols=[];
    for(let g of gs)for(let s of shifts){let c=Array(basis.length).fill(0);for(let [key,v] of Object.entries(g)){let k=key.split(",").map(Number).map((x,i)=>x+s[i]).join(",");c[ix.get(k)]+=v}cols.push(c)}
    return {basis,cols};
  };
  const power=(x,e)=>{let a=1;x=mod(x);while(e){if(e&1)a=mod(a*x);x=mod(x*x);e=Math.floor(e/2)}return a};
  const solve=(rows,rhs)=>{
    let M=rows.map((row,i)=>[...row.map(mod),mod(rhs[i])]),n=M[0].length-1,piv=[],r=0;
    for(let j=0;j<n;j++){
      let p=-1;for(let i=r;i<M.length;i++){if(M[i][j]){p=i;break}}if(p<0)continue;
      [M[p],M[r]]=[M[r],M[p]];let inv=power(M[r][j],q-2);M[r]=M[r].map(x=>mod(x*inv));
      for(let i=0;i<M.length;i++)if(i!==r&&M[i][j]){let a=M[i][j];M[i]=M[i].map((x,k)=>mod(x-a*M[r][k]))}
      piv.push(j);r++;if(r===M.length)break;
    }
    for(let row of M)if(row.slice(0,n).every(x=>x===0)&&row[n])return null;
    let ans=Array(n).fill(0);for(let i=0;i<piv.length;i++)ans[piv[i]]=M[i][n];return ans;
  };
  const cert=({basis,cols})=>solve(basis.map((_,i)=>cols.map(c=>c[i])),basis.map((_,i)=>Number(i===0)));
  const Bmul=(cols,r,m)=>{let v=Array(m).fill(0);for(let j=0;j<cols.length;j++)for(let i=0;i<m;i++)v[i]=mod(v[i]+cols[j][i]*r[j]);return v};
  const build=(S,mu)=>{let {basis,cols}=S,m=basis.length,r=cols.map(()=>randint(q)),e=basis.map(()=>randint(3)-1),C=Bmul(cols,r,m);for(let i=0;i<m;i++)C[i]=mod(C[i]+e[i]+(i===0?delta*mu:0));return {r,e,C}};
  const inner=(a,b)=>mod(a.reduce((u,x,i)=>u+x*b[i],0));
  const distance=(a,b)=>{let x=mod(a-b);return Math.min(x,q-x)};
  const decode=t=>distance(t,0)<distance(t,delta)?0:1;
  const assignments=n=>{let a=[];for(let v=0;v<(1<<n);v++)a.push(Array.from({length:n},(_,i)=>(v>>i)&1));return a};
  const sat=(clauses,w)=>clauses.every(cl=>cl.some(([i,pos])=>Boolean(w[i])===pos));
  const ev=(basis,w)=>basis.map(t=>t.every((e,i)=>e===0||Boolean(w[i]))?1:0);
  const trueClauses=[[[0,true],[1,true],[2,true]],[[0,false],[1,true],[2,true]],[[0,true],[1,false],[2,true]]];
  let truth=[];
  for(let d=0;d<=2;d++){
    let S=source(3,trueClauses,d),ws=assignments(3).filter(w=>sat(trueClauses,w));
    ck(ws.length===5,"five valid assignments");ck(cert(S)===null,"true ideal no unit certificate");
    for(let w of ws){let l=ev(S.basis,w);ck(l[0]===1,"constant eval");for(let col of S.cols)ck(inner(l,col)===0,"vanishing ideal")}
    for(let mu of [0,1])for(let trial=0;trial<64;trial++){
      let {C,e}=build(S,mu);
      for(let w of ws){let l=ev(S.basis,w),t=inner(l,C),noise=l.reduce((a,x,i)=>a+x*e[i],0);
        ck(Math.abs(noise)<=S.basis.length*eta,"honest noise");
        ck(mod(t-delta*mu-noise)===0,"true lift equation");
        ck(decode(t)===mu,"SAME key every witness");
      }
    }
    truth.push({d,monomials:S.basis.length,witnesses:ws.length,checked_bits:128});
  }
  const contradiction=[[[0,true],[0,true],[0,true]],[[0,false],[0,false],[0,false]]];
  let certified=[];
  for(let d=0;d<=2;d++){
    let S=source(2,contradiction,d),t=cert(S);
    ck(assignments(2).every(w=>!sat(contradiction,w)),"false contradictory formula");
    ck(t!==null,"explicit refutation coefficient vector");
    let unit=Bmul(S.cols,t,S.basis.length);ck(unit.every((x,i)=>x===Number(i===0)),"B*t=e0");
    for(let key=0;key<16;key++)for(let digit=0;digit<8;digit++)for(let j=0;j<3;j++){
      let mu=(key>>digit)&1,{r,e,C}=build(S,mu);
      let rs=r.map((x,i)=>mod(x+delta*mu*t[i])),Cp=Bmul(S.cols,rs,S.basis.length).map((x,i)=>mod(x+e[i]));
      ck(Cp.every((x,i)=>x===C[i]),"whole public ciphertext exact coupling");
    }
    certified.push({d,monomials:S.basis.length,related_couplings:384});
  }
  const false9=[
    [[3,false],[1,true],[2,false]],[[0,true],[3,true],[2,true]],
    [[2,true],[0,true],[3,false]],[[3,true],[2,false],[1,false]],
    [[1,true],[0,false],[3,true]],[[1,false],[2,true],[0,false]],
    [[2,false],[3,false],[1,false]],[[1,true],[2,false],[3,true]],
    [[2,true],[3,false],[0,false]]
  ];
  ck(assignments(4).every(w=>!sat(false9,w)),"nine-clause false");
  let S=source(4,false9,0),l=Array(S.basis.length).fill(0),idx=S.basis.findIndex(m=>m.join(",")==="1,0,1,0");
  ck(idx>=0,"target monomial exists");l[0]=1;l[idx]=-1;
  ck(cert(S)===null,"degree-0 has no refutation");
  ck(S.cols.every(c=>inner(l,c)===0),"public norm-two pseudo-evaluation");
  let leaks=0;
  for(let mu of [0,1])for(let j=0;j<512;j++){
    let {C,e}=build(S,mu),t=inner(l,C),noise=e[0]-e[idx];
    ck(Math.abs(noise)<=2,"pseudo norm-two noise");
    ck(mod(t-delta*mu-noise)===0,"witness-free FALSE release equation");
    ck(decode(t)===mu,"FALSE recovered capability bit");leaks++;
  }
  for(let d of [1,2])ck(cert(source(4,false9,d))!==null,"increased degree repairs this false");
  const pair=(a,sa,b,sb)=>[[a,sa],[b,sb],[b,sb]];
  const parity=[
    pair(0,false,1,true),pair(0,true,1,false),
    pair(1,false,2,true),pair(1,true,2,false),
    pair(0,true,2,true),pair(0,false,2,false)
  ];
  ck(assignments(3).every(w=>!sat(parity,w)),"parity false");
  let degreeGap=[];
  for(let d=0;d<=2;d++){let got=cert(source(3,parity,d))!==null;ck(got===(d===2),"varying refutation degree");degreeGap.push({d,certified:got})}
  return {id:"MINK-BOOLEAN-IDEAL-SOURCE-R19",q,delta,eta,assertions,pass:true,true_source:truth,rank_certified_false:certified,false9_break:{degree:0,short_dual_l1:2,recovered_bits:leaks},parity_false_gap:degreeGap,limitations:"NOT arbitrary-NP false security; NOT a structured-LWE QPT challenge simulator or recovered-key-to-ORIGINAL extractor"};
};
console.log(JSON.stringify(checker(),null,2));

```

Captured identical output of both executions:

```json
{
  "id": "MINK-BOOLEAN-IDEAL-SOURCE-R19",
  "q": 65537,
  "delta": 32768,
  "eta": 1,
  "assertions": 10474,
  "pass": true,
  "true_source": [
    {
      "d": 0,
      "monomials": 20,
      "witnesses": 5,
      "checked_bits": 128
    },
    {
      "d": 1,
      "monomials": 35,
      "witnesses": 5,
      "checked_bits": 128
    },
    {
      "d": 2,
      "monomials": 56,
      "witnesses": 5,
      "checked_bits": 128
    }
  ],
  "rank_certified_false": [
    {
      "d": 0,
      "monomials": 10,
      "related_couplings": 384
    },
    {
      "d": 1,
      "monomials": 15,
      "related_couplings": 384
    },
    {
      "d": 2,
      "monomials": 21,
      "related_couplings": 384
    }
  ],
  "false9_break": {
    "degree": 0,
    "short_dual_l1": 2,
    "recovered_bits": 1024
  },
  "parity_false_gap": [
    {
      "d": 0,
      "certified": false
    },
    {
      "d": 1,
      "certified": false
    },
    {
      "d": 2,
      "certified": true
    }
  ],
  "limitations": "NOT arbitrary-NP false security; NOT a structured-LWE QPT challenge simulator or recovered-key-to-ORIGINAL extractor"
}
```

## Provenance and exact unfinished equation
Run label R19; local extended independent Python-standard-library checker ran twice with byte-identical JSON and **8,999 assertions each**. That extended executable and output, and this run's full research derivation, are also preserved in a downloadable offline archive; they are not falsely described as identical to the JavaScript checker here. No independent agent or external literature was invoked. This single-file research publication uses GitHub's authorized contents API because the connected commit reader does not expose a base tree SHA required for a coherent guarded Git-tree commit; a preliminary dangling tree attempt failed HTTP 422 Invalid tree info. No forced update, production file or workflow write is authorized.

**Next required equations:** construct generic polynomial-time Build/Lift and a genuine source-dependent public-output simulator `Sim(R,x,C,vk,ck,aux,related)` covering *every adversarial FALSE ORIGINAL x* without the source challenge secret, and an arbitrary QPT `RecoverKey/ForgeNative -> ORIGINAL witness OR independently justified PQ break` theorem on hard-TRUE x. Rank-certified false hiding alone is not a universal source release construction.
