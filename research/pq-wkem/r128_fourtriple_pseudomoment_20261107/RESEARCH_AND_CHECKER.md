# R128 — Four-triple degree-three pseudo-moment ORIGINAL source
Run: R128-FOURTRIPLE-DEG3-PSEUDOMOMENT-20261107. Result: rejected candidate; no original-witness security advance and no user-facing ordinary comment. Research-only negative checkpoint.

## Continuity
PR syscoin/PVUGC#1 was open/draft/unmerged on research/pq-wkem-validation-20260918, initially cd78e33b965ea17b5f0e2148847151045a354e8e. Read the current PR metadata and latest ordinary issue comments (including 6698876958), and exact R127 source research file blob 274601b846df3bc9de44aa48d480820cf80ed01f. Guessed R126 source path gave 404, not substituted. No outside internet research. No entire PR diff or archive sweep.

## Candidate, exact source setup and all-valid-witness correctness
Original relation is Boolean six-variable 3-XOR sign equations
abc=1, ade=1, bdf=1, cef=-1, with a,b,c,d,e,f in {-1,1}.
Every variable occurs in exactly two equations. Multiplying the equations gives 1=-1; ORIGINAL instance is FALSE.

Use feature vector φ(w) indexed by all monomials of degree at most 3 in six signs, N=1+6+15+20=42. Define A as the five standard-basis row selectors for empty, abc, ade, bdf, cef, with δ=(1,1,1,1,-1). For every valid ORIGINAL witness, Aφ(w)=δ and ||φ(w)||_1=42. Honest classical Build samples q=179, Δ=floor(q/2)=89, r uniform Z_q^5, e uniform {-1,0,1}^42 independently, e0 uniform {-1,0,1}, B uniform {0,1}; publishes statement/relation, A, δ, U=A^T r+e (mod q), V=δ^T r+e0+BΔ (mod q), plus any derived public fields. Honest Open(w) computes z=φ(w) and nearest-center-decodes V-z^T U at centers 0 and Δ. For any satisfying w, the residual is BΔ+e0-z^T e and its absolute noise is <=43<Δ/2=44.5, hence EVERY supported tape and EVERY valid witness recovers the identical B. This correctness implication is vacuous on the chosen FALSE instance; it does not prove security.

## Direct public FALSE release, local positive-semidefinite repair tested
Take a publicly computable vector z* with z_empty=1, z_abc=z_ade=z_bdf=1, z_cef=-1 and every other degree<=3 moment zero. Then Az*=δ, ||z*||_1=5, ||z*||_2^2=5. Anyone can compute V-(z*)^T U=BΔ+e0-(z*)^T e modulo q. Its absolute noise is bounded by 6, so nearest-center decoding reveals B on EVERY source tape even though there is NO original witness. No adversary-supplied representation or LWE break is necessary. A nominal check in Open rejecting z* cannot stop raw public algebraic evaluation.

Attempted degree-one moment-matrix positivity repair: M1 indexed by {1,a,b,c,d,e,f}, with entries z_{u△v}. Because all degree-one and degree-two moments of z* vanish and z_empty=1, M1=I_7. It is strictly positive definite. Therefore degree-one local PSD enforcement and multilinear Boolean identities do not exclude this false release. Higher-degree or cryptographically nonlinear barriers are uninstantiated; do NOT describe them as repairs. Even a full public CK/context/Aux/related-capsule simulator cannot rescue false security once the source marginal itself publishes a deterministically recoverable bit. This is NOT a no-go for WE in general.

## Exact executable checker and captured result
The JavaScript function below was executed once in the connected V8 isolate, and its return value was captured verbatim below. It verifies original FALSE by exhaustive 64 assignments, the actual degree-three source algebra, moment PSD, 2048 source draws and public false release. Its deterministic xorshift sampler is only for reproducible finite tests, NOT a source of quantum hardness or a proof of a true uniform crypto sampler. The real source law is specified above. A separate independent LOCAL stdlib Python checker, NOT published with this file, ran 2048 source samples and all the algebra. It is saved in a local R128 directory with SHA256 checker f565bcf9fa1785cc2de84f8980ee74b5b4463a682dff8b3dc5d4f4c515dbcfb4; output hash f9ccd8c1ce3ead005c03ebefd9eab6a9bf09c3109c2b67f5053d0c5d581bf593.

```javascript
function r128_js_checker(){
  let checks=0; const ok=(condition,msg)=>{checks++;if(!condition)throw Error("check "+checks+" "+msg)};
  const n=6, triples=[[0,1,2],[0,3,4],[1,3,5],[2,4,5]], rhs=[1,1,1,-1];
  const features=[[]];
  function visit(start,k,arr){if(arr.length===k){features.push([...arr]);return};for(let i=start;i<n;i++)visit(i+1,k,[...arr,i])}
  for(let k=1;k<=3;k++)visit(0,k,[]);
  ok(features.length===42,"degree-three feature count");
  const idx=F=>features.findIndex(S=>S.length===F.length && S.every((x,i)=>x===F[i]));
  const rows=[idx([]),...triples.map(T=>idx(T.slice().sort((a,b)=>a-b)))]
  const delta=[1,...rhs];
  ok(rows.every(i=>i>=0),"exact row selectors");
  const z=Array(42).fill(0);rows.forEach((i,j)=>z[i]=delta[j]);
  ok(z.reduce((a,v)=>a+Math.abs(v),0)===5,"false l1");
  ok(z.reduce((a,v)=>a+v*v,0)===5,"false l2");
  for(let bits=0;bits<64;bits++){
    const w=Array.from({length:6},(_,i)=>(bits>>i)&1 ? 1:-1);
    const sat=triples.every((T,j)=>T.reduce((v,i)=>v*w[i],1)===rhs[j]);
    ok(!sat,"false ORIGINAL for all assignments");
  }
  // Degree-one local PSD moment matrix on indices empty and singletons is identity.
  for(let i=0;i<=n;i++)for(let j=0;j<=n;j++){
    const prod=i===0?(j===0?[]:[j-1]):j===0?[i-1]:(i===j?[]:[Math.min(i,j)-1,Math.max(i,j)-1]);
    const entry=z[idx(prod)];
    ok(entry===Number(i===j),"M1 is identity, so positive definite");
  }
  const q=179,D=89;ok(D/2>43 && D/2>6,"all-tape rounding");
  let seed=128007|0;
  function u32(){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0}
  function rand(m){return u32()%m}
  const mod=x=>(x%q+q)%q;
  const dist=(x,y)=>{const t=mod(x-y);return Math.min(t,q-t)};
  for(let k=0;k<2048;k++){
    const r=Array.from({length:5},()=>rand(q));
    const e=Array.from({length:42},()=>rand(3)-1);
    const e0=rand(3)-1,bit=rand(2);
    const U=e.map((ee,i)=>mod(ee+rows.reduce((v,row,j)=>v+(row===i?r[j]:0),0)));
    const V=mod(delta.reduce((v,d,j)=>v+d*r[j],0)+e0+bit*D);
    const t=mod(V-z.reduce((v,zz,i)=>v+zz*U[i],0));
    const got=dist(t,0)<dist(t,D)?0:1;
    ok(got===bit,"FALSE public recovery without witness");
    ok(Math.abs(e0-z.reduce((v,zz,i)=>v+zz*e[i],0))<=6,"exact bounded noise");
  }
  return {run:"R128-FOURTRIPLE-DEG3-PSEUDOMOMENT-20261107",checks,original_false_assignments:64,
    degree_three_features:features.length,public_false_vector_support:rows.length,
    false_vector_l1:5,false_vector_l2_squared:5,one_local_PSD:"I_7",
    source_q:q,offset:D,genuine_coin_cases:2048,false_open_failures:0,
    all_tape_proof:"Az*=δ, |e0-z*.e|<=6<44.5=Delta/2",
    status:"rejected; no security advance; QPT-LWE not broken"};
}
console.log(JSON.stringify(r128_js_checker(),null,2));
```

Captured first execution:
```json
{
  "run": "R128-FOURTRIPLE-DEG3-PSEUDOMOMENT-20261107",
  "checks": 4214,
  "original_false_assignments": 64,
  "degree_three_features": 42,
  "public_false_vector_support": 5,
  "false_vector_l1": 5,
  "false_vector_l2_squared": 5,
  "one_local_PSD": "I_7",
  "source_q": 179,
  "offset": 89,
  "genuine_coin_cases": 2048,
  "false_open_failures": 0,
  "all_tape_proof": "Az*=δ, |e0-z*.e|<=6<44.5=Delta/2",
  "status": "rejected; no security advance; QPT-LWE not broken"
}
```

## Fundamental gap/handoff
Reject this low-degree public-moment SOURCE. It has neither FALSE full-public security nor arbitrary hard-TRUE recovery->ORIGINAL-witness extraction. It is not justified by ordinary QPT-LWE despite its modular arithmetic. Next actual candidate must have a non-linear, cryptographically *hidden* discriminator at the level of capability recovery, instantiate its true setup and all witness openings together with a full-public straight-line QPT-LWE simulator (relation, statement, checking key, context, auxiliary fields and related capsules), recover the identical frozen native signature from ANY ORIGINAL witness and extract an actual ORIGINAL witness or independently break a PQ primitive from ANY unauthorized QPT final-key recovery/native forgery, without demanding an internal representation. Do not substitute ordinary WE/iO as an assumption, online release authority, signer oracle, or code availability/size optimization. Nothing here establishes malicious N-of-N setup, endpoint availability, or 128-bit calibrated QPT security.
