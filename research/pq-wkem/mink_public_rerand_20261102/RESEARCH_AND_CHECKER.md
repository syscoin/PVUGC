# MINK-PUBLIC-RERAND-R22 — Same-scope related SOURCE capsules by public rerandomization

**Research only, 2026-11-02. NOT a secure generic post-quantum witness-KEM.**

Predecessor: R21 Boolean-quotient SOURCE (file blob f94e7fc6332a93b345f9357bdd8e019492c42f34). Prior R20 simulated publicly degree-certified FALSE instances with genuine native vk and an explicitly public-G generator, but only for independently randomized unopened related capsules. This iteration instantiates a stronger related-capsule interface without any SourceOpen oracle or additional cryptographic assumption.

## Concrete classical-PPT algorithms

For immutable ORIGINAL relation/statement x (relation identity, claim/UTXO, branch, anchors/window, native vk and challenge path), R21 computes a public square-free Boolean-quotient matrix B_x of M rows and L columns. Each bit mu of the precommitted native signing tape K has base ciphertext

C_0 = B_x r_0 + Delta * mu * e_const + eps (mod q),

where r_0 is uniform in F_q^L, e_const=(1,0,...,0), and eps has independent bounded coordinates |eps_i|<=eta. KeyGen's genuine correlated vk, base checking key, source capsule, public context and whatever auxiliary data exist are in the **authenticated base view**. This does not make the unpublished native PQ endpoint a deployed feature.

New public, noninteractive DeriveSameScope(base, public_index, public_salt): compute an arbitrary public coefficient vector u = Expand(exact_base_scope, authenticated_base_identity, public_index, public_salt, bit_index) in F_q^L and output C_j = C_0 + B_x*u (mod q). The validator checks the exact immutable scope and equality of the derived vector; it rejects changes in claim, UTXO, intended native vk, branch, anchors/window, original relation, and path. The base must already be authenticated by the N-of-N preauthorization graph. The expansion is **public and does not require PRG/RO security**, because all derived data are public functions of the base. Uniform u is optional; a compact deterministic salt is also safe as *postprocessing*, but does NOT produce independent uniform r_j. Nothing creates a new underlying secret, opening, online committee, or preauthorization edge.

Every valid ORIGINAL witness w extends to its own Boolean satisfying assignment a, with evaluator lambda_a satisfying lambda_a^T B_x=0 and lambda_a^T e_const=1. Thus, as an **exact field identity**, for all j:

lambda_a^T C_j = lambda_a^T C_0 = Delta*mu + lambda_a^T eps (mod q).

With M*eta < min(Delta,q-Delta)/2, every valid ORIGINAL witness obtains the SAME precommitted K; for each fixed witness its raw extracted field value is even identical across all related capsules. Distinct witnesses need not share a state or preimage.

## Full-related-public-output reduction, arbitrary QPT

Let the single-base challenger publish *all* public data V_mu=(R,x,base capsule,checking key, genuine native vk, authenticated context, auxiliary, associated source data), together with any joint quantum auxiliary register E_mu. These may be correlated in arbitrary ways in the **base** game. This construction does NOT assert that the single-base games for mu=0,1 are indistinguishable; the all-FALSE and hard-TRUE obligations are still open.

The complete related-capsule view is a **classical efficiently computable channel** T(V_mu,U) using publicly chosen offsets/salts U independent of unrevealed secret information, with any derived checking data restricted to public deterministic G(V_mu,U). Every classical adaptive derived-capsule request, including adversarially selected public u, can be answered by a simulator knowing V_mu alone. For a deterministic public derivation oracle and quantum-coherent queries, the QPT simulator can implement the same reversible public function on superposed indices. Quantum auxiliary E_mu is simply carried through unchanged.

Consequently, for *any* QPT distinguisher, recovered-capability algorithm or native-signature forger A, an equally successful QPT single-base algorithm A' runs A on T(V_mu,U), exactly:

Pr[A(Extend(V_mu,E_mu)) wins] = Pr[A'(V_mu,E_mu) wins]

for each mu and for any polynomial number of public derivations. This exact theorem involves **no special quantum lifting of rewinding**, no challenge-secret source opener, and no unproved extractor. It preserves *whatever* single-base security or insecurity is present; it does not supply single-base security. Fresh secret-bearing signatures, new malicious per-capsule verification keys or secret-correlated private opening oracles are **not** covered; derived checking data must be public-only or already present in V_mu. Existing native signing oracles and their query rules are inherited from the base game without being silently enlarged.

## Restricted FALSE full-joint simulator

If R21's FALSE source has a publicly checkable degree-d refutation vector t with B_x*t=e_const, then for each bit

C_0 = B_x*(r_0+Delta*mu*t)+eps,

where r'_0=r_0+Delta*mu*t is exactly uniform under R21/R20's authorized public-G/auxiliary independence assumptions. Every related capsule simultaneously satisfies

C_j = B_x*(r'_0+u_j)+eps.

The complete base-plus-derived public transcript is **identically distributed** to a simulator that uses the genuine native vk and public G, but never knows mu or the signing tape. Correlated quantum postprocessing cannot distinguish identical classical/quantum ensembles. This improves the related-capsule composition for the R20/R21 *publicly certified FALSE* class, without broadening the class. In an optional uniform-u mode, the algebraic masks r_0,r_0+u_1,... are IID uniform **while the noise eps is deliberately the same** across these same-scope capsules (an invertible triangular transformation). A compact deterministic-u mode has no IID-mask claim; it still satisfies the exact postprocessing theorem.

## Selective opening / graph / scope boundaries

Publishing u/salt is safe, but revealing underlying r_0 or eps, or a private opening of ANY same-scope capsule, is unsafe before authorized release: from C_j - B_x*r_j = Delta*mu*e_const+eps the constant coordinate immediately reveals mu. This is not pre-release selective-opening security. Deliberate same-scope opening after legitimate whole-UTXO settlement is allowed declassification. Opening unrelated independently generated claim scopes adds no leakage *from public derivation* beyond whatever the original base multi-scope game already leaks; independent multi-scope security still needs proof.

N-of-N preauthorization must cover the full authenticated base plus this derivation rule, and the one honest participant must exclude bypass paths and erase/protect any source/native signing secrets before irrevocable funding. This theorem does not prove unknown-one-honest malicious setup, abort/liveness or pre-signature DA. A derived pointer is **not** new base data availability. Bitcoin's eventual contract challenge path still needs only an ordinary native PQ signature, conditionally on a future compatible no-EC-key-path output; Bitcoin does not run NP proofs, a VM, PCP or trace disputes.

## Resource note and security limits

For R21's toy n=4,c=9,d=1,q=65537: M=16,L=45, so one 256-bit signing-tape base is 256*16*17/8=8704 bytes of field-packed ciphertext, excluding all metadata, native vk and signatures. A derived **pointer plus public 32-byte salt/index** reconstitutes a same-scope capsule. The 32-byte salt alone is 272x smaller than a copied 8704-byte base; this excludes pointer/framing/DA and is not a 128-bit security estimate. Sparse multiplication needs O(8*L+M) field operations per bit for a distinct-variable 3CNF. The executable checkers use smaller deterministic public seeds; their unpredictability is not relied on.

**Unsolved, and not repaired here:** R19/R21's degree-zero adversarial FALSE classically leaks K; the structured B is not an ordinary-LWE challenger matrix; generic-NP polynomial-size all-FALSE confidentiality and arbitrary hard-TRUE recovery/native forgery => ACTUAL ORIGINAL witness or independent QPT break remain absent. Real QPT native signing, adverse checking-key/aux correlations, N-of-N graph and abort, keyless Build, claim-specific bearer/owner authorization, public BTC/SYS proof bounds, and concrete 128-bit resources remain unestablished. A successful attack on the base is automatically a successful attack on its derivatives. No native/private witness extractor is asserted.

**Next exact missing equation:** a classical-PPT generic-NP base Build(R,x,K), Lift(R,x,C,w)=K for every ORIGINAL witness, plus a jointly instantiated source setup/opening and QPT challenger simulator of the *single* authenticated base public view for every FALSE x; then an arbitrary unauthorized hard-TRUE recovered-key/native-forgery reduction to ORIGINAL witness or independently justified post-quantum break.

## Exact execution and provenance

Run MINK-PUBLIC-RERAND-R22. GitHub PR #1 was read open/draft/unmerged on research/pq-wkem-validation-20260918 at b4d1771c754ed758007ea892a735ed0bc8d2954f. Latest substantive ordinary comment inspected: 6586845357. Authorized connector reads: get_pr_info, fetch_issue_comments, exact-version fetch_file and fetch_commit/fetch of exact Git commit/tree metadata. Bounded **local** standard-library Python checker ran twice with 6,378 checks per run, byte-identical outputs, in an extended local artifact. The independent pure-JavaScript checker below was **actually run** in the connector execution sandbox; its exact source and captured output follow. Finite tests establish algebra and public transcript identities, not QPT security, native signatures or live Bitcoin behavior. No external literature or web search.

## Exact executed standalone JavaScript checker

```javascript
'use strict';
function runChecker(){
  const q=65537,delta=32768,eta=1;let checks=0,seed=2026110222;
  const ok=(b,msg)=>{checks++;if(!b)throw Error("assert "+checks+": "+msg)};
  const md=x=>((x%q)+q)%q;
  const rnd=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed};
  const pop=x=>{let n=0;for(;x;x>>>=1)n+=x&1;return n};
  const masks=(n,d)=>Array.from({length:1<<n},(_,i)=>i).filter(x=>pop(x)<=d).sort((a,b)=>pop(a)-pop(b)||a-b);
  function multiply(P,Q){const R=new Map();for(const [a,x] of P)for(const [b,y]of Q){let k=a|b;R.set(k,md((R.get(k)||0)+x*y))}return R}
  function mat(n,clauses,d){
    let rows=masks(n,d+3),shifts=masks(n,d),ix=new Map(rows.map((m,i)=>[m,i])),cols=[];
    for(const clause of clauses){
      let g=new Map([[0,1]]);
      for(const [i,pos]of clause)g=multiply(g,pos?new Map([[0,1],[1<<i,q-1]]):new Map([[1<<i,1]]));
      for(const t of shifts){
        let c=Array(rows.length).fill(0);
        for(const [m,x]of g)c[ix.get(m|t)]=md(c[ix.get(m|t)]+x);
        cols.push(c)
      }
    }
    return{rows,shifts,cols,clauses,n}
  }
  const prod=(B,r)=>{let v=Array(B.rows.length).fill(0);B.cols.forEach((c,j)=>c.forEach((x,i)=>v[i]=md(v[i]+x*r[j])));return v};
  const add=(a,b)=>a.map((x,i)=>md(x+b[i]));
  const randR=B=>B.cols.map(()=>rnd()%q);
  const randE=B=>B.rows.map(()=>rnd()%3-1);
  const valid=(cs,a)=>cs.every(cl=>cl.some(([i,p])=>!!((a>>>i)&1)===p));
  const evaluate=(B,a,C)=>md(C.reduce((z,x,i)=>z+((B.rows[i]&a)===B.rows[i]?x:0),0));
  const centered=x=>{x=md(x);return x>q/2?x-q:x};
  const decode=z=>Math.abs(centered(z))<Math.abs(centered(z-delta))?0:1;
  // This is a deterministic, PUBLIC expansion, not a cryptographic PRG claim.
  function expand(salt,index,bit,len){
    let x=(salt^Math.imul(index+1,0x45d9f3b)^Math.imul(bit+1,0x27d4eb2d))>>>0,r=[];
    for(let i=0;i<len;i++){x=(Math.imul(x,1664525)+1013904223)>>>0;r.push(x%q)}
    return r;
  }
  const derive=(B,C,salt,j,bit)=>{let u=expand(salt,j,bit,B.cols.length);return{C:add(C,prod(B,u)),u}};
  const goodcs=[[[0,true],[1,true],[2,true]],[[0,false],[1,true],[2,true]],[[0,true],[1,false],[2,true]]];
  const B=mat(3,goodcs,1),good=Array.from({length:8},(_,a)=>a).filter(a=>valid(goodcs,a));
  ok(good.length===5,"five independent ORIGINAL witnesses");
  for(let bit=0;bit<32;bit++){
    const mu=rnd()&1,baseR=randR(B),e=randE(B);
    const C0=add(add(prod(B,baseR),B.rows.map((_,i)=>i===0?delta*mu:0)),e);
    for(const a of good)ok(decode(evaluate(B,a,C0))===mu,"base correctness");
    for(let j=0;j<12;j++){
      let salt=(bit*7537+j*3331+991)>>>0,{C,u}=derive(B,C0,salt,j,bit);
      let shadow=add(add(prod(B,baseR.map((x,i)=>md(x+u[i]))),B.rows.map((_,i)=>i===0?delta*mu:0)),e);
      ok(JSON.stringify(C)===JSON.stringify(shadow),"same-noise real/sim ciphertext");
      for(const a of good){
        ok(evaluate(B,a,C)===evaluate(B,a,C0),"exact unchanged per-witness extraction");
        ok(decode(evaluate(B,a,C))===mu,"all witnesses recover same K");
      }
      ok(JSON.stringify(derive(B,C0,salt,j,bit).C)===JSON.stringify(C),"public validation");
      if(j===0){
        let corrupted=C.slice();corrupted[0]=md(corrupted[0]+1);
        ok(JSON.stringify(corrupted)!==JSON.stringify(derive(B,C0,salt,j,bit).C),"reject changed ciphertext")
      }
    }
  }
  const falsecs=[[[0,false],[1,true],[1,true]],[[0,true],[1,false],[1,false]],[[1,false],[2,true],[2,true]],[[1,true],[2,false],[2,false]],[[0,true],[2,true],[2,true]],[[0,false],[2,false],[2,false]]];
  const F=mat(3,falsecs,1);
  ok(Array.from({length:8},(_,a)=>a).every(a=>!valid(falsecs,a)),"FALSE parity-cycle");
  const t=Array(F.cols.length).fill(0),s=F.shifts.length;
  for(const[j,m,v]of [[0,0,1],[0,4,-2],[1,0,-1],[1,4,2],[2,0,1],[3,0,1],[4,0,1],[5,0,1]])t[j*s+F.shifts.indexOf(m)]=md(v);
  ok(JSON.stringify(prod(F,t))===JSON.stringify([1,0,0,0,0,0,0,0]),"exact refutation B*t=e0");
  for(let b=0;b<64;b++){
    const mu=rnd()&1,r=randR(F),e=randE(F);
    const C0=add(add(prod(F,r),F.rows.map((_,i)=>i===0?delta*mu:0)),e);
    const r0=r.map((x,i)=>md(x+delta*mu*t[i]));
    ok(JSON.stringify(C0)===JSON.stringify(add(prod(F,r0),e)),"base perfect-hiding shift");
    for(let j=0;j<9;j++){
      const{C,u}=derive(F,C0,22201+b,j,b);
      const fake=add(prod(F,r0.map((x,i)=>md(x+u[i]))),e);
      ok(JSON.stringify(C)===JSON.stringify(fake),"joint no-key simulator");
    }
  }
  for(const smallQ of[2,3,5]){
    const masks=Array.from({length:smallQ},(_,i)=>i),set=new Set();
    for(const r of masks)for(const u of masks)for(const v of masks)set.add([r,(r+u)%smallQ,(r+v)%smallQ].join(","));
    ok(set.size===smallQ**3,"triangular uniform-mask bijection");
  }
  return{run:"MINK-PUBLIC-RERAND-R22",passed:true,checks,trueWitnesses:good.length,trueBits:32,derivedPerBit:12,falseCertificateCouplings:64*9,claim:"Exact source-to-derived postprocessing; base SOURCE security not proved"};
}
console.log(JSON.stringify(runChecker(),null,2));
```

## Captured output

```json
{
  "run": "MINK-PUBLIC-RERAND-R22",
  "passed": true,
  "checks": 5446,
  "trueWitnesses": 5,
  "trueBits": 32,
  "derivedPerBit": 12,
  "falseCertificateCouplings": 576,
  "claim": "Exact source-to-derived postprocessing; base SOURCE security not proved"
}
```
