# R135 — Full ORIGINAL residual gate with publicly evaluable mask (REJECTED)

**Status:** NO positive ORIGINAL-witness construction/security advance. Bounded offline iteration, no internet/literature research, no efficiency work. This is an internal supporting record, **not a positive PR milestone and not a user-facing alert**. Research-only continuity: syscoin/PVUGC#1 open/draft/unmerged, branch `research/pq-wkem-validation-20260918`, starting head `b4aace2462dec2f88d9b26039a18bdcd9fab4149`; direct previous R134 artifact at head was read.

## Precisely attempted repair to R134

R134's Boolean residual source leaked the frozen key through affine interpolation using only local one-hot probes. This trial attempts to stop that interpolation by masking **every** evaluator call except one that satisfies the complete ORIGINAL relation, including Booleanity, per-pair normalization and the clause rows.

Use the unchanged exact integer 3-CNF source compiler: `P_x r=t_x`, with `B=n+2m` selector pairs and `N=2B` coordinates. Every satisfying ORIGINAL assignment has a one-hot integer extension `r(w)`; distinct witnesses have distinct vectors. On the fixed FALSE formula of all eight forbidden 3-bit assignments, `B=19,N=38`, and an explicit signed, non-Boolean vector `z` derived from assignment 000 satisfies `P_x z=t_x`, `||z||_1=B+2`, without an ORIGINAL witness.

For odd q=65521, delta=(q-1)/2, choose a genuine scalar-LWE vector `g=A^T s+e` with independent bounded noise (or uniform g in the decisional challenge hybrid), independent small `eta`, `eta0`, a frozen bit K, and set:

```
u = P_x^T g + eta             (mod q)
v = t_x^T g + eta0 + delta K  (mod q)
Good_x(r) = [r is one-hot in every pair AND P_x r=t_x]
M_a(r) = 0 when Good_x(r); otherwise F_a(tag(r))
E_x(r) = v - <r,u> + M_a(r) (mod q)
```

The candidate makes F_a a public, computationally evaluable keyed pseudorandom mask; the finite checker uses a simple deterministic 32-bit keyed mixer **only as a functional fixture**, never as a cryptographic PRF. Genuine witness correctness is exact: for each `r(w)`, `M_a(r(w))=0` and `E_x(r(w))=delta K + eta0 - <r(w),eta>`. Under the tested bounds nearest-centre decoding returns the SAME frozen K for every distinct valid ORIGINAL witness.

The LWE source/challenge simulator jointly samples `A,g,eta,eta0,a` and computes the exact public evaluator and context from those values; it needs no SourceOpen oracle. This is **not** security of the full-public distribution: a public mask key a gives the adversary precisely the subtraction attack below, and a secret key hidden inside executable public code is not justified by ordinary LWE/PRF security. Public CK, Aux, native VK and sibling capsules were not independently instantiated by this candidate.

## Exact algebraic counterexample (not a hardness assumption break)

For any locally normalized one-hot baseline r0, let rb flip exactly the bth selector pair. All queries are local one-hot. Since the source includes the publicly evaluable gate key a, the adversary computes `L(rb)=E(rb)-M_a(rb)=v-<rb,u>` without knowing the hidden source coefficients. Define:

```
D0 = L(r0)
Db = L(rb)-L(r0) = -(u[b,1]-u[b,0])
T(z) = D0 + SUM_b z[b,1]*Db = v-<z,u>
```

The signed FALSE z satisfies pair normalization and Pz=t despite not being Boolean, so `T(z)=delta K+eta0-<z,eta>`. At q=65521 and eta_i,eta0 in {-1,0,1}, this is within 22 of the true K centre on every tape. A classical polynomial-time attacker recovers K from exactly B+1=20 **local one-hot queries** and never evaluates the invalid signed z. The failure holds whether g is a genuine toy LWE sample or uniform, and thus provides no break of QPT-LWE.

A claimed repair retaining a hidden PRF seed inside an ordinary public classical program exposes that seed upon inspecting the program. Encrypting it with genuine LWE-PKE hides the seed but also prevents an arbitrary ORIGINAL witness from evaluating the PRF or decrypting the source unless there is a new independently instantiated mechanism mapping every valid ORIGINAL witness to a decryption capability. That is the missing generic source release compiler, not an ordinary PRF/LWE consequence. Merely defining a secret-key oracle or ideal obfuscated Good-gated evaluator renames the security obligation and is not a construction.

## Handoff

Do **not** revisit public subtractable residual masks as a repair. A serious next candidate must instantiate an LWE-dependent **non-subtractable** source with honest classical-PPT Setup/Build and a public off-chain Eval `Eval(Pub_x,w)=sigma` for every valid ORIGINAL w, without making a setup secret recoverable from public code. It must simultaneously give an exact full-public QPT challenge simulator and handle arbitrary key recovery/native forgery -> an ACTUAL ORIGINAL witness or independent PQ break, including malicious setup, correlated CK/Aux/sibling capsules and selective openings. No extraction guarantee may rely on the adversary volunteering a representation. R135 does not narrow this fundamental gap; no quantum-security/calibrated 128-bit claim.

## Exact executed checker

The following function was executed twice in the connected V8 runtime with identical results, before Git-object creation. It uses a TOY d=4 LWE dimension; neither the mixer nor toy data provides cryptographic security evidence.

```javascript
function runCheck(){
  const q=65521,half=(q-1)/2,seed0=1351107;
  let seed=seed0, checks=0, attacks=0, valid=0;
  const rnd=n=>(seed=(Math.imul(seed,1664525)+1013904223)>>>0)%n;
  const mod=x=>((x%q)+q)%q;
  const ck=(v,label)=>{checks++;if(!v)throw Error("check "+checks+" "+label)};
  const dot=(a,b)=>a.reduce((s,x,i)=>s+x*b[i],0);
  const dist=x=>Math.min(mod(x),mod(-x));
  const decode=x=>Number(dist(x-half)<dist(x));
  const clauses=Array.from({length:8},(_,a)=>Array.from({length:3},(_,i)=>[i,((a>>i)&1)===0]));
  const sat=(a,c)=>c.every(cl=>cl.some(([i,p])=>((a>>i)&1)===Number(p)));
  function build(cl){
    const B=3+2*cl.length,N=2*B,P=[],t=[];
    function row(items,rhs){const r=Array(N).fill(0);for(const [i,v] of items)r[i]+=v;P.push(r);t.push(rhs);}
    for(let b=0;b<B;b++)row([[2*b,1],[2*b+1,1]],1);
    cl.forEach((c,j)=>row([...c.map(([i,p])=>[2*i+Number(p),1]),[2*(3+2*j)+1,-1],[2*(3+2*j+1)+1,-2]],1));
    return {B,N,P,t,cl};
  }
  function rep(a,cl){
    const B=3+2*cl.length,r=Array(2*B).fill(0);let bad=0;
    for(let i=0;i<3;i++)r[2*i+((a>>i)&1)]=1;
    cl.forEach((c,j)=>{
      const n=c.filter(([i,p])=>((a>>i)&1)===Number(p)).length;
      if(!n)bad++;
      const lo=n?((n-1)&1):-1,hi=n?((n-1)>>1):0;
      for(const [b,z] of [[3+2*j,lo],[3+2*j+1,hi]]){r[2*b]=1-z;r[2*b+1]=z;}
    });return {r,bad};
  }
  function publicHash(r,key){
    let h=(2166136261^key)>>>0;
    for(let i=0;i<r.length;i++){h=Math.imul((h^(r[i]+11+67*i)),16777619)>>>0;}
    return h%q;
  }
  const F=build(clauses),T=build(clauses.slice(0,4));
  ck(Array.from({length:8},(_,i)=>sat(i,F.cl)).every(x=>!x),"F false");
  ck(Array.from({length:8},(_,i)=>sat(i,T.cl)).filter(Boolean).length===4,"T four witnesses");
  function gate(r,S){
    const onehot=r.every((z,i)=>Number.isInteger(z)&&(z===0||z===1))&&
      Array.from({length:S.B},(_,b)=>r[2*b]+r[2*b+1]===1).every(Boolean);
    return onehot&&S.P.every((row,j)=>dot(row,r)===S.t[j]);
  }
  function oneTape(S,mode,K){
    const {B,N,P,t,cl}=S,M=P.length,d=4;
    const A=Array.from({length:d},()=>Array.from({length:M},()=>rnd(q)));
    const s=Array.from({length:d},()=>rnd(q)),e=Array.from({length:M},()=>rnd(3)-1);
    const g=mode==="lwe"?Array.from({length:M},(_,j)=>mod(e[j]+A.reduce((a,row,i)=>a+row[j]*s[i],0))):Array.from({length:M},()=>rnd(q));
    const eta=Array.from({length:N},()=>rnd(3)-1),eta0=rnd(3)-1,key=rnd(2**30);
    const u=Array.from({length:N},(_,i)=>mod(eta[i]+P.reduce((a,row,j)=>a+row[i]*g[j],0)));
    const v=mod(dot(t,g)+eta0+half*K);
    const mask=r=>gate(r,S)?0:publicHash(r,key);
    const E=r=>mod(v-dot(r,u)+mask(r));
    const baseline=Array.from({length:B},()=>[1,0]).flat();
    const base=mod(E(baseline)-mask(baseline)),diff=[];
    for(let b=0;b<B;b++){
      const r=baseline.slice();r[2*b]=0;r[2*b+1]=1;
      diff.push(mod(E(r)-mask(r)-base));
    }
    const fake=rep(0,cl);
    ck(P.every((row,j)=>dot(row,fake.r)===t[j]),"signed false extension equation");
    ck(diff.every((x,b)=>x===mod(-u[2*b+1]+u[2*b])),"public gate subtraction restores local affine differences");
    const derived=mod(base+diff.reduce((a,x,b)=>a+fake.r[2*b+1]*x,0));
    ck(derived===mod(v-dot(fake.r,u)),"nonboolean point inferred without querying it");
    ck(decode(derived)===K,"publicly known gate cannot protect frozen capability");
    if(S===F){ck(!gate(fake.r,S)&&fake.bad===1,"FALSE fake disallowed by gate");attacks++;}
    for(let a=0;a<8;a++){
      const rr=rep(a,cl),truth=sat(a,cl);
      ck((rr.bad===0)===truth,"witness equivalence");
      if(truth){
        ck(gate(rr.r,S),"valid ORIGINAL witness admitted");
        ck(E(rr.r)===mod(half*K+eta0-dot(rr.r,eta)),"witness exact source cancellation");
        ck(decode(E(rr.r))===K,"distinct true witness recovers same bit");
        valid++;
      }
    }
  }
  for(const mode of ["lwe","uniform"])for(const K of [0,1])for(let tape=0;tape<32;tape++){
    oneTape(F,mode,K);oneTape(T,mode,K);
  }
  ck(attacks===128&&valid===512,"full bounded experiment count");
  return {run:"R135-PUBLIC-RESIDUAL-PRF-GATE",status:"REJECTED",assertions:checks,false_attacks:attacks,true_witness_openings:valid,source_modes:["toy LWE","uniform"],formula_cases:["FALSE eight-clause","TRUE four-clause"],public_gate_queries_per_false:20,conclusion:"Public gate seed permits stripping residual PRF mask on locally normalized queries; signed FALSE affine extension then recovers frozen K. An inaccessible PRF seed would need independently justified public obfuscation/witness-key cryptography."};
}
console.log(runCheck());
```

Captured result:

```json
{
  "run": "R135-PUBLIC-RESIDUAL-PRF-GATE",
  "status": "REJECTED",
  "assertions": 4739,
  "false_attacks": 128,
  "true_witness_openings": 512,
  "source_modes": [
    "toy LWE",
    "uniform"
  ],
  "formula_cases": [
    "FALSE eight-clause",
    "TRUE four-clause"
  ],
  "public_gate_queries_per_false": 20,
  "conclusion": "Public gate seed permits stripping residual PRF mask on locally normalized queries; signed FALSE affine extension then recovers frozen K. An inaccessible PRF seed would need independently justified public obfuscation/witness-key cryptography."
}
```

Provenance: actual tool execution of the source above, no independent agent, no web/literature research. This one-file research-only record is meant for continuity, not an announced security milestone.
