# R131 — Genuine circuit-dependent LWE source and QPT challenge simulator; universally false-openable (REJECTED)

**Decision:** No positive secure ORIGINAL-witness advance. Research-only negative record; no user-facing notification or ordinary top-level PR progress comment. This is not a claimed WE impossibility or ordinary LWE break.

**Provenance:** \`syscoin/PVUGC#1\`, branch \`research/pq-wkem-validation-20260918\`, preflight head \`ea13ca0397eef3604039c9efadc33a1ed493cb4e\`, open/draft/unmerged. Latest previously published substantive issue comment \`6698876958\` checked. Exact R130 research file at blob \`1e84a8cbef7dd48dd79be79040653847d574bd8c\` and R129 finite-tail source were inspected. Separate detailed offline derivation, independent Python checker and captured output are local only under \`/mnt/data/R131_ORIGINAL_3CNF_DUAL_LWE_20261107/\`. No web search, external literature, production change or merge.

## Actual classical-PPT setup and witness-dependent opening

Let ORIGINAL x be **any 3CNF** with n Boolean variables and m three-literal clauses. The actual relation/statement, claim/UTXO, branch, anchors/window, context, intended native verification key and challenge path must ultimately be bound to x; only the 3CNF source is tested here. Use an integer pair \`(r[i,0],r[i,1])\` for each original input bit and **two extra bit pairs** for each clause's slack. There are \`B=n+2m\` pairs, \`N=2B\` integer coordinates, \`M=B+m\` linear equations in the **public** integer matrix \`P=P_x\`, target \`t=t_x\`:

- Normalization: \`r[i,0]+r[i,1]=1\` for every pair.
- Clause with literals L1,L2,L3: \`L1(r)+L2(r)+L3(r)-r[slack_low,1]-2r[slack_high,1]=1\`; a positive literal is the appropriate selector-one coordinate and a negative literal is selector-zero.

For **every satisfying ORIGINAL assignment w**, set variable selectors one-hot, and encode the number of true clause literals minus one in two binary slack pairs. Then \`P r(w)=t\` **over the integers**, all selectors are one-hot, \`||r(w)||_1=||r(w)||_2²=B\`. Different satisfying witnesses may have different state, yet will open **the same chosen capability bit**. Conversely, if an *integer* r satisfies \`Pr=t\` and \`||r||_2²≤B\`, each normalization pair has squared norm at least one and total norm B forces every pair to be (1,0) or (0,1), so r yields a satisfying original assignment. This only proves **supplied SHORT representation -> ORIGINAL witness**, not recovery extraction.

Choose an odd prime q, public \`A0←U(Z_q^(d×M))\`, secret s uniform in \`Z_q^d\`, genuine scalar-LWE noise e0 sampled independently from a centered small-error law, and \`g=A0^T s+e0 mod q\`. Independently choose coordinate errors η in \`[-h,h]^N\` and η0 in \`[-h,h]\`. Set Δ=floor(q/2). For one precommitted frozen capability bit k publish
\[
u=P^T g+\eta\bmod q,\qquad v=t^Tg+\eta_0+\Delta k\bmod q.
\]
The complete *modelled* view is the actual x/context, A0,P,t,u,v and arbitrary **publicly recomputable** checking/auxiliary/related fields that do not depend on an unavailable challenge secret. Honest setup/evaluation are classical PPT. For any valid ORIGINAL w, define \`δ=v-r(w)^Tu\`; since \`Pr(w)=t\`, this equals \`Δk+η0-r(w)^Tη\` modulo q. If \`h(B+1)<min(Δ,q-Δ)/2\`, nearest-centre decoding gives the identical k for **all valid w on every tape**. Repeat independent copies bitwise to encode a fixed off-chain signature pad (no bit-count optimization is claimed).

**An actual ordinary-QPT-LWE challenge simulator exists for this candidate**, not a hypothetical SourceOpen oracle: receive \`(A0,g)\` where g is genuine scalar LWE or uniform, calculate the full public u,v using P,t and freshly sampled η,η0. Public deterministic/recomputable J,CK,Aux/context and sibling independent capsules can be generated from those actual bytes and known coins. A hybrid replaces g via decisional-QPT-LWE with the same A0; coherent QPT computations and quantum advice are allowed, provided no opening reveals g, η or another unavailable secret. This is an exact conditional hybrid for the *modelled* public distribution only. It is NOT a key-hiding or native-forgery proof, and arbitrary secret-dependent CK/Aux and selective openings remain unsimulated.

## Explicit unconditional classical FALSE key recovery

For **any** publicly chosen Boolean assignment a (even when x is FALSE), form its original one-hot selectors. For a clause with c true literals, choose the low/high slack values encoding \`c-1\`; when c=0, deliberately choose **invalid integer** low slack -1, i.e. pair \`(2,-1)\`, and high slack 0. The resulting public integer vector r_a satisfies \`Pr_a=t\` over the integers despite having no valid ORIGINAL witness. With k_a unsatisfied clauses,
\[
||r_a||_1=B+2k_a\le B+2m\le 2B,\qquad
||r_a||_2^2=B+4k_a\le 3B.
\]
**The adversary never volunteers this invalid representation to a checker.** It directly computes
\[
v-r_a^Tu=\Delta k+\eta_0-r_a^T\eta\pmod q
\]
and nearest-centre-decodes k. The entire LWE sample g cancels in BOTH real and uniform challenge hybrids. With h(1+2B)<τ=min(Δ,q-Δ)/2, this key recovery works on **every setup tape** for every FALSE 3CNF. For independent mean-zero bounded η, Hoeffding also gives
\[
\Pr[\text{attack decode error}]\le 2\exp[-\tau^2/(2h^2(1+||r_a||_2^2))]
\le2\exp[-\tau^2/(2h^2(1+3B))].
\]
Under an honest deterministic correctness margin τ>h(B+1), the false attack succeeds with probability tending exponentially to one as B grows. Over polynomially many capsule bits and related capsules a union bound applies. This is an unconditional **classical** break, so QPT hardness or quantum coherence cannot repair it. Public row randomization of P,t does not remove \`Pr_a=t\`; independent bounded noise or ordinary LWE wrapping cannot fix this family.

## Executed verification, exact scope and next attempt

The **exact JavaScript checker below was executed before any Git object write**, with deterministic seed, exact integer equations, true/fixed-false 3CNF cases, all four assignments, both k values, 256 genuine toy scalar-LWE tapes **and** 256 uniform-g hybrid tapes per bit per case, comparing exact cancellation and real/invalid opening. The independent local CPython checker ran 32,810 assertions over 512 tapes per mode and bit and reproduced byte-identical output on rerun. Toy \`q=65521,d=8\` do not represent calibrated 128-bit PQ hardness. The real checker result below is not a quantum experiment.

**REJECTED.** This instantiates a genuine ORIGINAL-dependent source and ordinary-LWE challenge simulator together, but *does not* give fixed-FALSE full-public security; the existing furnished-representation soundness does not imply **arbitrary recovery -> ORIGINAL witness**. Next candidate must protect the source **nonlinearly** against invalid-computation bypasses, not repeat transparent affine projections, scalar-noise retuning or inexpensive PRG/packing optimization. Remain honest about malicious N-of-N setup/abort, selective openings, quantum auxiliary inputs, multiple capsules, SYS/BTC evidence and hypothetical native PQ Bitcoin path. No new assumption already postulating WE/iO/WPRF release is justified here.

## Exact executed V8 checker
```javascript
function r131Checker(){
  "use strict";
  const q=65521,Delta=32760,d=8, T=256;
  let seed=131, checks=0;
  function rand(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;}
  function rnd(n){return rand()%n;}
  function err(){return rnd(3)-1;}
  function mod(v){return ((v%q)+q)%q;}
  function dot(a,b){let s=0;for(let i=0;i<a.length;i++)s+=a[i]*b[i];return s;}
  function ck(c,label){checks++;if(!c)throw Error("R131 test "+checks+" "+label);}
  const clauses=[
    [[0,1],[1,1],[1,1]],
    [[0,1],[1,0],[1,0]],
    [[0,0],[1,1],[1,1]],
    [[0,0],[1,0],[1,0]]
  ];
  function build(cs){
    const n=2,m=cs.length,B=n+2*m,N=2*B,P=[],b=[];
    for(let i=0;i<B;i++){let row=Array(N).fill(0);row[2*i]=row[2*i+1]=1;P.push(row);b.push(1);}
    for(let j=0;j<m;j++){
      let row=Array(N).fill(0);
      for(const [i,sign] of cs[j])row[2*i+(sign?1:0)]++;
      row[2*(n+2*j)+1]--;row[2*(n+2*j+1)+1]-=2;
      P.push(row);b.push(1);
    }
    return {P,b,B,N,m};
  }
  function repr(w,cs){
    let bits=[...w],viol=0;
    for(const clause of cs){
      let count=clause.reduce((s,[i,sign])=>s+(sign?w[i]:1-w[i]),0);
      if(count===0)viol++;
      let val=count-1;
      bits.push(val===-1?-1:val%2,val===-1?0:Math.floor(val/2));
    }
    let r=[];for(const bit of bits)r.push(1-bit,bit);
    return {r,viol};
  }
  function decode(z){
    z=mod(z);
    const dist=c=>Math.min(mod(z-c),mod(c-z));
    return dist(0)<dist(Delta)?0:1;
  }
  let details=[];
  for(const [name,cs] of [["FALSE-four",clauses],["TRUE-three",clauses.slice(0,3)]]){
    const {P,b,B,N,m}=build(cs);
    const states=[];
    for(const x of [0,1])for(const y of [0,1]){
      const {r,viol}=repr([x,y],cs);
      ck(r.length===N,"dimension");
      for(let j=0;j<P.length;j++)ck(dot(P[j],r)===b[j],"integer source constraint");
      ck(r.reduce((s,a)=>s+Math.abs(a),0)===B+2*viol,"l1 formula");
      ck(dot(r,r)===B+4*viol,"norm square formula");
      ck((viol===0)===r.every(v=>v===0||v===1),"sound small integer");
      states.push({r,viol,w:""+x+y});
    }
    ck(name.startsWith("FALSE")?states.every(s=>s.viol===1):states.some(s=>s.viol===0),"instance classification");
    let maxError=0;
    for(const mode of ["real-LWE","uniform-hybrid"])for(const K of [0,1])for(let j=0;j<T;j++){
      const M=b.length,A=Array.from({length:d},()=>Array.from({length:M},()=>rnd(q)));
      const s=Array.from({length:d},()=>rnd(q));
      const g=Array.from({length:M},(_,i)=>mode==="real-LWE"?mod(A.reduce((v,row,k)=>v+row[i]*s[k],0)+err()):rnd(q));
      const eta=Array.from({length:N},()=>err()),eta0=err();
      const u=Array.from({length:N},(_,i)=>mod(P.reduce((v,row,k)=>v+row[i]*g[k],0)+eta[i]));
      const v=mod(dot(b,g)+eta0+Delta*K);
      for(const {r} of states){
        const got=mod(v-dot(r,u)),expected=mod(Delta*K+eta0-dot(r,eta));
        ck(got===expected,"LWE g must cancel");
        ck(decode(got)===K,"valid and invalid routes recover SAME K");
        maxError=Math.max(maxError,Math.abs(eta0-dot(r,eta)));
      }
    }
    details.push({name,pairs:B,rows:b.length,columns:N,states:states.map(s=>({assignment:s.w,violations:s.viol,l1:s.r.reduce((v,x)=>v+Math.abs(x),0)})),max_error_seen:maxError,tapes_per_mode_per_bit:T});
  }
  return {run:"R131-ORIGINAL-3CNF-DUAL-LWE-20261107",classification:"REJECTED: authentic source-LWE challenge is simulatable, but FALSE 3CNF public invalid integer selector reveals the key",checks,details};
}
```

## Captured exact output
```json
{
  "run": "R131-ORIGINAL-3CNF-DUAL-LWE-20261107",
  "classification": "REJECTED: authentic source-LWE challenge is simulatable, but FALSE 3CNF public invalid integer selector reveals the key",
  "checks": 16518,
  "details": [
    {
      "name": "FALSE-four",
      "pairs": 10,
      "rows": 14,
      "columns": 20,
      "states": [
        {
          "assignment": "00",
          "violations": 1,
          "l1": 12
        },
        {
          "assignment": "01",
          "violations": 1,
          "l1": 12
        },
        {
          "assignment": "10",
          "violations": 1,
          "l1": 12
        },
        {
          "assignment": "11",
          "violations": 1,
          "l1": 12
        }
      ],
      "max_error_seen": 10,
      "tapes_per_mode_per_bit": 256
    },
    {
      "name": "TRUE-three",
      "pairs": 8,
      "rows": 11,
      "columns": 16,
      "states": [
        {
          "assignment": "00",
          "violations": 1,
          "l1": 10
        },
        {
          "assignment": "01",
          "violations": 1,
          "l1": 10
        },
        {
          "assignment": "10",
          "violations": 1,
          "l1": 10
        },
        {
          "assignment": "11",
          "violations": 0,
          "l1": 8
        }
      ],
      "max_error_seen": 10,
      "tapes_per_mode_per_bit": 256
    }
  ]
}
```
