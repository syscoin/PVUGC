# R132 — ORIGINAL-dependent degree-2 atom-consistency LWE release (REJECTED)

**Research-only negative record. No constructive secure ORIGINAL-witness result, no user notification or ordinary PR progress comment.** This is not a general witness-encryption impossibility theorem and does not break ordinary LWE.

## Continuity and scope
Read exact PR #1 head `34cb2749e4f740c93c077bb4eb4ebb0f96a178f2`, open/draft/unmerged on `research/pq-wkem-validation-20260918`, the latest relevant issue comments through 2026-11-06 23:46:34Z (including 6698876958), and exact R131 blob `0047bed33a47f40cfc7a89ef0ec10adf7ec9b2f6` plus R130 blob `1e84a8cbef7dd48dd79be79040653847d574bd8c`. No unrelated internet research or whole-PR diff. One bounded attempt at a genuinely ORIGINAL-dependent nonlinear-consistency repair, not an efficiency optimization.

## Explicit candidate, distribution, and simulation

For proper ORIGINAL 3CNF x with n Boolean variables and m clauses, form public integer atom blocks: (a) a two-atom value vector V_i per variable, (b) a four-atom joint-value vector Q_ij per global pair appearing in a clause, (c) an eight-atom literal-truth vector T_j per clause. Each block sums to one. The 000 unsatisfied atom of every T_j is fixed to zero. Add public linear equations equating each pair marginal to its global variable atom, and all three singleton and three pairwise literal-truth marginals of every T_j to the corresponding global V_i and Q_ij, with proper negated-literal polarity. These equations are the actual integer matrix P_x r=t_x. All blocks, dimensions, signs, and every row are constructed in the attached exact checker.

Every satisfying ORIGINAL assignment w gives one-hot V, Q and T with P_x r(w)=t_x. Let B be the number of blocks. Then ||r(w)||_1=||r(w)||_2²=B; the representations for different valid witnesses can differ.

Choose odd prime q, A0 uniform in Z_q^(d×M), s uniform in Z_q^d, e sampled independently from the stated centered small-error distribution, g=A0^T s+e modulo q, eta_i,eta0 uniform bounded errors [-h,h], Delta=floor(q/2), and a frozen capability bit K. Publish u=P_x^T g+eta and v=t_x^T g+eta0+Delta K modulo q. Open(r)=nearest-centre(v-r^T u) returns identical K for **every** valid ORIGINAL witness on all tapes satisfying h(B+1)<min(Delta,q-Delta)/2. The release is entirely off-chain and classical PPT.

The honest source-dependent simulator takes an actual ordinary decisional-QPT-LWE challenge (A0,g) where g is real LWE or uniform, samples eta, and computes these exact public coordinates, P,t, context and any deterministic J/CK/Aux derived from them. It needs neither the challenge secret nor a SourceOpen oracle. **This simulates only the modelled coordinates**; no claim about secret-dependent receipts, selective openings, related capsules with unknown coins, quantum extractability, calibrated hardness, or native signature security is made. In fact the modelled distribution is already broken.

For any integer r satisfying P_x r=t_x, identity:
v-r^T u = Delta K + eta0-r^T eta (mod q).

**Supplied-short-representation lemma.** Every integer block z with sum z=1 has squared Euclidean norm at least one, with equality iff it is a nonnegative standard basis vector. Thus P_x r=t_x and ||r||_2²<=B force every block one-hot; singleton/pair marginals give one globally consistent Boolean assignment, and the forbidden 000 clause atom proves it satisfies every ORIGINAL clause. This is not extraction from arbitrary key recovery.

## Explicit FALSE-instance bypass even with second-order consistency

Take ANY Boolean assignment a, including to an unsatisfiable x. Set global V_i and Q_ij one-hot according to a. For every satisfied clause, set T_j one-hot at the actual literal-truth tuple. For a violated clause the actual tuple is 000; instead set a **signed** local distribution p over 8 atoms:
p_empty=0; p_S=(-1)^(|S|+1) for each nonempty S subset {1,2,3}.
It has singleton atoms +1, doubletons -1, and triple +1, with total sum 1. For any nonempty proper subset T:
sum_{S superset T} p_S = (-1)^(|T|+1)(1-1)^(3-|T|)=0.
Thus **all singleton and pairwise moments** match the actual 000 literal tuple, the forbidden atom remains zero, and every global pair/variable marginal remains consistent. The public integer vector r_a exactly solves P_x r_a=t_x even on fixed-FALSE formulas. If a violates k clauses, ||r_a||_1=||r_a||_2²=B+6k (compared with B for a genuine witness).

An unauthorized adversary does not submit r_a to any verifier; it directly computes v-r_a^T u and decodes K. The entire scalar LWE sample g cancels whether it was real or uniform. With eta independent uniform in [-h,h], Hoeffding yields
Pr[decode error] <= 2 exp[-tau² / (2h²(1+B+6k))],
tau=min(Delta,q-Delta)/2.
For k bounded and B growing, honest deterministic completeness requires tau>h(B+1), making FALSE recovery overwhelmingly reliable. A fixed contradictory 3CNF core plus polynomially many satisfiable filler clauses preserves that condition. With q=65521, Delta=32760, h=1, the finite tested FALSE core is recovered on all tested tapes.

The lemma generalizes algebraically to a k-ary forbidden 0^k atom: signed p_S=(-1)^(|S|+1) on nonempty subsets reproduces all proper subset moments at total l1 norm 2^k-1. Larger arity alone is not an instantiated secure compiler: fake high-order global moments, polynomial public encoding and arbitrary recovery extraction remain unanswered.

## Actual execution, status and handoff

The embedded self-contained JavaScript function was executed and **reexecuted** with identical output before committing (6,208 assertions). Its exact captured output appears below. Independently, a LOCAL CPython standard-library checker under /mnt/data/R132_ATOM_LEVEL2_20261107/checker.py passed **20,037** assertions and reproduced byte-identical /mnt/data/R132_ATOM_LEVEL2_20261107/captured.json on rerun. Local files/hashes: RESEARCH.md SHA256 02336f09e163aff10dc56d23de4f0410a3269a37e6308912104e9a3fa0c9c7ff; checker.py SHA256 9dbb92f0aa36c1ed0268de86ca4e3348aa8ac7cd2ed9a94c8c5934b6896b47e3; captured.json SHA256 7e4e7adb1bc5aa0172c7f9c5aec2919da7261d0103409675bd03df7b476e2e73. Those three Python files are **LOCAL ONLY**, not claimed to be published on GitHub.

The checker builds full linear rows for TRUE four-clause (four valid distinct assignments), TRUE seven-clause (one valid), and FALSE eight-clause (none valid), verifies every equation and the precise norms for all eight assignments, and checks source cancellation and key recovery over independent real scalar-LWE and uniform-g fixtures. Tests do not imply PQ hardness.

**REJECTED.** This is another exact negative for *linearized* ORIGINAL source soundness, not for witness encryption in general. The remaining fundamental problem is a polynomial-time nonlinear ORIGINAL-derived opening algebra that binds Boolean multiplication/positivity within the release itself, while admitting full-public QPT simulation of genuine LWE setup/output and arbitrary unauthorized recovery/native forgery -> ORIGINAL witness or independent QPT break. Merely enforcing degree-2 moment equations or checking that an adversary volunteers a short representation cannot repair the attacked mechanism. No optimizations, production edits, merge, deployment or external research occurred.

## Exact executed checker

```javascript
function r132Checker(){
 "use strict";
 const q=65521,delta=32760,all=Array.from({length:8},(_,v)=>[(v>>2)&1,(v>>1)&1,v&1]);
 let seed=1320711,checks=0;
 function rand(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;}
 const rng=n=>rand()%n,err=()=>rng(3)-1,mod=x=>(x%q+q)%q,dot=(x,y)=>x.reduce((a,b,i)=>a+b*y[i],0);
 function ck(ok,msg){checks++;if(!ok)throw Error("R132 "+checks+" "+msg);}
 const pairs=[[0,1],[0,2],[1,2]];
 let record=[];
 for(const remove of [4,7,8]){
  const exclusions=all.slice(0,remove);
  const blocks=[];
  for(let i=0;i<3;i++)blocks.push({name:`v${i}`,atoms:[[0],[1]]});
  for(let k=0;k<3;k++)blocks.push({name:`p${k}`,atoms:[[0,0],[0,1],[1,0],[1,1]]});
  for(let c=0;c<remove;c++)blocks.push({name:`c${c}`,atoms:all});
  let N=0,offset={};
  for(const block of blocks){offset[block.name]=N;N+=block.atoms.length;}
  const rows=[],rhs=[];
  function row(terms,b=0){
   let w=Array(N).fill(0);
   for(const [name,co,pred] of terms){
    let block=blocks.find(b=>b.name===name);
    block.atoms.forEach((atom,i)=>{if(pred(atom))w[offset[name]+i]+=co;});
   }
   rows.push(w);rhs.push(b);
  }
  for(const b of blocks)row([[b.name,1,()=>true]],1);
  for(let k=0;k<3;k++){
   const [i,j]=pairs[k];
   for(const [pos,idx] of [[0,i],[1,j]])
    row([[`p${k}`,1,a=>a[pos]===1],[`v${idx}`,-1,a=>a[0]===1]]);
  }
  for(let c=0;c<remove;c++){
   const e=exclusions[c],name=`c${c}`;
   row([[name,1,a=>a[0]===0&&a[1]===0&&a[2]===0]]);
   const positive=e.map(b=>b===0);
   for(let i=0;i<3;i++)
    row([[name,1,a=>a[i]===1],[`v${i}`,-1,a=>a[0]===(positive[i]?1:0)]]);
   for(let k=0;k<3;k++){
    const [i,j]=pairs[k];
    row([[name,1,a=>a[i]===1&&a[j]===1],[`p${k}`,-1,a=>a[0]===(positive[i]?1:0)&&a[1]===(positive[j]?1:0)]]);
   }
  }
  function repr(a){
   let r=[],viol=0;
   for(const b of blocks){
    if(b.name[0]==="v"){r.push(a[+b.name[1]]===0?1:0,a[+b.name[1]]===1?1:0);}
    else if(b.name[0]==="p"){let [i,j]=pairs[+b.name[1]];b.atoms.forEach(at=>r.push(+(at[0]===a[i]&&at[1]===a[j])));}
    else {const e=exclusions[+b.name[1]],lit=e.map((bit,i)=>bit===0?a[i]:1-a[i]);
      if(lit.every(x=>x===0)){viol++;b.atoms.forEach(at=>r.push(at.every(v=>v===0)?0:(at.reduce((s,x)=>s+x,0)%2===1?1:-1)));}
      else b.atoms.forEach(at=>r.push(+at.every((v,i)=>v===lit[i])));
    }
   }
   return {r,viol};
  }
  const states=all.map(a=>({a,...repr(a)})),B=blocks.length,M=rhs.length;
  for(const {a,r,viol} of states){
   ck(r.length===N,"length");
   rows.forEach((w,i)=>ck(dot(w,r)===rhs[i],"all source equations"));
   ck(dot(r,r)===B+6*viol,"squared norm");
   ck(r.reduce((s,v)=>s+Math.abs(v),0)===B+6*viol,"l1 norm");
   ck((viol===0)===(exclusions.every(e=>!e.every((x,i)=>x===a[i]))),"truth classification");
  }
  let recoveries=0;
  for(const mode of ["real","uniform"])for(const K of [0,1])for(let tape=0;tape<24;tape++){
   const g=mode==="uniform"?Array.from({length:M},()=>rng(q)):(()=>{
    const d=4,s=Array.from({length:d},()=>rng(q)),
      A=Array.from({length:d},()=>Array.from({length:M},()=>rng(q)));
    return Array.from({length:M},(_,i)=>mod(A.reduce((sum,row,j)=>sum+row[i]*s[j],0)+err()));
   })();
   const eta=Array.from({length:N},err),eta0=err(),
       u=Array.from({length:N},(_,j)=>mod(rows.reduce((sum,row,i)=>sum+row[j]*g[i],0)+eta[j])),
       v=mod(dot(rhs,g)+eta0+delta*K);
   for(const {r,viol} of states){
    const opened=mod(v-dot(r,u));
    ck(opened===mod(delta*K+eta0-dot(r,eta)),"real or uniform LWE cancellation");
    const d0=Math.min(opened,q-opened),d1=mod(opened-delta),dist1=Math.min(d1,q-d1);
    ck(+(dist1<d0)===K,"native capability bit recovered");
    if(viol)recoveries++;
   }
  }
  record.push({clauses:remove,blocks:B,equations:M,coordinates:N,
      valid_assignments:states.filter(x=>x.viol===0).length,
      invalid_assignments:states.filter(x=>x.viol>0).length,
      invalid_recoveries:recoveries});
 }
 return {run:"R132-ORIGINAL-ATOM-LEVEL2-DUAL-LWE-20261107",classification:"REJECTED: all fixed-FALSE assignments recover K via degree-2 consistent signed pseudoatom",assertions:checks,record};
}
console.log(JSON.stringify(r132Checker(),null,2));
```

## Exact captured output

```json
{
  "run": "R132-ORIGINAL-ATOM-LEVEL2-DUAL-LWE-20261107",
  "classification": "REJECTED: all fixed-FALSE assignments recover K via degree-2 consistent signed pseudoatom",
  "assertions": 6208,
  "record": [
    {
      "clauses": 4,
      "blocks": 10,
      "equations": 44,
      "coordinates": 50,
      "valid_assignments": 4,
      "invalid_assignments": 4,
      "invalid_recoveries": 384
    },
    {
      "clauses": 7,
      "blocks": 13,
      "equations": 68,
      "coordinates": 74,
      "valid_assignments": 1,
      "invalid_assignments": 7,
      "invalid_recoveries": 672
    },
    {
      "clauses": 8,
      "blocks": 14,
      "equations": 76,
      "coordinates": 82,
      "valid_assignments": 0,
      "invalid_assignments": 8,
      "invalid_recoveries": 768
    }
  ]
}
```
