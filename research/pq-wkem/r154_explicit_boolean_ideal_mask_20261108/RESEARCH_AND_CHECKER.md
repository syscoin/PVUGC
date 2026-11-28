# R154 — Public explicit Boolean-ideal masking: classical key-recovery counterexample

**Run:** R154-EXPLICIT-BOOLEAN-IDEAL-MASK-20261108. **Status: REJECTED, INTERNAL NEGATIVE CHECKPOINT; NOT ORIGINAL-WITNESS SECURITY PROGRESS.** This is not a secure witness-KEM, not a positive milestone, and does not warrant a routine user notification. No size/performance optimization or external literature/web research.

**Continuity:** syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, verified start head 0b759ede8706926690a0116ddb85d4efc54f4e40, open/draft/unmerged. Read latest substantive ordinary comment 6718361572 and exact R153 research blob f7d8a85d233b157b521f13413f74ef6c61873569, plus earlier R152 exact rejected joint-source blob 2b7618ef2cd3fda9440f1ffcde61adf8ed78f1d8. The attempt tests whether explicitly enforcing Booleanity with polynomial constraints can replace the statistically hiding uniform-source target eliminated as a generally modest requirement by R153. It does not rebrand R152 as secure.

## Candidate: exact ORIGINAL-dependent classical-PPT release, with no hidden source oracle

Encode the complete ORIGINAL NP relation R(x,w) as polynomial constraints f_1(z)=...=f_m(z)=0 over a finite field F_q. Include Booleanity equations z_i(z_i-1)=0, circuit/SAT equations, and actual relation identity, claim/UTXO, branch, anchors/window, context, intended native VK/capability binding. Let V_D be the explicitly enumerated monomial coefficient space of total degree <=D; N=binom(n+D,D). This version is PPT only when its N and the generator count are polynomial in input length (e.g. D fixed). Let I_D=span{z^a f_i:deg(z^a f_i)<=D} subset V_D and let M_x be a public N-by-k matrix whose columns are those generators. Honest Build(x,K) draws independent uniform r in F_q^k and publishes the coefficient vector C=K*e_0+M_x*r. It needs no witness at setup. Open(C,w) verifies the ACTUAL original R(x,w)=1 off chain and outputs polynomial evaluation C(w). Distinct valid w need not share intermediate states. Every valid original w annihilates every column of M_x, so C(w)=K on every honest tape: exact same-capability correctness. A common K can in principle mask a frozen native signature, but no native security is claimed.

This candidate is **not an LWE construction**. It is a bounded nonlinear Boolean-source trial. Ordinary LWE wrapping would not close the demonstrated classically accessible public-output channel without a new independently justified non-affine release mechanism and a genuine complete-joint simulator.

## Universal public coefficient recovery for TRUE instances

If there is any valid w, evaluating at w defines a linear functional annihilating every column of M_x but sending the constant e_0 to 1. Thus e_0 is not in colspan(M_x). A **publicly computable** row vector ell with ell^T M_x=0 and ell^T e_0=1 exists. Gaussian elimination on the public generator matrix produces ell *without knowing w*. Therefore ell^T C=K on **all** honest tapes. Equivalently solving [M_x|e_0] (r',K')=C fixes K' uniquely, even if r' is not unique. This is an unconditional classical PPT early-release attack for all TRUE instances; QPT security already fails.

For any x with e_0 in colspan(M_x), the two distributions C_0 and C_1 are exactly equal, because uniform r maps to uniform colspan(M_x) and translation inside the span changes nothing. But a FALSE x with e_0 **outside** this truncated ideal also leaks K by the same public elimination. Thus neither false hiding for all FALSE nor unauthorized hard-TRUE security holds. This is a specialized explicit-polynomial/low-degree closure obstruction, not a new general no-go. It is compatible with R153's NP-subset-SZK consequence and known affine leakage warnings. Random public basis changes preserve the rank condition. A hidden basis or circuit obfuscation is not instantiated and cannot be assumed as a repair.

## Executed exact finite checker and reproducibility

The JavaScript checker below was actually executed before Git object creation. It forms the exact F_7 coefficient space of all degree<=3 bivariate monomials (10 coordinates), the Boolean constraints, the clause (x OR y) for a TRUE instance with three distinct valid witnesses, and contradictory constraints x=0,x=1 for a FALSE instance. It verifies rank(M), rank([M|e_0]), 30 deterministic seeded tapes per case, three valid-witness openings, public Gaussian extraction on TRUE, and identical C_K/C_0 descriptions on FALSE. These sanity assertions support the displayed finite examples, **not quantum hardness**. A separately executed independent CPython standard-library implementation (local-only, not included in this GitHub file) passed 185 exact algebraic assertions and produced SHA256 a3eb5e7b5101d8d9587aeb81e68a19c33faf083adcca19c616c3c40954ed6f30 twice byte-identically. Its source SHA256 is df36abf253233cf4f7d32c4ee795f6922e054d92ed95344f4704b243d750576d; expanded derivation SHA256 e3822fbea3a31228ea69c16d7c2cbd9a3d9b4df082cadeda640814e7b4f813ae. These local-only artifacts are not claimed to have been published.

## Next concrete obligation and guardrails

Do **not** optimize this rejected component or present a conditional theorem as a generic solution. The exact missing step is a real classical-PPT ORIGINAL-NP dependent source release with nontrivial computational nonlinear correlations that cannot be collapsed by polynomial-dimensional public coefficient-span algebra. It must generate source-dependent setup, public witness-opening algorithm and an ACTUAL ordinary-QPT-LWE challenge simulator jointly across relation/statement, all checking keys, auxiliary input, related capsules, and permitted selective openings; no SourceOpen oracle. Every valid ORIGINAL witness must release the identical frozen claim/path-bound native capability. False-instance full-joint-output QPT hiding and arbitrary hard-TRUE key recovery or accepted native forgery -> actual ORIGINAL witness or independently justified QPT break remain unproved and not instantiated. Never require a volunteered internal representation. Malicious N-of-N honest-cut/abort/DA/graph and the hypothetical Bitcoin-native PQ endpoint remain separately unresolved. This research tests a failed step and does not relax the generic-NP requirement.

## Exact executed JavaScript checker

\`\`\`javascript
(function r154Checker(){
  "use strict";
  const q=7,D=3;
  const mons=[];
  for(let i=0;i<=D;i++)for(let j=0;j+i<=D;j++)mons.push([i,j]);
  const pos=(i,j)=>mons.findIndex(z=>z[0]===i&&z[1]===j);
  const unit=(i,j)=>{const a=Array(mons.length).fill(0);a[pos(i,j)]=1;return a};
  const one=unit(0,0), x=unit(1,0), y=unit(0,1);
  const mod=a=>((a%q)+q)%q;
  const add=(a,b)=>a.map((v,i)=>mod(v+b[i]));
  const sub=(a,b)=>a.map((v,i)=>mod(v-b[i]));
  const mul=(a,b)=>{
    let c=Array(mons.length).fill(0);
    for(let i=0;i<mons.length;i++)if(a[i])
      for(let j=0;j<mons.length;j++)if(b[j]){
        const X=mons[i][0]+mons[j][0],Y=mons[i][1]+mons[j][1];
        if(X+Y<=D)c[pos(X,Y)]=mod(c[pos(X,Y)]+a[i]*b[j]);
      }
    return c;
  };
  const evalAt=(a,z)=>mod(a.reduce((s,v,i)=>s+v*z[0]**mons[i][0]*z[1]**mons[i][1],0));
  const deg=a=>Math.max(...a.flatMap((v,i)=>v?[mons[i][0]+mons[i][1]]:[]));
  const colsFrom=gs=>{
    const cs=[];
    for(const g of gs)for(let j=0;j<mons.length;j++)
      if(mons[j][0]+mons[j][1]+deg(g)<=D)cs.push(mul(g,unit(...mons[j])));
    return cs;
  };
  const matFrom=cs=>mons.map((_,i)=>cs.map(c=>c[i]));
  const solve=(A,b)=>{
    let M=A.map((r,i)=>[...r,mod(b[i])]);
    const rows=M.length, cols=A[0].length;
    let p=0, piv=[];
    for(let col=0;col<cols&&p<rows;col++){
      let k=p;while(k<rows&&!M[k][col])k++;
      if(k===rows)continue;
      [M[p],M[k]]=[M[k],M[p]];
      let inv=1;while(mod(inv*M[p][col])!==1)inv++;
      M[p]=M[p].map(v=>mod(v*inv));
      for(let i=0;i<rows;i++)if(i!==p&&M[i][col]){
        const t=M[i][col];
        M[i]=M[i].map((v,j)=>mod(v-t*M[p][j]));
      }
      piv.push(col);p++;
    }
    if(M.some(r=>r.slice(0,cols).every(v=>!v)&&r[cols]))return null;
    const ans=Array(cols).fill(0);
    piv.forEach((col,i)=>ans[col]=M[i][cols]);
    return ans;
  };
  const rank=A=>{
    const b=Array(A.length).fill(0);
    // rank by pivot rows after augmenting independent random RHS? Use exact elimination.
    let M=A.map(r=>r.slice()),r=0;
    if(!M.length||!M[0].length)return 0;
    for(let j=0;j<M[0].length&&r<M.length;j++){
      let t=r;while(t<M.length&&!M[t][j])t++;
      if(t===M.length)continue;
      [M[r],M[t]]=[M[t],M[r]];
      let inv=1;while(mod(inv*M[r][j])!==1)inv++;
      M[r]=M[r].map(v=>mod(v*inv));
      for(let k=0;k<M.length;k++)if(k!==r&&M[k][j]){
        const a=M[k][j];M[k]=M[k].map((v,h)=>mod(v-a*M[r][h]));
      }
      r++;
    }
    return r;
  };
  let seed=20261108, assertions=0;
  const rnd=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return (seed>>>0)%q;};
  const test=(ok,label)=>{assertions++;if(!ok)throw Error("R154 checker failure "+label+" #"+assertions)};
  const cases=[
    {label:"TRUE_x_or_y",gs:[mul(x,sub(x,one)),mul(y,sub(y,one)),mul(sub(one,x),sub(one,y))],valid:[[1,0],[0,1],[1,1]]},
    {label:"FALSE_x_and_not_x",gs:[mul(x,sub(x,one)),mul(y,sub(y,one)),x,sub(one,x)],valid:[]}
  ], rows=[];
  for(const fixture of cases){
    const cs=colsFrom(fixture.gs), A=matFrom(cs);
    const rk=rank(A),rank1=rank(A.map((row,i)=>[...row,one[i]]));
    test(rank1-rk===(fixture.valid.length?1:0),fixture.label+" constant span");
    fixture.valid.forEach(w=>fixture.gs.forEach(g=>test(evalAt(g,w)===0,"constraint satisfied")));
    for(let rep=0;rep<30;rep++){
      const coins=cs.map(()=>rnd()),K=rnd();
      const C=one.map((e,i)=>mod(K*e+cs.reduce((s,c,j)=>s+coins[j]*c[i],0)));
      if(fixture.valid.length){
        const all=solve(A.map((row,i)=>[...row,one[i]]),C);
        test(all!==null&&all[all.length-1]===K,"public coefficient recovery");
        for(const w of fixture.valid)test(evalAt(C,w)===K,"every witness same K");
      } else {
        const t=solve(A,one);
        test(t!==null,"false constant certificate");
        const newCoins=coins.map((v,i)=>mod(v+K*t[i]));
        const C0=one.map((_,i)=>mod(cs.reduce((s,c,j)=>s+newCoins[j]*c[i],0)));
        test(C.every((v,i)=>v===C0[i]),"false exact remasking");
      }
    }
    rows.push({fixture:fixture.label,variables:2,monomials:mons.length,columns:cs.length,rank:rk,rankPlusConstant:rank1,validWitnesses:fixture.valid.length,trials:30});
  }
  return {run:"R154",q,D,assertions,rows,scope:"Exact finite-field algebra only; no QPT hardness or general witness encryption claim."};
})()
\`\`\`

## Captured executed output

\`\`\`json
{
  "run": "R154",
  "q": 7,
  "D": 3,
  "assertions": 191,
  "rows": [
    {
      "fixture": "TRUE_x_or_y",
      "variables": 2,
      "monomials": 10,
      "columns": 9,
      "rank": 7,
      "rankPlusConstant": 8,
      "validWitnesses": 3,
      "trials": 30
    },
    {
      "fixture": "FALSE_x_and_not_x",
      "variables": 2,
      "monomials": 10,
      "columns": 18,
      "rank": 10,
      "rankPlusConstant": 10,
      "validWitnesses": 0,
      "trials": 30
    }
  ],
  "scope": "Exact finite-field algebra only; no QPT hardness or general witness encryption claim."
}
\`\`\`
