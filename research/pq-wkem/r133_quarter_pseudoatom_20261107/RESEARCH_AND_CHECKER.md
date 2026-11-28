# R133 — quarter-pseudoatom leakage in the R132 ORIGINAL-source projection

**Classification:** structural negative, not a secure ORIGINAL witness-KEM construction; no user-facing notification or ordinary PR progress comment. No external internet research.

## Exact continuity and model

PR #1 on branch research/pq-wkem-validation-20260918, observed starting head 1a5db1bb569d31148a2c916835084e4e1d85310d. R132's exact prior file was \`research/pq-wkem/r132_atom_level2_20261107/RESEARCH_AND_CHECKER.md\`, blob \`7ffdaac67810d31e6a61e24fe94b1e171bf82873\`. The ordinary PR issue comments through ID 6698876958 were read. The R132 signed **integer** pseudoatom already disproved its direct source. This follow-up investigates whether PCP-like norm-gap amplification of integer solutions could ever establish false-instance privacy of the *same public linear source*. The new result is a polynomial distinguishing attack independent of any integer short-solution gap.

For proper ORIGINAL 3CNF x with n Boolean variables, p used variable pairs, and m clauses, R132 forms public integer P_x r=t_x with B=n+p+m blocks: a 2-atom block per variable, a 4-atom block per used pair and an 8-atom literal-truth block per clause. Each block sums to one. Clause 000 is forbidden, and all singleton/pairwise clause marginals must agree with global variable/pair marginals (respecting negations). Any genuine satisfying assignment is a one-hot integer solution with l1 norm B.

Choose odd q, Delta=(q-1)/2, independent bounded integer noise eta_0,eta_i in [-h,h], hidden g distributed as a real ordinary LWE sample A^T s+e (or uniform in an attempted QPT-LWE hybrid), and key bit K. Public source:
  u=P_x^T g+eta mod q
  v=t_x^T g+eta_0+Delta*K mod q.
The joint public view may contain x, A, verification/checking key, context, claim/branch/anchor data, auxiliary data, related capsules and quantum advice. The attack ignores all extra fields, so including them cannot erase the leakage. It does not assume any SourceOpen oracle or adversary-volunteered representation.

## Public quarter-pseudoatom

Define integer R_x in polynomial time, without an ORIGINAL witness:
* Every variable block is (2,2).
* Every used pair block is (1,1,1,1).
* Every clause block has coefficient 1 on odd-parity literal-truth triples {100,010,001,111} and 0 on the other four, including forbidden 000.

All blocks sum to 4. Odd parity has exactly two atoms with any chosen singleton bit true and exactly one atom with any chosen *pair* of bits true. Variable and pair blocks have the same marginals, independent of literal polarity. Thus **for every TRUE or FALSE x**:
  P_x R_x=4 t_x, and ||R_x||_1=4B.
R_x/4 is a nonnegative rational locally consistent pseudo-distribution, not a valid Boolean assignment and not a certified short INTEGER solution. It survives any change of x that merely improves the length of INVALID INTEGER solutions, including a gap-transformed formula whose atom matrix has exactly this layout.

## Exact leakage theorem

Set H=4h(B+1), and require q>2(H+2). The public adversary computes
  Z=center_q(4v-R_x^T u).
By the displayed linear identity,
  4v-R_x^T u = 4Delta K + X (mod q),
  X=4eta_0-R_x^T eta, |X|<=H.
Since 4Delta=2q-2=-2 (mod q), and there is no centered modular wrap,
  **Z=X-2K** as an ordinary integer.
All coordinates of the genuine scalar-LWE sample g cancel identically. This attack applies whether g is real LWE, uniform, or otherwise correlated with fields the adversary ignores.

The following classical randomized polynomial-time output test needs no noise distribution knowledge: draw uniform integer T in {0,...,2(H+2)-1}; output 1 iff T<Z+H+2. This is well-defined because -H-2<=Z<=H. The two challenge worlds yield an *exact* probability gap
  |Pr[A(C_0)=1]-Pr[A(C_1)=1]| = 1/(H+2) = 1/(4h(B+1)+2).
In an equal-prior KEY-BIT guessing game the success advantage above 1/2 is half this probability gap. For polynomial h and B the leakage is inverse polynomial, violating full-public FALSE-instance *bit semantic indistinguishability*. The theorem does NOT establish full native-signature recovery, and does NOT break standard LWE. It applies specifically to this scalar linear projection with odd q, near-half Delta and the stated no-wrap inequality; it is not a general WE impossibility theorem.

## Bounded execution

The exact self-contained V8 checker below was executed twice, both times producing exactly 641 assertions and identical JSON. It compiles complete actual P,t rows for an unsatisfiable eight-clause 3-variable formula and two satisfying mixed-negation examples, checks the quarter-pseudoatom identities against all rows, and checks residual cancellation on actual toy LWE and uniform-g tapes. In the FALSE case, n=3, p=3, m=8, B=14, rows=76, coordinates=82, H=60 with q=65521,h=1,Delta=32760. The constructed distinguishing gap is exactly 1/62. The embedded checker also independently counts an exact convolution over 3^51 noise tapes; its deterministic sign-threshold advantage is approximately 0.104919906662. These are algebraic/statistical checks, NOT a QPT hardness experiment. Independent local CPython checkers under /mnt/data/R133_RATIONAL_PSEUDOATOM_NOISE_LEAK_20261107 verified 672 assertions and a second exact noise dynamic program, and reproduced byte-identical captures; they are local-only, not GitHub-published in this artifact. One initial local Python syntax error was corrected before successful execution.

**Unresolved and next exact step:** The ORIGINAL-dependent release must enforce Boolean gate/multiplicative constraints *cryptographically within the release operation*, rather than only requiring a short integer certificate in an external predicate. A genuine successor must instantiate its classically PPT source opening and a QPT-LWE simulator together, including all checking-key, auxiliary, multiple-capsule and selective-opening correlations. More importantly, ANY unauthorized hard-TRUE final-key recovery/native forgery must imply an actual ORIGINAL witness or an independently justified QPT break, without volunteering a representation. R133 supplies no such construction and no efficiency work.

## Exact executed V8 checker (source)

\`\`\`javascript
function r133Checker() {
 let checks=0,seed=1330711;
 function ck(ok,s){checks++;if(!ok)throw Error("R133 "+checks+": "+s);}
 function rand(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;}
 const rng=n=>rand()%n,q=65521,Delta=(q-1)/2,h=1;
 const mod=x=>((x%q)+q)%q, dot=(a,b)=>a.reduce((s,v,i)=>s+v*b[i],0);
 function compile(n,clauses){
  const ps=new Map();
  for(const clause of clauses)for(let i=0;i<3;i++)for(let j=i+1;j<3;j++){
   const a=Math.min(clause[i][0],clause[j][0]),b=Math.max(clause[i][0],clause[j][0]);
   ps.set(a+":"+b,[a,b]);
  }
  const pairs=[...ps.values()].sort((x,y)=>x[0]-y[0]||x[1]-y[1]);
  const blocks=[];
  for(let i=0;i<n;i++)blocks.push(["v"+i,2]);
  for(const [a,b] of pairs)blocks.push([`p${a}_${b}`,4]);
  clauses.forEach((_,i)=>blocks.push(["c"+i,8]));
  const offsets={},lengths={};let N=0;
  for(const [name,sz] of blocks){offsets[name]=N;lengths[name]=sz;N+=sz;}
  const rows=[],rhs=[];
  function row(terms,b){const r=Array(N).fill(0);for(const [name,k,pred] of terms)
   for(let i=0;i<lengths[name];i++)if(pred(i))r[offsets[name]+i]+=k;
   rows.push(r);rhs.push(b);}
  for(const [name] of blocks)row([[name,1,()=>true]],1);
  for(const [a,b] of pairs)for(const [v,pos] of [[a,0],[b,1]])
   row([[`p${a}_${b}`,1,i=>((i>>(1-pos))&1)===1],[`v${v}`,-1,i=>i===1]],0);
  for(let j=0;j<clauses.length;j++){
   const clause=clauses[j],name="c"+j;
   row([[name,1,i=>i===0]],0);
   for(let z=0;z<3;z++){
    const [v,sign]=clause[z];
    row([[name,1,i=>((i>>(2-z))&1)===1],[`v${v}`,-1,i=>i===Number(sign)]],0);
   }
   for(const [z,t] of [[0,1],[0,2],[1,2]]){
    const [v,sv]=clause[z],[w,sw]=clause[t],a=Math.min(v,w),b=Math.max(v,w);
    const va=v===a?sv:sw,vb=w===b?sw:sv;
    row([[name,1,i=>((i>>(2-z))&1)===1&&((i>>(2-t))&1)===1],
      [`p${a}_${b}`,-1,i=>((i>>1)&1)===Number(va)&&(i&1)===Number(vb)]],0);
   }
  }
  const R=Array(N).fill(0);
  for(const [name,sz] of blocks){
   const values=name[0]==="v"?[2,2]:name[0]==="p"?[1,1,1,1]:
    Array.from({length:8},(_,i)=>((i>>2)+(i>>1&1)+(i&1))%2);
   ck(values.length===sz,"block length");
   for(let i=0;i<sz;i++)R[offsets[name]+i]=values[i];
  }
  return {rows,rhs,R,B:blocks.length};
 }
 const all=Array.from({length:8},(_,i)=>[Boolean((i>>2)&1),Boolean((i>>1)&1),Boolean(i&1)]);
 const tests=[{name:"FALSE_8",n:3,clauses:all.map(s=>s.map((v,i)=>[i,v]))},
 {name:"TRUE_mixed",n:3,clauses:[[[0,true],[1,false],[2,true]],[[0,false],[1,true],[2,false]]]},
 {name:"TRUE_graph",n:5,clauses:[[[0,true],[2,false],[4,true]],[[1,false],[2,true],[3,true]],[[0,false],[3,false],[4,false]]]}];
 const cases=[];
 for(const test of tests){
  const {rows,rhs,R,B}=compile(test.n,test.clauses);
  rows.forEach((row,i)=>ck(dot(row,R)===4*rhs[i],"quarter atom equation"));
  const l1=R.reduce((s,v)=>s+Math.abs(v),0),H=4*h*(B+1);
  ck(l1===4*B,"l1");ck(q>2*(H+2),"no wrap");ck(mod(4*Delta)===q-2,"key shift");
  for(const mode of ["real-LWE","uniform"])for(let K=0;K<2;K++)for(let z=0;z<13;z++){
   let g;
   if(mode==="uniform")g=rows.map(()=>rng(q));
   else {
    const d=4,A=Array.from({length:d},()=>rows.map(()=>rng(q))),s=Array.from({length:d},()=>rng(q));
    g=rows.map((_,i)=>mod(A.reduce((total,col,j)=>total+col[i]*s[j],0)+rng(3)-1));
   }
   const eta=R.map(()=>rng(3)-1),eta0=rng(3)-1;
   const u=R.map((_,j)=>mod(rows.reduce((total,row,i)=>total+row[j]*g[i],0)+eta[j]));
   const v=mod(dot(rhs,g)+eta0+Delta*K);
   let residual=mod(4*v-dot(R,u));if(residual>q/2)residual-=q;
   const X=4*eta0-dot(R,eta);
   ck(residual===X-2*K,"LWE cancellation");
   ck(Math.abs(X)<=H,"error bounded");
  }
  cases.push({name:test.name,B,equations:rows.length,coordinates:R.length,H,advantage:`1/${H+2}`});
 }
 let dist=new Map([[0,1n]]);
 for(const a of [4,...Array(6).fill(2),...Array(44).fill(1)]){
  const next=new Map();
  for(const [x,n] of dist)for(const z of [-a,0,a])next.set(x+z,(next.get(x+z)||0n)+n);
  dist=next;
 }
 const allCount=[...dist.values()].reduce((a,b)=>a+b,0n);
 ck(allCount===3n**51n,"exact total");
 ck(dist.size===121,"full support");
 for(const [x,v] of dist)ck(v===dist.get(-x),"symmetry");
 const moment=[...dist].reduce((s,[x,v])=>s+BigInt(x)*v,0n);
 ck(moment===0n,"zero mean");
 const thresholdGap=Number(dist.get(0)+dist.get(1))/Number(allCount);
 ck(thresholdGap>0.10&&thresholdGap<0.11,"threshold advantage");
 return {run:"R133-quarter-pseudoatom-LWE-leak-20261107",classification:"structural negative, not a generic WKEM advance",checks,cases,
  false8:{randomized_test_gap:"1/62",deterministic_threshold_gap:thresholdGap.toFixed(12),sample_space_size:allCount.toString()}};
}
console.log(JSON.stringify(r133Checker(),null,2));
\`\`\`

## Exact captured V8 result

\`\`\`json
{
  "run": "R133-quarter-pseudoatom-LWE-leak-20261107",
  "classification": "structural negative, not a generic WKEM advance",
  "checks": 641,
  "cases": [
    {
      "name": "FALSE_8",
      "B": 14,
      "equations": 76,
      "coordinates": 82,
      "H": 60,
      "advantage": "1/62"
    },
    {
      "name": "TRUE_mixed",
      "B": 8,
      "equations": 28,
      "coordinates": 34,
      "H": 36,
      "advantage": "1/38"
    },
    {
      "name": "TRUE_graph",
      "B": 16,
      "equations": 53,
      "coordinates": 66,
      "H": 68,
      "advantage": "1/70"
    }
  ],
  "false8": {
    "randomized_test_gap": "1/62",
    "deterministic_threshold_gap": "0.104919906662",
    "sample_space_size": "2153693963075557766310747"
  }
}
\`\`\`
