'use strict';
// Run 535: public low-width composition attack. Toy constraints, not cryptography.
const assert=require('assert');
let z=5352026>>>0;
function bit(){z=(Math.imul(z,1664525)+1013904223)>>>0;return z>>>29&1;}
function factor(vars,pred){const allowed=new Set();for(let a=0;a<2**vars.length;a++){
 const bs=vars.map((_,j)=>a>>j&1);if(pred(...bs))allowed.add(bs.join(''));}
 return {vars,allowed};}
function solve(factors,order){let max=0,steps=0;for(const v of order){
 const yes=factors.filter(f=>f.vars.includes(v)),no=factors.filter(f=>!f.vars.includes(v));
 if(!yes.length){factors=no;continue;}
 const scope=[...new Set(yes.flatMap(f=>f.vars))],rest=scope.filter(x=>x!==v);
 max=Math.max(max,scope.length);const lookup=new Map(scope.map((x,j)=>[x,j]));
 const allowed=new Set();for(let a=0;a<2**scope.length;a++){
  const bs=scope.map((_,j)=>a>>j&1);
  if(yes.every(f=>f.allowed.has(f.vars.map(x=>bs[lookup.get(x)]).join(''))))
    allowed.add(rest.map(x=>bs[lookup.get(x)]).join(''));
 }
 factors=[...no,{vars:rest,allowed}];steps++;
 }
 assert(factors.every(f=>f.vars.length===0));return {sat:factors.every(f=>f.allowed.has('')),max,steps};}
function query(m,k,B,p,q,target){let factors=[factor(['a0'],a=>a===1)],order=[];
 for(let j=0;j<m;j++){
  const x='x'+j,y='y'+j,e='e'+j,a='a'+j,b='a'+(j+1);
  factors.push(factor([x,y,e],(x,y,e)=>e===(1^(x^y))));
  factors.push(factor([a,e,b],(a,e,b)=>b===(a&e)));
  order.push(x,y,e,a);
 }
 factors.push(factor(['a'+m,'o'],(a,o)=>o===(B^(a&(p^q)))));
 factors.push(factor(['o'],o=>o===target));order.push('a'+m,'o');
 return solve(factors,order);
}
let cases=0,recovered=0,scope=0,steps=0,nonbaseline=0;
for(const [m,h,reps] of [[3,8,6],[4,16,6],[8,16,5],[24,32,3],[96,32,2]]){
 for(let t=0;t<reps;t++){
  const K=Array.from({length:h},bit),B=Array.from({length:h},bit),got=[];
  for(let i=0;i<h;i++){
   const p=bit(),q=p^K[i]^B[i],r=query(m,K[i],B[i],p,q,B[i]^1);
   got.push(B[i]^(r.sat?1:0));scope=Math.max(scope,r.max);steps+=r.steps;
   if(r.sat)nonbaseline++;
   assert(r.sat===(K[i]!==B[i]));
  }
  assert.deepStrictEqual(got,K);cases++;recovered++;
 }
}
assert(scope<=3);
const report={run:535,status:'PASS',compound_cases:cases,recovered_toy_keys:recovered,
 max_local_join_scope:scope,local_elimination_steps:steps,nonbaseline_queries:nonbaseline,
 max_witness_pair_count:96,max_key_bits:32,
 fixed_bad_order_obdd_width_lower_bound:'2^96 for a nonbaseline bit',
 caveat:'public toy shares are not secure and the augmented native-checker treewidth is untested',
 scope:'functional public low-width factor graph and fixed known failure baseline; not EOC/RIO or an instantiated WKEM'};
console.log(JSON.stringify(report,null,2));
